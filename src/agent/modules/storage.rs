//! Storage inspection and configuration module.
//!
//! Surfaces host storage state (`/proc/mounts`, `/proc/partitions`, `df`) and
//! performs mount/unmount and `/etc/fstab` edits. The `mount` and `configure`
//! actions also accept the shared `selinux` payload so the control plane can
//! label a freshly mounted or configured path in the same request — important
//! on SELinux-enabled hosts where an unlabeled mount point would be denied
//! access to its intended service.

use serde_json::json;

use crate::actions;
use crate::agent::modules::Mod;
use crate::prelude::*;

use crate::agent::module_support::{
    ModuleInfo, ModuleStatus, SelinuxOptions, apply_selinux, option_arg, positional, run_for,
};
use std::process::Command;

/// Storage module entry point registered under feature `storage`.
#[derive(Clone, Copy, Debug)]
pub struct StorageModule;

/// Static capability metadata published via `capabilities`/`plan`.
const INFO: ModuleInfo = ModuleInfo {
    name: "storage",
    feature: "storage",
    description: "Inspect disks, filesystems, mounts, and storage-related configuration.",
    status: ModuleStatus::Available,
    actions: &[
        "capabilities",
        "plan",
        "list",
        "status",
        "zfs",
        "mount",
        "unmount",
        "configure",
    ],
    privileged_actions: &["mount", "unmount", "configure"],
};

impl Mod for StorageModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    List => Ok(json!({
        // unwrap_or_default swallows read/parse errors and yields an
        // empty list — `list` is best-effort inventory, not a health
        // probe, so a missing `/proc/*` file should not fail the call.
        "mounts": read_mounts("/proc/mounts").unwrap_or_default(),
        "partitions": read_partitions("/proc/partitions").unwrap_or_default(),
    })),
    Status {
        path: PathBuf,
        #[serde(default)]
        dry_run: bool,
    } => {
        let result = run_for(
            &INFO, "status", user,
            "df", ["-h", positional("path", &payload.path.to_string_lossy())?], false,
        )?.into_json();
        Ok(json!({ "result": result, "dry_run": payload.dry_run, "zfs": discover_zfs() }))
    },
    Zfs => Ok(discover_zfs()),
    Mount {
        source: String,
        target: String,
        fstype: Option<String>,
        options: Option<String>,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        selinux: Option<SelinuxOptions>,
    } => {
        let mut args = Vec::new();
        option_arg(&mut args, "-t", payload.fstype);
        option_arg(&mut args, "-o", payload.options);
        let target = PathBuf::from(&payload.target);
        positional("source", &payload.source)?;
        positional("target", &payload.target)?;
        args.extend([payload.source, payload.target]);
        let mount = run_for(&INFO, "mount", user, "mount", &args, payload.dry_run)?.into_json();
        let selinux = apply_selinux(payload.selinux.as_ref(), Some(&target), payload.dry_run)?;
        Ok(json!({ "mount": mount, "selinux": selinux }))
    },
    Unmount {
        path: PathBuf,
        #[serde(default)]
        dry_run: bool,
    } => Ok(run_for(
        &INFO, "unmount", user,
        "umount", [positional("path", &payload.path.to_string_lossy())?], payload.dry_run,
    )?.into_json()),
    Configure {
        #[serde(default = "default_fstab_path")]
        fstab_path: PathBuf,
        entry: String,
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        selinux: Option<SelinuxOptions>,
    } => {
        validate_fstab_entry(&payload.entry)?;
        if !payload.dry_run {
            append_fstab_entry(&payload.fstab_path, &payload.entry)?;
        }
        let selinux = apply_selinux(
            payload.selinux.as_ref(),
            Some(&payload.fstab_path),
            payload.dry_run,
        )?;
        Ok(json!({
            "fstab_path": payload.fstab_path,
            "configured": !payload.dry_run,
            "dry_run": payload.dry_run,
            "selinux": selinux,
        }))
    },
});

/// Discover ZFS without making its absence an error. Distributions may expose
/// the tools in different locations, so invoking by PATH is preferable to
/// assuming `/usr/sbin` or `/sbin`. Both commands are read-only.
fn discover_zfs() -> Value {
    let kernel_module = Path::new("/sys/module/zfs").exists()
        || fs::read_to_string("/proc/modules")
            .is_ok_and(|modules| modules.lines().any(|line| line.starts_with("zfs ")));
    let (tooling, pools) = run_zfs_list(
        "zpool",
        &[
            "list",
            "-H",
            "-p",
            "-o",
            "name,size,alloc,free,frag,cap,dedupratio,health,altroot",
        ],
        &[
            "name",
            "size",
            "allocated",
            "free",
            "fragmentation",
            "capacity",
            "deduplication",
            "health",
            "altroot",
        ],
    );
    let (zfs_tooling, datasets) = run_zfs_list(
        "zfs",
        &[
            "list",
            "-H",
            "-p",
            "-o",
            "name,used,available,refer,mountpoint",
        ],
        &["name", "used", "available", "referenced", "mountpoint"],
    );
    json!({
        "available": kernel_module || tooling || zfs_tooling,
        "kernel_module": kernel_module,
        "tools": tooling || zfs_tooling,
        "pools": pools,
        "datasets": datasets,
    })
}

fn run_zfs_list(program: &str, args: &[&str], fields: &[&str]) -> (bool, Vec<Value>) {
    // Under the timeout: `zfs`/`zpool` block indefinitely on a suspended pool.
    let output = match crate::agent::module_support::output_with_timeout(
        Command::new(program).args(args),
        None,
    ) {
        Ok((output, _)) if output.status.success() => output,
        _ => return (false, Vec::new()),
    };
    let rows = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let values: Vec<_> = line.split('\t').collect();
            (values.len() == fields.len()).then(|| {
                fields
                    .iter()
                    .zip(values)
                    .map(|(field, value)| ((*field).to_owned(), Value::String(value.to_owned())))
                    .collect::<serde_json::Map<String, Value>>()
            })
        })
        .map(Value::Object)
        .collect();
    (true, rows)
}

/// Default fstab location used when `configure` is invoked without an
/// explicit `fstab_path`.
fn default_fstab_path() -> PathBuf {
    PathBuf::from("/etc/fstab")
}

/// Parses `/proc/mounts`, whose rows are whitespace-delimited as
/// `source target fstype opts dump pass`. Only the first four fields are
/// surfaced; rows with fewer than four fields are skipped rather than
/// erroring, so a malformed kernel-provided line never breaks the call.
fn read_mounts(path: impl Into<PathBuf>) -> Result<Vec<Value>> {
    let path = path.into();
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read mounts `{}`", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 4).then(|| {
                json!({
                    "source": fields[0],
                    "target": fields[1],
                    "filesystem": fields[2],
                    "options": fields[3],
                })
            })
        })
        .collect())
}

/// Parses `/proc/partitions`, which has a two-line header (a column line
/// followed by a blank line) and then `major minor blocks name` rows.
/// `skip(2)` drops the header; the strict four-field filter then keeps only
/// real partition rows.
fn read_partitions(path: impl Into<PathBuf>) -> Result<Vec<Value>> {
    let path = path.into();
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read partitions `{}`", path.display()))?;
    Ok(text
        .lines()
        .skip(2)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() == 4).then(|| {
                json!({
                    "major": fields[0],
                    "minor": fields[1],
                    "blocks": fields[2],
                    "name": fields[3],
                })
            })
        })
        .collect())
}

/// Appends a single entry to an fstab file safely.
///
/// Reads the existing file (treating a missing file as empty), guarantees a
/// newline separates any existing content from the new entry, trims trailing
/// whitespace from the entry, and ensures the file ends with exactly one
/// newline. This sidesteps the two common fstab foot-guns: joining two lines
/// into one (no separator), and leaving the file without a terminating
/// newline (which some fstab parsers reject).
///
/// Only a missing file counts as empty: any other read error would otherwise
/// rewrite `/etc/fstab` with just the new entry. The file is replaced
/// atomically.
fn append_fstab_entry(path: &Path, entry: &str) -> Result<()> {
    let mut text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read `{}`", path.display()));
        }
    };
    // Only add a separator when there is existing content that lacks a
    // trailing newline; an empty file or one already ending in `\n` needs
    // none, and adding one would create a stray blank line.
    if !text.ends_with('\n') && !text.is_empty() {
        text.push('\n');
    }
    text.push_str(entry.trim_end());
    // Always terminate the file with a newline so subsequent appends and most
    // fstab parsers stay happy.
    text.push('\n');
    crate::auth::store::replace(path, text.as_bytes(), 0o644)
}

/// One fstab line: `spec file [vfstype [options [freq [passno]]]]`.
fn validate_fstab_entry(entry: &str) -> Result<()> {
    let entry = entry.trim();
    ensure!(
        !entry.contains(['\n', '\r'])
            && !entry.starts_with('#')
            && (2..=6).contains(&entry.split_whitespace().count()),
        "fstab entry must be one line of 2 to 6 fields"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::modules::Act;

    #[test]
    fn absent_zfs_is_reported_without_failing() {
        let discovery = discover_zfs();
        assert!(discovery["pools"].is_array());
        assert!(discovery["datasets"].is_array());
    }

    #[test]
    fn parses_mounts_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mounts");
        fs::write(&path, "/dev/sda1 / ext4 rw,relatime 0 0\n").unwrap();

        let mounts = read_mounts(path).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0]["source"], "/dev/sda1");
        assert_eq!(mounts[0]["target"], "/");
        assert_eq!(mounts[0]["filesystem"], "ext4");
    }

    #[test]
    fn parses_partitions_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partitions");
        fs::write(
            &path,
            "major minor  #blocks  name\n\n   8        0  976762584 sda\n",
        )
        .unwrap();

        let partitions = read_partitions(path).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0]["name"], "sda");
        assert_eq!(partitions[0]["blocks"], "976762584");
    }

    #[test]
    fn appends_fstab_entries_with_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fstab");
        fs::write(&path, "/dev/sda1 / ext4 defaults 0 1").unwrap();

        append_fstab_entry(&path, "/dev/sdb1 /data ext4 defaults 0 2").unwrap();

        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "/dev/sda1 / ext4 defaults 0 1\n/dev/sdb1 /data ext4 defaults 0 2\n"
        );
    }

    #[test]
    fn dry_run_configure_does_not_write_fstab() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fstab");
        fs::write(&path, "/dev/sda1 / ext4 defaults 0 1\n").unwrap();

        let response = Configure {
            fstab_path: path.clone(),
            entry: "/dev/sdb1 /data ext4 defaults 0 2".into(),
            dry_run: true,
            selinux: None,
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["configured"], false);
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "/dev/sda1 / ext4 defaults 0 1\n"
        );
    }

    #[test]
    fn dry_run_mount_does_not_call_mount() {
        let response = Mount {
            source: "/dev/example".into(),
            target: "/mnt/example".into(),
            fstype: None,
            options: None,
            dry_run: true,
            selinux: None,
        }
        .handle(None)
        .unwrap();

        assert_eq!(
            response["mount"]["command"],
            "mount /dev/example /mnt/example"
        );
        assert_eq!(response["mount"]["dry_run"], true);
        assert!(response["mount"]["status"].is_null());
    }

    #[test]
    fn mount_can_apply_selinux_context_to_target() {
        let response = Mount {
            source: "/dev/example".into(),
            target: "/srv/data".into(),
            fstype: None,
            options: None,
            dry_run: true,
            selinux: Some(SelinuxOptions {
                context_type: Some("container_file_t".into()),
                recursive: true,
                ..SelinuxOptions::default()
            }),
        }
        .handle(None)
        .unwrap();

        assert_eq!(response["selinux"].as_array().unwrap().len(), 2);
        assert_eq!(
            response["selinux"][0]["command"],
            "semanage fcontext -a -t container_file_t /srv/data(/.*)?"
        );
        assert_eq!(
            response["selinux"][1]["command"],
            "restorecon -R -v /srv/data"
        );
    }
}
