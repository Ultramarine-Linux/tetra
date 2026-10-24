//! File read/write module for managed host configuration.
//!
//! `files` is the lowest-level persistence module: it lets the control plane
//! read an arbitrary path and write contents to it, optionally relabeling the
//! result with SELinux via the shared `apply_selinux` helper. Other modules
//! (network, quadlets, samba, nfs, storage) reuse the same write + SELinux
//! pattern but scope writes to their own managed paths; this module is the
//! general-purpose escape hatch.

use crate::agent::module_support::apply_selinux;
use crate::prelude::*;

use crate::types::{FileReadRequest, FileWriteRequest};

/// Marker type for the files module. Stateless; all behavior lives in the
/// [`Mod`] impl and the static [`INFO`] descriptor.
#[derive(Clone, Copy, Debug)]
pub struct FilesModule;

const INFO: ModuleInfo = ModuleInfo {
    name: "files",
    feature: "files",
    description: "Read and write host files for managed configuration.",
    status: ModuleStatus::Available,
    actions: &["capabilities", "read", "write"],
    privileged_actions: &["write"],
};

impl Mod for FilesModule {
    fn info(&self) -> ModuleInfo {
        INFO
    }

    fn handle(&self, action: &str, payload: Value, user: Option<&str>) -> Result<Value> {
        // Delegate `capabilities`/`plan` to the module descriptor first.
        if let Some(response) = INFO.metadata_response(action, &payload) {
            return Ok(response);
        }
        Action::from_payload(action, payload)?.handle(user)
    }
}

actions!(Action [payload user] => {
    Read: FileReadRequest => {
        Ok(jsonf! { payload.path, "contents": payload.read()? })
    },
    Write: FileWriteRequest => {
        // Skip the actual write in dry-run; the SELinux plan below is
        // still computed and echoed back so callers can preview it.
        payload.write()?;
        // `apply_selinux` is a no-op when no options are supplied, so
        // calling it unconditionally is safe. It returns a list of
        // command-result objects (empty when nothing was requested).
        let selinux = apply_selinux(
            payload.selinux.as_ref(),
            Some(&payload.path),
            payload.dry_run,
        )?;
        Ok(jsonf! { payload.path, "written": !payload.dry_run, payload.dry_run, selinux })
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::module_support::SelinuxOptions;

    #[test]
    fn dry_run_write_does_not_create_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.conf");
        let response = Write(FileWriteRequest {
            path,
            contents: "enabled=true\n".into(),
            dry_run: true,
            selinux: None,
        })
        .handle(None)
        .unwrap();

        assert_eq!(response["written"], false);
        assert_eq!(response["dry_run"], true);
        assert!(!dir.path().join("managed.conf").exists());
    }

    #[test]
    fn write_can_apply_selinux_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed.conf");
        let response = Write(FileWriteRequest {
            path,
            contents: "enabled=true\n".to_owned(),
            dry_run: true,
            selinux: Some(SelinuxOptions {
                context_type: Some("container_file_t".to_owned()),
                ..SelinuxOptions::default()
            }),
        })
        .handle(None)
        .unwrap();

        assert_eq!(response["selinux"].as_array().unwrap().len(), 2);
        assert!(
            response["selinux"][0]["command"]
                .as_str()
                .unwrap()
                .contains("semanage fcontext -a -t container_file_t")
        );
        assert!(
            response["selinux"][1]["command"]
                .as_str()
                .unwrap()
                .contains("restorecon -v")
        );
    }
}
