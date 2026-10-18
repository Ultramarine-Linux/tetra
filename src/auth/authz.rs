//! Authorization: who may run which module action.
//!
//! Every action maps to a [`Requirement`] in [`requirement`]. Permissions are
//! grouped by dashboard [`Page`] with a `view` and a `manage` [`Level`];
//! `manage` implies `view`.
//!
//! - Administrators (`ultramarine-admin` or `wheel`) may run everything.
//! - Other users get `services: view` by default, plus whatever an
//!   administrator granted them, stored per UID in
//!   `/var/lib/tetra/auth/grants.json`.
//! - Actions that are root-equivalent are [`Requirement::AdminOnly`] and can
//!   never be granted: managing users, writing files, changing settings and
//!   SELinux, mounting or configuring storage, and anything that manages
//!   rootful systemd units, containers or VMs. Apps are installed as system-scope units today, so app management is
//!   admin-only too; it becomes grantable once apps run rootless under
//!   `ultramarine-apps`.
//! - Actions missing from the table are admin-only, so a new action is never
//!   accidentally open. A test checks that every action of every compiled
//!   module is listed.
//! - The setup session may only run the actions in [`SETUP_ALLOWED`].
//! - Remote controllers (the outbound mTLS control plane) may run everything;
//!   their actions are recorded in the audit log.

use std::collections::BTreeMap;

use crate::prelude::*;

use super::store::{self, Extra, Header, Record, StoreLock};

/// A dashboard page that permissions are grouped by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Page {
    Services,
    Apps,
    Containers,
    Storage,
    Sharing,
    Network,
    VirtualMachines,
    Settings,
    Users,
    Files,
}

impl Page {
    pub const ALL: [Self; 10] = [
        Self::Services,
        Self::Apps,
        Self::Containers,
        Self::Storage,
        Self::Sharing,
        Self::Network,
        Self::VirtualMachines,
        Self::Settings,
        Self::Users,
        Self::Files,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    View,
    Manage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Any logged-in user (metadata such as `capabilities`).
    Authenticated,
    Page(Page, Level),
    AdminOnly,
}

use Level::{Manage, View};
use Page::{
    Apps, Containers, Files, Network, Services, Settings, Sharing, Storage, Users, VirtualMachines,
};
use Requirement::{AdminOnly, Authenticated};

const fn page(page: Page, level: Level) -> Requirement {
    Requirement::Page(page, level)
}

/// `(module, action, requirement)` for every module action.
const TABLE: &[(&str, &str, Requirement)] = &[
    ("settings", "get_system", Authenticated),
    ("settings", "set_hostname", AdminOnly),
    // Services are system units: viewing is the default permission,
    // managing them is admin-only.
    ("services", "list", page(Services, View)),
    ("services", "status", page(Services, View)),
    ("services", "logs", page(Services, View)),
    ("services", "daemon_reload", AdminOnly),
    ("services", "start", AdminOnly),
    ("services", "stop", AdminOnly),
    ("services", "restart", AdminOnly),
    ("services", "enable", AdminOnly),
    ("services", "disable", AdminOnly),
    ("apps", "list", page(Apps, View)),
    ("apps", "get", page(Apps, View)),
    ("apps", "create", AdminOnly),
    ("apps", "update", AdminOnly),
    ("apps", "remove", AdminOnly),
    ("quadlets", "list", page(Apps, View)),
    ("quadlets", "read", page(Apps, View)),
    ("quadlets", "validate", page(Apps, View)),
    ("quadlets", "list_files", page(Apps, View)),
    ("quadlets", "write", AdminOnly),
    ("quadlets", "delete", AdminOnly),
    ("quadlets", "install", AdminOnly),
    ("recipes", "render", page(Apps, View)),
    ("recipes", "render_inline", page(Apps, View)),
    ("recipes", "context", page(Apps, View)),
    ("recipes", "context_inline", page(Apps, View)),
    ("podman", "containers", page(Containers, View)),
    ("podman", "inspect", page(Containers, View)),
    ("podman", "images", page(Containers, View)),
    ("podman", "volumes", page(Containers, View)),
    ("podman", "networks", page(Containers, View)),
    ("podman", "logs", page(Containers, View)),
    ("podman", "start", AdminOnly),
    ("podman", "stop", AdminOnly),
    ("podman", "restart", AdminOnly),
    ("podman", "remove", AdminOnly),
    ("storage", "list", page(Storage, View)),
    ("storage", "status", page(Storage, View)),
    ("storage", "zfs", page(Storage, View)),
    // Mounting and configuring storage is root-equivalent.
    ("storage", "mount", AdminOnly),
    ("storage", "unmount", AdminOnly),
    ("storage", "configure", AdminOnly),
    ("samba", "list_shares", page(Sharing, View)),
    ("samba", "get_config", page(Sharing, View)),
    ("samba", "set_config", page(Sharing, Manage)),
    ("samba", "reload", page(Sharing, Manage)),
    ("samba", "enable", AdminOnly),
    ("samba", "disable", AdminOnly),
    ("nfs", "list_exports", page(Sharing, View)),
    ("nfs", "get_config", page(Sharing, View)),
    ("nfs", "set_config", page(Sharing, Manage)),
    ("nfs", "reload", page(Sharing, Manage)),
    ("nfs", "enable", AdminOnly),
    ("nfs", "disable", AdminOnly),
    ("network", "interfaces", page(Network, View)),
    ("network", "status", page(Network, View)),
    ("network", "dns", page(Network, View)),
    ("network", "routes", page(Network, View)),
    // Network configuration is administrator-only: a bad change can cut the
    // dashboard off. `configure` applies a change that rolls back unless
    // `confirm` follows; the setup session may use that pair as well.
    ("network", "get_config", AdminOnly),
    ("network", "set_config", AdminOnly),
    ("network", "reload", AdminOnly),
    ("network", "configure", AdminOnly),
    ("network", "confirm", AdminOnly),
    ("reverse_proxy", "list", page(Network, View)),
    ("reverse_proxy", "render", page(Network, View)),
    ("reverse_proxy", "write", page(Network, Manage)),
    ("reverse_proxy", "delete", page(Network, Manage)),
    ("reverse_proxy", "reload", page(Network, Manage)),
    ("selinux", "status", page(Settings, View)),
    ("selinux", "booleans", page(Settings, View)),
    ("selinux", "file_contexts", page(Settings, View)),
    ("selinux", "enforce", AdminOnly),
    ("selinux", "set_boolean", AdminOnly),
    ("selinux", "add_file_context", AdminOnly),
    ("selinux", "delete_file_context", AdminOnly),
    ("selinux", "restore_context", AdminOnly),
    ("users", "list", page(Users, View)),
    ("users", "status", page(Users, View)),
    ("users", "groups", page(Users, View)),
    ("users", "create", AdminOnly),
    ("users", "update", AdminOnly),
    ("users", "delete", AdminOnly),
    ("users", "set_password", AdminOnly),
    ("files", "read", page(Files, View)),
    ("files", "write", AdminOnly),
    ("virtual_machines", "list", page(VirtualMachines, View)),
    ("virtual_machines", "status", page(VirtualMachines, View)),
    ("virtual_machines", "logs", page(VirtualMachines, View)),
    ("virtual_machines", "start", AdminOnly),
    ("virtual_machines", "stop", AdminOnly),
    ("virtual_machines", "restart", AdminOnly),
    ("virtual_machines", "create", AdminOnly),
    ("virtual_machines", "delete", AdminOnly),
];

/// What the setup session may run: OOBE operations only. `*` matches every
/// action of a module. Extend this list as the OOBE grows (an updates module
/// will need an entry).
pub const SETUP_ALLOWED: &[(&str, &str)] = &[
    ("agent", "capabilities"),
    ("settings", "get_system"),
    ("settings", "set_hostname"),
    ("network", "configure"),
    ("network", "confirm"),
    ("reverse_proxy", "*"),
    ("users", "list"),
    ("users", "status"),
    ("users", "groups"),
    ("users", "create"),
    ("users", "update"),
    ("users", "set_password"),
];

/// The requirement for `module.action`.
#[must_use]
pub fn requirement(module: &str, action: &str) -> Requirement {
    if matches!(action, "capabilities" | "plan") {
        return Authenticated;
    }
    TABLE
        .iter()
        .find(|(m, a, _)| *m == module && *a == action)
        .map_or(AdminOnly, |(_, _, requirement)| *requirement)
}

/// Whether the setup session may run `module.action`.
#[must_use]
pub fn setup_allows(module: &str, action: &str) -> bool {
    SETUP_ALLOWED
        .iter()
        .any(|(m, a)| *m == module && (*a == "*" || *a == action))
}

/// Whether `level` on `page` can be granted: some action needs exactly it.
#[must_use]
pub fn grantable(page: Page, level: Level) -> bool {
    TABLE
        .iter()
        .any(|(_, _, requirement)| *requirement == Requirement::Page(page, level))
}

/// A user's effective non-admin permissions: the default plus grants.
pub type Permissions = BTreeMap<Page, Level>;

/// Permissions every non-admin has.
#[must_use]
pub fn default_permissions() -> Permissions {
    BTreeMap::from([(Services, View)])
}

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    User {
        uid: u32,
        username: String,
        admin: bool,
        permissions: Permissions,
    },
    Setup,
    RemoteController,
}

impl Principal {
    /// Whether this principal may run `module.action`.
    #[must_use]
    pub fn allows(&self, module: &str, action: &str) -> bool {
        match self {
            Self::RemoteController => true,
            Self::Setup => setup_allows(module, action),
            Self::User {
                admin, permissions, ..
            } => {
                if *admin {
                    return true;
                }
                match requirement(module, action) {
                    Authenticated => true,
                    AdminOnly => false,
                    Requirement::Page(page, level) => {
                        permissions.get(&page).is_some_and(|held| *held >= level)
                    }
                }
            }
        }
    }
}

/// Stored grants, keyed by UID.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GrantsFile {
    #[serde(flatten)]
    header: Header,
    #[serde(default)]
    pub grants: BTreeMap<u32, Permissions>,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for GrantsFile {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

/// `grants.json`.
#[derive(Debug, Clone)]
pub struct GrantStore {
    path: PathBuf,
}

impl GrantStore {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Grants for `uid` (without the defaults).
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn get(&self, uid: u32) -> Result<Permissions> {
        Ok(self.all()?.remove(&uid).unwrap_or_default())
    }

    /// Every stored grant.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn all(&self) -> Result<BTreeMap<u32, Permissions>> {
        Ok(store::read::<GrantsFile>(&self.path)?
            .unwrap_or_default()
            .grants)
    }

    /// Default permissions merged with `uid`'s grants.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn effective(&self, uid: u32) -> Result<Permissions> {
        let mut permissions = default_permissions();
        for (page, level) in self.get(uid)? {
            let entry = permissions.entry(page).or_insert(level);
            *entry = (*entry).max(level);
        }
        Ok(permissions)
    }

    /// Replace `uid`'s grants. `None` for a page removes its grant.
    ///
    /// # Errors
    /// Fails when a grant is not grantable or the file cannot be written.
    pub fn set(&self, uid: u32, changes: &BTreeMap<Page, Option<Level>>) -> Result<Permissions> {
        for (page, level) in changes {
            if let Some(level) = level {
                ensure!(
                    grantable(*page, *level),
                    "{} on {} cannot be granted",
                    serde_json::to_string(level)?,
                    serde_json::to_string(page)?
                );
            }
        }
        let dir = self.path.parent().context("grants path has no parent")?;
        let _lock = StoreLock::acquire(dir)?;
        let mut file = store::read::<GrantsFile>(&self.path)?.unwrap_or_default();
        let grants = file.grants.entry(uid).or_default();
        for (page, level) in changes {
            match level {
                Some(level) => grants.insert(*page, *level),
                None => grants.remove(page),
            };
        }
        let result = grants.clone();
        if result.is_empty() {
            file.grants.remove(&uid);
        }
        store::write(&self.path, &mut file)?;
        Ok(result)
    }
}

/// The permission catalog for the dashboard's grant editor.
#[must_use]
pub fn catalog() -> Value {
    let pages: Vec<Value> = Page::ALL
        .iter()
        .map(|page| {
            jsonf! {
                "page": page,
                "grantable": [View, Manage].into_iter().filter(|level| grantable(*page, *level)).collect::<Vec<_>>(),
                "default": default_permissions().get(page),
            }
        })
        .collect();
    jsonf! { pages }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Dispatcher;

    fn user(admin: bool, permissions: Permissions) -> Principal {
        Principal::User {
            uid: 1000,
            username: "alice".into(),
            admin,
            permissions,
        }
    }

    #[test]
    fn every_compiled_action_is_classified() {
        for module in Dispatcher::full().capabilities() {
            for action in module.actions {
                if matches!(*action, "capabilities" | "plan") {
                    continue;
                }
                assert!(
                    TABLE
                        .iter()
                        .any(|(m, a, _)| *m == module.name && a == action),
                    "{}.{action} is missing from the authorization table",
                    module.name
                );
            }
        }
    }

    #[test]
    fn non_admins_can_view_services_by_default() {
        let alice = user(false, default_permissions());
        assert!(alice.allows("services", "list"));
        assert!(alice.allows("services", "capabilities"));
        assert!(!alice.allows("services", "restart"));
        assert!(!alice.allows("storage", "list"));
        assert!(!alice.allows("users", "create"));
    }

    #[test]
    fn manage_implies_view_and_admins_may_do_anything() {
        let alice = user(false, BTreeMap::from([(Network, Manage)]));
        assert!(alice.allows("network", "status"));
        assert!(alice.allows("reverse_proxy", "write"));
        let admin = user(true, Permissions::new());
        assert!(admin.allows("users", "create"));
        assert!(admin.allows("unknown", "action"));
    }

    #[test]
    fn unknown_actions_are_admin_only() {
        assert_eq!(requirement("services", "format_disk"), AdminOnly);
        assert!(!user(false, default_permissions()).allows("nope", "nope"));
    }

    #[test]
    fn root_equivalent_permissions_cannot_be_granted() {
        for page in [
            Users,
            Files,
            Settings,
            Services,
            Apps,
            Containers,
            VirtualMachines,
            Storage,
        ] {
            assert!(
                !grantable(page, Manage),
                "{page:?} manage must not be grantable"
            );
        }
        for page in Page::ALL {
            assert!(grantable(page, View), "{page:?} view should be grantable");
        }
        assert!(grantable(Network, Manage));
        assert!(grantable(Sharing, Manage));
        let alice = user(false, BTreeMap::from([(Storage, View)]));
        assert!(alice.allows("storage", "list"));
        assert!(!alice.allows("storage", "mount"));
    }

    #[test]
    fn setup_is_limited_to_oobe_actions() {
        let setup = Principal::Setup;
        assert!(setup.allows("users", "create"));
        assert!(!setup.allows("network", "set_config"));
        assert!(setup.allows("settings", "set_hostname"));
        assert!(!setup.allows("files", "write"));
        assert!(!setup.allows("services", "start"));
        assert!(!setup.allows("users", "delete"));
    }

    #[test]
    fn setup_may_only_configure_and_confirm_the_network() {
        let setup = Principal::Setup;
        assert!(setup.allows("network", "configure"));
        assert!(setup.allows("network", "confirm"));
        assert!(!setup.allows("network", "get_config"));
        assert!(!setup.allows("network", "reload"));
    }

    #[test]
    fn network_configuration_is_admin_only() {
        for action in ["get_config", "set_config", "reload", "configure", "confirm"] {
            assert_eq!(
                requirement("network", action),
                AdminOnly,
                "network.{action}"
            );
        }
        let alice = user(false, BTreeMap::from([(Network, Manage)]));
        assert!(alice.allows("network", "status"));
        assert!(!alice.allows("network", "get_config"));
        assert!(!alice.allows("network", "configure"));
        assert!(user(true, Permissions::new()).allows("network", "configure"));
    }

    #[test]
    fn remote_controllers_may_do_anything() {
        assert!(Principal::RemoteController.allows("files", "write"));
    }

    #[test]
    fn grants_are_stored_merged_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let grants = GrantStore::new(dir.path().join("grants.json"));
        grants
            .set(
                1000,
                &BTreeMap::from([(Network, Some(Manage)), (Services, Some(View))]),
            )
            .unwrap();
        let effective = grants.effective(1000).unwrap();
        assert_eq!(effective.get(&Network), Some(&Manage));
        assert_eq!(effective.get(&Services), Some(&View));
        assert_eq!(grants.effective(1001).unwrap(), default_permissions());

        grants
            .set(1000, &BTreeMap::from([(Users, Some(Manage))]))
            .unwrap_err();
        grants
            .set(1000, &BTreeMap::from([(Network, None)]))
            .unwrap();
        assert_eq!(grants.get(1000).unwrap().get(&Network), None);
    }
}
