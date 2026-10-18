//! Authorization: who may run which module action.
//!
//! Every action maps to a [`Requirement`] in [`requirement`]. Permissions are
//! grouped by dashboard [`Page`] with a `view` and a `manage` [`Level`];
//! `manage` implies `view`.
//!
//! - Administrators (`ultramarine-admin` or `wheel`) may run everything.
//! - Other users get `launcher: view` by default (the apps they can open),
//!   plus whatever an administrator granted them, stored per UID in
//!   `/var/lib/tetra/auth/grants.json`. `system_services` (systemd units and
//!   their journal) is administrator-only unless granted.
//! - Actions that are root-equivalent are [`Requirement::AdminOnly`] and can
//!   never be granted: managing users, reading or writing files (the files
//!   module runs as root on any path), changing settings and
//!   SELinux, mounting or configuring storage, and anything that manages
//!   rootful systemd units, containers or VMs. Apps are installed as system-scope units today, so app management is
//!   admin-only too; it becomes grantable once apps run rootless under
//!   `ultramarine-apps`.
//! - Actions missing from the table are admin-only, so a new action is never
//!   accidentally open. A test checks that every action of every compiled
//!   module is listed.
//! - The setup session may only use the operations in [`SETUP_OPERATIONS`]
//!   and run the module actions in [`SETUP_ALLOWED`], each named
//!   individually; actions in [`SETUP_ONLY_WITHOUT_ADMIN`] only while no
//!   eligible administrator exists.
//! - Remote controllers (the outbound mTLS control plane) may run everything;
//!   their actions are recorded in the audit log.

use std::collections::BTreeMap;

use crate::prelude::*;

use super::store::{self, Extra, Header, Record, StoreLock, Tolerant};

/// A dashboard page that permissions are grouped by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Page {
    /// The apps a user can open (`launcher.*` operations).
    Launcher,
    /// Systemd units and their logs. Earlier builds called it `services`.
    #[serde(alias = "services")]
    SystemServices,
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
    /// Name shown in the dashboard's grant editor.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Launcher => "Services",
            Self::SystemServices => "System services",
            Self::Apps => "Apps",
            Self::Containers => "Containers",
            Self::Storage => "Storage",
            Self::Sharing => "Sharing",
            Self::Network => "Network",
            Self::VirtualMachines => "Virtual machines",
            Self::Settings => "Settings",
            Self::Users => "Users",
            Self::Files => "Files",
        }
    }

    pub const ALL: [Self; 11] = [
        Self::Launcher,
        Self::SystemServices,
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
    Apps, Containers, Launcher, Network, Settings, Sharing, Storage, SystemServices, Users,
    VirtualMachines,
};
use Requirement::{AdminOnly, Authenticated};

const fn page(page: Page, level: Level) -> Requirement {
    Requirement::Page(page, level)
}

/// `(module, action, requirement)` for every module action.
const TABLE: &[(&str, &str, Requirement)] = &[
    ("settings", "get_system", Authenticated),
    ("settings", "set_hostname", AdminOnly),
    ("settings", "set_keymap", AdminOnly),
    ("settings", "set_locale", AdminOnly),
    ("settings", "set_timezone", AdminOnly),
    ("power", "reboot", AdminOnly),
    ("power", "poweroff", AdminOnly),
    ("updates", "get_policy", page(Settings, View)),
    ("updates", "set_policy", AdminOnly),
    // The launcher is a session operation (`launcher.*`), not a module, but
    // it is authorized through this table too. Which entries a user sees is
    // decided per entry (`src/auth/launcher.rs`).
    ("launcher", "list", page(Launcher, View)),
    ("launcher", "get", page(Launcher, View)),
    ("launcher", "set", AdminOnly),
    ("launcher", "remove", AdminOnly),
    ("launcher", "public_get", AdminOnly),
    ("launcher", "public_set", AdminOnly),
    // System units and their journal: viewing can be granted, managing them
    // is admin-only.
    ("services", "list", page(SystemServices, View)),
    ("services", "status", page(SystemServices, View)),
    ("services", "logs", page(SystemServices, View)),
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
    // `render` and `context` read recipes and templates from any path as
    // root (and `render` can write rendered files anywhere); the inline forms
    // take their input in the payload.
    ("recipes", "render", AdminOnly),
    ("recipes", "render_inline", page(Apps, View)),
    ("recipes", "context", AdminOnly),
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
    ("network", "scan_wifi", AdminOnly),
    ("network", "connect_wifi", AdminOnly),
    ("reverse_proxy", "list", page(Network, View)),
    ("reverse_proxy", "render", page(Network, View)),
    ("reverse_proxy", "write", page(Network, Manage)),
    ("reverse_proxy", "delete", page(Network, Manage)),
    ("reverse_proxy", "reload", page(Network, Manage)),
    // Remote access exposes the dashboard beyond the local network and
    // handles credentials; even its status comes from root-only tools.
    ("remote_access", "status", AdminOnly),
    ("remote_access", "tailscale_up", AdminOnly),
    ("remote_access", "tailscale_disable", AdminOnly),
    ("remote_access", "cloudflared_set_token", AdminOnly),
    ("remote_access", "cloudflared_disable", AdminOnly),
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
    ("users", "set_authorized_keys", AdminOnly),
    ("users", "add_admin", AdminOnly),
    // Reads any path as root (`/etc/shadow`, the store key): root-equivalent.
    ("files", "read", AdminOnly),
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

/// The module actions the setup session may run: what the OOBE needs, each
/// named individually (never a whole module).
///
/// No `services.*`, no raw network
/// configuration (`network.get_config`/`set_config`), no user deletion and no
/// `users.update` (which can change group memberships, and with them who is
/// an administrator). Extend this list deliberately as the OOBE grows.
pub const SETUP_ALLOWED: &[(&str, &str)] = &[
    ("agent", "capabilities"),
    ("settings", "set_hostname"),
    ("settings", "set_keymap"),
    ("settings", "set_locale"),
    ("settings", "set_timezone"),
    ("users", "create"),
    ("users", "set_password"),
    ("users", "set_authorized_keys"),
    ("users", "add_admin"),
    ("power", "reboot"),
    ("power", "poweroff"),
    ("network", "interfaces"),
    ("network", "status"),
    ("network", "scan_wifi"),
    ("network", "connect_wifi"),
    ("network", "configure"),
    ("network", "confirm"),
    ("updates", "set_policy"),
    ("remote_access", "status"),
    ("remote_access", "tailscale_up"),
    ("remote_access", "tailscale_disable"),
    ("remote_access", "cloudflared_set_token"),
    ("remote_access", "cloudflared_disable"),
];

/// Setup actions that are refused once an eligible administrator exists, so
/// the setup code cannot be used to make more administrators (for example on
/// a host installed with one by Readymade).
pub const SETUP_ONLY_WITHOUT_ADMIN: &[(&str, &str)] = &[("users", "add_admin")];

/// The socket operations (other than login and `setup.redeem`) the setup
/// session may use.
///
/// `access.set` and `setup.complete` are operations rather
/// than module actions because Tetra itself owns the dashboard's Caddy site,
/// its credentials and the handoff to the dashboard.
pub const SETUP_OPERATIONS: &[&str] = &[
    "session.info",
    "session.logout",
    "setup.status",
    "setup.complete",
    "access.get",
    "access.set",
    "module.dispatch",
];

/// Payload fields that only administrators (and remote controllers) may set,
/// because they point an action at arbitrary host paths. The setup session
/// and granted users always get the defaults.
const ADMIN_ONLY_FIELDS: &[(&str, &str)] = &[
    ("reverse_proxy", "config_dir"),
    ("quadlets", "base_dir"),
    ("quadlets", "files_base_dir"),
    ("apps", "base_dir"),
    ("apps", "files_base_dir"),
];

/// The first admin-only field set in a `module` payload, if any.
#[must_use]
pub fn admin_only_field(module: &str, payload: &Value) -> Option<&'static str> {
    ADMIN_ONLY_FIELDS
        .iter()
        .find(|(m, field)| *m == module && payload.get(field).is_some())
        .map(|(_, field)| *field)
}

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
        .any(|(m, a)| *m == module && *a == action)
}

/// Whether the setup session may only run `module.action` while no eligible
/// administrator exists.
#[must_use]
pub fn setup_needs_no_admin(module: &str, action: &str) -> bool {
    SETUP_ONLY_WITHOUT_ADMIN
        .iter()
        .any(|(m, a)| *m == module && *a == action)
}

/// Whether the setup session may use the socket operation `op`.
#[must_use]
pub fn setup_allows_operation(op: &str) -> bool {
    SETUP_OPERATIONS.contains(&op)
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
    BTreeMap::from([(Launcher, View)])
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

/// One user's grants as stored: page names as written, so pages and levels
/// from a newer build survive a rewrite. Only the entries this build
/// understands grant anything ([`known_permissions`]).
pub type StoredGrants = BTreeMap<String, Tolerant<Level>>;

/// The page a stored key names, if this build knows it (earlier names
/// included).
fn parse_page(key: &str) -> Option<Page> {
    serde_json::from_value(Value::String(key.to_owned())).ok()
}

/// The pages and levels of `stored` that this build knows. Unknown entries
/// grant nothing.
#[must_use]
pub fn known_permissions(stored: &StoredGrants) -> Permissions {
    let mut permissions = Permissions::new();
    for (key, level) in stored {
        if let (Some(page), Some(level)) = (parse_page(key), level.known()) {
            let entry = permissions.entry(page).or_insert(*level);
            *entry = (*entry).max(*level);
        }
    }
    permissions
}

/// Stored grants, keyed by UID.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GrantsFile {
    #[serde(flatten)]
    header: Header,
    #[serde(default)]
    pub grants: BTreeMap<u32, StoredGrants>,
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
            .grants
            .iter()
            .map(|(uid, stored)| (*uid, known_permissions(stored)))
            .filter(|(_, permissions)| !permissions.is_empty())
            .collect())
    }

    /// Default permissions merged with `uid`'s grants.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn effective(&self, uid: u32) -> Result<Permissions> {
        let mut permissions = default_permissions();
        // A stored grant that is no longer grantable (an action became
        // admin-only in a later release) is ignored.
        for (page, level) in self
            .get(uid)?
            .into_iter()
            .filter(|(page, level)| grantable(*page, *level))
        {
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
            // Also drops the page's entries under earlier names.
            grants.retain(|key, _| parse_page(key) != Some(*page));
            if let Some(level) = level {
                let key = serde_json::to_value(page)?
                    .as_str()
                    .context("page names are strings")?
                    .to_owned();
                grants.insert(key, Tolerant::Known(*level));
            }
        }
        let result = known_permissions(grants);
        if grants.is_empty() {
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
                "label": page.label(),
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
    fn non_admins_only_get_the_launcher_by_default() {
        let alice = user(false, default_permissions());
        assert!(alice.allows("launcher", "list"));
        assert!(alice.allows("launcher", "get"));
        assert!(!alice.allows("launcher", "set"));
        assert!(alice.allows("services", "capabilities"));
        for action in ["list", "status", "logs", "restart"] {
            assert!(!alice.allows("services", action), "services.{action}");
        }
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
            Page::Files,
            Settings,
            Launcher,
            SystemServices,
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
            // The files module reads any path as root.
            let expected = page != Page::Files;
            assert_eq!(grantable(page, View), expected, "{page:?} view");
        }
        assert_eq!(requirement("files", "read"), AdminOnly);
        assert!(grantable(Network, Manage));
        assert!(grantable(Sharing, Manage));
        let alice = user(false, BTreeMap::from([(Storage, View)]));
        assert!(alice.allows("storage", "list"));
        assert!(!alice.allows("storage", "mount"));
    }

    #[test]
    fn system_services_can_be_granted_view() {
        assert!(!default_permissions().contains_key(&SystemServices));
        assert!(grantable(SystemServices, View));
        let alice = user(false, BTreeMap::from([(SystemServices, View)]));
        assert!(alice.allows("services", "logs"));
        assert!(!alice.allows("services", "restart"));
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
        assert!(!setup.allows("network", "set_config"));
        assert!(!setup.allows("network", "reload"));
    }

    #[test]
    fn setup_allowlist_names_individual_actions() {
        for (module, action) in SETUP_ALLOWED {
            assert_ne!(*action, "*", "{module}.* must not be allowed as a whole");
        }
        let setup = Principal::Setup;
        for (module, action) in [
            ("settings", "set_keymap"),
            ("settings", "set_locale"),
            ("settings", "set_timezone"),
            ("users", "set_authorized_keys"),
            ("users", "add_admin"),
            ("power", "reboot"),
            ("power", "poweroff"),
            ("network", "interfaces"),
            ("network", "status"),
            ("network", "scan_wifi"),
            ("network", "connect_wifi"),
            ("updates", "set_policy"),
            ("remote_access", "tailscale_up"),
            ("remote_access", "cloudflared_set_token"),
            ("remote_access", "status"),
        ] {
            assert!(setup.allows(module, action), "{module}.{action}");
        }
        for (module, action) in [
            ("services", "start"),
            ("services", "list"),
            ("reverse_proxy", "write"),
            ("reverse_proxy", "list"),
            ("users", "update"),
            ("users", "delete"),
            ("updates", "get_policy"),
            ("files", "read"),
            ("settings", "get_system"),
        ] {
            assert!(!setup.allows(module, action), "{module}.{action}");
        }
        assert!(setup_needs_no_admin("users", "add_admin"));
        assert!(!setup_needs_no_admin("users", "create"));
    }

    #[test]
    fn setup_allowlist_names_real_actions() {
        let modules = Dispatcher::full().capabilities();
        for (module, action) in SETUP_ALLOWED {
            if *module == "agent" {
                continue;
            }
            // Modules compiled out by features cannot be checked.
            if let Some(info) = modules.iter().find(|info| info.name == *module) {
                assert!(
                    info.actions.contains(action),
                    "{module}.{action} is allowed for setup but does not exist"
                );
            }
        }
    }

    #[test]
    fn setup_operations_are_listed() {
        for op in [
            "access.set",
            "setup.complete",
            "module.dispatch",
            "session.info",
        ] {
            assert!(setup_allows_operation(op), "{op}");
        }
        for op in [
            "admin.grants_set",
            "admin.actions",
            "account.totp_begin",
            "session.list",
            "authz.catalog",
        ] {
            assert!(!setup_allows_operation(op), "{op}");
        }
    }

    #[test]
    fn new_host_actions_are_admin_only() {
        for (module, action) in [
            ("settings", "set_keymap"),
            ("users", "add_admin"),
            ("users", "set_authorized_keys"),
            ("power", "reboot"),
            ("updates", "set_policy"),
            ("remote_access", "tailscale_up"),
            ("remote_access", "status"),
        ] {
            assert_eq!(requirement(module, action), AdminOnly, "{module}.{action}");
        }
        assert_eq!(requirement("updates", "get_policy"), page(Settings, View));
    }

    #[test]
    fn network_configuration_is_admin_only() {
        for action in [
            "get_config",
            "set_config",
            "reload",
            "configure",
            "confirm",
            "scan_wifi",
            "connect_wifi",
        ] {
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
                &BTreeMap::from([(Network, Some(Manage)), (SystemServices, Some(View))]),
            )
            .unwrap();
        let effective = grants.effective(1000).unwrap();
        assert_eq!(effective.get(&Network), Some(&Manage));
        assert_eq!(effective.get(&SystemServices), Some(&View));
        assert_eq!(effective.get(&Launcher), Some(&View));
        assert_eq!(grants.effective(1001).unwrap(), default_permissions());

        grants
            .set(1000, &BTreeMap::from([(Users, Some(Manage))]))
            .unwrap_err();
        grants
            .set(1000, &BTreeMap::from([(Network, None)]))
            .unwrap();
        assert_eq!(grants.get(1000).unwrap().get(&Network), None);
    }

    #[test]
    fn grants_that_are_no_longer_grantable_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        // Written by a release in which `files.read` needed `files: view`.
        fs::write(
            &path,
            r#"{"schema": 1, "compat": 1, "grants": {"1000": {"files": "view", "storage": "view"}}}"#,
        )
        .unwrap();
        let effective = GrantStore::new(path).effective(1000).unwrap();
        assert_eq!(effective.get(&Page::Files), None);
        assert_eq!(effective.get(&Storage), Some(&View));
    }

    #[test]
    fn grants_for_pages_and_levels_from_a_newer_build_grant_nothing_and_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        fs::write(
            &path,
            r#"{"schema": 2, "compat": 1, "grants": {
                "1000": {"future_page": "manage", "storage": "view", "network": "superpower"},
                "1001": {"future_page": {"level": "view", "scope": ["x"]}}
            }}"#,
        )
        .unwrap();
        let grants = GrantStore::new(path.clone());
        let effective = grants.effective(1000).unwrap();
        assert_eq!(
            effective,
            BTreeMap::from([(Launcher, View), (Storage, View)])
        );
        assert_eq!(grants.effective(1001).unwrap(), default_permissions());
        assert_eq!(
            grants.all().unwrap(),
            BTreeMap::from([(1000, BTreeMap::from([(Storage, View)]))])
        );

        grants
            .set(
                1000,
                &BTreeMap::from([(Sharing, Some(Manage)), (Storage, None)]),
            )
            .unwrap();
        let written: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            written["grants"],
            serde_json::json!({
                "1000": {"future_page": "manage", "network": "superpower", "sharing": "manage"},
                "1001": {"future_page": {"level": "view", "scope": ["x"]}}
            })
        );
        assert_eq!(
            grants.get(1000).unwrap(),
            BTreeMap::from([(Sharing, Manage)])
        );
    }

    #[test]
    fn grants_of_the_old_services_page_mean_system_services() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        fs::write(
            &path,
            r#"{"schema": 1, "compat": 1, "grants": {"1000": {"services": "view"}}}"#,
        )
        .unwrap();
        let grants = GrantStore::new(path.clone());
        assert_eq!(
            grants.effective(1000).unwrap().get(&SystemServices),
            Some(&View)
        );
        // Changing the page replaces the entry under its old name.
        grants
            .set(1000, &BTreeMap::from([(SystemServices, None)]))
            .unwrap();
        assert_eq!(grants.get(1000).unwrap(), Permissions::new());
        assert!(!fs::read_to_string(&path).unwrap().contains("services"));
    }

    #[test]
    fn path_overrides_are_admin_only_fields() {
        let payload = serde_json::json!({"filename": "x", "files_base_dir": "/etc"});
        assert_eq!(
            admin_only_field("quadlets", &payload),
            Some("files_base_dir")
        );
        assert_eq!(
            admin_only_field("quadlets", &serde_json::json!({"filename": "x"})),
            None
        );
        assert_eq!(requirement("recipes", "render"), AdminOnly);
    }
}
