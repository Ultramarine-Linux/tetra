//! The launcher: the apps each user can open from the dashboard's Services
//! page, stored in `/var/lib/tetra/launcher.json`.
//!
//! An entry has a name, an optional icon, a URL and a [`Visibility`]. Every
//! read goes through the same rule ([`Entry::visible_to`]), so `launcher.list`,
//! `launcher.get` and `launcher.can_access` always agree. Non-administrators
//! only ever get an entry's id, name, icon and URL.
//!
//! Entries marked `public` are also written, with names, icons and URLs only,
//! to a static page Caddy serves without a login. The page is off unless an
//! administrator enables it, and is regenerated whenever entries change.
//!
//! [`Source::Manual`] entries keep the URL an administrator typed.
//! [`Source::Catalog`] entries (installed apps, not created by this build) get
//! their URL from a [`CatalogRoute`] and `access.json`, so they follow changes
//! of the access mode.
//!
//! A visibility, source or route kind from a newer build is kept as it is
//! ([`Tolerant`]): such an entry is shown to administrators only, opens its
//! stored URL, and is written back unchanged.

use std::{collections::BTreeSet, os::unix::fs::PermissionsExt, sync::Arc};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::json;
use webauthn_rs::prelude::Url;

use crate::prelude::*;

use super::{
    access::{AccessConfig, AccessMode},
    store::{self, Cached, Extra, Header, Record, StoreLock, Tolerant},
};

const MAX_NAME: usize = 64;
const MAX_URL: usize = 2048;
const MAX_ICON_NAME: usize = 64;
/// Largest `data:` icon, encoded.
const MAX_ICON_DATA: usize = 64 * 1024;
const MAX_MEMBER_NAME: usize = 64;
const ICON_TYPES: &[&str] = &["png", "jpeg", "gif", "webp", "svg+xml"];
/// Where the public page is written. Outside `/var/lib/tetra`, which only
/// root can read, so Caddy can serve it.
pub const DEFAULT_PUBLIC_DIR: &str = "/var/lib/tetra-public";
/// File name of the public page inside the public directory.
pub const PUBLIC_PAGE: &str = "index.html";
const PUBLIC_DIR_MODE: u32 = 0o755;
const PUBLIC_FILE_MODE: u32 = 0o644;

/// Who can see an entry. Administrators see every entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Visibility {
    /// Every user who can log in.
    Everyone,
    /// Administrators only.
    Admins,
    /// The listed users and members of the listed groups.
    Members {
        #[serde(default)]
        users: Vec<String>,
        #[serde(default)]
        groups: Vec<String>,
    },
}

/// Where an entry came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Added by an administrator through `launcher.set`.
    #[default]
    Manual,
    /// Added when an app was installed from the catalog. Not created yet.
    Catalog,
}

/// How a catalog app is reached, combined with `access.json` to build its URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRoute {
    /// The app's address in domain mode.
    pub domain: Tolerant<DomainRoute>,
    /// The HTTPS port Caddy serves the app on in IP mode.
    pub port: u16,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A catalog app's address in domain mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainRoute {
    /// `https://<name>.<hostname>/`.
    Subdomain { name: String },
    /// `https://<hostname>/<prefix>/`.
    Path { prefix: String },
}

impl CatalogRoute {
    /// The app's URL under `access`.
    ///
    /// # Errors
    /// Fails when the route's subdomain or path is not valid, or the IP-mode
    /// port is 0.
    pub fn url(&self, access: &AccessConfig) -> Result<String> {
        let url = match access.mode {
            AccessMode::Domain => {
                let port = access
                    .port
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default();
                let domain = self
                    .domain
                    .known()
                    .context("this Tetra does not know the app's route kind")?;
                match domain {
                    DomainRoute::Subdomain { name } => {
                        let label = name.trim().to_ascii_lowercase();
                        ensure!(
                            super::access::is_dns_label(&label),
                            "`{name}` is not a valid subdomain label"
                        );
                        format!("https://{label}.{}{port}/", access.url_host())
                    }
                    DomainRoute::Path { prefix } => {
                        let prefix = prefix.trim().trim_matches('/');
                        ensure!(
                            !prefix.is_empty() && prefix.split('/').all(is_path_segment),
                            "`{prefix}` is not a valid path prefix"
                        );
                        format!("https://{}{port}/{prefix}/", access.url_host())
                    }
                }
            }
            AccessMode::Ip => {
                ensure!(self.port != 0, "port must not be 0");
                format!("https://{}:{}/", access.url_host(), self.port)
            }
        };
        Url::parse(&url).with_context(|| format!("invalid app URL `{url}`"))?;
        Ok(url)
    }
}

fn is_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

/// One stored entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub name: String,
    /// A small `data:image/…;base64,` image or an icon name.
    #[serde(default)]
    pub icon: Option<String>,
    /// The URL as an administrator gave it. For catalog entries, the URL
    /// last built from the route, used when no access configuration exists.
    #[serde(default)]
    pub url: String,
    pub visibility: Tolerant<Visibility>,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub source: Tolerant<Source>,
    /// Set for catalog entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<CatalogRoute>,
    #[serde(flatten)]
    extra: Extra,
}

/// Who is looking at the launcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    pub username: String,
    pub groups: Vec<String>,
    pub admin: bool,
}

impl Entry {
    /// The one visibility rule behind `list`, `get` and `can_access`.
    #[must_use]
    pub fn visible_to(&self, viewer: &Viewer) -> bool {
        if viewer.admin {
            return true;
        }
        let Some(visibility) = self.visibility.known() else {
            // Shared in a way this build does not understand: nobody but
            // administrators.
            return false;
        };
        match visibility {
            Visibility::Everyone => true,
            Visibility::Admins => false,
            Visibility::Members { users, groups } => {
                users.contains(&viewer.username)
                    || groups.iter().any(|group| viewer.groups.contains(group))
            }
        }
    }

    /// The URL to open: built from the route for catalog entries (when there
    /// is an access configuration), as stored otherwise.
    #[must_use]
    pub fn resolved_url(&self, access: Option<&AccessConfig>) -> String {
        if self.source.known() == Some(&Source::Catalog)
            && let (Some(route), Some(access)) = (&self.route, access)
        {
            match route.url(access) {
                Ok(url) => return url,
                Err(error) => eprintln!("launcher entry `{}`: {error:#}", self.id),
            }
        }
        self.url.clone()
    }

    /// The entry as an API result. Administrators also get how it is shared
    /// and where it came from; everyone else only what they need to open it.
    #[must_use]
    pub fn to_json(&self, admin: bool, access: Option<&AccessConfig>) -> Value {
        let mut entry = json!({
            "id": self.id, "name": self.name, "icon": self.icon, "url": self.resolved_url(access),
        });
        if admin {
            entry["visibility"] = serde_json::to_value(&self.visibility).unwrap_or(Value::Null);
            entry["public"] = Value::Bool(self.public);
            entry["source"] = serde_json::to_value(&self.source).unwrap_or(Value::Null);
        }
        entry
    }
}

/// `launcher.set` `entry` parameter.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryInput {
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    pub url: String,
    pub visibility: Visibility,
    #[serde(default)]
    pub public: bool,
}

/// A validated [`EntryInput`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Validated {
    name: String,
    icon: Option<String>,
    url: String,
    visibility: Visibility,
    public: bool,
}

impl EntryInput {
    fn validate(self) -> Result<Validated> {
        let name = self.name.trim();
        ensure!(
            !name.is_empty()
                && name.chars().count() <= MAX_NAME
                && !name.chars().any(char::is_control),
            "name must be 1 to {MAX_NAME} printable characters"
        );
        let icon = self
            .icon
            .as_deref()
            .map(str::trim)
            .filter(|icon| !icon.is_empty())
            .map(validate_icon)
            .transpose()?;
        Ok(Validated {
            name: name.to_owned(),
            icon,
            url: validate_url(&self.url)?,
            visibility: validate_visibility(self.visibility)?,
            public: self.public,
        })
    }
}

/// Any absolute http(s) URL, stored as given (without surrounding
/// whitespace).
fn validate_url(url: &str) -> Result<String> {
    let url = url.trim();
    ensure!(
        url.len() <= MAX_URL && !url.chars().any(|ch| ch.is_control() || ch.is_whitespace()),
        "url must be at most {MAX_URL} characters without spaces"
    );
    let parsed = Url::parse(url).map_err(|_| anyhow::anyhow!("url must be an absolute URL"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host().is_some(),
        "url must be an http or https URL with a host"
    );
    Ok(url.to_owned())
}

/// A `data:image/<type>;base64,` image of at most [`MAX_ICON_DATA`] bytes, or
/// an icon name.
fn validate_icon(icon: &str) -> Result<String> {
    if let Some(rest) = icon.strip_prefix("data:image/") {
        ensure!(
            icon.len() <= MAX_ICON_DATA,
            "icon images must be at most {} KiB encoded",
            MAX_ICON_DATA / 1024
        );
        let (kind, data) = rest
            .split_once(";base64,")
            .context("icon images must be base64 data: URLs")?;
        ensure!(
            ICON_TYPES.contains(&kind),
            "icon images must be PNG, JPEG, GIF, WebP or SVG"
        );
        STANDARD
            .decode(data)
            .map_err(|_| anyhow::anyhow!("icon image is not valid base64"))?;
        return Ok(icon.to_owned());
    }
    ensure!(
        icon.len() <= MAX_ICON_NAME
            && icon
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':')),
        "icon must be a data:image URL or an icon name of up to {MAX_ICON_NAME} letters, digits, `-`, `_`, `.` or `:`"
    );
    Ok(icon.to_owned())
}

fn validate_visibility(visibility: Visibility) -> Result<Visibility> {
    let Visibility::Members { users, groups } = visibility else {
        return Ok(visibility);
    };
    let names = |names: Vec<String>, what: &str| -> Result<Vec<String>> {
        let mut seen = BTreeSet::new();
        let mut kept = Vec::new();
        for name in names {
            let name = name.trim().to_owned();
            ensure!(
                !name.is_empty()
                    && name.len() <= MAX_MEMBER_NAME
                    && name.chars().all(|ch| {
                        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@' | '$')
                    }),
                "`{name}` is not a valid {what} name"
            );
            if seen.insert(name.clone()) {
                kept.push(name);
            }
        }
        Ok(kept)
    };
    Ok(Visibility::Members {
        users: names(users, "user")?,
        groups: names(groups, "group")?,
    })
}

/// `launcher.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LauncherFile {
    #[serde(flatten)]
    header: Header,
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// Whether the public page is served. Off by default.
    #[serde(default)]
    pub public_page: bool,
    #[serde(flatten)]
    extra: Extra,
}

impl Record for LauncherFile {
    fn header(&self) -> &Header {
        &self.header
    }
    fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

/// Why a change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeError {
    NotFound,
    Invalid(String),
}

/// The launcher file and the public page directory.
#[derive(Debug, Clone)]
pub struct LauncherStore {
    path: PathBuf,
    public_dir: PathBuf,
    /// The entries last read: `launcher.can_access` runs for every
    /// `forward_auth` request.
    cache: Cached<[Entry]>,
}

impl LauncherStore {
    #[must_use]
    pub fn new(path: PathBuf, public_dir: PathBuf) -> Self {
        Self {
            path,
            public_dir,
            cache: Cached::new(),
        }
    }

    /// The stored entries, parsed again only when the file changed.
    fn entries(&self) -> Result<Arc<[Entry]>> {
        self.cache.get((), &self.path, || Ok(self.load()?.entries))
    }

    /// The public page's path.
    #[must_use]
    pub fn public_page_path(&self) -> PathBuf {
        self.public_dir.join(PUBLIC_PAGE)
    }

    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn load(&self) -> Result<LauncherFile> {
        Ok(store::read(&self.path)?.unwrap_or_default())
    }

    /// The entries `viewer` can see, in stored order.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn visible(&self, viewer: &Viewer) -> Result<Vec<Entry>> {
        Ok(self
            .entries()?
            .iter()
            .filter(|entry| entry.visible_to(viewer))
            .cloned()
            .collect())
    }

    /// Entry `id`, if `viewer` can see it. Entries the viewer cannot see are
    /// reported exactly like missing ones.
    ///
    /// # Errors
    /// Fails when the file exists but cannot be read.
    pub fn get(&self, id: &str, viewer: &Viewer) -> Result<Option<Entry>> {
        Ok(self
            .entries()?
            .iter()
            .find(|entry| entry.id == id && entry.visible_to(viewer))
            .cloned())
    }

    /// Add an entry (`id` is `None`) or replace entry `id`, then regenerate
    /// the public page. Replacing keeps the entry's source, route and fields
    /// from newer builds.
    ///
    /// # Errors
    /// The outer error is a storage failure; the inner one a refused change.
    pub fn set(
        &self,
        id: Option<&str>,
        input: EntryInput,
        access: Option<&AccessConfig>,
    ) -> Result<Result<Entry, ChangeError>> {
        let input = match input.validate() {
            Ok(input) => input,
            Err(error) => return Ok(Err(ChangeError::Invalid(format!("{error:#}")))),
        };
        self.change(access, |file| {
            let entry = if let Some(id) = id {
                let Some(entry) = file.entries.iter_mut().find(|entry| entry.id == id) else {
                    return Err(ChangeError::NotFound);
                };
                entry
            } else {
                let id = new_id(file);
                file.entries.push(Entry {
                    id,
                    name: String::new(),
                    icon: None,
                    url: String::new(),
                    visibility: Visibility::Admins.into(),
                    public: false,
                    source: Source::Manual.into(),
                    route: None,
                    extra: Extra::new(),
                });
                file.entries.last_mut().ok_or(ChangeError::NotFound)?
            };
            entry.name = input.name;
            entry.icon = input.icon;
            entry.url = input.url;
            entry.visibility = input.visibility.into();
            entry.public = input.public;
            Ok(entry.clone())
        })
    }

    /// Remove entry `id`, then regenerate the public page.
    ///
    /// # Errors
    /// The outer error is a storage failure; the inner one a refused change.
    pub fn remove(
        &self,
        id: &str,
        access: Option<&AccessConfig>,
    ) -> Result<Result<(), ChangeError>> {
        self.change(access, |file| {
            let before = file.entries.len();
            file.entries.retain(|entry| entry.id != id);
            if file.entries.len() == before {
                Err(ChangeError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    /// Turn the public page on or off, then regenerate (or remove) it.
    ///
    /// # Errors
    /// Fails when the file or the page cannot be written.
    pub fn set_public_page(&self, enabled: bool, access: Option<&AccessConfig>) -> Result<()> {
        self.change(access, |file| {
            file.public_page = enabled;
            Ok(())
        })?
        .map_err(|error| anyhow::anyhow!("public page change refused: {error:?}"))
    }

    /// Read-modify-write under the store lock. The file and the public page
    /// are written only when `change` succeeds.
    fn change<R>(
        &self,
        access: Option<&AccessConfig>,
        change: impl FnOnce(&mut LauncherFile) -> Result<R, ChangeError>,
    ) -> Result<Result<R, ChangeError>> {
        let dir = self.path.parent().context("launcher path has no parent")?;
        let _lock = StoreLock::acquire(dir)?;
        let mut file = self.load()?;
        let result = match change(&mut file) {
            Ok(result) => result,
            Err(error) => return Ok(Err(error)),
        };
        let written = store::write(&self.path, &mut file);
        self.cache.invalidate(&());
        written?;
        self.write_public_page(&file, access)?;
        Ok(Ok(result))
    }

    /// Regenerate the public page from the stored entries, for example after
    /// a restart or an `access.set`.
    ///
    /// # Errors
    /// Fails when the file cannot be read or the page cannot be written.
    pub fn refresh_public_page(&self, access: Option<&AccessConfig>) -> Result<()> {
        let dir = self.path.parent().context("launcher path has no parent")?;
        let _lock = StoreLock::acquire(dir)?;
        let file = self.load()?;
        self.write_public_page(&file, access)
    }

    /// Write the public page when it is enabled, remove it otherwise.
    fn write_public_page(&self, file: &LauncherFile, access: Option<&AccessConfig>) -> Result<()> {
        let path = self.public_page_path();
        if !file.public_page {
            return store::remove(&path);
        }
        fs::create_dir_all(&self.public_dir)
            .with_context(|| format!("failed to create `{}`", self.public_dir.display()))?;
        fs::set_permissions(
            &self.public_dir,
            fs::Permissions::from_mode(PUBLIC_DIR_MODE),
        )
        .with_context(|| format!("failed to set the mode of `{}`", self.public_dir.display()))?;
        let html = public_html(&file.entries, access);
        // Unchanged pages keep their mtime (and caches stay valid).
        store::replace_if_changed(&path, html.as_bytes(), PUBLIC_FILE_MODE).map(drop)
    }
}

/// A fresh random id that no entry in `file` has.
fn new_id(file: &LauncherFile) -> String {
    loop {
        let mut bytes = [0_u8; 9];
        rand::fill(&mut bytes);
        let id = URL_SAFE_NO_PAD.encode(bytes);
        if !file.entries.iter().any(|entry| entry.id == id) {
            return id;
        }
    }
}

fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            ch => escaped.push(ch),
        }
    }
    escaped
}

const PUBLIC_STYLE: &str = "body{margin:0;font-family:system-ui,sans-serif;background:#f6f7f9;color:#1c1e21}\
main{max-width:48rem;margin:0 auto;padding:2rem 1rem}\
h1{font-size:1.5rem;margin:0 0 1.5rem}\
ul{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(12rem,1fr));gap:.75rem}\
a{display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;border-radius:.5rem;background:#fff;color:inherit;text-decoration:none;box-shadow:0 1px 2px #0002}\
a:hover{box-shadow:0 2px 6px #0003}\
img,.initial{width:2rem;height:2rem;flex:none;border-radius:.375rem}\
.initial{display:grid;place-items:center;background:#dfe3ea;font-weight:600}\
p{color:#5f6368}\
@media (prefers-color-scheme:dark){body{background:#17181b;color:#e8eaed}a{background:#24262b}.initial{background:#3a3d44}p{color:#9aa0a6}}";

/// The public page: names, icons and URLs of public entries, nothing else.
/// The page loads nothing from anywhere (its CSP allows only inline styles
/// and `data:` images).
#[must_use]
pub fn public_html(entries: &[Entry], access: Option<&AccessConfig>) -> String {
    let items = entries
        .iter()
        .filter(|entry| entry.public)
        .map(|entry| {
            let icon = match entry.icon.as_deref() {
                Some(icon) if icon.starts_with("data:image/") => {
                    format!("<img src=\"{}\" alt=\"\">", escape_html(icon))
                }
                _ => {
                    let initial = entry.name.chars().next().unwrap_or('?').to_uppercase();
                    format!(
                        "<span class=\"initial\" aria-hidden=\"true\">{}</span>",
                        escape_html(&initial.to_string())
                    )
                }
            };
            format!(
                "<li><a href=\"{}\" rel=\"noopener noreferrer\">{icon}<span>{}</span></a></li>\n",
                escape_html(&entry.resolved_url(access)),
                escape_html(&entry.name),
            )
        })
        .collect::<Vec<_>>()
        .concat();
    let body = if items.is_empty() {
        "<p>No services are listed here.</p>\n".to_owned()
    } else {
        format!("<ul>\n{items}</ul>\n")
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n<meta name=\"robots\" content=\"noindex\">\n\
<title>Services</title>\n<style>{PUBLIC_STYLE}</style>\n</head>\n<body>\n<main>\n<h1>Services</h1>\n{body}</main>\n</body>\n</html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::access::{AccessRequest, DEFAULT_DASHBOARD_UPSTREAM};
    use serde_json::json;

    fn viewer(username: &str, groups: &[&str], admin: bool) -> Viewer {
        Viewer {
            username: username.into(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            admin,
        }
    }

    fn input(name: &str, visibility: Visibility, public: bool) -> EntryInput {
        EntryInput {
            name: name.into(),
            icon: None,
            url: format!("https://{}.example.com", name.to_ascii_lowercase()),
            visibility,
            public,
        }
    }

    fn entry(visibility: Visibility) -> Entry {
        Entry {
            id: "x".into(),
            name: "App".into(),
            icon: None,
            url: "https://app.example.com/".into(),
            visibility: visibility.into(),
            public: false,
            source: Source::Manual.into(),
            route: None,
            extra: Extra::new(),
        }
    }

    fn store(dir: &Path) -> LauncherStore {
        LauncherStore::new(dir.join("launcher.json"), dir.join("public"))
    }

    fn add(store: &LauncherStore, input: EntryInput) -> Entry {
        store.set(None, input, None).unwrap().unwrap()
    }

    fn access(mode: AccessMode, hostname: &str, port: Option<u16>) -> AccessConfig {
        AccessConfig::from_request(
            &AccessRequest {
                mode,
                hostname: hostname.into(),
                port,
                dashboard_upstream: None,
                challenge: crate::auth::access::AcmeChallenge::Http01,
                dns_provider: None,
                dns_credentials: None,
            },
            DEFAULT_DASHBOARD_UPSTREAM,
        )
        .unwrap()
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.name.as_str()).collect()
    }

    #[test]
    fn visibility_for_admins_listed_users_group_members_and_everyone_else() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        add(&store, input("Everyone", Visibility::Everyone, false));
        add(&store, input("Admins", Visibility::Admins, false));
        add(
            &store,
            input(
                "Alice",
                Visibility::Members {
                    users: vec!["alice".into()],
                    groups: vec![],
                },
                false,
            ),
        );
        add(
            &store,
            input(
                "Media",
                Visibility::Members {
                    users: vec![],
                    groups: vec!["media".into()],
                },
                false,
            ),
        );

        let admin = viewer("root-admin", &["wheel"], true);
        let alice = viewer("alice", &["alice"], false);
        let member = viewer("bob", &["bob", "media"], false);
        let carol = viewer("carol", &["carol"], false);
        assert_eq!(
            names(&store.visible(&admin).unwrap()),
            ["Everyone", "Admins", "Alice", "Media"]
        );
        assert_eq!(
            names(&store.visible(&alice).unwrap()),
            ["Everyone", "Alice"]
        );
        assert_eq!(
            names(&store.visible(&member).unwrap()),
            ["Everyone", "Media"]
        );
        assert_eq!(names(&store.visible(&carol).unwrap()), ["Everyone"]);

        // `get` follows the same rule and hides what it does not show.
        let media = store.visible(&member).unwrap()[1].id.clone();
        assert!(store.get(&media, &member).unwrap().is_some());
        assert!(store.get(&media, &carol).unwrap().is_none());
        assert!(store.get("missing", &carol).unwrap().is_none());
    }

    #[test]
    fn a_username_is_not_a_group_name() {
        let entry = entry(Visibility::Members {
            users: vec![],
            groups: vec!["alice".into()],
        });
        // alice's primary group is `alice`, so she sees it through the group.
        assert!(entry.visible_to(&viewer("alice", &["alice"], false)));
        // A user named like the group, but not in it, does not.
        assert!(!entry.visible_to(&viewer("alice", &[], false)));
        let listed = Entry {
            visibility: Visibility::Members {
                users: vec!["alice".into()],
                groups: vec![],
            }
            .into(),
            ..entry
        };
        assert!(!listed.visible_to(&viewer("bob", &["alice"], false)));
    }

    #[test]
    fn non_admins_only_get_id_name_icon_and_url() {
        let dir = tempfile::tempdir().unwrap();
        let entry = add(
            &store(dir.path()),
            input("Wiki", Visibility::Everyone, true),
        );
        let shown = entry.to_json(false, None);
        assert_eq!(
            shown,
            json!({"id": entry.id, "name": "Wiki", "icon": null, "url": "https://wiki.example.com"})
        );
        let full = entry.to_json(true, None);
        assert_eq!(full["visibility"], json!({"kind": "everyone"}));
        assert_eq!(full["public"], true);
        assert_eq!(full["source"], "manual");
    }

    #[test]
    fn set_replaces_and_remove_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let entry = add(&store, input("Wiki", Visibility::Everyone, false));
        let replaced = store
            .set(
                Some(&entry.id),
                input("Docs", Visibility::Admins, false),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(replaced.id, entry.id);
        assert_eq!(store.load().unwrap().entries, [replaced]);
        assert_eq!(
            store
                .set(Some("missing"), input("x", Visibility::Admins, false), None)
                .unwrap(),
            Err(ChangeError::NotFound)
        );
        assert_eq!(
            store.remove("missing", None).unwrap(),
            Err(ChangeError::NotFound)
        );
        store.remove(&entry.id, None).unwrap().unwrap();
        assert_eq!(store.load().unwrap().entries, []);
    }

    #[test]
    fn validates_entries() {
        let check = |change: fn(&mut EntryInput)| {
            let mut entry = input("App", Visibility::Everyone, false);
            change(&mut entry);
            entry.validate()
        };
        check(|_| {}).unwrap();
        // URLs are stored as given.
        let kept = check(|e| e.url = " http://192.0.2.1:8080/a/../b?x=1 ".into()).unwrap();
        assert_eq!(kept.url, "http://192.0.2.1:8080/a/../b?x=1");
        check(|e| e.url = "javascript:alert(1)".into()).unwrap_err();
        check(|e| e.url = "ftp://example.com".into()).unwrap_err();
        check(|e| e.url = "/relative".into()).unwrap_err();
        check(|e| e.url = "https://exa mple.com".into()).unwrap_err();
        check(|e| e.name = "  ".into()).unwrap_err();
        check(|e| e.name = "a\nb".into()).unwrap_err();
        check(|e| e.icon = Some("lucide:server".into())).unwrap();
        check(|e| e.icon = Some("data:image/png;base64,iVBORw0KGgo=".into())).unwrap();
        check(|e| e.icon = Some("data:text/html;base64,PGI+".into())).unwrap_err();
        check(|e| e.icon = Some("data:image/png;base64,not base64!".into())).unwrap_err();
        check(|e| e.icon = Some("https://example.com/icon.png".into())).unwrap_err();
        assert_eq!(check(|e| e.icon = Some(" ".into())).unwrap().icon, None);
        let members = check(|e| {
            e.visibility = Visibility::Members {
                users: vec![" alice ".into(), "alice".into()],
                groups: vec!["media".into()],
            };
        })
        .unwrap();
        assert_eq!(
            members.visibility,
            Visibility::Members {
                users: vec!["alice".into()],
                groups: vec!["media".into()]
            }
        );
        check(|e| {
            e.visibility = Visibility::Members {
                users: vec!["a b".into()],
                groups: vec![],
            };
        })
        .unwrap_err();
    }

    #[test]
    fn public_page_is_off_by_default_and_lists_only_public_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut secret = input("Secret <b>", Visibility::Everyone, false);
        secret.url = "https://secret.example.com/hidden-path".into();
        add(&store, secret);
        let mut wiki = input("Wiki & \"Docs\"", Visibility::Admins, true);
        wiki.url = "https://wiki.example.com/?a=1&b=2".into();
        wiki.icon = Some("data:image/png;base64,iVBORw0KGgo=".into());
        add(&store, wiki);
        assert!(!store.public_page_path().exists());

        store.set_public_page(true, None).unwrap();
        let page = fs::read_to_string(store.public_page_path()).unwrap();
        assert!(page.contains("Wiki &amp; &quot;Docs&quot;"));
        assert!(page.contains("href=\"https://wiki.example.com/?a=1&amp;b=2\""));
        assert!(page.contains("data:image/png;base64,iVBORw0KGgo="));
        assert!(!page.contains("Secret"));
        assert!(!page.contains("secret.example.com"));
        assert!(!page.contains("admins"));
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store.public_page_path()), PUBLIC_FILE_MODE);
        assert_eq!(mode(&dir.path().join("public")), PUBLIC_DIR_MODE);

        // Regenerated on every change.
        let entry = add(&store, input("Photos", Visibility::Everyone, true));
        assert!(
            fs::read_to_string(store.public_page_path())
                .unwrap()
                .contains("Photos")
        );
        store
            .set(
                Some(&entry.id),
                input("Photos", Visibility::Everyone, false),
                None,
            )
            .unwrap()
            .unwrap();
        assert!(
            !fs::read_to_string(store.public_page_path())
                .unwrap()
                .contains("Photos")
        );

        store.set_public_page(false, None).unwrap();
        assert!(!store.public_page_path().exists());
        assert!(!store.load().unwrap().public_page);
    }

    #[test]
    fn public_page_escapes_everything() {
        let entry = Entry {
            name: "<script>alert(1)</script>".into(),
            icon: Some("icon\"><script>".into()),
            url: "https://example.com/?a=\"><script>".into(),
            public: true,
            ..entry(Visibility::Everyone)
        };
        let page = public_html(&[entry], None);
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn catalog_urls_follow_the_access_mode() {
        let subdomain = CatalogRoute {
            domain: DomainRoute::Subdomain {
                name: "Photos".into(),
            }
            .into(),
            port: 8443,
            extra: Extra::new(),
        };
        let path = CatalogRoute {
            domain: DomainRoute::Path {
                prefix: "/photos/".into(),
            }
            .into(),
            ..subdomain.clone()
        };
        let domain = access(AccessMode::Domain, "server.example.com", None);
        assert_eq!(
            subdomain.url(&domain).unwrap(),
            "https://photos.server.example.com/"
        );
        assert_eq!(
            path.url(&domain).unwrap(),
            "https://server.example.com/photos/"
        );
        let other_port = access(AccessMode::Domain, "server.example.com", Some(8000));
        assert_eq!(
            path.url(&other_port).unwrap(),
            "https://server.example.com:8000/photos/"
        );
        let ipv4 = access(AccessMode::Ip, "192.0.2.10", None);
        assert_eq!(subdomain.url(&ipv4).unwrap(), "https://192.0.2.10:8443/");
        let ipv6 = access(AccessMode::Ip, "2001:db8::1", None);
        assert_eq!(path.url(&ipv6).unwrap(), "https://[2001:db8::1]:8443/");

        let bad = CatalogRoute {
            domain: DomainRoute::Path {
                prefix: "../etc".into(),
            }
            .into(),
            ..subdomain.clone()
        };
        bad.url(&domain).unwrap_err();
        let bad = CatalogRoute {
            domain: DomainRoute::Subdomain { name: "a.b".into() }.into(),
            ..subdomain
        };
        bad.url(&domain).unwrap_err();
    }

    #[test]
    fn catalog_entries_resolve_their_url_from_the_route() {
        let entry = Entry {
            url: "https://stale.example.com/".into(),
            source: Source::Catalog.into(),
            route: Some(CatalogRoute {
                domain: DomainRoute::Subdomain {
                    name: "photos".into(),
                }
                .into(),
                port: 8443,
                extra: Extra::new(),
            }),
            ..entry(Visibility::Everyone)
        };
        let ip = access(AccessMode::Ip, "192.0.2.10", None);
        assert_eq!(entry.resolved_url(Some(&ip)), "https://192.0.2.10:8443/");
        assert_eq!(entry.resolved_url(None), "https://stale.example.com/");
        let manual = Entry {
            source: Source::Manual.into(),
            ..entry
        };
        assert_eq!(manual.resolved_url(Some(&ip)), "https://stale.example.com/");
    }

    #[test]
    fn kinds_from_a_newer_build_grant_nothing_and_survive_a_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let future = json!({
            "schema": 2, "compat": 1,
            "entries": [
                {"id": "a", "name": "A", "icon": null, "url": "https://a.example.com",
                 "visibility": {"kind": "signed_in_from", "networks": ["10.0.0.0/8"]},
                 "public": false, "source": "manual"},
                {"id": "b", "name": "B", "icon": null, "url": "https://b.example.com/",
                 "visibility": {"kind": "everyone"}, "public": false,
                 "source": {"marketplace": "x"},
                 "route": {"domain": {"kind": "port_range", "from": 1}, "port": 8443}},
            ],
        });
        fs::write(dir.path().join("launcher.json"), future.to_string()).unwrap();

        let carol = viewer("carol", &["carol"], false);
        assert_eq!(names(&store.visible(&carol).unwrap()), ["B"]);
        assert!(store.get("a", &carol).unwrap().is_none());
        let admin = viewer("admin", &["wheel"], true);
        let entries = store.visible(&admin).unwrap();
        assert_eq!(names(&entries), ["A", "B"]);
        // An unknown source or route kind opens the stored URL.
        let ip = access(AccessMode::Ip, "192.0.2.10", None);
        assert_eq!(entries[1].resolved_url(Some(&ip)), "https://b.example.com/");
        assert_eq!(
            entries[0].to_json(true, None)["visibility"],
            future["entries"][0]["visibility"]
        );

        add(&store, input("C", Visibility::Everyone, false));
        let written: Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("launcher.json")).unwrap())
                .unwrap();
        assert_eq!(written["entries"][0], future["entries"][0]);
        assert_eq!(written["entries"][1], future["entries"][1]);
    }

    #[test]
    fn rewrite_keeps_fields_from_a_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let future = json!({
            "schema": 2, "compat": 1, "future_setting": 1,
            "entries": [{
                "id": "a", "name": "A", "url": "https://a.example.com",
                "visibility": {"kind": "everyone"}, "public": false,
                "source": "manual", "future_field": [1, 2],
            }],
        });
        fs::write(dir.path().join("launcher.json"), future.to_string()).unwrap();
        store
            .set(Some("a"), input("B", Visibility::Everyone, false), None)
            .unwrap()
            .unwrap();
        add(&store, input("C", Visibility::Everyone, false));
        let written: Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("launcher.json")).unwrap())
                .unwrap();
        assert_eq!(written["future_setting"], 1);
        assert_eq!(written["entries"][0]["future_field"], json!([1, 2]));
        assert_eq!(written["entries"][0]["name"], "B");
        assert_eq!(written["schema"], store::SCHEMA);
        assert_eq!(written["compat"], 1);
        let mode = fs::metadata(dir.path().join("launcher.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_files_that_need_a_newer_reader() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("launcher.json"),
            json!({"schema": 9, "compat": 9}).to_string(),
        )
        .unwrap();
        store(dir.path()).load().unwrap_err();
    }
}
