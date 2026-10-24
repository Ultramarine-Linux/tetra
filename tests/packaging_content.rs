//! Keep installed account state and PAM defaults aligned with the host agent.

#[test]
fn tmpfiles_provisions_the_apps_home_and_linger_marker() {
    let lines: Vec<_> = include_str!("../systemd/tetra.tmpfiles.conf")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(
        lines,
        [
            "d /var/lib/ultramarine-apps 0700 ultramarine-apps ultramarine-apps -",
            "d /var/lib/systemd/linger 0755 root root -",
            "f /var/lib/systemd/linger/ultramarine-apps 0644 root root -",
        ]
    );
}

#[test]
fn shell_default_pam_service_matches_the_packaged_file() {
    let pam_file = std::path::Path::new("pam/tetra-shell");
    assert_eq!(
        pam_file.file_name().unwrap().to_str().unwrap(),
        tetra::agent::shell::pty::DEFAULT_PAM_SERVICE,
    );
    assert!(!include_str!("../pam/tetra-shell").trim().is_empty());
}
