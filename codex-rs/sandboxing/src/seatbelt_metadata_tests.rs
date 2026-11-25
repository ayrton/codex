use super::CreateSeatbeltCommandArgsParams;
use super::MACOS_PATH_TO_SEATBELT_EXECUTABLE;
use super::create_seatbelt_command_args;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

struct MetadataFixture {
    directory: TempDir,
    entries: Vec<FileSystemSandboxEntry>,
}

impl MetadataFixture {
    fn new(parent: &str) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("codex-synthetic-metadata-")
            .tempdir_in(parent)
            .expect("synthetic fixture directory");
        let root = directory.path().canonicalize().expect("canonical fixture");
        fs::write(root.join("control"), "synthetic permitted control").expect("control");
        let entries = vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Minimal,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::from_absolute_path(&root)
                    .expect("absolute fixture")
                    .into(),
                FileSystemAccessMode::Read,
            ),
        ];
        Self { directory, entries }
    }
    fn root(&self) -> PathBuf {
        self.directory
            .path()
            .canonicalize()
            .expect("canonical fixture")
    }
    fn access(&mut self, relative: &str, access: FileSystemAccessMode) {
        self.entries.push(FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(self.root().join(relative))
                .expect("absolute fixture path")
                .into(),
            access,
        ));
    }
    fn args(&self, script: &str) -> Vec<String> {
        create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                script.to_string(),
                "synthetic-metadata-check".to_string(),
                self.root().display().to_string(),
            ],
            file_system_sandbox_policy: &FileSystemSandboxPolicy::restricted(self.entries.clone()),
            network_sandbox_policy: NetworkSandboxPolicy::Restricted,
            sandbox_policy_cwd: &self.root(),
            enforce_managed_network: false,
            managed_network: None,
            extra_allow_unix_sockets: &[],
        })
        .expect("synthetic sandbox policy")
    }
    fn run(&self, script: &str) {
        self.run_args(self.args(script));
    }
    fn run_args(&self, args: Vec<String>) {
        let output = Command::new(MACOS_PATH_TO_SEATBELT_EXECUTABLE)
            .args(args)
            .current_dir(self.root())
            .output()
            .expect("native synthetic sandbox command");
        assert!(
            output.status.success(),
            "synthetic metadata check failed: status={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn secret_directory(&self, relative: &str) {
        let path = self.root().join(relative);
        fs::create_dir_all(&path).expect("synthetic denied directory");
        fs::write(path.join("synthetic-key"), "synthetic credential fixture")
            .expect("synthetic credential fixture");
    }
}
const CHECK_DENIED_DIRECTORY: &str = r#"
set -eu
[ "$(/bin/cat "$1/control")" = 'synthetic permitted control' ]
/usr/bin/stat -f %d:%i "$1/control" >/dev/null
/bin/ls -A "$1" >/dev/null
if /usr/bin/stat -f %d:%i "$1/secret" >/dev/null 2>&1; then exit 11; fi
if /bin/ls -A "$1/secret" >/dev/null 2>&1; then exit 12; fi
if /bin/cat "$1/secret/synthetic-key" >/dev/null 2>&1; then exit 13; fi
"#;
#[test]
fn denied_directory_metadata_stays_hidden_outside_var() {
    let mut fixture = MetadataFixture::new("/Users/Shared");
    fixture.secret_directory("secret");
    fixture.access("secret", FileSystemAccessMode::Deny);
    fixture.run(CHECK_DENIED_DIRECTORY);
}
#[test]
fn denied_directory_metadata_stays_hidden_inside_var() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.secret_directory("secret");
    fixture.access("secret", FileSystemAccessMode::Deny);
    fixture.run(CHECK_DENIED_DIRECTORY);
}
#[test]
fn metadata_denials_cover_targets_created_after_policy_construction() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.access("secret", FileSystemAccessMode::Deny);
    let args = fixture.args(CHECK_DENIED_DIRECTORY);
    fixture.secret_directory("secret");
    fixture.run_args(args);
}
#[test]
fn metadata_deny_globs_override_platform_defaults() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.secret_directory("secret");
    fixture.entries.push(FileSystemSandboxEntry::new(
        FileSystemPath::GlobPattern {
            pattern: format!("{}/{{secret,secret/**}}", fixture.root().display()),
        },
        FileSystemAccessMode::Deny,
    ));
    fixture.run(CHECK_DENIED_DIRECTORY);
}
#[test]
fn denied_file_metadata_stays_hidden_inside_var() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fs::write(
        fixture.root().join("secret"),
        "synthetic credential fixture",
    )
    .expect("synthetic denied file");
    fixture.access("secret", FileSystemAccessMode::Deny);
    fixture.run(
        r#"
set -eu
/bin/cat "$1/control" >/dev/null
/usr/bin/stat -f %d:%i "$1/control" >/dev/null
if /usr/bin/stat -f %d:%i "$1/secret" >/dev/null 2>&1; then exit 11; fi
if /bin/cat "$1/secret" >/dev/null 2>&1; then exit 12; fi
"#,
    );
}
#[test]
fn metadata_denials_preserve_explicit_nested_read_grants() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.secret_directory("secret/allowed");
    fixture.secret_directory("secret/sibling");
    fixture.access("secret", FileSystemAccessMode::Deny);
    fixture.access("secret/allowed", FileSystemAccessMode::Read);
    fixture.run(
        r#"
set -eu
/bin/cat "$1/control" >/dev/null
/bin/cat "$1/secret/allowed/synthetic-key" >/dev/null
/usr/bin/stat -f %d:%i "$1/secret/allowed" >/dev/null
if /usr/bin/stat -f %d:%i "$1/secret/sibling" >/dev/null 2>&1; then exit 11; fi
if /bin/cat "$1/secret/sibling/synthetic-key" >/dev/null 2>&1; then exit 12; fi
"#,
    );
}
#[test]
fn metadata_denials_apply_again_below_nested_read_grants() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.secret_directory("secret/allowed/denied");
    fs::write(fixture.root().join("secret/allowed/control"), "permitted").expect("nested control");
    fixture.access("secret", FileSystemAccessMode::Deny);
    fixture.access("secret/allowed", FileSystemAccessMode::Read);
    fixture.access("secret/allowed/denied", FileSystemAccessMode::Deny);
    fixture.run(
        r#"
set -eu
/bin/cat "$1/control" >/dev/null
/bin/cat "$1/secret/allowed/control" >/dev/null
if /usr/bin/stat -f %d:%i "$1/secret/allowed/denied" >/dev/null 2>&1; then exit 11; fi
if /bin/cat "$1/secret/allowed/denied/synthetic-key" >/dev/null 2>&1; then exit 12; fi
"#,
    );
}

#[test]
fn metadata_denials_preserve_explicit_nested_write_grants() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.secret_directory("secret/allowed");
    fixture.secret_directory("secret/sibling");
    fixture.access("secret", FileSystemAccessMode::Deny);
    fixture.access("secret/allowed", FileSystemAccessMode::Write);
    fixture.run(
        r#"
set -eu
/bin/cat "$1/control" >/dev/null
printf permitted > "$1/secret/allowed/control"
/bin/cat "$1/secret/allowed/control" >/dev/null
/usr/bin/stat -f %d:%i "$1/secret/allowed" >/dev/null
if /usr/bin/stat -f %d:%i "$1/secret/sibling" >/dev/null 2>&1; then exit 11; fi
"#,
    );
}

#[test]
fn metadata_denials_normalize_the_var_system_alias() {
    let mut fixture = MetadataFixture::new("/private/var/tmp");
    fixture.secret_directory("secret");
    let logical = fixture
        .root()
        .join("secret")
        .display()
        .to_string()
        .replacen("/private/var/", "/var/", 1);
    fixture.entries.push(FileSystemSandboxEntry::new(
        AbsolutePathBuf::from_absolute_path(logical)
            .expect("system alias path")
            .into(),
        FileSystemAccessMode::Deny,
    ));
    fixture.run(CHECK_DENIED_DIRECTORY);
}

#[test]
fn platform_defaults_do_not_grant_unlisted_directory_metadata() {
    let fixture = MetadataFixture::new("/Users/Shared");
    let unlisted = MetadataFixture::new("/Users/Shared");
    fixture.run(&format!(
        r#"
set -eu
/bin/cat "$1/control" >/dev/null
/usr/bin/stat -f %d:%i "$1/control" >/dev/null
if /usr/bin/stat -f %d:%i '{}' >/dev/null 2>&1; then exit 11; fi
"#,
        unlisted.root().display()
    ));
}
