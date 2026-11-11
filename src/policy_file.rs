//! Policy labels kept in a file instead of on the container.
//!
//! Anyone who can inspect a container sees its labels. A container's
//! `portcullis.policy-file` label names a file in the policy directory (`policy-dir`)
//! whose lines are more of its policy labels, `<label>=<value>`, as in a file for
//! `docker run --label-file`. Only the file's name is in Docker's metadata.
//!
//! What the file says is never logged or reported: errors name the file, line numbers and
//! labels, not values.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Where policy files are, unless `policy-dir` says otherwise.
pub const DEFAULT_POLICY_DIR: &str = "/etc/portcullis/policies";

/// The largest policy file read.
const MAX_SIZE: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum PolicyFileError {
    #[error("{0:?} isn't a file name: name a file directly in the policy directory")]
    InvalidName(String),
    #[error("can't read {path}: {error}")]
    Read { path: PathBuf, error: io::Error },
    #[error("{0} is outside the policy directory")]
    Outside(PathBuf),
    #[error("{0} isn't a regular file")]
    NotAFile(PathBuf),
    #[error(
        "{0} could be changed by other users: it has to be owned by root and not writable by group or others"
    )]
    Unprotected(PathBuf),
    #[error("{0} is larger than 64 KiB")]
    TooLarge(PathBuf),
    #[error("{0} isn't UTF-8 text")]
    NotText(PathBuf),
    #[error("{path} line {line}: expected <label>=<value>")]
    Syntax { path: PathBuf, line: usize },
}

/// A label set by a policy file.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub line: usize,
    pub key: String,
    pub value: String,
}

/// The labels of policy file `name` in `directory`.
///
/// `name` has to be the name of a file directly in `directory`, and the file, after
/// following links, has to be in it too. The file and the directory have to be owned by
/// root (or the user Portcullis runs as) and not writable by anyone else, since what they
/// say opens up containers.
pub fn load(directory: &Path, name: &str) -> Result<Vec<Entry>, PolicyFileError> {
    let mut components = Path::new(name).components();
    if !matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return Err(PolicyFileError::InvalidName(name.to_string()));
    }
    let read_error = |path: &Path| {
        let path = path.to_path_buf();
        move |error| PolicyFileError::Read { path, error }
    };
    let directory = directory.canonicalize().map_err(read_error(directory))?;
    let owner = process_owner().map_err(read_error(Path::new("/proc/self")))?;
    protected(&directory, owner)?;

    let path = directory.join(name);
    let path = path.canonicalize().map_err(read_error(&path))?;
    if path.parent() != Some(directory.as_path()) {
        return Err(PolicyFileError::Outside(path));
    }
    let mut file = File::open(&path).map_err(read_error(&path))?;
    let metadata = file.metadata().map_err(read_error(&path))?;
    if !metadata.is_file() {
        return Err(PolicyFileError::NotAFile(path));
    }
    if !is_protected(&metadata, owner) {
        return Err(PolicyFileError::Unprotected(path));
    }
    if metadata.len() > MAX_SIZE {
        return Err(PolicyFileError::TooLarge(path));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or_default());
    file.by_ref()
        .take(MAX_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error(&path))?;
    if bytes.len() as u64 > MAX_SIZE {
        return Err(PolicyFileError::TooLarge(path));
    }
    let text = String::from_utf8(bytes).map_err(|_| PolicyFileError::NotText(path.clone()))?;
    parse(&text).map_err(|line| PolicyFileError::Syntax { path, line })
}

/// The labels of a policy file's text: one `<label>=<value>` per line, blank lines and
/// lines starting with `#` skipped. The number of the first line that is neither, if any.
fn parse(text: &str) -> Result<Vec<Entry>, usize> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .filter(|(key, _)| !key.trim().is_empty())
            .ok_or(index + 1)?;
        entries.push(Entry {
            line: index + 1,
            key: key.trim().to_string(),
            value: value.trim().to_string(),
        });
    }
    Ok(entries)
}

/// The user Portcullis runs as.
fn process_owner() -> io::Result<u32> {
    std::fs::metadata("/proc/self").map(|metadata| metadata.uid())
}

fn protected(directory: &Path, owner: u32) -> Result<(), PolicyFileError> {
    let metadata = std::fs::metadata(directory).map_err(|error| PolicyFileError::Read {
        path: directory.to_path_buf(),
        error,
    })?;
    if is_protected(&metadata, owner) {
        Ok(())
    } else {
        Err(PolicyFileError::Unprotected(directory.to_path_buf()))
    }
}

/// Owned by root or `owner`, and not writable by group or others.
fn is_protected(metadata: &std::fs::Metadata, owner: u32) -> bool {
    (metadata.uid() == 0 || metadata.uid() == owner) && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A fresh, protected directory for a test.
    fn directory(test: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("portcullis-policy-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("protect directory");
        path
    }

    fn write(directory: &Path, name: &str, text: &str, mode: u32) {
        let path = directory.join(name);
        std::fs::write(&path, text).expect("write file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("set mode");
    }

    fn entry(line: usize, key: &str, value: &str) -> Entry {
        Entry {
            line,
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn parses_labels_comments_and_blank_lines() {
        let text = "# VPN\n\nportcullis.egress.vpn = ip:192.0.2.10,udp:51820\n  portcullis.icc.mode=deny  \nportcullis.domains.0=a=b\n";
        assert_eq!(
            parse(text),
            Ok(vec![
                entry(3, "portcullis.egress.vpn", "ip:192.0.2.10,udp:51820"),
                entry(4, "portcullis.icc.mode", "deny"),
                entry(5, "portcullis.domains.0", "a=b"),
            ])
        );
    }

    #[test]
    fn lines_without_a_label_are_errors() {
        assert_eq!(parse("portcullis.icc.mode=deny\nip:192.0.2.10\n"), Err(2));
        assert_eq!(parse("=deny\n"), Err(1));
    }

    #[test]
    fn loads_a_file_in_the_directory() {
        let directory = directory("load");
        write(
            &directory,
            "vpn",
            "portcullis.egress.vpn=ip:192.0.2.10,udp:51820\n",
            0o600,
        );
        let entries = load(&directory, "vpn").expect("load");
        assert_eq!(
            entries,
            vec![entry(1, "portcullis.egress.vpn", "ip:192.0.2.10,udp:51820")]
        );
    }

    #[test]
    fn only_names_files_directly_in_the_directory() {
        let directory = directory("names");
        for name in ["", "../vpn", "/etc/passwd", "sub/vpn", ".", ".."] {
            assert!(
                matches!(load(&directory, name), Err(PolicyFileError::InvalidName(_))),
                "{name:?}"
            );
        }
    }

    #[test]
    fn links_out_of_the_directory_are_refused() {
        let outside = directory("outside-target");
        write(&outside, "vpn", "portcullis.icc.mode=allow\n", 0o600);
        let directory = directory("outside");
        symlink(outside.join("vpn"), directory.join("vpn")).expect("link");
        assert!(matches!(
            load(&directory, "vpn"),
            Err(PolicyFileError::Outside(_))
        ));
    }

    #[test]
    fn files_others_can_write_are_refused() {
        let directory = directory("writable");
        write(&directory, "group", "portcullis.icc.mode=allow\n", 0o620);
        write(&directory, "world", "portcullis.icc.mode=allow\n", 0o602);
        for name in ["group", "world"] {
            assert!(matches!(
                load(&directory, name),
                Err(PolicyFileError::Unprotected(_))
            ));
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
            .expect("open directory");
        write(&directory, "vpn", "portcullis.icc.mode=allow\n", 0o600);
        assert!(matches!(
            load(&directory, "vpn"),
            Err(PolicyFileError::Unprotected(_))
        ));
    }

    #[test]
    fn missing_large_and_binary_files_are_errors() {
        let directory = directory("errors");
        assert!(matches!(
            load(&directory, "missing"),
            Err(PolicyFileError::Read { .. })
        ));
        std::fs::create_dir(directory.join("sub")).expect("subdirectory");
        assert!(matches!(
            load(&directory, "sub"),
            Err(PolicyFileError::NotAFile(_))
        ));
        let large = format!("# {}\n", "x".repeat(usize::try_from(MAX_SIZE).unwrap_or(0)));
        write(&directory, "large", &large, 0o600);
        assert!(matches!(
            load(&directory, "large"),
            Err(PolicyFileError::TooLarge(_))
        ));
        std::fs::write(directory.join("binary"), [0xff, 0xfe]).expect("write");
        std::fs::set_permissions(
            directory.join("binary"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("mode");
        assert!(matches!(
            load(&directory, "binary"),
            Err(PolicyFileError::NotText(_))
        ));
    }

    #[test]
    fn errors_never_contain_the_file_s_values() {
        let directory = directory("secret");
        write(
            &directory,
            "vpn",
            "portcullis.icc.mode=deny\n192.0.2.10\n",
            0o600,
        );
        let error = load(&directory, "vpn").expect_err("syntax error");
        assert!(matches!(error, PolicyFileError::Syntax { line: 2, .. }));
        assert!(!error.to_string().contains("192.0.2.10"));
    }
}
