//! Safe rendering for shell commands shown to users.

/// Render one POSIX-shell command from already-separated arguments. Every
/// argument is single-quoted; embedded quotes use the portable close/escape/open
/// sequence. This preserves argument boundaries for spaces, newlines, leading
/// dashes, and shell metacharacters.
pub fn shell(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn pipe_fd_to_rg(
    ext: &str,
    pattern: &str,
    root: &str,
    extra_fd: &[&str],
    extra_rg: &[&str],
) -> String {
    let mut fd = extra_fd.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // `.` is fd's match-all pattern. It keeps `root` in the path position;
    // the `--` boundary also makes a root that starts with `-` unambiguous.
    fd.extend([
        "-0".into(),
        "-e".into(),
        ext.into(),
        ".".into(),
        "--".into(),
        root.into(),
    ]);
    let mut rg = extra_rg.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    rg.extend([
        "-0".into(),
        "-l".into(),
        "-e".into(),
        pattern.into(),
        "--".into(),
    ]);
    format!("{} | xargs -0 {}", shell("fd", &fd), shell("rg", &rg))
}

#[cfg(test)]
mod tests {
    use super::{pipe_fd_to_rg, shell};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rf-command-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn executable(path: &std::path::Path, text: &str) {
        fs::write(path, text).unwrap();
        let mut mode = fs::metadata(path).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(path, mode).unwrap();
    }

    #[test]
    fn shell_preserves_special_user_arguments_when_executed() {
        let dir = temp_dir("args");
        let out = dir.join("out file");
        let value = " -dash ' quote\n$meta;*?[x]";
        let command = shell(
            "sh",
            &[
                "-c".into(),
                "printf '%s' \"$1\" > \"$2\"".into(),
                "--".into(),
                value.into(),
                out.to_string_lossy().into_owned(),
            ],
        );
        let status = Command::new("/bin/sh")
            .args(["-c", &command])
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_to_string(&out).unwrap(), value);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nul_pipe_preserves_special_file_names() {
        let dir = temp_dir("pipe");
        let bin = dir.join("bin");
        let root = dir.join(" root ' $meta\n");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&root).unwrap();
        let names = [
            "space name.rs",
            "quote'file.rs",
            "line\nbreak.rs",
            "-dash.rs",
            "$meta;*?[x].rs",
        ];
        let mut expected = Vec::new();
        for name in names {
            let path = root.join(name);
            fs::write(&path, "needle").unwrap();
            expected.push(path.into_os_string().into_string().unwrap());
        }
        expected.sort();

        executable(
            &bin.join("fd"),
            "#!/bin/sh\nlast=''\nfor arg in \"$@\"; do last=$arg; done\nfind \"$last\" -type f -print0\n",
        );
        executable(
            &bin.join("rg"),
            "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  [ \"$1\" = -- ] && { shift; break; }\n  shift\ndone\nprintf '%s\\0' \"$@\" > \"$OUT_FILE\"\n",
        );
        let out = dir.join("received");
        let command = pipe_fd_to_rg("rs", "-needle '$meta", &root.to_string_lossy(), &[], &[]);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let status = Command::new("/bin/sh")
            .args(["-c", &command])
            .env("PATH", path)
            .env("OUT_FILE", &out)
            .status()
            .unwrap();
        assert!(status.success());
        let mut received = fs::read(&out)
            .unwrap()
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8(part.to_vec()).unwrap())
            .collect::<Vec<_>>();
        received.sort();
        assert_eq!(received, expected);
        fs::remove_dir_all(dir).unwrap();
    }
}
