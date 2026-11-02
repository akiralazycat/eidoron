//! End-to-end commands against a temp folder.
//!
//! Passwords are environment variables or stdin. They are not process arguments.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const PASS: &str = "synthetic-vault-pass";
const NEW_PASS: &str = "synthetic-new-pass";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "eidoron-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("scratch");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_eidoron")
}

fn run(state: &Path, password: &str, args: &[&str]) -> Output {
    assert!(
        args.iter()
            .all(|arg| !arg.contains(password) && !arg.contains(NEW_PASS)),
        "password must not be an argument"
    );
    let output = Command::new(bin())
        .args(args)
        .env("EIDORON_STATE_DIR", state)
        .env("EIDORON_PASSWORD", password)
        .env_remove("EIDORON_NEW_PASSWORD")
        .env_remove("EIDORON_PASSWORD_STDIN")
        .output()
        .expect("run");
    assert_no_secret(&output);
    output
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_no_secret(output: &Output) {
    let stderr = text(&output.stderr);
    let stdout = text(&output.stdout);
    assert!(!stderr.contains(PASS), "{stderr}");
    assert!(!stderr.contains(NEW_PASS), "{stderr}");
    assert!(!stdout.contains(PASS), "{stdout}");
    assert!(!stdout.contains(NEW_PASS), "{stdout}");
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

#[test]
fn help_has_no_password_argument() {
    for args in [
        vec!["--help"],
        vec!["passwd", "--help"],
        vec!["create", "--help"],
    ] {
        let output = Command::new(bin())
            .args(&args)
            .env_remove("EIDORON_PASSWORD")
            .output()
            .expect("help");
        assert_eq!(code(&output), 0, "{}", text(&output.stderr));
        let help = text(&output.stdout);
        assert!(!help.contains("--password"), "{help}");
        assert!(!help.contains("EIDORON_PASSWORD"), "{help}");
    }
}

#[test]
fn create_put_get_and_passwd_roundtrip() {
    let scratch = Scratch::new();
    let vault = scratch.0.join("vault");
    let state = scratch.0.join("state");
    let source = scratch.0.join("note.txt");
    let replaced = scratch.0.join("replaced.txt");
    let fetched = scratch.0.join("out.txt");
    fs::write(&source, b"hello-vault").expect("source");
    fs::write(&replaced, b"replaced-bytes").expect("replaced");

    let mut child = Command::new(bin())
        .args(["create", vault.to_str().expect("utf8")])
        .env("EIDORON_STATE_DIR", &state)
        .env_remove("EIDORON_PASSWORD")
        .env("EIDORON_PASSWORD_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"synthetic-vault-pass\n")
        .expect("write password");
    drop(child.stdin.take());
    let created = child.wait_with_output().expect("create");
    assert_eq!(code(&created), 0, "{}", text(&created.stderr));
    assert!(text(&created.stderr).contains("created"));
    assert_no_secret(&created);

    fs::write(vault.join("vault.header (1)"), b"numbered-copy").expect("header copy");
    fs::write(vault.join("notes (1)"), b"not-a-header").expect("notes");
    let status = run(
        &state,
        PASS,
        &["status", "--vault", vault.to_str().unwrap()],
    );
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    let status_err = text(&status.stderr);
    assert!(status_err.lines().any(|line| line == "ok"), "{status_err}");
    assert!(
        status_err.contains("header conflict copy, not opened: vault.header (1)"),
        "{status_err}"
    );
    assert!(!status_err.contains("notes (1)"), "{status_err}");
    assert_eq!(
        fs::read(vault.join("vault.header (1)")).expect("copy stays"),
        b"numbered-copy"
    );

    let put = run(
        &state,
        PASS,
        &[
            "put",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&put), 0, "{}", text(&put.stderr));
    assert!(
        text(&put.stderr).contains("wrote "),
        "{}",
        text(&put.stderr)
    );

    let again = run(
        &state,
        PASS,
        &[
            "put",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&again), 1, "{}", text(&again.stderr));
    assert!(
        text(&again.stderr).contains("duplicate name"),
        "{}",
        text(&again.stderr)
    );

    let got = run(
        &state,
        PASS,
        &[
            "get",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            "--output",
            fetched.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&got), 0, "{}", text(&got.stderr));
    assert_eq!(fs::read(&fetched).expect("fetched"), b"hello-vault");

    let stdout_get = run(
        &state,
        PASS,
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&stdout_get), 0, "{}", text(&stdout_get.stderr));
    assert_eq!(stdout_get.stdout, b"hello-vault");

    let listed = run(&state, PASS, &["ls", "--vault", vault.to_str().unwrap()]);
    assert_eq!(code(&listed), 0, "{}", text(&listed.stderr));
    assert_eq!(text(&listed.stdout), "note\tfile\n");

    let replaced_out = run(
        &state,
        PASS,
        &[
            "replace",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            replaced.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&replaced_out), 0, "{}", text(&replaced_out.stderr));
    let after = run(
        &state,
        PASS,
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(after.stdout, b"replaced-bytes");

    let removed = run(
        &state,
        PASS,
        &["rm", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&removed), 0, "{}", text(&removed.stderr));
    assert!(
        text(&removed.stderr).contains("unlinked "),
        "{}",
        text(&removed.stderr)
    );
    let missing = run(
        &state,
        PASS,
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&missing), 1);
    assert!(text(&missing.stderr).contains("unavailable"));

    let put_again = run(
        &state,
        PASS,
        &[
            "put",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&put_again), 0, "{}", text(&put_again.stderr));

    let changed = Command::new(bin())
        .args(["passwd", "--vault", vault.to_str().unwrap()])
        .env("EIDORON_STATE_DIR", &state)
        .env("EIDORON_PASSWORD", PASS)
        .env("EIDORON_NEW_PASSWORD", NEW_PASS)
        .env_remove("EIDORON_PASSWORD_STDIN")
        .output()
        .expect("passwd");
    assert!(
        ["passwd", "--vault"]
            .iter()
            .all(|arg| !arg.contains(PASS) && !arg.contains(NEW_PASS))
    );
    assert_eq!(code(&changed), 0, "{}", text(&changed.stderr));
    let changed_err = text(&changed.stderr);
    assert!(changed_err.contains("password changed"), "{changed_err}");
    assert!(
        changed_err.contains("a saved copy of the old header still opens with the old password"),
        "{changed_err}"
    );
    assert_no_secret(&changed);
    assert_eq!(
        fs::read(vault.join("vault.header (1)")).expect("copy after passwd"),
        b"numbered-copy"
    );

    let old = run(
        &state,
        PASS,
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&old), 1);
    assert!(text(&old.stderr).contains("unavailable"));
    let fresh = run(
        &state,
        NEW_PASS,
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&fresh), 0, "{}", text(&fresh.stderr));
    assert_eq!(fresh.stdout, b"hello-vault");
}

#[test]
fn conflict_requires_select_head_before_write() {
    let scratch = Scratch::new();
    let vault_a = scratch.0.join("a");
    let vault_b = scratch.0.join("b");
    let state_a = scratch.0.join("state-a");
    let state_b = scratch.0.join("state-b");
    let state_fresh = scratch.0.join("state-fresh");
    let alpha = scratch.0.join("alpha.txt");
    let beta = scratch.0.join("beta.txt");
    let more = scratch.0.join("more.txt");
    fs::write(&alpha, b"from-a").expect("alpha");
    fs::write(&beta, b"from-b").expect("beta");
    fs::write(&more, b"after-select").expect("more");

    let created = run(&state_a, PASS, &["create", vault_a.to_str().unwrap()]);
    assert_eq!(code(&created), 0, "{}", text(&created.stderr));
    copy_files(&vault_a, &vault_b);

    let wrote_a = run(
        &state_a,
        PASS,
        &[
            "put",
            "--vault",
            vault_a.to_str().unwrap(),
            "alpha",
            alpha.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&wrote_a), 0, "{}", text(&wrote_a.stderr));
    let head_a = wrote_id(&text(&wrote_a.stderr));
    let wrote_b = run(
        &state_b,
        PASS,
        &[
            "put",
            "--vault",
            vault_b.to_str().unwrap(),
            "beta",
            beta.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&wrote_b), 0, "{}", text(&wrote_b.stderr));
    let head_b = wrote_id(&text(&wrote_b.stderr));
    copy_missing(&vault_b, &vault_a);

    let status = run(
        &state_fresh,
        PASS,
        &["status", "--vault", vault_a.to_str().unwrap()],
    );
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    let status_err = text(&status.stderr);
    assert!(status_err.contains("conflict: 2 heads"), "{status_err}");
    assert!(status_err.contains(&head_a), "{status_err}");
    assert!(status_err.contains(&head_b), "{status_err}");

    let blocked = run(
        &state_fresh,
        PASS,
        &[
            "put",
            "--vault",
            vault_a.to_str().unwrap(),
            "more",
            more.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&blocked), 2, "{}", text(&blocked.stderr));
    let blocked_err = text(&blocked.stderr);
    assert!(blocked_err.contains("conflict: 2 heads"), "{blocked_err}");
    assert!(
        blocked_err.contains(&head_a) && blocked_err.contains(&head_b),
        "{blocked_err}"
    );
    assert!(
        blocked_err.contains("select-head is required before writing"),
        "{blocked_err}"
    );
    assert!(blocked.stdout.is_empty());

    let selected = run(
        &state_fresh,
        PASS,
        &["select-head", "--vault", vault_a.to_str().unwrap(), &head_a],
    );
    assert_eq!(code(&selected), 0, "{}", text(&selected.stderr));
    assert!(text(&selected.stderr).contains("selected "));
    let wrote = run(
        &state_fresh,
        PASS,
        &[
            "put",
            "--vault",
            vault_a.to_str().unwrap(),
            "more",
            more.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&wrote), 0, "{}", text(&wrote.stderr));
    let got = run(
        &state_fresh,
        PASS,
        &["get", "--vault", vault_a.to_str().unwrap(), "more"],
    );
    assert_eq!(got.stdout, b"after-select");

    let other = run(
        &state_fresh,
        PASS,
        &["select-head", "--vault", vault_a.to_str().unwrap(), &head_b],
    );
    assert_eq!(code(&other), 0, "{}", text(&other.stderr));
    let beta_out = run(
        &state_fresh,
        PASS,
        &["get", "--vault", vault_a.to_str().unwrap(), "beta"],
    );
    assert_eq!(code(&beta_out), 0, "{}", text(&beta_out.stderr));
    assert_eq!(beta_out.stdout, b"from-b");
    let absent = run(
        &state_fresh,
        PASS,
        &["get", "--vault", vault_a.to_str().unwrap(), "alpha"],
    );
    assert_ne!(code(&absent), 0);
}

fn wrote_id(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("wrote "))
        .expect("wrote line")
        .trim()
        .to_string()
}

fn copy_files(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("dest");
    for entry in fs::read_dir(from).expect("read") {
        let entry = entry.expect("entry");
        if entry.path().is_file() {
            fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
        }
    }
}

fn copy_missing(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).expect("read") {
        let entry = entry.expect("entry");
        let dest = to.join(entry.file_name());
        if entry.path().is_file() && !dest.exists() {
            fs::copy(entry.path(), dest).expect("copy missing");
        }
    }
}
