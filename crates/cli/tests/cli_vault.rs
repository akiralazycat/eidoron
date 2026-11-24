//! End-to-end commands against a temp folder.
//!
//! Passwords are stdin lines. They are not process arguments or environment values.

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

fn run(state: &Path, passwords: &[&str], args: &[&str]) -> Output {
    assert!(
        args.iter().all(|arg| {
            !arg.contains(PASS)
                && !arg.contains(NEW_PASS)
                && !passwords.iter().any(|pw| arg.contains(pw))
        }),
        "password must not be an argument"
    );
    let mut child = Command::new(bin())
        .args(args)
        .env("EIDORON_STATE_DIR", state)
        .env("EIDORON_PASSWORD_STDIN", "1")
        .env_remove("EIDORON_PASSWORD")
        .env_remove("EIDORON_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for password in passwords {
            writeln!(stdin, "{password}").expect("password line");
        }
    }
    let output = child.wait_with_output().expect("run");
    assert_no_secret(&output);
    output
}

fn password_prompts(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .map(str::trim)
        .filter(|line| {
            matches!(
                *line,
                "password:" | "current password:" | "new password:" | "repeat new password:"
            )
        })
        .collect()
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
        assert!(!help.contains("EIDORON_NEW_PASSWORD"), "{help}");
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

    let created = run(&state, &[PASS], &["create", vault.to_str().expect("utf8")]);
    assert_eq!(code(&created), 0, "{}", text(&created.stderr));
    assert!(text(&created.stderr).contains("created"));
    assert_eq!(password_prompts(&text(&created.stderr)), vec!["password:"]);

    fs::write(vault.join("vault.header (1)"), b"numbered-copy").expect("header copy");
    fs::write(vault.join("notes (1)"), b"not-a-header").expect("notes");
    let status = run(
        &state,
        &[PASS],
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
        &[PASS],
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
        &[PASS],
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
        &[PASS],
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
        &[PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&stdout_get), 0, "{}", text(&stdout_get.stderr));
    assert_eq!(stdout_get.stdout, b"hello-vault");

    let listed = run(&state, &[PASS], &["ls", "--vault", vault.to_str().unwrap()]);
    assert_eq!(code(&listed), 0, "{}", text(&listed.stderr));
    assert_eq!(text(&listed.stdout), "note\tfile\n");

    let replaced_out = run(
        &state,
        &[PASS],
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
        &[PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(after.stdout, b"replaced-bytes");

    let removed = run(
        &state,
        &[PASS],
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
        &[PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&missing), 1);
    assert!(text(&missing.stderr).contains("unavailable"));

    let put_again = run(
        &state,
        &[PASS],
        &[
            "put",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&put_again), 0, "{}", text(&put_again.stderr));

    let changed = run(
        &state,
        &[PASS, NEW_PASS, NEW_PASS],
        &["passwd", "--vault", vault.to_str().unwrap()],
    );
    assert_eq!(code(&changed), 0, "{}", text(&changed.stderr));
    let changed_err = text(&changed.stderr);
    assert_eq!(
        password_prompts(&changed_err),
        vec!["current password:", "new password:", "repeat new password:"]
    );
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
        &[PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&old), 1);
    assert!(text(&old.stderr).contains("unavailable"));
    let fresh = run(
        &state,
        &[NEW_PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&fresh), 0, "{}", text(&fresh.stderr));
    assert_eq!(fresh.stdout, b"hello-vault");
}

#[test]
fn password_environment_variable_is_ignored() {
    let scratch = Scratch::new();
    let vault = scratch.0.join("vault");
    let state = scratch.0.join("state");
    let created = Command::new(bin())
        .args(["create", vault.to_str().expect("utf8")])
        .env("EIDORON_STATE_DIR", &state)
        .env("EIDORON_PASSWORD", "wrong-env-secret")
        .env("EIDORON_NEW_PASSWORD", "other-env-secret")
        .env("EIDORON_PASSWORD_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut created = created;
    writeln!(created.stdin.as_mut().expect("stdin"), "{PASS}").expect("line");
    drop(created.stdin.take());
    let created = created.wait_with_output().expect("create");
    let err = text(&created.stderr);
    assert_eq!(code(&created), 0, "{err}");
    assert!(err.contains("EIDORON_PASSWORD is ignored"), "{err}");
    assert!(err.contains("EIDORON_NEW_PASSWORD is ignored"), "{err}");
    assert!(!err.contains("wrong-env-secret"), "{err}");
    assert!(!err.contains("other-env-secret"), "{err}");
    assert!(!err.contains(PASS), "{err}");
    let opened = run(
        &state,
        &[PASS],
        &["status", "--vault", vault.to_str().unwrap()],
    );
    assert_eq!(code(&opened), 0, "{}", text(&opened.stderr));
    let rejected = run(
        &state,
        &["wrong-env-secret"],
        &["status", "--vault", vault.to_str().unwrap()],
    );
    assert_eq!(code(&rejected), 1);
    assert!(text(&rejected.stderr).contains("unavailable"));
}

#[test]
fn passwd_reads_the_current_password_once() {
    let scratch = Scratch::new();
    let vault = scratch.0.join("vault");
    let state = scratch.0.join("state");
    let source = scratch.0.join("note.txt");
    fs::write(&source, b"kept").expect("source");
    let created = run(&state, &[PASS], &["create", vault.to_str().unwrap()]);
    assert_eq!(code(&created), 0, "{}", text(&created.stderr));
    assert_eq!(password_prompts(&text(&created.stderr)), vec!["password:"]);
    let put = run(
        &state,
        &[PASS],
        &[
            "put",
            "--vault",
            vault.to_str().unwrap(),
            "note",
            source.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&put), 0, "{}", text(&put.stderr));
    let before = fs::read(vault.join("vault.header")).expect("header");

    let mismatched = run(
        &state,
        &[PASS, "synthetic-one", "synthetic-two"],
        &["passwd", "--vault", vault.to_str().unwrap()],
    );
    assert_eq!(code(&mismatched), 2, "{}", text(&mismatched.stderr));
    let mismatched_err = text(&mismatched.stderr);
    assert_eq!(
        password_prompts(&mismatched_err),
        vec!["current password:", "new password:", "repeat new password:"]
    );
    assert!(
        mismatched_err.contains("passwords do not match"),
        "{mismatched_err}"
    );
    assert!(
        !mismatched_err
            .lines()
            .any(|line| line.trim() == "password:")
    );
    assert_eq!(
        fs::read(vault.join("vault.header")).expect("unchanged"),
        before
    );
    let still = run(
        &state,
        &[PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(still.stdout, b"kept");

    let changed = run(
        &state,
        &[PASS, NEW_PASS, NEW_PASS],
        &["passwd", "--vault", vault.to_str().unwrap()],
    );
    assert_eq!(code(&changed), 0, "{}", text(&changed.stderr));
    assert_eq!(
        password_prompts(&text(&changed.stderr)),
        vec!["current password:", "new password:", "repeat new password:"]
    );
    assert_ne!(
        fs::read(vault.join("vault.header")).expect("rewritten"),
        before
    );
    let old = run(
        &state,
        &[PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(code(&old), 1);
    let fresh = run(
        &state,
        &[NEW_PASS],
        &["get", "--vault", vault.to_str().unwrap(), "note"],
    );
    assert_eq!(fresh.stdout, b"kept");
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

    let created = run(&state_a, &[PASS], &["create", vault_a.to_str().unwrap()]);
    assert_eq!(code(&created), 0, "{}", text(&created.stderr));
    copy_files(&vault_a, &vault_b);

    let wrote_a = run(
        &state_a,
        &[PASS],
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
        &[PASS],
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
        &[PASS],
        &["status", "--vault", vault_a.to_str().unwrap()],
    );
    assert_eq!(code(&status), 0, "{}", text(&status.stderr));
    let status_err = text(&status.stderr);
    assert!(status_err.contains("conflict: 2 heads"), "{status_err}");
    assert!(status_err.contains(&head_a), "{status_err}");
    assert!(status_err.contains(&head_b), "{status_err}");

    let blocked = run(
        &state_fresh,
        &[PASS],
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
        &[PASS],
        &["select-head", "--vault", vault_a.to_str().unwrap(), &head_a],
    );
    assert_eq!(code(&selected), 0, "{}", text(&selected.stderr));
    assert!(text(&selected.stderr).contains("selected "));
    let wrote = run(
        &state_fresh,
        &[PASS],
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
        &[PASS],
        &["get", "--vault", vault_a.to_str().unwrap(), "more"],
    );
    assert_eq!(got.stdout, b"after-select");

    let other = run(
        &state_fresh,
        &[PASS],
        &["select-head", "--vault", vault_a.to_str().unwrap(), &head_b],
    );
    assert_eq!(code(&other), 0, "{}", text(&other.stderr));
    let beta_out = run(
        &state_fresh,
        &[PASS],
        &["get", "--vault", vault_a.to_str().unwrap(), "beta"],
    );
    assert_eq!(code(&beta_out), 0, "{}", text(&beta_out.stderr));
    assert_eq!(beta_out.stdout, b"from-b");
    let absent = run(
        &state_fresh,
        &[PASS],
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
