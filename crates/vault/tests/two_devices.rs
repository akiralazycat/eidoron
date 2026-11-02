//! Two sessions, one vault folder or two folders joined by copying files.
//!
//! Copying stands in for a sync tool. Conflict-copy names are planted the way
//! that tool names them. These tests do not call a cloud API.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eidoron_provider_local::VAULT_HEADER_NAME;
use eidoron_vault::{Session, VaultStatus, WaitingFile, create_vault, open_vault};

const PASS: &str = "synthetic-vault-pass";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "eidoron-devices-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).expect("read") {
        let entry = entry.expect("entry");
        if entry.path().is_file() {
            let name = entry.file_name().into_string().expect("name");
            files.push((name, fs::read(entry.path()).expect("bytes")));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn only_head(session: &Session) -> [u8; 32] {
    let heads = session.heads().expect("heads");
    assert_eq!(heads.len(), 1);
    heads[0]
}

#[test]
fn two_devices_diverge_then_one_appends_and_both_reopen() {
    let device_a = Scratch::new();
    let mut first = create_vault(&device_a.0, PASS).expect("create");
    let genesis = only_head(&first);
    let device_b = Scratch::new();
    copy_files(&device_a.0, &device_b.0);
    let mut second = open_vault(&device_b.0, PASS).expect("open b");
    first.select_head(genesis).expect("select a");
    second.select_head(genesis).expect("select b");
    let left = first
        .write_file(genesis, "from-a", b"alpha")
        .expect("write a");
    let right = second
        .write_file(genesis, "from-b", b"beta")
        .expect("write b");
    drop(second);
    copy_missing(&device_b.0, &device_a.0);
    match first.status().expect("fork") {
        VaultStatus::Conflict { heads, waiting } => {
            assert!(waiting.is_empty());
            assert!(heads.contains(&left) && heads.contains(&right));
        }
        other => panic!("expected conflict, got {other:?}"),
    }
    let before = snapshot(&device_a.0);
    first.select_head(left).expect("stay on a");
    let child = first
        .write_file(left, "only-a", b"more")
        .expect("append on a");
    for (name, bytes) in &before {
        if snapshot(&device_a.0).iter().any(|(found, _)| found == name) {
            let now = fs::read(device_a.0.join(name)).expect("still");
            assert_eq!(&now, bytes, "{name}");
        }
    }
    match first.status().expect("after append") {
        VaultStatus::Conflict { heads, waiting } => {
            assert!(waiting.is_empty());
            assert!(heads.contains(&child) && heads.contains(&right));
            assert!(!heads.contains(&left));
        }
        other => panic!("expected conflict, got {other:?}"),
    }
    copy_missing(&device_a.0, &device_b.0);
    let mut reopened_b = open_vault(&device_b.0, PASS).expect("reopen b");
    let reopened_a = open_vault(&device_a.0, PASS).expect("reopen a");
    assert_eq!(
        reopened_a.heads().expect("heads a"),
        reopened_b.heads().expect("heads b")
    );
    reopened_b.select_head(right).expect("b selects its head");
    assert_eq!(reopened_b.read_file("from-b").expect("beta"), b"beta");
    assert_eq!(
        reopened_b.read_file("from-a").err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
}

#[test]
fn a_late_chunk_is_waiting_and_conflict_copies_stay_put() {
    let device_a = Scratch::new();
    let mut writer = create_vault(&device_a.0, PASS).expect("create");
    let genesis = only_head(&writer);
    writer.select_head(genesis).expect("select");
    let head = writer
        .write_file(genesis, "note", b"sync-me")
        .expect("write");
    drop(writer);
    let device_b = Scratch::new();
    copy_files(&device_a.0, &device_b.0);
    let mut reader = open_vault(&device_b.0, PASS).expect("open b");
    reader.select_head(head).expect("select");
    assert_eq!(reader.read_file("note").expect("full"), b"sync-me");
    // 88-byte object prefix, 26-byte chunk header, 16-byte tag.
    let overhead = 88 + 26 + 16;
    let bucket = 4096;
    let mut hidden = None;
    for (name, bytes) in snapshot(&device_b.0) {
        if name.len() == 64 && bytes.len() == overhead + bucket {
            hidden = Some((device_b.0.join(&name), bytes));
            break;
        }
    }
    let (path, bytes) = hidden.expect("padded chunk");
    let copy_path = device_b.0.join("notes (1)");
    let conflicted_path = device_b.0.join("notes (conflicted copy)");
    fs::write(&copy_path, b"drive-copy").expect("copy");
    fs::write(&conflicted_path, b"dropbox-copy").expect("conflicted");
    fs::remove_file(&path).expect("delay chunk");
    match reader.status().expect("waiting") {
        VaultStatus::Incomplete {
            head: Some(seen),
            waiting,
        } => {
            assert_eq!(seen, head);
            assert_eq!(
                waiting,
                vec![WaitingFile {
                    head,
                    name: "note".to_string(),
                }]
            );
        }
        other => panic!("expected incomplete, got {other:?}"),
    }
    assert_eq!(
        reader.read_file("note").err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
    assert_eq!(fs::read(&copy_path).expect("copy"), b"drive-copy");
    fs::write(&path, &bytes).expect("chunk arrives");
    assert_eq!(reader.status().expect("complete"), VaultStatus::Ok);
    assert_eq!(reader.read_file("note").expect("note"), b"sync-me");
    assert_eq!(fs::read(&copy_path).expect("copy after"), b"drive-copy");
    assert_eq!(
        fs::read(&conflicted_path).expect("conflicted after"),
        b"dropbox-copy"
    );
}

#[test]
fn password_change_does_not_touch_a_header_conflict_copy() {
    let folder = Scratch::new();
    let mut session = create_vault(&folder.0, PASS).expect("create");
    let genesis = only_head(&session);
    session.select_head(genesis).expect("select");
    let head = session
        .write_file(genesis, "kept", b"still-here")
        .expect("file");
    let objects_before: Vec<_> = snapshot(&folder.0)
        .into_iter()
        .filter(|(name, _)| name != VAULT_HEADER_NAME)
        .collect();
    let header_path = folder.0.join(VAULT_HEADER_NAME);
    let old_header = fs::read(&header_path).expect("old header");
    let copy_path = folder.0.join("vault.header (1)");
    fs::write(&copy_path, b"provider-header-copy").expect("header copy");
    session
        .change_password(PASS, "synthetic-new-pass")
        .expect("change");
    assert_ne!(fs::read(&header_path).expect("new header"), old_header);
    assert_eq!(
        fs::read(&copy_path).expect("copy untouched"),
        b"provider-header-copy"
    );
    for (name, bytes) in &objects_before {
        assert_eq!(
            fs::read(folder.0.join(name)).expect("object"),
            *bytes,
            "{name}"
        );
    }
    session.select_head(head).expect("still selected");
    assert_eq!(session.read_file("kept").expect("same root"), b"still-here");
    drop(session);
    assert_eq!(
        open_vault(&folder.0, PASS).err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
    let mut opened = open_vault(&folder.0, "synthetic-new-pass").expect("new pass");
    opened.select_head(head).expect("select");
    assert_eq!(
        opened.read_file("kept").expect("after reopen"),
        b"still-here"
    );
    let mut other = open_vault(&folder.0, "synthetic-new-pass").expect("second device");
    let saved = fs::read(&header_path).expect("saved");
    assert_eq!(
        other.change_password(PASS, "synthetic-other-pass").err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
    assert_eq!(fs::read(&header_path).expect("header stays"), saved);
    fs::remove_file(&header_path).expect("hide real header");
    assert_eq!(
        open_vault(&folder.0, "synthetic-new-pass").err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
    assert_eq!(
        fs::read(&copy_path).expect("copy still"),
        b"provider-header-copy"
    );
    fs::write(&header_path, &saved).expect("restore");
    fs::write(folder.0.join("old-header-kept-by-user"), &old_header).expect("stash old");
    assert_eq!(
        open_vault(&folder.0, PASS).err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
    fs::write(&header_path, &old_header).expect("attacker replays the old header");
    let mut replayed = open_vault(&folder.0, PASS).expect("old header still unwraps");
    replayed.select_head(head).expect("select");
    assert_eq!(
        replayed.read_file("kept").expect("root unchanged"),
        b"still-here"
    );
    assert_eq!(
        open_vault(&folder.0, "synthetic-new-pass").err(),
        Some(eidoron_vault::VaultError::Unavailable)
    );
}
