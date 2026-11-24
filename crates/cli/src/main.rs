//! Local commands for one sync-folder vault.
//!
//! A person types a password at a hidden prompt. It is never a command-line
//! argument. `EIDORON_PASSWORD` and `EIDORON_NEW_PASSWORD` are ignored.
//! Automation sets `EIDORON_PASSWORD_STDIN` and writes one line per prompt.
//! The selected head is stored outside the vault folder.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::{Parser, Subcommand};
use eidoron_vault::{Session, VaultError, VaultStatus, create_vault, open_vault};

#[derive(Parser)]
#[command(name = "eidoron", about = "Local encrypted vault in a sync folder")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a vault in an empty directory.
    Create { folder: PathBuf },
    /// Print heads, waiting files, and header conflict copies.
    Status {
        #[arg(long)]
        vault: PathBuf,
    },
    /// Remember a head outside the vault folder.
    SelectHead {
        #[arg(long)]
        vault: PathBuf,
        head: String,
    },
    /// List names in the selected head.
    Ls {
        #[arg(long)]
        vault: PathBuf,
    },
    /// Add a file from a local path.
    Put {
        #[arg(long)]
        vault: PathBuf,
        name: String,
        file: PathBuf,
    },
    /// Replace a file. The old objects stay on disk.
    Replace {
        #[arg(long)]
        vault: PathBuf,
        name: String,
        file: PathBuf,
    },
    /// Unlink a name. The object stays on disk.
    Rm {
        #[arg(long)]
        vault: PathBuf,
        name: String,
    },
    /// Read a file. Bytes go to stdout, or to --output.
    Get {
        #[arg(long)]
        vault: PathBuf,
        name: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Change the local password. This does not revoke a saved header.
    Passwd {
        #[arg(long)]
        vault: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Create { folder } => create(&folder),
        Command::Status { vault } => status(&vault),
        Command::SelectHead { vault, head } => select_head(&vault, &head),
        Command::Ls { vault } => ls(&vault),
        Command::Put { vault, name, file } => write_path(&vault, &name, &file, false),
        Command::Replace { vault, name, file } => write_path(&vault, &name, &file, true),
        Command::Rm { vault, name } => rm(&vault, &name),
        Command::Get {
            vault,
            name,
            output,
        } => get(&vault, &name, output.as_deref()),
        Command::Passwd { vault } => passwd(&vault),
    }
}

fn create(folder: &Path) -> ExitCode {
    let password = match password_line("password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };
    match create_vault(folder, &password) {
        Ok(_) => {
            eprintln!("created");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn status(vault: &Path) -> ExitCode {
    let Some(session) = open_session(vault) else {
        return ExitCode::from(1);
    };
    let state = match session.status() {
        Ok(state) => state,
        Err(error) => return fail(error),
    };
    print_state(&state);
    match session.header_conflict_copies() {
        Ok(copies) => print_header_copies(&copies),
        Err(error) => return fail(error),
    }
    ExitCode::SUCCESS
}

fn select_head(vault: &Path, head: &str) -> ExitCode {
    let Some(mut session) = open_session(vault) else {
        return ExitCode::from(1);
    };
    let Some(id) = parse_hex(head) else {
        eprintln!("head must be 64 lowercase hex characters");
        return ExitCode::from(2);
    };
    if let Err(error) = session.select_head(id) {
        return fail(error);
    }
    if let Err(error) = save_head(vault, &id) {
        eprintln!("could not store the selected head: {error}");
        return ExitCode::from(1);
    }
    eprintln!("selected {}", hex_id(&id));
    ExitCode::SUCCESS
}

fn ls(vault: &Path) -> ExitCode {
    let Some(mut session) = open_session(vault) else {
        return ExitCode::from(1);
    };
    let Some(head) = prepare_head(&mut session, vault, false) else {
        return ExitCode::from(2);
    };
    if let Err(error) = session.select_head(head) {
        return fail(error);
    }
    match session.list_directory() {
        Ok(entries) => {
            for entry in entries {
                println!("{}\t{}", entry.name, kind_label(entry.kind));
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn write_path(vault: &Path, name: &str, file: &Path, replace: bool) -> ExitCode {
    let Some(mut session) = open_session(vault) else {
        return ExitCode::from(1);
    };
    let Some(head) = prepare_head(&mut session, vault, true) else {
        return ExitCode::from(2);
    };
    if let Err(error) = session.select_head(head) {
        return fail(error);
    }
    let bytes = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("could not read the file");
            return ExitCode::from(1);
        }
    };
    let result = if replace {
        session.replace_file(head, name, &bytes)
    } else {
        session.write_file(head, name, &bytes)
    };
    match result {
        Ok(new_head) => {
            let _ = save_head(vault, &new_head);
            eprintln!("wrote {}", hex_id(&new_head));
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn rm(vault: &Path, name: &str) -> ExitCode {
    let Some(mut session) = open_session(vault) else {
        return ExitCode::from(1);
    };
    let Some(head) = prepare_head(&mut session, vault, true) else {
        return ExitCode::from(2);
    };
    if let Err(error) = session.select_head(head) {
        return fail(error);
    }
    match session.delete_entry(head, name) {
        Ok(new_head) => {
            let _ = save_head(vault, &new_head);
            eprintln!("unlinked {}", hex_id(&new_head));
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn get(vault: &Path, name: &str, output: Option<&Path>) -> ExitCode {
    let Some(mut session) = open_session(vault) else {
        return ExitCode::from(1);
    };
    let Some(head) = prepare_head(&mut session, vault, false) else {
        return ExitCode::from(2);
    };
    if let Err(error) = session.select_head(head) {
        return fail(error);
    }
    let mut stream = match session.read_file_chunks(name) {
        Ok(stream) => stream,
        Err(error) => return fail(error),
    };
    let mut file;
    let mut stdout;
    let sink: &mut dyn Write = if let Some(path) = output {
        file = match File::create(path) {
            Ok(file) => file,
            Err(_) => {
                eprintln!("could not create the output file");
                return ExitCode::from(1);
            }
        };
        &mut file
    } else {
        stdout = io::stdout();
        &mut stdout
    };
    loop {
        match stream.next_chunk() {
            Ok(Some(chunk)) => {
                if sink.write_all(&chunk).is_err() {
                    eprintln!("could not write output");
                    return ExitCode::from(1);
                }
            }
            Ok(None) => break,
            Err(error) => return fail(error),
        }
    }
    ExitCode::SUCCESS
}

fn passwd(vault: &Path) -> ExitCode {
    let current = match password_line("current password: ") {
        Ok(password) => password,
        Err(code) => return code,
    };
    let mut session = match open_vault(vault, &current) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let new_password = match new_password() {
        Ok(password) => password,
        Err(code) => return code,
    };
    match session.change_password(&current, &new_password) {
        Ok(()) => {
            eprintln!("password changed");
            eprintln!("a saved copy of the old header still opens with the old password");
            ExitCode::SUCCESS
        }
        Err(VaultError::PasswordNotApplied) => {
            eprintln!("{}", VaultError::PasswordNotApplied);
            ExitCode::from(2)
        }
        Err(error) => fail(error),
    }
}

fn open_session(vault: &Path) -> Option<Session> {
    let password = match password_line("password: ") {
        Ok(password) => password,
        Err(_) => return None,
    };
    match open_vault(vault, &password) {
        Ok(session) => Some(session),
        Err(error) => {
            eprintln!("{error}");
            None
        }
    }
}

fn prepare_head(session: &mut Session, vault: &Path, for_write: bool) -> Option<[u8; 32]> {
    let state = match session.status() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("{error}");
            return None;
        }
    };
    print_header_warning(session);
    let heads = match &state {
        VaultStatus::Ok => match session.heads() {
            Ok(heads) => heads,
            Err(error) => {
                eprintln!("{error}");
                return None;
            }
        },
        VaultStatus::Conflict { heads, waiting } => {
            if let Some(saved) = load_head(vault)
                && heads.contains(&saved)
            {
                return Some(saved);
            }
            eprintln!("conflict: {} heads", heads.len());
            for head in heads {
                eprintln!("  {}", hex_id(head));
            }
            for file in waiting {
                eprintln!("waiting: head {} {}", hex_id(&file.head), file.name);
            }
            need_select(for_write);
            return None;
        }
        VaultStatus::Incomplete { head, waiting } => {
            eprintln!("incomplete");
            for file in waiting {
                eprintln!("waiting: head {} {}", hex_id(&file.head), file.name);
            }
            let known = match session.heads() {
                Ok(heads) => heads,
                Err(error) => {
                    eprintln!("{error}");
                    return None;
                }
            };
            if let Some(saved) = load_head(vault)
                && (head.is_some_and(|id| id == saved) || known.contains(&saved))
            {
                return Some(saved);
            }
            if let Some(id) = head {
                if waiting.is_empty() {
                    return None;
                }
                return Some(*id);
            }
            return None;
        }
        VaultStatus::Locked => {
            eprintln!("locked");
            return None;
        }
    };
    if heads.len() == 1 {
        return Some(heads[0]);
    }
    if let Some(saved) = load_head(vault)
        && heads.contains(&saved)
    {
        return Some(saved);
    }
    need_select(for_write);
    None
}

fn need_select(for_write: bool) {
    if for_write {
        eprintln!("select-head is required before writing");
    } else {
        eprintln!("select-head is required");
    }
}

fn print_state(state: &VaultStatus) {
    match state {
        VaultStatus::Ok => eprintln!("ok"),
        VaultStatus::Locked => eprintln!("locked"),
        VaultStatus::Conflict { heads, waiting } => {
            eprintln!("conflict: {} heads", heads.len());
            for head in heads {
                eprintln!("  {}", hex_id(head));
            }
            for file in waiting {
                eprintln!("waiting: head {} {}", hex_id(&file.head), file.name);
            }
        }
        VaultStatus::Incomplete { head, waiting } => {
            eprintln!("incomplete");
            if let Some(head) = head {
                eprintln!("head {}", hex_id(head));
            }
            for file in waiting {
                eprintln!("waiting: head {} {}", hex_id(&file.head), file.name);
            }
        }
    }
}

fn print_header_warning(session: &Session) {
    if let Ok(copies) = session.header_conflict_copies() {
        print_header_copies(&copies);
    }
}

fn print_header_copies(copies: &[String]) {
    for name in copies {
        eprintln!("header conflict copy, not opened: {name}");
    }
}

fn kind_label(kind: eidoron_vault::ChildKind) -> &'static str {
    match kind {
        eidoron_vault::ChildKind::File => "file",
        eidoron_vault::ChildKind::Directory => "directory",
    }
}

fn fail(error: VaultError) -> ExitCode {
    eprintln!("{error}");
    match error {
        VaultError::PasswordNotApplied | VaultError::HeadNotSelected | VaultError::WrongHead => {
            ExitCode::from(2)
        }
        _ => ExitCode::from(1),
    }
}

fn password_line(prompt: &str) -> Result<String, ExitCode> {
    note_ignored_password_env();
    if std::env::var_os("EIDORON_PASSWORD_STDIN").is_some() {
        eprintln!("{prompt}");
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                eprintln!("could not read the password");
                return Err(ExitCode::from(1));
            }
            Ok(_) => {}
            Err(_) => {
                eprintln!("could not read the password");
                return Err(ExitCode::from(1));
            }
        }
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        return Ok(line);
    }
    rpassword::prompt_password(prompt).map_err(|_| {
        eprintln!("could not read the password");
        ExitCode::from(1)
    })
}

fn note_ignored_password_env() {
    static NOTED: AtomicBool = AtomicBool::new(false);
    if NOTED.swap(true, Ordering::Relaxed) {
        return;
    }
    if std::env::var_os("EIDORON_PASSWORD").is_some() {
        eprintln!("EIDORON_PASSWORD is ignored");
    }
    if std::env::var_os("EIDORON_NEW_PASSWORD").is_some() {
        eprintln!("EIDORON_NEW_PASSWORD is ignored");
    }
}

fn new_password() -> Result<String, ExitCode> {
    let first = password_line("new password: ")?;
    let second = password_line("repeat new password: ")?;
    if first != second {
        eprintln!("passwords do not match");
        return Err(ExitCode::from(2));
    }
    Ok(first)
}

fn state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EIDORON_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(xdg).join("eidoron");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/state/eidoron");
    }
    std::env::temp_dir().join("eidoron-state")
}

fn state_path(vault: &Path) -> PathBuf {
    let key = vault_key(vault);
    state_dir().join(key)
}

fn vault_key(vault: &Path) -> String {
    let text = vault.canonicalize().unwrap_or_else(|_| vault.to_path_buf());
    let mut hash = [0u8; 32];
    let bytes = text.to_string_lossy();
    for (index, byte) in bytes.as_bytes().iter().enumerate() {
        let mix = u8::try_from(index & 0xff).unwrap_or(0);
        hash[index % 32] ^= byte.wrapping_add(mix);
    }
    hex_id(&hash)
}

fn save_head(vault: &Path, head: &[u8; 32]) -> io::Result<()> {
    let path = state_path(vault);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let label = vault.canonicalize().unwrap_or_else(|_| vault.to_path_buf());
    let body = format!("{}\n{}\n", label.display(), hex_id(head));
    fs::write(path, body)
}

fn load_head(vault: &Path) -> Option<[u8; 32]> {
    let text = fs::read_to_string(state_path(vault)).ok()?;
    let mut lines = text.lines();
    let stored = lines.next()?;
    let head = lines.next()?;
    let label = vault.canonicalize().unwrap_or_else(|_| vault.to_path_buf());
    if stored != label.display().to_string() {
        return None;
    }
    parse_hex(head)
}

fn parse_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let mut id = [0u8; 32];
    let bytes = text.as_bytes();
    for (index, slot) in id.iter_mut().enumerate() {
        let hi = hex_value(bytes[index * 2])?;
        let lo = hex_value(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(id)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_id(id: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in id {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}
