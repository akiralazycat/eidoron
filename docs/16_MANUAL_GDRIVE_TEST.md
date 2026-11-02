# Manual check with Google Drive for desktop

- Created: **2026-11-02**
- Status: **a procedure for a person. Not an automated test, and not a guarantee.**
- Related: [envelope](09_ENVELOPE_FORMAT_V0.md), [metadata](14_METADATA_LEAKAGE.md), [cleanup policy](15_GC_POLICY.md)

Two computers each run Google Drive for desktop and the `eidoron` binary against one shared folder. The app does not call Google. Drive copies files on its own. This note says what to do, what to write down, and which results the repository's tests already cover. It does not say that Drive, the network, or a crash will behave.

Use a disposable passphrase and a disposable text file. Do not put a real secret in the folder. Do not commit the folder or the passphrase.

## What the automated tests already show

These are local tests. They copy files in a temp directory. They do not start Drive.

- One folder can hold two heads. `status` stays `conflict: N heads` and lists each head. A write before `select-head` stops with `select-head is required before writing`.
- A missing chunk or descriptor is `incomplete` with `waiting: head <hex> <name>`. Reading that file is `unavailable` and does not print a partial plaintext.
- A name such as `vault.header (1)` or `vault.header (conflicted copy)` is printed as `header conflict copy, not opened: <name>`. The bytes are not read and are not deleted.
- `passwd` asks `current password:`, then `new password:`, then `repeat new password:`. It does not ask `password:` first. A mismatch prints `passwords do not match` and leaves `vault.header` as it was.
- After a local password change, a byte-for-byte copy of the previous header still opens with the old password. Password change is not revocation.
- If the header on disk is no longer the one just written, the command prints `password change did not take effect`. Two devices that both finish `passwd` and then sync are a different case: each command can succeed on its own disk. Which header remains is decided later by the sync tool.
- The selected head is not a file in the vault folder. Conflict copies are not deleted. Nothing is garbage-collected.
- A short file's chunk object is 4226 bytes in the tests: 88-byte object prefix, 26-byte chunk header, 4096-byte padded payload, 16-byte tag. `vault.header` is 136 bytes. Object names are 64 lowercase hex characters.

## Setup

Record this before changing anything:

| Field | Device A | Device B |
|---|---|---|
| OS and Drive for desktop version | | |
| `eidoron` git commit (`git rev-parse HEAD`) | | |
| Path of the synced folder | | |
| Path of the selection state (must be outside that folder) | | |
| How you paused sync (client pause, quit, or network off) | | |

Build from this repository with `cargo build --release --locked -p eidoron-cli`. The binary is `target/release/eidoron`.

The vault folder is a directory Drive already syncs. Examples that exist on some installs are `~/Library/CloudStorage/GoogleDrive-…/My Drive/…` on macOS and a `My Drive` directory on Windows. Use the path the client actually shows. Write that path down. Do not assume a path from this note.

The selection file must not live in the Drive folder. Leave `EIDORON_STATE_DIR` unset and confirm the state directory is `~/.local/state/eidoron` or `$XDG_STATE_HOME/eidoron`, and that this path is outside Drive. Each device has its own state. `select-head` on A does not travel to B.

Passwords are typed at the prompt. They are not command-line arguments. `EIDORON_PASSWORD` and `EIDORON_NEW_PASSWORD` are ignored; if either is set, stderr says so and does not print the value. Do not set `EIDORON_PASSWORD_STDIN` for this procedure. That switch is only for automation: prompts are written to stderr and each password is one stdin line.

Commands below use `eidoron` and `--vault <folder>`. `<folder>` is the synced directory.

## A. Create on device A

1. Start from an empty synced directory, or a new empty subdirectory.
2. Run `eidoron create <folder>`.
3. The prompt is `password:` once. The characters you type are not echoed.
4. Expect stderr to include `created`.

Write down: the prompt text, the exit, the names and sizes in the folder. Expect a 136-byte `vault.header` and one or more 64-hex files. Expect no file in this folder whose job is "the selected head".

Stop if create fails because the directory was not empty. Do not delete Drive's own files to force it.

## B. Write and read on device A

1. Put a short text file outside the vault, for example a few bytes of synthetic text.
2. `eidoron put --vault <folder> note <that-file>`.
3. Expect `wrote` and a 64-hex head id. Copy that id.
4. `eidoron get --vault <folder> note` and compare stdout with the file.
5. `eidoron status --vault <folder>`. Expect a line `ok`.
6. `eidoron ls --vault <folder>`. Expect `note	file`.

Write down: the head id, whether stdout matched, the new 64-hex names, and their sizes. For this short file the tests expect one new object of 4226 bytes (the padded chunk) plus smaller objects (commit, directory, descriptor). If a size is different, record the size you saw. Do not "correct" it.

## C. Sync to device B

1. Wait until Drive shows the same names and sizes on B. Record how long you waited and whether the client said the folder was synced.
2. On B, `eidoron status --vault <folder>`. Expect `ok` if every file arrived and there is still one head.
3. On B, `eidoron get --vault <folder> note`. Expect the same bytes as on A.

Write down: the file list on B before and after, and both status outputs.

If B already shows a name like `something (1)` or `conflicted copy`, stop the later steps. Record the exact name and size, and that you did not delete it. `eidoron` does not remove those files. A header copy is only a warning when the name matches the patterns in the tests (` (digits)` or `conflicted copy`, and the name contains `vault.header`).

## D. Concurrent edits, then Conflict

Object names are random hex, so two devices adding different files usually create different names. Drive may not invent a ` (1)` file for those objects. The fork is two commits that share a parent, once both sets of files are in one folder.

1. Wait until A and B are both `ok` on the same files.
2. Pause sync with the method you recorded. Do this on both devices before either write.
3. On A, `eidoron put` a new name, such as `from-a`.
4. On B, `eidoron put` a different name, such as `from-b`.
5. Resume sync. Wait until each folder contains the hex files the other device added. Record the lists.
6. On each device, `eidoron status --vault <folder>`.

Expect:

```text
conflict: 2 heads
  <64 hex>
  <64 hex>
```

7. On A, `eidoron put` another name before `select-head`, using a state directory that does not already remember one of those heads. If A saved a head at the earlier `put`, that saved head is still a head, and a further write is allowed. To see the refusal, point `EIDORON_STATE_DIR` at an empty directory outside Drive for this one command.

Expect exit code 2 and:

```text
conflict: 2 heads
  <64 hex>
  <64 hex>
select-head is required before writing
```

8. `eidoron select-head --vault <folder> <one of the hex ids>`. Expect `selected` and that id. This writes the choice outside the vault folder. Confirm the synced folder did not gain a new non-hex file from this command.
9. `eidoron get` the name written on that head. Expect those bytes.
10. `select-head` the other id and `get` the other name. Expect those bytes, and `unavailable` for the name that exists only on the first head.

Write down: both head ids, both status transcripts, the refused write, and that you did not delete either head's files. If Drive created a conflict copy, record the exact name and size and leave the file in place. `eidoron` must not have removed it.

This does not show that Drive will always deliver both sides, or that the app merges them. The tests show that a folder which contains both heads reports both, and that a write needs a selected head.

## E. A file that has not arrived, then Incomplete

Prefer to catch this during step C or D if B's folder is missing a hex file that A already has. If the client only syncs whole files, you may not see a half-written object. In that case use the local stand-in below. Label it as a stand-in in your notes. It is the situation the unit test builds by deleting a chunk file. It is not a measurement of Drive's uploader.

Stand-in, on a copy or after sync is paused:

1. From step B, the short file's chunk is the new object whose size is 4226 bytes, if that size matched. Move that one file aside, outside the synced folder. Do not move `vault.header`. Do not move a conflict copy.
2. `eidoron status --vault <folder>`.

Expect `incomplete`, a `head <64 hex>` line, and `waiting: head <64 hex> note` when the missing file is that note's descriptor or chunk.

3. `eidoron get --vault <folder> note`. Expect `unavailable` and empty stdout.
4. Move the file back. `status` with one head and no other damage expects `ok`. `get` expects the original bytes.

Write down: the file name and size you moved, the status text, and whether stdout was empty. If you moved a commit instead of the chunk, status can be `incomplete` with no `waiting` line, or `unavailable` if a remaining file does not decrypt. Record that result; do not describe it as the chunk case.

A fork plus a missing file is still `conflict: N heads`, with `waiting:` lines. `incomplete` is only for a single head. The tests pin that. If you see something else, copy the transcript.

## F. Concurrent passwd, then a header copy

Do this only on the disposable vault.

1. Sync so A and B both open with the same password and `status` is `ok`.
2. Outside the synced folder, copy `vault.header` to a private path. Record its size (136 bytes in the tests).
3. Pause sync.
4. On A, `eidoron passwd --vault <folder>`. The prompts are, in order, `current password:`, `new password:`, `repeat new password:`. There is no earlier `password:` prompt. Use a new disposable passphrase and type it twice.
5. Expect `password changed` and `a saved copy of the old header still opens with the old password`.
6. On B, `passwd` as well, with a different new passphrase, still typing the original current password (B has not seen A's header yet).
7. Resume sync.

Write down, after the client settles:

- The exact names in the folder that contain `vault.header`.
- The size of each.
- `eidoron status` on each device. A recognized copy looks like `header conflict copy, not opened: vault.header (1)` or the same with `conflicted copy`. The name has to match what the tests classify. If Drive uses another name, status may not warn. Record the real name. Do not rename the file to force the warning.
- Which of the two new passphrases still opens `vault.header` (`status` prints `ok` or `conflict`, not `unavailable`).
- That the other new passphrase prints `unavailable`.
- That the conflict-copy file's bytes are unchanged across a later `status` (compare a hash you took before and after). Do not delete it.
- Optional, and only on the private copy from step 2, not inside the Drive folder: `eidoron status` cannot see that copy. To check non-revocation without touching Drive, point a throwaway directory's `vault.header` at those saved bytes and open it with the original passphrase. The tests show those bytes still unwrap the same root. Do not copy them back over the live `vault.header` unless you intend to throw the vault away.

`password change did not take effect` is what one local command returns when the header changes during that command. It is not what you should require from Drive after both commands have already printed `password changed`.

What you must not conclude: that the losing passphrase is revoked everywhere, that an old header copy is useless, that Drive kept both headers, or that the warning appears for every sync product's naming.

## G. Afterward

- Delete the disposable vault from Drive on purpose, from the client, if you are finished. `eidoron` will not do that.
- Confirm no passphrase was written into the shell history as an argument.
- Keep the notes with the commit hash. A result that differs from the expected text above is a finding. Copy stderr. Do not explain it away as "Drive will catch up" unless a later `status` actually changed, and record that too.

## What this procedure does not show

- Crash safety beyond the tested temp file, `sync_all`, and rename.
- That Google Drive delivers, orders, or retries bytes in any particular way.
- That conflict copies are merged or deleted.
- That password change revokes a saved header.
- That both heads can be read in one view. They cannot. You select one.
- A clean bill of health for production use.
