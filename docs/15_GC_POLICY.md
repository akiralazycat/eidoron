# Unreachable-object cleanup

- Created: **2026-11-01**
- Status: **policy only. No deletion code.**
- Related: [metadata](14_METADATA_LEAKAGE.md), [envelope](09_ENVELOPE_FORMAT_V0.md)

`write_file`, `replace_file`, and `delete_entry` add objects and leave the previous ones in the folder. After a replace or an unlink, some objects may be unreachable from every commit that is still a head. This note is the rule for whether those objects may be removed. It does not add a sweeper.

## What may never be removed

- Any object reachable from any head, including a head whose parent or chunk has not arrived yet (`Incomplete`). A missing chunk means the device does not yet know the whole file. Deleting some other object in that gap can destroy a file the other device still needs.
- Conflict copies (`name (1)`, `conflicted copy`) and any other name that is not an object id. Those files belong to the sync tool.
- `vault.header`.
- Objects that this device cannot decrypt. Failure to open is not proof that the object is unused.

## Why this is not automatic

A sync folder is not a single disk. One device can be offline for weeks. Its head may be a commit this device no longer considers current, and the sync tool may not have delivered that commit yet. An automatic sweep on the device that is online would delete chunks the offline device still reaches. When that device reconnects, the sync tool may also propagate the deletions and erase the only remaining copy.

Automatic deletion would also change the folder while a user is not looking, which is the opposite of the rule that conflict copies and old heads stay until a person acts.

## When a person may ask for a sweep

A sweep is allowed only as an explicit user action, after the app has told them that other devices must be online and caught up. The sweep may remove an object only when all of the following hold:

1. The object name is a 64-character lowercase hex id.
2. Every head currently in the folder has been opened, and none of those heads is `Incomplete`.
3. The object is not reachable from any of those heads.
4. The user confirmed this run. The app does not repeat it on a timer, on startup, or because the folder looks large.

Even then, a device that has not synced can still lose data if its unique head never arrived. The confirmation text has to say that. There is no safer automatic default.

## What this repository does today

Nothing is deleted by a sweep. `delete_entry` only stops naming an object in a new commit. Tests check that the previous descriptor and chunk files are still in the folder after replace and unlink.
