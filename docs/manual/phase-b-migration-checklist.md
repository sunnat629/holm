# Phase B manual check: migrating a vault to format 2

Tests cover the migration, the backup and the prompts with fake stores and a fake window. They
cannot show the real dialog flow or a real disk. Run this once on a real Mac before the merge,
and write down who ran it, the date, the macOS version and the chip.

## What the user is told

- The first time a vault from an older Holm is saved, Holm moves it to a new file format. It
  first writes a copy of the old file next to the vault, named like `holm.vault.v1-0123456789abcdef.bak`.
- After the next unlock Holm asks whether to delete that copy, and asks again at each unlock until you decide. Holm never deletes it without a yes.
- The copy opens with the password the vault had before the move. If you change the password,
  the copy still opens with the old one. Deleting it does not remove Time Machine copies,
  other snapshots, and an SSD can keep traces of a deleted file.
- An older Holm cannot open the new format. It says "This file isn't a Holm vault, or it is
  damaged." and leaves the file unchanged. Edits made after the move are not in the copy.

## Going back to the older Holm

1. Quit Holm.
2. Move the vault file somewhere else (do not delete it yet).
3. Rename the `.bak` copy to the vault's name.
4. Open it with the older Holm and the old password.

## Runs

Use a copy of a real v1 vault (one made by the 0.1.x app), never your only copy.

| Step | Expect | Result |
|---|---|---|
| Open the v1 copy, unlock, change nothing, lock | File unchanged byte for byte, no `.bak` written | |
| Unlock, edit one title, save | `.bak` appears, file now format 2 (`holm list` still works) | |
| Lock, unlock again | The "old copy" prompt appears with Delete and Keep | |
| Choose Keep (Later), then lock and unlock again | Prompt is gone for this session and comes back at the next unlock; the `.bak` stays | |
| Change the master password | A stronger prompt names the old password | |
| Choose Delete | `.bak` is gone, prompt gone | |
| Put a different file at the `.bak` name, then migrate another v1 copy that maps to it | Save fails with the message about removing the stale `.bak` | |
| Run an older `holm list` on the format 2 vault | "This file isn't a Holm vault, or it is damaged."; file unchanged | |
| Show a password, then hide it, with Activity Monitor open | No visible growth per frame while idle (nothing decrypts per frame) | |

| Who | Date | macOS | Chip | Result |
|---|---|---|---|---|
| | | | | |
