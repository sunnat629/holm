# Phase 5 manual check: lock on sleep, screen lock and logout

The tests drive the GUI with a fake window that can post an OS lock event, and both
front ends with a test clock that can jump the wall clock as a sleep would. They cannot
close a real lid, lock a real screen or switch a real user. This list covers those. Run
it once on a real Mac before the Phase 5 merge, and write down who ran it, the date, the
macOS version and the chip.

## Runs

| Run | Who | Date | macOS | Chip | Result |
|---|---|---|---|---|---|
| 1 | Implementer (agent, no screen) | 2026-10-22 | | | Automatic parts only: see below |
| 2 | Owner | | | | |

## Before you start

- Use a throwaway vault with fake data only, as in the Phase 4 checklist:

  ```
  V="$(mktemp -d)/Holm/holm.vault"; echo "$V"
  cargo build -p holm-cli -p holm-gui --locked
  ./target/debug/holm --vault "$V" init
  ```
- Keep auto-lock at the default 300 s, so a lock within a minute is the sleep lock and
  not the idle lock. The lock line says which: the GUI shows "Holm locked because the
  Mac slept, the screen locked or you logged out."; the shell prints "Locked because the
  computer slept." or, after a user switch, "Locked because the Mac switched to another
  user or the login window."
- Before each check, copy a password (GUI "Copy", shell `get <name> --copy`), so you can
  also see that the clipboard is cleared by the lock (paste into TextEdit: nothing).

## Run 1: what was checked without a person at the screen

- [x] `cargo test --workspace --locked`: GUI tests `os_lock_event_locks_before_draw`,
  `wall_jump_locks_gui`, `lock_on_sleep_false_ignores_event`,
  `sleep_lock_clears_clipboard`, `sleep_during_job_locks_when_job_ends`; shell tests
  `shell_locks_on_sleep_at_prompt`, `shell_locks_on_sleep_inside_inner_prompt`,
  `shell_keeps_typed_line_until_sleep_lock`, `shell_lock_on_sleep_false_stays_open`,
  `sleep_while_locked_then_unlock_stays_open`, `shell_locks_when_console_user_changes`,
  `shell_locks_on_console_change_inside_inner_prompt`,
  `shell_unreadable_console_is_no_change`, `shell_unlock_takes_the_console_owner_again`;
  `copy_wait_ends_on_wake_after_sleep` (one-shot `get --copy`); `tty` tests for
  interrupt and polling.
- [x] `LockEvents::install()` off the main thread returns `None`
  (`install_off_main_thread_is_none`).
- [ ] Everything below needs a person at the Mac.

## 1. Sleep (close the lid, or Apple menu > Sleep)

GUI:
- [ ] Open the vault in Holm.app (or `./target/debug/holm-gui --vault "$V"`), copy a
  password, then sleep the Mac for at least 10 s and wake it.
- [ ] The unlock screen shows, with the sleep lock line. No vault row was visible after
  the wake, not even for a moment.
- [ ] The clipboard is empty.

`holm shell`:
- [ ] Start `./target/debug/holm --vault "$V" shell`, unlock, copy a password, type a
  few letters at `holm>` without Enter, then sleep the Mac for at least 10 s and wake it.
- [ ] The shell prints the sleep lock line and shows the locked prompt. The half-typed
  letters were not run (no "unknown command" line).
- [ ] The clipboard is empty.

## 2. Screen lock (Ctrl-Cmd-Q)

GUI:
- [ ] With the vault open, press Ctrl-Cmd-Q, wait 5 s, log back in.
- [ ] Holm shows the unlock screen with the sleep lock line; the clipboard is empty.

`holm shell`:
- [ ] With the shell unlocked, press Ctrl-Cmd-Q, wait 5 s, log back in.
- [ ] Expected: the shell stays unlocked. It has no run loop and cannot see a screen
  lock that neither sleeps nor switches users (the console keeps its owner); the idle
  lock (auto-lock time) still applies. If the Mac slept while locked (screens off long
  enough for system sleep), it locks on wake. Write down what you saw.

## 3. Fast user switch (Control Centre > user name > another user, or Login Window)

GUI:
- [ ] With the vault open, switch to the login window, wait 5 s, switch back.
- [ ] Holm shows the unlock screen with the sleep lock line.

`holm shell`:
- [ ] With the shell unlocked and a password copied, type a few letters at `holm>`
  without Enter, switch to the login window (or another user), wait 5 s, switch back.
- [ ] Within about a second of the switch the shell locked: it prints the user switch
  lock line and the locked prompt, the half-typed letters were not run, and the
  clipboard is empty. Check with `stat -f %Su /dev/console` in another terminal that
  the console's owner changed while you were away (root at the login window).

## 4. Logout

- [ ] With the GUI vault open, log out and log back in. Holm must not come back with the
  vault open: it either locked (a session going inactive posts
  `NSWorkspaceSessionDidResignActiveNotification`) or quit. Write down which, and
  whether the clipboard was empty after logging back in.

## 5. The setting is off

Neither front end has a control for `lock_on_sleep` yet (it is on in every new vault,
and turning it off needs the password through `Session::update_settings`). The off case
is covered by `lock_on_sleep_false_ignores_event` (GUI) and
`shell_lock_on_sleep_false_stays_open` (shell). Nothing to do here by hand until a
settings screen lands.

## Known limits (expected, not failures)

- `holm shell` locks on sleep and on a new `/dev/console` owner (user switch, login
  window), not on a screen lock (Ctrl-Cmd-Q) with neither. The idle lock covers it
  there. If `/dev/console` can't be read, the user switch check is off (no lock on
  errors).
- A sleep shorter than 5 s with no notification is missed by the shell.
- Setting the clock forward by more than 5 s locks both front ends. That is on purpose.
