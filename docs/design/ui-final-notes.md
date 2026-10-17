# Holm v1 desktop design: notes

Source file: `ui-final.html` (same folder). The earlier mock, `ui-mock.html`, was not changed.
Binding spec: holm/docs/superpowers/specs/2026-10-17-holm-v1-design.md (§7–§11). All data in the design is fake (example.com, "EXAMPLE-not-real" passwords, a made-up phrase).

## 1. UX audit of the first mock (prioritised)

P0 items affect trust or how honest the app is about security. P1 items affect flow. P2 items affect access and polish.

| # | Pri | Area | Problem | Fix |
|---|---|---|---|---|
| 1 | P0 | Lock states | "Locked" and "Unlock" are two separate screens. Getting back in takes an extra click, and the locked view hints that something is still loaded. | One unlock screen with a reason line (idle, sleep, manual). Spec §10. |
| 2 | P0 | Honest copy | The status bar says "Clipboard: empty" and the lock view says "Clipboard was cleared". Holm can't know either. | Show a clipboard segment only while Holm's copy is pending. After a lock, say "Holm's copy was removed" only if it was still there. |
| 3 | P0 | Honest copy | "Wrong master password." hides the other possible cause: a tampered file gives the same error (§6). | "That password didn't open this vault. Either the password is wrong, or the file was changed or damaged." |
| 4 | P0 | Dangerous actions | Delete forever and Empty trash act on one click. Nothing says that old copies and backups still hold the data. | Confirm modal with Cancel focused. Enter never confirms. The text says honestly what remains (§7). |
| 5 | P0 | Shoulder-surfing | Reveal is a sticky toggle with no timer. The note says "hold to reveal" but the mock does something else. | One rule everywhere: a toggle, an amber frame, and "Visible · hides in 30 s". It hides on timeout, item change, lock or window blur. The mask is always 12 dots. |
| 6 | P0 | Data loss | Nothing says what happens to an unsaved edit when auto-lock fires. | Unsaved edits are discarded on lock. The status bar turns amber 30 s before, and the unlock screen says what was discarded. |
| 7 | P0 | Errors | A save failure is a full-page "Something went wrong" that throws you out of the editor. | An inline banner that keeps your input and says the cause, plus "the file on disk is unchanged". Actions: Try again, Save a copy elsewhere. The status bar shows "Not saved". |
| 8 | P0 | Spec drift | The default path is ~/Documents/Holm. | Use the per-OS app-data path from §8.0. |
| 9 | P1 | Layout | "+ New" sits in the menu. Filters are dropdowns, there's no sort, and the category chips are missing. | The sidebar holds types, Favourites and Trash. The list pane holds search, chips, sort and New (§10). |
| 10 | P1 | First run | No welcome choice, no success screen, no empty-vault state. | Welcome, then Vault created (add, import, back up), then an empty vault. |
| 11 | P1 | Create form | The mismatch error shows while you're still typing the first field. The meter uses colour alone. | Check the match when Confirm loses focus, or on submit. Use a 4-segment meter with a word label and the zxcvbn tip. |
| 12 | P1 | Keyboard | No shortcuts, no Enter or Esc rules, and focus order isn't defined. | Add a shortcut map, autofocus, safe Enter and Esc rules (section 6). |
| 13 | P1 | Recovery phrase | The phrase shows as one line inside the modal, with no timer. | The modal asks only for the password. Then the detail pane shows a numbered 3×4 grid with a 60 s countdown and Hide now. |
| 14 | P1 | Settings | The copy says weakening a setting needs the password, but no flow is drawn. | A weaken-confirm modal shows the old and new value and asks for the password. Settings have ceilings and no "Never". |
| 15 | P1 | Import | Only row-level issues are shown. | Add Too large, Wrong columns and Not UTF-8 errors, a preview that never shows values, and a Done screen with a reminder to delete the source file. |
| 16 | P1 | Change password | No nudge to replace old backups. | The Done screen offers "Save a new backup copy" first. |
| 17 | P2 | Accessibility | Type is shown as letter codes ("Lg"), favourite as "*", and danger only as a red outline. | Give each type its own icon shape plus a text label, and give the star an AccessKit name. Danger buttons get an icon, a verb and a fixed position. |
| 18 | P2 | Accessibility | Focus can leave the modal, and the focus ring looks like the selection. | Use egui::Modal with a Tab-wrap check, and a 2 px inset focus ring that is separate from the selection fill. |
| 19 | P2 | Privacy | The window title "Holm - Edit item" leaks what you're doing to window lists. | The title is always "Holm". |
| 20 | P2 | Crypto UX | Addresses show as one block. | Group addresses in 4s, and after a copy prompt you to check the first and last characters. |
| 21 | P2 | Copy tone | "Something went wrong", mixed separators, inconsistent ellipses. | Say what happened, then what to do. Use "·" as the separator. An ellipsis means the action asks for more input. |
| 22 | P2 | Status bar | Shows an item count and the full path. | Show the lock state, auto-lock countdown, clipboard countdown, save state and file name. |

## 2. Design tokens (map one to one onto egui `Visuals` and `Spacing`)

Neutrals lean slightly blue, towards the accent. Every text pair passes WCAG AA, and borders and focus rings reach at least 3:1. Checked with contrast.js.

| Token | egui field | Light | Dark |
|---|---|---|---|
| bg | panel_fill (centred screens) | #F4F6F8 | #14171B |
| surface | window_fill, CentralPanel | #FFFFFF | #1B1F24 |
| side | Panel (side and status) Frame fill, faint_bg_color | #E9EDF1 | #202429 |
| field | extreme_bg_color | #FFFFFF | #111418 |
| btn / btn-hover | widgets.inactive / hovered weak_bg_fill | #E2E7ED / #D5DCE4 | #2A3038 / #343B45 |
| fg | override_text_color | #18212C | #E7EAEE |
| muted | weak text | #4B5767 | #A9B2BE |
| line | noninteractive.bg_stroke (decorative) | #D3D9E0 | #2F353D |
| line-strong | inactive.bg_stroke (inputs, chips) | #7F8A99 | #6F7A88 |
| accent | selection.stroke, primary fill, focus | #1D5AA6 | #86B4F0 |
| on-accent | primary text | #FFFFFF | #0C1828 |
| accent-weak | selection.bg_fill | #DBE7F6 | #22344B |
| accent-text | hyperlink_color | #174B8C | #9CC3F5 |
| danger | danger button fill | #B3261E | #F0857B |
| danger-bg / danger-text | error_fg_color = danger-text | #FCEBEA / #9C1F18 | #3A1C1A / #FFAAA2 |
| warn-bg / warn / warn-line | warn_fg_color = warn | #FFF3D9 / #8A5100 / #B97A12 | #32260E / #F0B44C / #B58222 |
| ok-bg / ok | custom | #E5F3EA / #1C6B3A | #15301F / #72D29B |

**Type.** Atkinson Hyperlegible Next for the UI and Atkinson Hyperlegible Mono for secrets, both OFL-1.1 and subset to Latin. They are the only fonts: egui's `default_fonts` feature is off (it pulls in OFL-1.1 and Ubuntu-font-1.0 files that `deny.toml` does not allow), and `deny.toml` gets OFL-1.1 when the GUI crate lands.

| Style | Size and weight | Used for |
|---|---|---|
| Name("Title") | 22 bold | Unlock, create and welcome headings |
| Heading | 18 semibold | Item, modal and page titles |
| Body | 14 | Everything else |
| Button | 14 | Buttons |
| Small | 12 | Labels, second lines, status bar, hints |
| Monospace | 14 | Secrets, addresses, phrase words |
| Name("Gen") | 18 mono | Generator output |

**Spacing.** The scale is 4, 8, 12, 16, 24, 32.

| Setting | Value |
|---|---|
| item_spacing | (8, 8) |
| button_padding | (10, 5) |
| interact_size | (40, 28); 44 on mobile later |
| window_margin | 16 |
| menu_margin | 8 |
| Scroll bar | 8 px, always visible in lists |

**Shape and motion.**
- Corner radius: widgets 4, banners 6, windows and modals 8, chips 12.
- Only the modal has a shadow.
- Animations last 0.08 s. Respect reduce-motion.

**Icons.** A 26-glyph subset of Phosphor Regular (MIT) as one TTF, about 8 KB, loaded as FontFamily::Name("icons"). No extra crate. Rules:
- Every icon has a hover text and an AccessKit label.
- Each item type has its own shape.
- Each banner tone has its own shape.

## 3. Component specs

**ItemRow** (custom)
- 52 px tall, with a 30 px type tile.
- Title in SemiBold, second line in Small muted.
- States: rest, hover, selected (accent-weak fill), and focus (2 px inset ring, separate from the selection).
- No copy button and no secret, ever.
- AccessKit name example: "Example Mail, Login, favourite, ada@example.com".
- Keys:
  - ↑ ↓ Home End move through the list.
  - Enter or → goes to the detail pane.
  - Delete moves the item to Trash, with Undo.

**SecretDisplay** (custom; has a PhraseGrid mode)
- The mask is always 12 dots.
- When shown: an amber frame plus "Visible · hides in N s". Hide timeouts:
  - Passwords: 30 s.
  - Phrases: 60 s.
  - Note bodies: shown until you leave the item.
  - Everything hides on window blur and on lock.
- The shown text can't be selected. Copying goes only through the Copy button, which reads "Copied" for 2 s.
- AccessKit gives the field name and state, never the value.

**SecretField / SecretTextArea** (custom)
- Looks like a TextEdit: 30 px tall, line-strong border, mono mask.
- No undo history, and only the mask glyphs are laid out.
- Uses a pre-allocated buffer that is wiped on drop and on lock. Holm keeps no preedit text of its own (the IME is still processed by the OS and egui).
- The eye toggle hides itself again after 30 s.
- AccessKit role PasswordInput, with no value.

**StrengthMeter** (custom, small)
- A 4-segment painter bar, a word label ("Weak · refused", "Strong", "Very strong") and the zxcvbn tip.
- A password is accepted only if zxcvbn scores it 3 or more and it has at least 12 characters.

**Buttons** (stock)
- Primary: accent fill.
- Normal: btn fill.
- Outline danger: reversible actions, such as Move to Trash with Undo.
- Filled danger: irreversible actions only, always inside a confirm, on the right, and never focused by default. Enter never activates it.
- Labels are an icon plus the exact verb and object. Never "OK" or "Yes".

**Banner** (stock Frame)
- Four tones: info, warn, danger, ok.
- Each tone has an icon shape and a bold first sentence.
- Actions sit inside the banner.
- The banner sits where the problem is.
- Live region: polite, or assertive for danger.

**Modal** (stock egui::Modal)
- Max 460 px wide.
- Focus starts on the first field, or on Cancel for a confirm. Tab wraps inside the modal.
- Esc means Cancel, except while working.
- Clicking the backdrop does nothing.

**Status bar** (stock Panel::bottom)
- 28 px tall.
- Left: lock state and auto-lock countdown. In the last 30 s it turns amber, and adds "Unsaved changes will be discarded" when you're editing.
- Middle: the clipboard countdown with Clear now, shown only while Holm's copy is pending.
- Right: save state (Saved, Unsaved changes, Saving…, Not saved) and the file name.
- It repaints once a second with request_repaint_after, only while a countdown is visible.

**Chip** (stock Button::selectable)
- A 24 px pill.
- Selected means accent-weak fill, accent border, a check icon and SemiBold.

## 4. Screens (16) and states

| # | Group | Screen | States |
|---|---|---|---|
| 1 | First run | Welcome | No vault yet; last vault missing |
| 2 | First run | Create vault | Empty, weak and refused, mismatch, ready, creating |
| 3 | First run | Vault created | New success state |
| 4 | Unlock | Unlock | Ready, auto-locked, locked by you, edits discarded, wrong password, throttled (live countdown), unlocking, cost too high, cost too low, not enough memory, open in another window, not a vault, newer format, file missing |
| 5 | Unlock | Open another vault | Confirm, locked and choosing a file |
| 6 | Vault | Items | Normal, password shown, copied, crypto address, secure note, locking soon, empty vault, no results, moved to Trash with undo |
| 7 | Vault | Recovery phrase | Hidden, password gate, gate with wrong password (throttled), shown, hidden again |
| 8 | Vault | Add or edit | Edit, new with type picker, missing title, saving, save failed, discard changes |
| 9 | Vault | Trash | List, delete one, empty trash, empty |
| 10 | Vault | Generator | Password, passphrase, username, opened from an edit |
| 11 | Settings | Settings | Normal, weaken confirm, backup saved; plus an honest per-OS protections section |
| 12 | Settings | Change master password | Form, new password weak, wrong current password, working, done with a backup prompt |
| 13 | Settings | Export plaintext CSV | Form, ready, done |
| 14 | Settings | Import | Choose, preview, too large, unknown columns, not UTF-8, done |
| 15 | Settings | Categories | List, delete confirm |
| 16 | Reference | Error messages | A table of every user-facing error |

## 5. Changes from the mock, and why

| Area | Mock | Final | Why |
|---|---|---|---|
| Lock | Locked view, then Unlock | One unlock screen with a reason line | One step back in. Spec §10. |
| First run | Straight into Create | Welcome, Create, Vault created, then an empty vault | Clear choice. Next steps include a backup. |
| Create | Mismatch shown while typing; colour-only meter | Match checked on blur or submit; meter with a label and tip; one checkbox saying Holm can't recover the password | Errors appear at the right time. Friction is deliberate and explained. |
| Navigation | New in the menu; dropdown filters; no sort | Sidebar: types, Favourites, Trash, Generator, Settings, Lock. List: search, chips, sort, New | Spec §10. |
| Reveal | Sticky toggle | Toggle, amber frame, countdown, hide on blur | Protects against shoulder-surfing. |
| Recovery phrase | Phrase inside the modal | The modal asks only for the password; numbered grid; 60 s; Hide now | Easier to write down. The timer is visible. |
| Edit | Replaced the list and detail panes | Edits in the detail pane; type fixed; unsaved marker; discard guard | You keep your context, and no fields are lost. |
| Save failure | Full-page error | Inline banner; input kept; file unchanged; Save a copy elsewhere | No data loss. |
| Trash | One-click delete | Confirm with honest scope; Undo for Move to Trash | Irreversible actions get deliberate friction. |
| Unlock errors | Three cases | Every state the core can return | Honest, specific messages. |
| Status bar | Count and path | Lock, countdowns, clipboard, save state, file name | Shows state you act on. |
| Settings | Claimed a password check | Weaken-confirm modal; ceilings | Spec §8.9. |
| Import | Preview only | File-level errors and a done reminder | File-level failures come first. |
| Crypto | One address line | Grouped in 4s, plus a check-after-paste hint | Clipboard-swapping malware. |
| Window title | "Holm - Edit item" | "Holm" | Window lists and screen sharing. |

## 6. Keyboard

| Key | Action |
|---|---|
| Cmd/Ctrl L | Lock |
| Cmd/Ctrl F | Search |
| Cmd/Ctrl N | New item |
| Cmd/Ctrl E | Edit |
| Cmd/Ctrl S | Save |
| Cmd/Ctrl G | Generator |
| Cmd/Ctrl , | Settings |
| Cmd/Ctrl C | Copy the focused detail field only |
| Arrows, Home, End | Move in the list |
| Enter or → | Go to the detail pane |
| ← | Back to the list |
| Esc | Close a modal, cancel an edit, hide a shown secret, or clear search |
| Enter | Submits safe forms only, never a destructive confirm |

Modifiers::COMMAND maps to ⌘ on macOS and Ctrl elsewhere.

## 7. Custom egui widgets

1. **SecretField**: single-line secret input. Wiping buffer, mask-only layout, no undo, no AccessKit value, eye toggle with a 30 s auto-hide.
2. **SecretTextArea**: the multi-line version, for note bodies and phrase entry.
3. **SecretDisplay**: read-only shown value from the wiping buffer. Not selectable, amber frame, countdown. Its PhraseGrid mode shows the numbered words.
4. **ItemRow**: two-line selectable row with its own AccessKit node.
5. **StrengthMeter**: 4-segment painter bar with a label.

Also check whether egui::Modal traps Tab focus, and add a wrap if it doesn't. Everything else is stock egui, with rfd for file dialogs.

## 8. Security calls (see the "Security decision" lines in the spec)

- **Reveal timeouts:** passwords 30 s, phrases 60 s. Note bodies stay shown until you leave the item. Everything hides on blur and on lock.
- **Copying:** shown secrets can't be selected, so copying goes only through Copy and auto-clear always applies.
- **Screen readers:** never read secret values.
- **Recovery phrase copy:** only inside a session the password opened. Same 30 s clear, and never the default action.
- **Ceilings:** auto-lock at most 60 min, clipboard clear at most 90 s, no "Never". Turning off lock-on-sleep needs the password.
- **Destructive actions:** Enter never confirms them, and Cancel holds focus.
- **Auto-lock:** unsaved edits are discarded, with a 30 s warning before and a note on the unlock screen after.
- **Window title:** always "Holm".
- **Masks:** always 12 dots.
- **Visibility by type:** crypto addresses show in clear; note bodies start hidden.
- **Throttle:** the notice appears after the first failure and the countdown starts after the third. Changing the password and the phrase gate share the same throttle.
- **Cost errors:** hide the password field.
- **Item type:** fixed after creation.
- **CSV export:** excludes Trash.
- **Open another vault:** locks the current one first.

## 9. Owner answers

1. Fonts: bundle Atkinson Hyperlegible (about 150 KB, OFL-1.1). It is the only font.
2. Imports: items keep their source categories. Unmatched ones go to Uncategorised.
3. First run: keep the "I understand Holm can't recover my vault" checkbox.
