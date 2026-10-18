# Holm GUI mock: screen map
Old = harbor/harbor-ui/ (the earlier Kotlin project; path relative to its repo root) src/commonMain/kotlin/harbor/ui/. Spec = holm/docs/superpowers/specs/2026-10-17-holm-v1-design.md.

| Screen | Old Compose source | Change and why | Spec |
|---|---|---|---|
| Create vault | unlock/UnlockScreen.kt, CreateUnlockCopy.kt | Char-class checklist replaced by strength meter; weak refused (score 4, 1e10 guesses; 12 to 1,024 chars). Sync/cloud copy dropped. Path chooser added. | passwords, GUI first run |
| Open or create file | none (old had one fixed vault) | New. One vault at a time, open/create file anywhere, native dialog. | vault paths |
| Unlock + errors | UnlockScreen.kt | "N of M attempts left" and minutes lockout replaced by in-memory wait (3 fails, 2/4/8..60 s). Added cost-rejected message (not "wrong password") and working state on worker thread. | throttle, KDF cost bounds |
| Locked | HarborApp.kt overlays | No separate Locked screen. "Locking vault"/"Restart required" overlays replaced by the unlock screen with a reason line; data dropped from memory. | auto-lock, GUI (locked state shows only the unlock screen) |
| Vault list + detail | shell/MenuPane.kt, vault/ListToolbar.kt, CategoryChipRow.kt, ItemRow.kt, detail/ItemDetailForm.kt | Keep 3-pane layout. Types now Login/Crypto/Recovery/Note. Search covers title/user/URL/chain/category, never secrets. Copy-count footer replaced by auto-lock and clipboard status bar. | item types, search |
| Add/edit item | detail/ItemDetailForm.kt, NewItemForm.kt | Save-confirm dialog removed (save at once). Custom secret field. Move to trash instead of hard delete. | items, GUI secret widget |
| Recovery phrase | ItemDetailForm.kt (reveal dialog) | Re-entry shares unlock throttle; auto re-hide; never copied by default. | recovery phrase |
| Trash | none in UI (filter chip only) | Restore, delete forever, empty trash. | trash |
| Generator | generator/GeneratorScreen.kt | Added length slider, look-alikes, min digits/symbols, EFF passphrase options, usernames. | generator |
| Copy and auto-lock | none | New live demo of clipboard auto-clear (30 s, only if still ours) and auto-lock countdown. | clipboard, auto-lock |
| Settings | settings/SettingsScreen.kt | Dropped biometrics, cloud, trust notes. Added auto-lock, clipboard time, encrypted backup. Weakening a setting needs master password. | settings |
| Change master password | settings/SecurityDialogs.kt | Meter + same rules as create; new data key; worker thread; throttle. | KEK/DEK |
| Export plaintext CSV | none | New. Password re-entry plus danger warning plus acknowledge box. | export |
| Import | settings/SecurityDialogs.kt (import dialog) | Generic CSV/JSON plus Chrome/Firefox/Safari; preview; size limit; delete-source warning. | import |
| Error state | HarborApp.kt error banner | Inline error frame, no secrets in text; other error strings listed. | errors |
