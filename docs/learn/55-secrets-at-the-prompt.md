# Secrets at the prompt

## Why this matters

A custom secret on the command line is visible to other processes, and the shell
keeps it in history. If those characters also landed in the args struct, the
first `Debug` of a parsed command would print them.

Holm refuses `--value` for a secret kind. `Debug` prints lengths, so a label or
a text value that did get parsed is not written out as characters.

## What we built

`holm get` prints each custom field after the built-in lines. A text value is
shown. A date is `YYYY-MM-DD`. A secret or a multiline value is `(hidden)`.
That path does not call `expose`.

`holm get ID --copy field=N` loads the value into a `Zeroizing<String>` and
passes it to `copy_and_wait`. The clipboard gets it, Holm waits, and
`PendingClear` clears it if the clipboard still holds Holm's value. Stdout
never receives it. An empty field is an error. A number past the item's fields
is an error. A custom field does not ask for the master password again. A
recovery phrase still does.

`holm add --preset NAME` stores that preset's labels and kinds with empty
values. A date row is left out, so Holm does not invent a day. When at least
one field is stored, the line before `Added {id}.` says how many. Add does not
prompt for each field.

`holm edit` changes the list with `--field-add`, `--field-remove`,
`--field-move` and `--to`, or `--field-set`. Numbers on the command line start
at 1. A secret or a multiline value is read once with `term.secret` and the
prompt `Field value: `. `--value` on those kinds is a usage error. Text and
date need `--value`, because that kind is shown.

For `--field-add`, the error returns before `EditArgs` is built. For
`--field-set`, the kind is on the item, so `--value` sits in a `Zeroizing`
buffer until the vault is open. A secret kind drops that buffer and returns
the same error. `Debug` of `EditArgs` and `AddArgs` prints lengths and kinds.

`holm list --expiring` keeps an item whose reminder is inside 30 days,
including dates already past. `holm list --search` matches a custom label and
does not match a secret. `holm export --format json` writes a JSON array.
`--format` together with `--backup` is refused. With no `--format`, export
stays CSV.

## Rust ideas in this task

### Refuse the flag before the struct exists

```rust
[flag, _, ..] if flag == "--value" && f.field_kind.is_some_and(secret_kind) => {
    Err(SECRET_ON_COMMAND_LINE)
}
```

The `_` is the word after `--value`. It is never copied. If `--value` came
first, the bytes were held in a wiping buffer because the kind was not known
yet. Naming a secret kind drops them:

```rust
if secret_kind(kind) && f.field_value.is_some() {
    f.field_value = None;
    return Err(SECRET_ON_COMMAND_LINE);
}
```

In Kotlin you'd reject that argument in the parser and read the password with
`System.console().readPassword()`, so it never becomes a field of the args
object.

### `Debug` prints the length

```rust
.field("value_len", &self.field_value.as_ref().map(|s| s.len()))
```

`EditArgs` does not derive `Debug`. The hand-written impl prints `value_len`,
`label_len` and the kind. `AddArgs` prints `title_len` and the preset. A test
formats the struct and checks that the example text is absent.

In Kotlin you'd override `toString()` and print `value.length`. A data class
would print the characters.

### Show a constant, and clear the copy

```rust
FieldValue::Secret(_) | FieldValue::MultilineSecret(_) => Cow::Borrowed(HIDDEN),
```

`_` drops the secret. `Cow::Borrowed` points at the static `(hidden)`, so the
line does not allocate a copy of a value it never read. A date allocates the
ten characters of `YYYY-MM-DD`, which is not a secret.

In Kotlin you'd return the constant `"(hidden)"` and never open the secret.

Copy goes the other way. `copy_and_wait` moves the wiping buffer into
`PendingClear`, and the clear runs from that owner when the wait ends.

```rust
let pending = PendingClear::new(value, secs, clock);
```

In Kotlin you'd keep the copied text in a `char[]` and fill it with zeros
after the clipboard is done, instead of a `String` the runtime keeps.

## Exercises

1. In `secret_value_rejected_on_command_line`, add a fourth command where
   `--value EXAMPLE-LATE` comes before `--kind MULTILINE`. Expect the same
   usage error, no `EXAMPLE-LATE` on stderr, and the vault file unchanged.
   `cargo test -p holm-cli --locked --test write_commands secret_value_rejected_on_command_line`
2. In `get_hides_custom_secrets`, add a multiline field whose value is
   `EXAMPLE-multi-secret`. Expect a line with `(multiline) = (hidden)`, and
   expect that text to be absent from stdout and stderr.
   `cargo test -p holm-cli --locked --test read_commands get_hides_custom_secrets`
3. In `args_debug_has_no_secret`, parse
   `add login --title EXAMPLE-title --preset SERVER`. `Debug` must not contain
   `EXAMPLE`, and it must contain `Server`.
   `cargo test -p holm-cli --locked --test write_commands args_debug_has_no_secret`

## Read next

- [Command arguments](../../crates/holm-cli/src/args.rs)
- [Showing an item](../../crates/holm-cli/src/commands/read.rs)
- [Copy and clear](../../crates/holm-cli/src/commands/copy.rs)
- [Add and edit](../../crates/holm-cli/src/commands/write.rs)
- [Example structs](https://doc.rust-lang.org/book/ch05-02-example-structs.html)
