//! Holm's two fonts, built into the binary with `include_bytes!`.
//!
//! egui's own fonts (`default_fonts`) are off, so these are the only fonts: Atkinson
//! Hyperlegible Next for text and Atkinson Hyperlegible Mono for monospace, both
//! OFL-1.1 (see `LICENSES/OFL-1.1.txt` and `NOTICE`; `scripts/ci-local.sh` checks
//! their SHA-256). Nothing is read from the system's font folders.

use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

/// Font name for proportional text.
const TEXT_FONT_NAME: &str = "AtkinsonHyperlegibleNext-Regular";
/// Font name for monospace text.
const MONO_FONT_NAME: &str = "AtkinsonHyperlegibleMono-Regular";

/// Atkinson Hyperlegible Next, Regular (static instance, TrueType).
static TEXT_FONT: &[u8] = include_bytes!("../assets/fonts/AtkinsonHyperlegibleNext-Regular.ttf");
/// Atkinson Hyperlegible Mono, Regular (static instance, TrueType).
static MONO_FONT: &[u8] = include_bytes!("../assets/fonts/AtkinsonHyperlegibleMono-Regular.ttf");

/// Replaces every font in `ctx` with Holm's two: the text font as
/// [`FontFamily::Proportional`] and the mono font as [`FontFamily::Monospace`].
pub fn install_fonts(ctx: &egui::Context) {
    ctx.set_fonts(definitions());
}

/// An empty [`FontDefinitions`] plus the two built-in fonts, nothing else.
fn definitions() -> FontDefinitions {
    let mut defs = FontDefinitions::empty();
    defs.font_data.insert(
        TEXT_FONT_NAME.to_owned(),
        Arc::new(FontData::from_static(TEXT_FONT)),
    );
    defs.font_data.insert(
        MONO_FONT_NAME.to_owned(),
        Arc::new(FontData::from_static(MONO_FONT)),
    );
    defs.families
        .insert(FontFamily::Proportional, vec![TEXT_FONT_NAME.to_owned()]);
    defs.families
        .insert(FontFamily::Monospace, vec![MONO_FONT_NAME.to_owned()]);
    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    /// The TrueType (not OpenType CFF) file signature.
    const TRUETYPE_MAGIC: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

    #[test]
    fn only_the_two_fonts_are_defined() {
        let defs = definitions();
        let names: Vec<&str> = defs.font_data.keys().map(String::as_str).collect();
        assert_eq!(names, [MONO_FONT_NAME, TEXT_FONT_NAME]);
        assert_eq!(defs.families.len(), 2);
        assert_eq!(
            defs.families[&FontFamily::Proportional],
            [TEXT_FONT_NAME.to_owned()]
        );
        assert_eq!(
            defs.families[&FontFamily::Monospace],
            [MONO_FONT_NAME.to_owned()]
        );
    }

    #[test]
    fn fonts_are_truetype_files() {
        assert_eq!(TEXT_FONT[..4], TRUETYPE_MAGIC);
        assert_eq!(MONO_FONT[..4], TRUETYPE_MAGIC);
    }

    /// kittest panics on a missing glyph, so this proves both fonts cover printable
    /// ASCII and the bullet that hides secrets.
    #[test]
    fn both_fonts_draw_ascii_and_the_bullet() {
        let ascii: String = (0x20u8..0x7f).map(char::from).collect();
        let text = format!("{ascii} \u{2022}");
        let mut harness = Harness::builder()
            .with_context_setup(install_fonts)
            .build_ui(move |ui| {
                ui.heading("Holm");
                ui.label(text.as_str());
                ui.monospace(text.as_str());
            });
        harness.run();
        let _ = harness.get_by_label("Holm");
    }
}
