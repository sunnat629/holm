//! The master password strength meter: four segments, a word, and core's warning.
//!
//! The meter only shows what `holm_core::strength::check` decided. The word always
//! comes with the segments, so colour is never the only signal, and every text is fixed
//! wording (from here or from core), never part of the password.

use eframe::egui::{self, Color32, CornerRadius, Sense, vec2};
use holm_core::strength::{MAX_MASTER_CHARS, MIN_MASTER_CHARS, StrengthReport, StrengthVerdict};

/// How many segments the meter has.
const SEGMENTS: u8 = 4;
/// Size of one segment, in points.
const SEGMENT_SIZE: egui::Vec2 = vec2(40.0, 6.0);
/// Gap between segments, in points.
const SEGMENT_GAP: f32 = 4.0;
/// Fill of an accepted password's segments (a green that reads on light and dark).
const STRONG_FILL: Color32 = Color32::from_rgb(0x2e, 0x9d, 0x4f);

/// How many of the four segments to fill: the score, at most 4, and none for empty input.
#[must_use]
pub fn meter_segments(verdict: &StrengthVerdict) -> u8 {
    if verdict.chars == 0 {
        0
    } else {
        verdict.score.min(SEGMENTS)
    }
}

/// The word shown next to the segments. Empty for empty input. "Strong" only when core
/// accepts the password.
#[must_use]
pub fn meter_word(verdict: &StrengthVerdict) -> &'static str {
    if verdict.chars == 0 {
        ""
    } else if verdict.chars > MAX_MASTER_CHARS {
        "Too long"
    } else if !verdict.acceptable && verdict.chars < MIN_MASTER_CHARS {
        "Too short"
    } else {
        match verdict.score {
            0 | 1 => "Very weak",
            2 => "Weak",
            3 => "Fair",
            _ if verdict.acceptable => "Strong",
            // Score 4 that core still refuses cannot happen for a length in range, but if
            // it ever did, the meter must not call it strong.
            _ => "Fair",
        }
    }
}

/// Draws the meter for `report`: four painted segments and the word on one row, then
/// core's warning, if any, on the next.
pub fn strength_meter(ui: &mut egui::Ui, report: &StrengthReport) {
    let verdict = &report.verdict;
    let filled = meter_segments(verdict);
    let fill = segment_fill(ui.visuals(), verdict, filled);
    let empty = ui.visuals().widgets.inactive.bg_fill;
    ui.horizontal(|ui| {
        let width = f32::from(SEGMENTS) * SEGMENT_SIZE.x + f32::from(SEGMENTS - 1) * SEGMENT_GAP;
        let (rect, _) = ui.allocate_exact_size(vec2(width, SEGMENT_SIZE.y), Sense::hover());
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            for i in 0..SEGMENTS {
                let x = rect.min.x + f32::from(i) * (SEGMENT_SIZE.x + SEGMENT_GAP);
                let segment = egui::Rect::from_min_size(egui::pos2(x, rect.min.y), SEGMENT_SIZE);
                let colour = if i < filled { fill } else { empty };
                painter.rect_filled(segment, CornerRadius::same(2), colour);
            }
        }
        let word = meter_word(verdict);
        if !word.is_empty() {
            ui.label(word);
        }
    });
    if let Some(warning) = &report.warning {
        ui.label(warning.as_str());
    }
}

/// The colour of the filled segments: green only when core accepts the password.
fn segment_fill(visuals: &egui::Visuals, verdict: &StrengthVerdict, filled: u8) -> Color32 {
    if verdict.acceptable {
        STRONG_FILL
    } else if filled <= 1 {
        visuals.error_fg_color
    } else {
        visuals.warn_fg_color
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holm_core::strength::check;
    use holm_crypto::MasterPassword;

    fn verdict(password: &str) -> StrengthVerdict {
        check(&MasterPassword::new(password.to_owned())).verdict
    }

    #[test]
    fn meter_table() {
        let empty = verdict("");
        assert_eq!(meter_segments(&empty), 0);
        assert_eq!(meter_word(&empty), "");

        assert_eq!(meter_word(&verdict("Xk#9vQ!2mLp")), "Too short");

        let common = verdict("password1234");
        assert!(meter_segments(&common) <= 2);
        assert_ne!(meter_word(&common), "Strong");

        let strong = verdict("q7#Vt9!mZ2@rL5$w");
        assert_eq!(meter_segments(&strong), 4);
        assert_eq!(meter_word(&strong), "Strong");

        let long = verdict(&"a".repeat(MAX_MASTER_CHARS + 1));
        assert_eq!(meter_word(&long), "Too long");
    }

    #[test]
    fn words_follow_the_score_bands() {
        let at = |score: u8, chars: usize, acceptable: bool| StrengthVerdict {
            score,
            chars,
            acceptable,
        };
        assert_eq!(meter_word(&at(0, 12, false)), "Very weak");
        assert_eq!(meter_word(&at(1, 12, false)), "Very weak");
        assert_eq!(meter_word(&at(2, 12, false)), "Weak");
        assert_eq!(meter_word(&at(3, 12, false)), "Fair");
        assert_eq!(meter_word(&at(4, 12, true)), "Strong");
        // Never "Strong" unless core accepts it.
        assert_ne!(meter_word(&at(4, 12, false)), "Strong");
        assert_eq!(meter_segments(&at(9, 12, false)), 4);
        assert_eq!(meter_segments(&at(3, 0, false)), 0);
    }

    #[test]
    fn meter_draws_word_and_warning() {
        use egui_kittest::Harness;
        use egui_kittest::kittest::Queryable;

        let report = check(&MasterPassword::new("password1234".to_owned()));
        let warning = report
            .warning
            .clone()
            .expect("a common password has a warning");
        let word = meter_word(&report.verdict);
        let mut harness = Harness::builder()
            .with_context_setup(crate::fonts::install_fonts)
            .build_ui(move |ui| strength_meter(ui, &report));
        harness.run();
        let _ = harness.get_by_label(word);
        let _ = harness.get_by_label(warning.as_str());
    }
}
