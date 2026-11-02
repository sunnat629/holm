//! The letter avatar: a coloured circle with the first letter of an item's title.
//!
//! Everything is painted from lines and text. There is no image, no texture and no
//! network fetch (no favicons), and the letter comes from the public title, never from a
//! secret.

use eframe::egui;

/// Width and height of the avatar, in points.
pub const AVATAR_SIZE: f32 = 24.0;

/// Circle fills for the dark theme, one per category slot. White text reads on each.
pub const PALETTE_DARK: [egui::Color32; 8] = [
    egui::Color32::from_rgb(37, 99, 235),
    egui::Color32::from_rgb(22, 128, 61),
    egui::Color32::from_rgb(194, 65, 12),
    egui::Color32::from_rgb(126, 34, 206),
    egui::Color32::from_rgb(190, 24, 93),
    egui::Color32::from_rgb(15, 118, 110),
    egui::Color32::from_rgb(185, 28, 28),
    egui::Color32::from_rgb(161, 98, 7),
];

/// Circle fills for the light theme: the same hues as [`PALETTE_DARK`], a bit deeper.
pub const PALETTE_LIGHT: [egui::Color32; 8] = [
    egui::Color32::from_rgb(30, 64, 175),
    egui::Color32::from_rgb(22, 101, 52),
    egui::Color32::from_rgb(154, 52, 18),
    egui::Color32::from_rgb(107, 33, 168),
    egui::Color32::from_rgb(157, 23, 77),
    egui::Color32::from_rgb(17, 94, 89),
    egui::Color32::from_rgb(153, 27, 27),
    egui::Color32::from_rgb(133, 77, 14),
];

/// The fill of an item with no category, in the dark theme.
pub const GREY_DARK: egui::Color32 = egui::Color32::from_rgb(95, 99, 104);

/// The fill of an item with no category, in the light theme.
pub const GREY_LIGHT: egui::Color32 = egui::Color32::from_rgb(75, 85, 99);

/// The letter shown for `title`: its first alphanumeric character, upper-cased, or `•`
/// when there is none. A character whose upper case is several letters (`ß` is `SS`)
/// shows the first of them.
#[must_use]
pub fn avatar_letter(title: &str) -> char {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .and_then(|c| c.to_uppercase().next())
        .unwrap_or('•')
}

/// The fill for a category's `slot` (its index in the session's category list), or grey
/// for no category. Slots past the palette wrap around.
#[must_use]
pub fn avatar_colour(slot: Option<usize>, dark: bool) -> egui::Color32 {
    let (palette, grey) = if dark {
        (&PALETTE_DARK, GREY_DARK)
    } else {
        (&PALETTE_LIGHT, GREY_LIGHT)
    };
    slot.map_or(grey, |i| palette[i % palette.len()])
}

/// Draws the avatar: a filled circle with `letter` in white at its centre. It has no
/// accessibility label of its own, because the row's title already names the item.
pub fn avatar(ui: &mut egui::Ui, letter: char, colour: egui::Color32) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::Vec2::splat(AVATAR_SIZE), egui::Sense::hover());
    let painter = ui.painter();
    painter.circle_filled(rect.center(), AVATAR_SIZE / 2.0, colour);
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        letter,
        egui::FontId::proportional(13.0),
        egui::Color32::WHITE,
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn letter_from_title() {
        assert_eq!(avatar_letter("github"), 'G');
        assert_eq!(avatar_letter("  9lives"), '9');
        assert_eq!(avatar_letter("---"), '•');
        assert_eq!(avatar_letter("ßeta"), 'S');
        assert_eq!(avatar_letter(""), '•');
    }

    #[test]
    fn colour_stable_per_category() {
        for dark in [true, false] {
            assert_eq!(avatar_colour(Some(3), dark), avatar_colour(Some(3), dark));
            assert_eq!(avatar_colour(Some(8), dark), avatar_colour(Some(0), dark));
            let all: HashSet<egui::Color32> =
                (0..8).map(|i| avatar_colour(Some(i), dark)).collect();
            assert_eq!(all.len(), 8, "eight distinct fills (dark: {dark})");
            assert!(!all.contains(&avatar_colour(None, dark)));
        }
    }

    #[test]
    fn uncategorised_is_grey() {
        assert_eq!(avatar_colour(None, true), GREY_DARK);
        assert_eq!(avatar_colour(None, false), GREY_LIGHT);
    }

    /// Walks `shape`, failing on an image or a callback and counting circles.
    fn check(shape: &egui::Shape, circles: &mut usize) {
        match shape {
            egui::Shape::Vec(shapes) => {
                for inner in shapes {
                    check(inner, circles);
                }
            }
            egui::Shape::Circle(_) => *circles += 1,
            egui::Shape::Mesh(mesh) => {
                assert_eq!(mesh.texture_id, egui::TextureId::default(), "no image");
            }
            egui::Shape::Callback(_) => panic!("the avatar paints no callback"),
            _ => {}
        }
    }

    #[test]
    fn avatar_draws_no_image_shape() {
        let ctx = egui::Context::default();
        let mut shapes = Vec::new();
        // Two frames, so a first-frame layout pass cannot hide the shapes.
        for _ in 0..2 {
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                avatar(ui, 'G', PALETTE_DARK[0]);
            });
            output.textures_delta.clear();
            shapes = output.shapes;
        }
        let mut circles = 0;
        for clipped in &shapes {
            check(&clipped.shape, &mut circles);
        }
        assert!(circles >= 1, "the avatar paints a circle");
    }
}
