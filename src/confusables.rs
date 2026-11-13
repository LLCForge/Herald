//! Unicode TR39 confusable skeletons (full table from confusables.txt).
//!
//! `data/confusables-compact.txt` is generated from the official Unicode file by
//! `tools/gen_confusables.py` (Unicode License v3, see NOTICE). The skeleton is
//! TR39's `NFD -> map -> NFD`, made case-insensitive for host names and with a
//! few Herald extras (digits that pass for letters, stripped Latin diacritics).

use std::collections::HashMap;
use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;

const TABLE: &str = include_str!("../data/confusables-compact.txt");

fn table() -> &'static HashMap<char, String> {
    static T: OnceLock<HashMap<char, String>> = OnceLock::new();
    T.get_or_init(|| {
        let mut map = HashMap::with_capacity(7000);
        for line in TABLE.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split_ascii_whitespace();
            let src = parts
                .next()
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .and_then(char::from_u32);
            let dst: Option<String> = parts
                .map(|h| u32::from_str_radix(h, 16).ok().and_then(char::from_u32))
                .collect();
            if let (Some(s), Some(d)) = (src, dst) {
                map.insert(s, d);
            }
        }
        map
    })
}

/// Number of TR39 mappings loaded (for diagnostics and tests).
pub fn table_len() -> usize {
    table().len()
}

/// Herald extras applied before TR39 (the pre-TR39 map, kept so existing rules
/// behave the same): digits used as letters and lowercase Cyrillic/Greek letters
/// that TR39 maps to non-Latin prototypes (e.g. Cyrillic `м` -> `ʍ`).
fn herald_fold(c: char) -> char {
    match c {
        '0' => 'o',
        '1' => 'l',
        '3' => 'e',
        '5' => 's',
        'а' => 'a',
        'в' => 'b',
        'с' => 'c',
        'ԁ' => 'd',
        'е' | 'ё' => 'e',
        'һ' => 'h',
        'і' | 'ї' => 'i',
        'ј' => 'j',
        'к' => 'k',
        'ӏ' => 'l',
        'м' => 'm',
        'п' => 'n',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'т' => 't',
        'ս' => 'u',
        'ѵ' => 'v',
        'ԝ' => 'w',
        'х' => 'x',
        'у' => 'y',
        'α' => 'a',
        'β' => 'b',
        'ε' => 'e',
        'ι' => 'i',
        'κ' => 'k',
        'ν' => 'v',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'υ' => 'u',
        'χ' => 'x',
        'ı' => 'i',
        other => other,
    }
}

/// Combining diacritical marks (U+0300..U+036F) are dropped so `exämple` folds to `example`.
fn is_latin_mark(c: char) -> bool {
    ('\u{300}'..='\u{36f}').contains(&c)
}

/// Case-insensitive TR39 skeleton of a Unicode string: digit fold, NFD, map,
/// lowercase, map again (catches capitals whose lowercase form has its own
/// prototype, e.g. Cyrillic `М` -> `M` -> `m` -> `rn`), NFD, strip marks.
pub fn skeleton_str(s: &str) -> String {
    let t = table();
    let map = |input: &str| {
        let mut out = String::with_capacity(input.len());
        for c in input.nfd() {
            match t.get(&c) {
                Some(m) => out.push_str(m),
                None => out.push(c),
            }
        }
        out
    };
    let folded: String = s
        .chars()
        .flat_map(char::to_lowercase)
        .map(herald_fold)
        .collect();
    let once: String = map(&folded).chars().flat_map(char::to_lowercase).collect();
    map(&once)
        .nfd()
        .filter(|c| !is_latin_mark(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_table_is_loaded() {
        assert!(table_len() > 6000, "{}", table_len());
    }

    #[test]
    fn skeletons_collapse_confusables() {
        let base = skeleton_str("example.org");
        for s in [
            "exаmple.org",  // Cyrillic а
            "ЕХАМРLЕ.org",  // Cyrillic capitals
            "examp1e.org",  // digit one
            "exarnple.org", // rn for m (TR39)
            "exämple.org",  // diacritic
            "ехаmрlе.org",  // mixed Cyrillic
        ] {
            assert_eq!(skeleton_str(s), base, "{s}");
        }
        assert_ne!(skeleton_str("exanple.org"), base);
        assert_eq!(skeleton_str("g00gle"), skeleton_str("google"));
        // Greek omicron and the Latin o.
        assert_eq!(skeleton_str("gοοgle"), skeleton_str("google"));
    }
}
