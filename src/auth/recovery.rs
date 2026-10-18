//! Single-use recovery codes, issued with TOTP enrollment.
//!
//! Each code is 10 Crockford base32 characters (50 random bits), shown once as
//! `xxxxx-xxxxx`. Only SHA-256 hashes are stored: the codes are random and
//! long enough that a slow password hash would add nothing.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{sessions::hex, store::Extra, users::RecoveryCode};

/// Codes issued per enrollment.
pub const COUNT: usize = 10;
const CODE_CHARS: usize = 10;
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Generate a fresh set of codes, returning the codes to show the user and
/// the records to store.
#[must_use]
pub fn generate() -> (Vec<String>, Vec<RecoveryCode>) {
    (0..COUNT)
        .map(|_| {
            let mut bytes = [0_u8; CODE_CHARS];
            rand::fill(&mut bytes);
            let raw: String = bytes
                .iter()
                .map(|byte| char::from(ALPHABET[usize::from(byte % 32)]))
                .collect();
            let shown = format!("{}-{}", &raw[..5], &raw[5..]);
            let record = RecoveryCode {
                hash: hash(&raw),
                used_at: None,
                extra: Extra::new(),
            };
            (shown, record)
        })
        .unzip()
}

/// Normalize user input the way Crockford base32 intends: case-insensitive,
/// separators ignored, `o` read as `0` and `i`/`l` as `1`.
fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| match ch.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            other => other,
        })
        .collect()
}

fn hash(normalized: &str) -> String {
    hex(&Sha256::digest(normalized.as_bytes()))
}

/// Mark the unused code matching `input` as used at `now`. Returns whether
/// one matched. Every stored code is compared in constant time.
pub fn redeem(codes: &mut [RecoveryCode], input: &str, now: i64) -> bool {
    let candidate = hash(&normalize(input));
    let mut matched = None;
    for (index, code) in codes.iter().enumerate() {
        let equal: bool = code.hash.as_bytes().ct_eq(candidate.as_bytes()).into();
        if equal && code.used_at.is_none() {
            matched = Some(index);
        }
    }
    matched
        .and_then(|index| codes.get_mut(index))
        .map(|code| code.used_at = Some(now))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_single_use() {
        let (shown, mut stored) = generate();
        assert_eq!(shown.len(), COUNT);
        assert!(redeem(&mut stored, &shown[3], 10));
        assert!(!redeem(&mut stored, &shown[3], 11));
        assert!(redeem(&mut stored, &shown[4], 12));
        assert_eq!(
            stored.iter().filter(|code| code.used_at.is_some()).count(),
            2
        );
    }

    #[test]
    fn input_is_normalized() {
        let (shown, mut stored) = generate();
        let sloppy = format!(" {} ", shown[0].to_uppercase().replace('-', " "));
        assert!(redeem(&mut stored, &sloppy, 1));
    }

    #[test]
    fn unknown_codes_are_rejected_and_hashes_hide_the_codes() {
        let (shown, mut stored) = generate();
        assert!(!redeem(&mut stored, "00000-00000", 1));
        let json = serde_json::to_string(&stored).unwrap();
        assert!(!json.contains(&shown[0].replace('-', "")));
    }
}
