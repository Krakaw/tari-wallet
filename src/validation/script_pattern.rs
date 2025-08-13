use tari_crypto::ristretto::RistrettoPublicKey;
use tari_script::{Opcode, TariScript};

/// Represents the different types of script patterns we can detect
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptPattern {
    /// Standard output with single Nop instruction
    Standard,
    /// Simple one-sided output: PushPubKey(scanned_pk) where we might own the key
    SimpleOneSided { key_hex: String },
    /// Stealth one-sided output: PushPubKey(nonce), Drop, PushPubKey(scanned_pk) where we might own the scanned key
    StealthOneSided { nonce_hex: String, key_hex: String },
    /// Unrecognized one-sided pattern (has PushPubKey but we don't check ownership)
    UnrecognizedOneSided,
    /// Unrecognized stealth pattern (has the right structure)
    UnrecognizedStealth,
    /// Unknown or unsupported pattern
    Unknown,
}

/// Check if a script matches the standard output pattern (single Nop instruction)
pub fn is_standard_output(script: &TariScript) -> bool {
    if script.size() != 1 {
        return false;
    }

    matches!(script.opcode(0), Some(Opcode::Nop))
}

/// Check if a script has the simple one-sided structure and return the key hex
pub fn check_simple_one_sided_structure(script: &TariScript) -> Option<String> {
    if script.size() != 1 {
        return None;
    }

    if let Some(Opcode::PushPubKey(key)) = script.opcode(0) {
        // Use debug representation as a simple way to get a comparable string
        Some(format!("{key:?}"))
    } else {
        None
    }
}

/// Check if a script has the stealth one-sided structure and return the nonce and key hex
pub fn check_stealth_one_sided_structure(script: &TariScript) -> Option<(String, String)> {
    if script.size() != 3 {
        return None;
    }

    // Check pattern: PushPubKey(nonce), Drop, PushPubKey(scanned_pk)
    let nonce_hex = match script.opcode(0) {
        Some(Opcode::PushPubKey(key)) => format!("{key:?}"),
        _ => return None,
    };

    if !matches!(script.opcode(1), Some(Opcode::Drop)) {
        return None;
    }

    if let Some(Opcode::PushPubKey(scanned_key)) = script.opcode(2) {
        let key_hex = format!("{scanned_key:?}");
        Some((nonce_hex, key_hex))
    } else {
        None
    }
}

/// Analyze a script and determine which pattern it matches
/// Note: Key ownership verification is disabled due to tari_crypto version conflicts
pub fn analyze_script_pattern(
    script: &TariScript,
    _derived_keys: &[RistrettoPublicKey],
) -> ScriptPattern {
    // Check for standard output pattern first
    if is_standard_output(script) {
        return ScriptPattern::Standard;
    }

    // Check for simple one-sided pattern
    if let Some(key_hex) = check_simple_one_sided_structure(script) {
        return ScriptPattern::SimpleOneSided { key_hex };
    }

    // Check for stealth one-sided pattern
    if let Some((nonce_hex, key_hex)) = check_stealth_one_sided_structure(script) {
        return ScriptPattern::StealthOneSided { nonce_hex, key_hex };
    }

    ScriptPattern::Unknown
}

/// Check if any of the script patterns indicate this output might belong to our wallet
/// Note: This now only checks for recognizable patterns, not actual key ownership
pub fn is_wallet_output(script: &TariScript, derived_keys: &[RistrettoPublicKey]) -> bool {
    match analyze_script_pattern(script, derived_keys) {
        ScriptPattern::Standard => true, // All standard outputs are potential wallet outputs
        ScriptPattern::SimpleOneSided { .. } => false, // Can't verify ownership due to version conflicts
        ScriptPattern::StealthOneSided { .. } => false, // Can't verify ownership due to version conflicts
        ScriptPattern::UnrecognizedOneSided => false,
        ScriptPattern::UnrecognizedStealth => false,
        ScriptPattern::Unknown => false,
    }
}

/// Get the key hex for simple one-sided outputs
pub fn get_simple_key_hex(pattern: &ScriptPattern) -> Option<&str> {
    match pattern {
        ScriptPattern::SimpleOneSided { key_hex } => Some(key_hex),
        _ => None,
    }
}

/// Get the nonce and key hex for stealth outputs
pub fn get_stealth_keys(pattern: &ScriptPattern) -> Option<(&str, &str)> {
    match pattern {
        ScriptPattern::StealthOneSided { nonce_hex, key_hex } => Some((nonce_hex, key_hex)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_script::script;

    #[test]
    fn test_standard_output_pattern() {
        let script = script!(Nop).unwrap();
        assert!(is_standard_output(&script));

        let script = script!(Nop Nop).unwrap();
        assert!(!is_standard_output(&script));
    }

    #[test]
    fn test_script_pattern_analysis() {
        let derived_keys = vec![];

        let script = script!(Nop).unwrap();
        assert_eq!(
            analyze_script_pattern(&script, &derived_keys),
            ScriptPattern::Standard
        );

        let script = script!(PushZero).unwrap();
        assert_eq!(
            analyze_script_pattern(&script, &derived_keys),
            ScriptPattern::Unknown
        );
    }
}
