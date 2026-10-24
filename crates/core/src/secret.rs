//! API keys. `Debug` and `Display` always mask the value.

use std::fmt;

/// Credential held only for outbound auth headers.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Store a key. Empty strings are still stored; callers should skip those.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the raw key for an outbound header. Do not log the result.
    pub fn as_header_value(&self) -> &str {
        &self.0
    }

    /// Short prefix plus a mask, or `****` when the key is short.
    pub fn masked(&self) -> String {
        mask(&self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({})", self.masked())
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.masked())
    }
}

/// Hide a secret inside a provider error body.
pub fn redact(text: &str, secret: &Secret) -> String {
    let raw = secret.as_header_value();
    if raw.is_empty() {
        return text.to_string();
    }
    text.replace(raw, &mask(raw))
}

fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        "****".to_string()
    } else {
        format!("{}****", chars.iter().take(4).collect::<String>())
    }
}

/// Truncate then redact, for HTTP error bodies.
pub(crate) fn redact_truncate(text: &str, secret: &Secret, max_chars: usize) -> String {
    let mut clipped: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        clipped.push('…');
    }
    redact(&clipped, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_hide_the_key() {
        let secret = Secret::new("bb-test-secret-key");
        let rendered = format!("{secret:?} {secret}");
        assert!(!rendered.contains("secret-key"));
        assert!(rendered.contains("bb-t****"));
    }

    #[test]
    fn short_keys_are_fully_masked() {
        assert_eq!(mask("short"), "****");
    }

    #[test]
    fn redact_replaces_every_copy() {
        let secret = Secret::new("bb-test-secret-key");
        let out = redact("saw bb-test-secret-key twice bb-test-secret-key", &secret);
        assert!(!out.contains("secret-key"));
        assert_eq!(out.matches("bb-t****").count(), 2);
    }
}
