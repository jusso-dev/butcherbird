//! Generic reset advice from a breach's data classes.
//!
//! This is a recommendation for the operator. Nothing here touches a tenant.

use serde::Serialize;

use super::Breach;

/// One recommended step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Reset the password for the account, and anywhere it was reused.
    PasswordReset,
    /// Sign the account out everywhere and revoke refresh tokens.
    SessionRevoke,
    /// Review and rotate API keys, app passwords and OAuth grants.
    TokenReview,
    /// Check MFA methods and account recovery details.
    MfaReview,
    /// Warn the person that targeted phishing is likely.
    PhishingWatch,
}

impl Action {
    /// Every action, in the order they are shown.
    pub const ALL: [Self; 5] = [
        Self::PasswordReset,
        Self::SessionRevoke,
        Self::TokenReview,
        Self::MfaReview,
        Self::PhishingWatch,
    ];

    /// Stable id used in JSON.
    pub fn id(self) -> &'static str {
        match self {
            Self::PasswordReset => "password_reset",
            Self::SessionRevoke => "session_revoke",
            Self::TokenReview => "token_review",
            Self::MfaReview => "mfa_review",
            Self::PhishingWatch => "phishing_watch",
        }
    }

    /// One-line instruction for a person.
    pub fn summary(self) -> &'static str {
        match self {
            Self::PasswordReset => {
                "Reset the password, and any other account that used the same password"
            }
            Self::SessionRevoke => "Sign the account out of all sessions and revoke refresh tokens",
            Self::TokenReview => "Review and rotate API keys, app passwords and OAuth app grants",
            Self::MfaReview => "Check MFA methods and recovery details have not been changed",
            Self::PhishingWatch => "Tell the person to expect targeted phishing using this data",
        }
    }
}

/// Recommended steps, in a fixed order. Never empty.
///
/// A breach with no data classes is one whose metadata could not be read.
/// It gets every step, because the safe guess is that passwords and sessions
/// were exposed.
pub fn recommend(breach: &Breach) -> Vec<Action> {
    if breach.data_classes.is_empty() {
        return Action::ALL.to_vec();
    }
    let mut out = Vec::new();
    let classes: Vec<String> = breach
        .data_classes
        .iter()
        .map(|class| class.to_ascii_lowercase())
        .collect();
    let any = |needles: &[&str]| {
        classes
            .iter()
            .any(|class| needles.iter().any(|needle| class.contains(needle)))
    };

    if any(&["password"]) || breach.is_stealer_log {
        out.push(Action::PasswordReset);
        out.push(Action::SessionRevoke);
    }
    if breach.is_stealer_log || any(&["auth token", "session", "cookie"]) {
        out.push(Action::SessionRevoke);
        out.push(Action::TokenReview);
    }
    if any(&["api key", "access token", "private key", "token"]) {
        out.push(Action::TokenReview);
    }
    if any(&["security question", "phone", "mfa", "2fa", "recovery"]) {
        out.push(Action::MfaReview);
    }
    out.push(Action::PhishingWatch);
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn breach(classes: &[&str]) -> Breach {
        Breach {
            name: "Quokka".into(),
            title: None,
            domain: None,
            breach_date: None,
            added_date: None,
            data_classes: classes.iter().map(|c| c.to_string()).collect(),
            is_verified: true,
            is_sensitive: false,
            is_spam_list: false,
            is_fabricated: false,
            is_stealer_log: false,
        }
    }

    #[test]
    fn passwords_mean_reset_and_revoke() {
        assert_eq!(
            recommend(&breach(&["Email addresses", "Passwords"])),
            [
                Action::PasswordReset,
                Action::SessionRevoke,
                Action::PhishingWatch
            ]
        );
    }

    #[test]
    fn email_only_is_phishing_watch() {
        assert_eq!(
            recommend(&breach(&["Email addresses", "Names"])),
            [Action::PhishingWatch]
        );
    }

    #[test]
    fn stealer_logs_cover_sessions_and_tokens() {
        let mut stealer = breach(&["Email addresses", "URLs"]);
        stealer.is_stealer_log = true;
        assert_eq!(
            recommend(&stealer),
            [
                Action::PasswordReset,
                Action::SessionRevoke,
                Action::TokenReview,
                Action::PhishingWatch
            ]
        );
    }

    #[test]
    fn tokens_and_recovery_data() {
        assert_eq!(
            recommend(&breach(&[
                "Auth tokens",
                "Phone numbers",
                "Security questions and answers"
            ])),
            [
                Action::SessionRevoke,
                Action::TokenReview,
                Action::MfaReview,
                Action::PhishingWatch
            ]
        );
    }

    #[test]
    fn unknown_data_classes_get_every_step() {
        assert_eq!(recommend(&breach(&[])), Action::ALL);
    }

    #[test]
    fn user_agent_data_is_not_a_session() {
        assert_eq!(
            recommend(&breach(&["Browser user agent details", "Email addresses"])),
            [Action::PhishingWatch]
        );
    }
}
