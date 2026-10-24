// SPDX-License-Identifier: MIT OR Apache-2.0
//! A vault value that is really a non-secret (an account id typed into the
//! token's entry, 2026-10-23) must be flagged by NAME and RULE, never by value.

use chrono::Utc;
use with_secret::suspect::{audit_value, audit_vault, is_non_secret_env_name};
use with_secret::vault::{Access, Secret, Vault};

const ID: &str = "0123456789abcdef0123456789abcdef"; // 32 hex: account-id shaped
const TOKEN: &str = "cfut_Zk3-pQ9xLm2VbN7wTr5YhJ8aSd4FgC1eUo6iXq0AbEzK"; // 48, not hex

fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn secret(value: &str) -> Secret {
    Secret {
        value: value.into(),
        env_var: "X".into(),
        access: Access::Read,
        created_at: Utc::now(),
        rotate_by: None,
        lanes: vec![],
    }
}

#[test]
fn exactly_32_hex_chars_is_flagged() {
    let r = audit_value(ID, &[]);
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].contains("32 hex"), "{r:?}");
}

#[test]
fn control_a_real_token_shape_is_not_flagged() {
    assert!(audit_value(TOKEN, &env(&[("CLOUDFLARE_ACCOUNT_ID", ID)])).is_empty());
}

#[test]
fn near_misses_of_the_hex_rule_are_not_flagged() {
    assert!(audit_value(&ID[..31], &[]).is_empty(), "31 chars");
    assert!(audit_value(&format!("{ID}0"), &[]).is_empty(), "33 chars");
    assert!(
        audit_value(&ID.replace('0', "g"), &[]).is_empty(),
        "non-hex char"
    );
}

#[test]
fn equal_to_a_non_secret_env_var_names_the_var_not_the_value() {
    let value = "my-company-prod-project-name";
    let r = audit_value(value, &env(&[("MYAPP_PROJECT_ID", value)]));
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].contains("MYAPP_PROJECT_ID"), "{r:?}");
    assert!(
        !r.iter().any(|s| s.contains(value)),
        "a rule text carried the value"
    );
}

#[test]
fn a_secret_named_env_var_is_not_a_non_secret() {
    // the same value sitting in an env var that IS a secret must not fire:
    // it is how with-secret hands the real value to a child
    let value = "my-company-prod-project-name";
    assert!(audit_value(value, &env(&[("CLOUDFLARE_API_TOKEN", value)])).is_empty());
    assert!(!is_non_secret_env_name("CLOUDFLARE_API_TOKEN"));
    assert!(!is_non_secret_env_name("MY_PROJECT_ID_KEY"));
    assert!(is_non_secret_env_name("CLOUDFLARE_ACCOUNT_ID"));
    assert!(is_non_secret_env_name("AWS_REGION"));
}

#[test]
fn an_empty_or_short_env_value_never_matches() {
    assert!(audit_value("short", &env(&[("X_REGION", "short")])).is_empty());
    assert!(audit_value("whatever-long-enough", &env(&[("X_REGION", "")])).is_empty());
}

#[test]
fn audit_vault_reports_names_and_rules_and_catches_duplicates() {
    let mut v = Vault::default();
    v.secrets.insert("CF_WORKERS_AI".into(), secret(ID)); // the real incident
    v.secrets.insert("GOOD_TOKEN".into(), secret(TOKEN));
    v.secrets
        .insert("DUP_A".into(), secret("shared-value-0001-xyz"));
    v.secrets
        .insert("DUP_B".into(), secret("shared-value-0001-xyz"));
    let got = audit_vault(&v, &env(&[("CLOUDFLARE_ACCOUNT_ID", ID)]));
    let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["CF_WORKERS_AI", "DUP_A", "DUP_B"], "{got:?}");
    let cf = &got[0].1;
    assert!(cf.iter().any(|r| r.contains("32 hex")), "{cf:?}");
    assert!(
        cf.iter().any(|r| r.contains("CLOUDFLARE_ACCOUNT_ID")),
        "{cf:?}"
    );
    assert!(got[1].1.iter().any(|r| r.contains("DUP_B")), "{got:?}");
    assert!(got[2].1.iter().any(|r| r.contains("DUP_A")), "{got:?}");
    let all = format!("{got:?}");
    for leaked in [ID, TOKEN, "shared-value-0001-xyz"] {
        assert!(!all.contains(leaked), "audit output carried a value");
    }
}
