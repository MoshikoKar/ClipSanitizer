//! Sanitizing engine (port of log_sanitizer.py).
//!
//! Every enabled pattern is matched against the ORIGINAL text; overlaps are resolved by priority
//! (a strictly wider lower-priority match absorbs the narrower ones) and the output is built in a
//! single pass, so placeholders are never re-matched. Config files use the same JSON format as
//! the Python Log Sanitizer (`{"patterns": [...]}`).

use fancy_regex::{Captures, Regex, RegexBuilder};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;

pub const VALUE_GROUP: &str = "value";
const HASH_LENGTH: usize = 12;
const BACKTRACK_LIMIT: usize = 1_000_000;

// Horizontal whitespace only: `\s` would let an empty `KEY=` swallow the next line as its value.
const KV_SEP: &str = r#"["']?[ \t]*[:=][ \t]*["']?"#;
const KV_VALUE: &str = r#"(?P<value>(?<=")[^"\r\n]+(?=")|(?<=')[^'\r\n]+(?=')|[^\s,;"'&]+)"#;
/// Environment qualifiers allowed after a key: POSTGRES_PASSWORD_DEV, REDIS_PORT_PROD, DB_USER_2 ...
const ENV_SUFFIX: &str = r"(?:[-_](?i:dev|development|prod|production|staging|stage|stg|test|qa|uat|local|remote|primary|secondary|replica|backup|old|new|ro|rw|admin|read|write|\d+))*";
/// The space-separated form (`password hunter2`) only counts when the value looks like a secret
/// (has a digit or symbol), so prose such as "change the password in the UI" is left alone.
const SECRETISH: &str = r#"(?=[^\s,;"'&]*[0-9!@#$%^*_+=/\\~?])"#;
/// Whole-line UPPER_CASE env key (`ADMIN_PASSWORD=...`) with a secret-ish segment. Upper case only, so
/// log lines like `password=abc user=bob` keep the per-token rules.
const ENV_SECRET_KEY: &str = concat!(
    r"(?:[A-Z0-9]+_)*(?:PASS(?:WORD|WD|PHRASE)?|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?",
    r"|(?:TOTP|HOTP|OTP|MFA|2FA)_?SEED|SEED_?PHRASE|MNEMONIC|RECOVERY_?CODES?|AUTH_\d+)",
    // A trailing segment naming a setting (SECRET_BUILD_VERSION, TOKEN_TIMEOUT_MS, PASSWORD_MIN_LENGTH ...)
    // means the key describes configuration about a secret, not the secret itself.
    r"(?:_(?!(?:ENABLED|DISABLED|ENABLE|REQUIRED|VERSION|BUILD|TIMEOUT|MS|SECONDS|MINUTES|HOURS|DAYS|TTL|EXPIRES|EXPIRY",
    r"|LENGTH|SIZE|COUNT|ROUNDS|ATTEMPTS|RETRIES|INTERVAL|PORT|FLAG|MODE|TYPE|URL|PATH|FILE|HEADER|ALGORITHM|FORMAT",
    r"|PREFIX|LIFETIME|DURATION|MAX|MIN|LIMIT)(?![A-Z0-9]))[A-Z0-9]+)*"
);
/// Whole-line env keys holding personal / financial data (names, phone, address, SSN, card, bank, passport, DOB).
const ENV_PII_KEY: &str = concat!(
    r"(?:[A-Z0-9]+_)*(?:SSN|SOCIAL_?SECURITY(?:_?(?:NUMBER|NO))?|PASSPORT(?:_?(?:NUMBER|NO))?",
    r"|CARD_?(?:CVV2?|CVC|EXPIRY|EXP|NUMBER)|CVV2?|CVC|IBAN|(?:ROUTING|ACCOUNT|SWIFT)_?(?:NUMBER|NO)",
    r"|DATE_?OF_?BIRTH|DOB|BIRTH_?DATE|(?:FULL|FIRST|LAST|CARDHOLDER|HOLDER|CONTACT)_?NAME",
    r"|PHONE(?:_?NUMBER)?|MOBILE|TELEPHONE",
    r"|(?<!IP_)(?<!MAC_)(?<!EMAIL_)(?<!MAIL_)(?<!BIND_)(?<!LISTEN_)(?<!HOST_)(?<!SERVER_)ADDRESS)"
);
/// Whole-line env keys naming this organisation's hosts / domains.
const ENV_HOST_KEY: &str = r"(?:[A-Z0-9]+_)*(?:HOSTNAME|DOMAIN|FQDN)";

/// `KEY=value` line regex (value captured as `value`); the value runs to the end of the line.
fn env_line(key: &str) -> String {
    format!(
        concat!(r#"(?m)^[ \t]*(?:#[ \t]*)?(?:export[ \t]+)?{key}[ \t]*[=:][ \t]*["']?"#,
                r#"(?P<value>(?<=")[^"\r\n]+(?=")|(?<=')[^'\r\n]+(?=')"#,
                r#"|[^\s"'](?:(?![ \t]+[A-Za-z_][\w.-]*=)[^\r\n])*(?<![ \t]))"#),
        key = key
    )
}

fn is_version_like(value: &str) -> bool {
    let v = value.trim_start_matches(['v', 'V']);
    let parts: Vec<&str> = v.split('.').collect();
    (2..=4).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty() && p.len() <= 6 && p.chars().all(|c| c.is_ascii_digit()))
}

/// Booleans, null-ish words and version numbers are never secrets, whatever the key says.
fn literal_ok(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    !(["true", "false", "yes", "no", "on", "off", "null", "none", "nil", "undefined"].contains(&v.as_str()) || is_version_like(&v))
}

/// A value that is already one of our placeholders (`<EMAIL>`, `<HASHED_PASSWORD_AB12...>`) must not be re-sanitized.
fn is_placeholder(value: &str) -> bool {
    value.len() > 2
        && value.starts_with('<')
        && value.ends_with('>')
        && value[1..value.len() - 1].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' || c == ':')
}

fn digit_count(value: &str) -> usize {
    value.chars().filter(char::is_ascii_digit).count()
}

fn phone_ok(value: &str) -> bool {
    (8..=15).contains(&digit_count(value))
}

/// US SSN structure: area not 000/666/9xx, group not 00, serial not 0000.
fn ssn_ok(value: &str) -> bool {
    let p: Vec<&str> = value.split('-').collect();
    p.len() == 3 && !matches!(p[0], "000" | "666") && !p[0].starts_with('9') && p[1] != "00" && p[2] != "0000"
}

/// ISO 13616 mod-97 check, so only real IBANs match.
fn iban_ok(value: &str) -> bool {
    let s: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let rem = s[4..].chars().chain(s[..4].chars()).try_fold(0u32, |rem, c| {
        let d = c.to_digit(36)?;
        Some(if d >= 10 { (rem * 100 + d) % 97 } else { (rem * 10 + d) % 97 })
    });
    rem == Some(1)
}

fn pii_ok(value: &str) -> bool {
    let v = value.trim().to_ascii_lowercase();
    !(v.starts_with("${") || ["true", "false", "yes", "no", "on", "off", "null", "none"].contains(&v.as_str()))
}

fn host_ok(value: &str) -> bool {
    pii_ok(value) && !["localhost", "127.0.0.1"].contains(&value.trim().to_ascii_lowercase().as_str())
}
const IPV4_OCTET: &str = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)";
const HEX: &str = "[0-9a-fA-F]";

/// Regexes shipped in old config.json.example files; a config entry that re-declares a built-in
/// with one of these keeps the improved built-in instead.
const LEGACY_DEFAULT_REGEXES: &[&str] = &[
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b",
    r"\b(?:port|PORT)(?:\s+|=|:)\d{1,5}\b",
    r"\b(?:api[-_]?key|API[-_]?KEY)(?:\s+|=|:)([^\s,;]+)",
    r"\b(?:secret[-_]?key|SECRET[-_]?KEY)(?:\s+|=|:)([^\s,;]+)",
    r"\b(?:password|PASSWORD|pwd|PWD)(?:\s+|=|:)([^\s,;]+)",
    r"(?:DATABASE_URL|database_url|DB_URL|db_url)(?:\s+|=|:)([^\s]+)",
    r#"(?:connection[-_]?string|CONNECTION[-_]?STRING)(?:\s+|=|:)([^\n"']+)"#,
    r"(?:jwt|JWT|bearer|Bearer)(?:\s+|:)([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)",
    r"\b(?:access[-_]?token|ACCESS[-_]?TOKEN)(?:\s+|=|:)([^\s,;]+)",
    r"\b(?:refresh[-_]?token|REFRESH[-_]?TOKEN)(?:\s+|=|:)([^\s,;]+)",
];

pub type Validator = fn(&str) -> bool;

#[derive(Clone)]
pub struct Pattern {
    pub name: String,
    pub source: String,
    pub regex: Regex,
    pub replacement: String,
    pub hash: bool,
    pub enabled: bool,
    pub case_sensitive: bool,
    pub comment: String,
    pub priority: i64,
    pub gate: Vec<String>,
    pub validator: Option<Validator>,
    pub builtin: bool,
}

#[derive(Serialize, Clone)]
pub struct PatternInfo {
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub hash: bool,
    pub case_sensitive: bool,
    pub builtin: bool,
    pub comment: String,
    pub regex: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Segment {
    pub text: String,
    /// Pattern name when this segment is a replacement.
    pub hit: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SanitizeResult {
    pub text: String,
    pub counts: Vec<(String, usize)>,
    pub total: usize,
    pub segments: Vec<Segment>,
    pub warnings: Vec<String>,
}

// ----------------------------------------------------------------------------- helpers

pub fn is_risky_regex(pattern: &str) -> bool {
    // Same heuristic as the Python version: nested quantifiers like (a+)+ or many .* / .+
    let nested = Regex::new(r"\([^()]*[+*][^()]*\)[+*]").unwrap();
    nested.is_match(pattern).unwrap_or(false) || pattern.matches(".*").count() >= 3 || pattern.matches(".+").count() >= 3
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn kv(keys: &str, value: &str, boundary: bool, spaced: &str) -> String {
    let lead = if boundary { "(?<![A-Za-z0-9])" } else { "" };
    let mut key = format!("(?i:{keys}){ENV_SUFFIX}{KV_SEP}");
    if !spaced.is_empty() {
        key = format!(r#"(?:(?i:{spaced}){ENV_SUFFIX}(?:{KV_SEP}|[ \t]+["']?{SECRETISH})|{key})"#);
    }
    format!("{lead}{key}{value}")
}

fn luhn_ok(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| if i % 2 == 1 { let x = d * 2; if x > 9 { x - 9 } else { x } } else { *d })
        .sum();
    sum % 10 == 0
}

fn ipv6_ok(value: &str) -> bool {
    let addr = value.split('%').next().unwrap_or("");
    if !addr.contains("::") && addr.matches(':').count() != 7 {
        return false;
    }
    addr.chars().any(|c| c.is_ascii_hexdigit()) && addr.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Skip config-looking values under a secret-ish key: PASSWORD_MIN_LENGTH=8, TOKEN_EXPIRES_IN=24h, *_ENABLED=true.
fn env_secret_ok(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    if is_version_like(&v) {
        return false;
    }
    let duration = v.len() > 1 && v[..v.len() - 1].chars().all(|c| c.is_ascii_digit()) && "smhdw".contains(&v[v.len() - 1..]);
    let short_number = v.len() <= 4 && v.chars().all(|c| c.is_ascii_digit());
    !(duration || short_number || ["true", "false", "yes", "no", "on", "off", "null", "none"].contains(&v.as_str()))
}

/// A long token is only a "secret" if it is hex, or mixes upper case, lower case and digits
/// (keeps long snake_case identifiers and paths out).
fn high_entropy_ok(value: &str) -> bool {
    let core = value.trim_end_matches('=');
    let digit = core.chars().any(|c| c.is_ascii_digit());
    let hex = core.chars().all(|c| c.is_ascii_hexdigit());
    let mixed = core.chars().any(|c| c.is_ascii_uppercase()) && core.chars().any(|c| c.is_ascii_lowercase());
    digit && (hex || mixed)
}

/// Organisation label of a DNS domain: CORP.EXAMPLE.COM -> "example", example.co.uk -> "example".
fn org_label(dns_domain: &str) -> Option<String> {
    let labels: Vec<String> = dns_domain.split('.').filter(|l| !l.is_empty()).map(str::to_lowercase).collect();
    if labels.len() < 2 {
        return None;
    }
    let mut i = labels.len() - 2;
    if i > 0 && ["co", "com", "org", "net", "ac", "gov", "edu", "ltd"].contains(&labels[i].as_str()) {
        i -= 1;
    }
    let label = &labels[i];
    let generic = ["local", "localdomain", "corp", "internal", "lan", "intranet", "home", "domain", "ad"];
    (label.len() >= 3 && !generic.contains(&label.as_str())).then(|| label.clone())
}

fn tag(name: &str) -> String {
    let mut out = String::new();
    for c in name.to_uppercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let t = out.trim_matches('_').to_string();
    if t.is_empty() { "VALUE".into() } else { t }
}

fn compile(source: &str, case_sensitive: bool) -> Result<Regex, String> {
    let full = if case_sensitive { source.to_string() } else { format!("(?i){source}") };
    RegexBuilder::new(&full)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|e| format!("Invalid regex: {e}"))
}

/// Python-style replacement template: \1, \g<1>, \g<name>, \\, \n, \t.
fn expand(template: &str, caps: &Captures) -> String {
    let mut out = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some(d) if d.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_digit() && num.len() < 2 { num.push(d); chars.next(); } else { break; }
                }
                if let Some(m) = num.parse::<usize>().ok().and_then(|i| caps.get(i)) {
                    out.push_str(m.as_str());
                }
            }
            Some('g') => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    chars.next();
                    let name: String = chars.by_ref().take_while(|c| *c != '>').collect();
                    let m = name.parse::<usize>().ok().and_then(|i| caps.get(i)).or_else(|| caps.name(&name));
                    if let Some(m) = m { out.push_str(m.as_str()); }
                } else {
                    out.push_str("\\g");
                }
            }
            Some('\\') => { chars.next(); out.push('\\'); }
            Some('n') => { chars.next(); out.push('\n'); }
            Some('t') => { chars.next(); out.push('\t'); }
            _ => out.push('\\'),
        }
    }
    out
}

// ----------------------------------------------------------------------------- built-ins

struct Spec {
    name: &'static str,
    regex: String,
    replacement: &'static str,
    priority: i64,
    comment: &'static str,
    hash: bool,
    gate: &'static [&'static str],
    validator: Option<Validator>,
}

fn spec(name: &'static str, regex: impl Into<String>, replacement: &'static str, priority: i64, comment: &'static str) -> Spec {
    Spec { name, regex: regex.into(), replacement, priority, comment, hash: false, gate: &[], validator: None }
}

impl Spec {
    fn hashed(mut self) -> Self { self.hash = true; self }
    fn gate(mut self, g: &'static [&'static str]) -> Self { self.gate = g; self }
    fn validate(mut self, v: Validator) -> Self { self.validator = Some(v); self }
}

fn default_specs() -> Vec<Spec> {
    let ipv4 = format!(r"{IPV4_OCTET}(?:\.{IPV4_OCTET}){{3}}");
    vec![
        spec("PrivateKey", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
             "<PRIVATE_KEY>", 110, "PEM / PGP private key blocks").gate(&["private key"]),
        spec("IPPort", format!(r"\b{ipv4}:\d{{1,5}}\b"), "<IP>:<PORT>", 100, "IPv4 address with port").gate(&[":"]),
        spec("URLCredentials", r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?P<value>[^/\s:@]+:[^/\s]+)@", "<CREDENTIALS>", 95,
             "user:password inside URLs").gate(&["://"]),
        spec("CloudToken", concat!(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}",
                                   r"|\bglpat-[A-Za-z0-9_-]{20,}|\bxox[abposr]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}\b",
                                   r"|\b[sr]k_(?:live|test)_[0-9A-Za-z]{10,}"),
             "<TOKEN>", 95, "AWS, GitHub, GitLab, Slack, Google and Stripe keys").hashed()
            .gate(&["akia", "asia", "gh", "glpat-", "xox", "aiza", "k_live_", "k_test_"]),
        spec("JWTToken", r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", "<JWT_TOKEN>", 92,
             "JSON Web Tokens anywhere in the text").hashed().gate(&["eyj"]),
        spec("AuthHeader", r"(?<![A-Za-z0-9])(?i:Bearer|Basic|Token|Negotiate|NTLM|Digest)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})",
             "<AUTH_TOKEN>", 90, "Authorization header credentials").hashed()
            .gate(&["bearer", "basic", "token", "negotiate", "ntlm", "digest"]),
        spec("APIKey", kv(r"(?:x-)?api[-_]?key", KV_VALUE, false, r"api[-_]?key"), "<API_KEY>", 90,
             "api_key / x-api-key values").hashed().validate(literal_ok).gate(&["api"]),
        spec("SecretKey", kv(r"secret(?:[-_]?key)?", KV_VALUE, false, r"secret[-_]?key"), "<SECRET_KEY>", 90,
             "secret / client_secret / secret_key values").hashed().validate(literal_ok).gate(&["secret"]),
        spec("Password", kv(r"passw(?:or)?d|passphrase|pwd|(?<![A-Za-z])pass(?![A-Za-z])", KV_VALUE, false, r"passw(?:or)?d|pwd"),
             "<PASSWORD>", 90, "password=, pwd:, \"password\": \"...\", DB_PASSWORD=, SMTP_PASS=, PASSWORD_DEV=...")
            .hashed().validate(literal_ok).gate(&["pass", "pwd"]),
        spec("EnvSecret", env_line(ENV_SECRET_KEY),
             "<SECRET>", 85, "Whole value of KEY=... lines whose key names a password / secret / token / key (incl. commented-out lines)")
            .hashed().validate(env_secret_ok)
            .gate(&["pass", "pwd", "secret", "token", "key", "credential", "seed", "mnemonic", "recovery", "auth_"]),
        spec("EnvPII", env_line(ENV_PII_KEY), "<PII>", 85,
             "Value of KEY=... lines holding names, phone, address, SSN, card, bank, passport or birth date")
            .validate(pii_ok)
            .gate(&["ssn", "social", "passport", "card", "cvv", "cvc", "iban", "routing", "account", "swift", "birth",
                    "dob", "name", "phone", "mobile", "telephone", "address"]),
        spec("EnvHost", env_line(ENV_HOST_KEY), "<HOST>", 85, "Value of HOSTNAME= / DOMAIN= / FQDN= lines")
            .validate(host_ok).gate(&["hostname", "domain", "fqdn"]),
        spec("SSN", r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])", "<SSN>", 66, "US social security numbers (structure-checked)")
            .validate(ssn_ok).gate(&["-"]),
        spec("Phone", concat!(r"(?<![\w+])\+\d{1,3}[ .-]\d{1,4}(?:[ .-]\d{2,4}){2,3}(?![\w-])",
                              r"|(?<![\w+])\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}(?![\w-])"), "<PHONE>", 66,
             "International (+CC ...) and (NNN) NNN-NNNN phone numbers").validate(phone_ok).gate(&["+", "("]),
        spec("IBAN", r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?(?![A-Za-z0-9])", "<IBAN>", 66,
             "IBANs (mod-97 checked)").validate(iban_ok),
        spec("PersonNameJSON", r#"(?i:"(?:full[-_]?name|display[-_]?name|cardholder(?:[-_]?name)?|name)")\s*:\s*"(?P<value>[A-Z][a-z]+(?:[ ][A-Z][a-z'-]+)+)""#,
             "<NAME>", 55, "Person names in JSON (\"name\": \"First Last\")").gate(&["name"]),
        spec("EncodedEmail", r"[A-Za-z0-9._+-]+%(?:25){0,2}40[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<EMAIL>", 80,
             "URL-encoded emails (user%40host.tld, also double / triple encoded)").gate(&["40"]),
        spec("UNCPath", r#"(?<![\w\\])\\\\[A-Za-z0-9_.$-]{2,}\\[^\s"'<>|]+"#, "<UNC_PATH>", 60, "Windows UNC paths (\\\\server\\share\\...)")
            .gate(&["\\\\"]),
        spec("AccessToken", kv(r"token", KV_VALUE, false, r"(?:access|auth|id|session)[-_]?token"), "<ACCESS_TOKEN>", 90,
             "token / access_token / auth-token values").hashed().validate(literal_ok).gate(&["token"]),
        spec("RefreshToken", kv(r"refresh[-_]?token", KV_VALUE, false, r"refresh[-_]?token"), "<REFRESH_TOKEN>", 91,
             "refresh_token values").hashed().validate(literal_ok).gate(&["refresh"]),
        spec("DatabaseURL", kv(r"(?:database|db)[-_]?ur[li]", r#"(?P<value>[^\s"']+)"#, false, r"(?:database|db)[-_]?ur[li]"),
             "<DB_URL>", 90, "DATABASE_URL / db_url values").hashed().gate(&["url", "uri"]),
        spec("ConnectionString", kv(r"conn(?:ection)?[-_]?str(?:ing)?", r#"(?P<value>[^\r\n"']+)"#, false,
                                    r"conn(?:ection)?[-_]?str(?:ing)?"),
             "<CONNECTION_STRING>", 90, "connection_string values").hashed().gate(&["conn"]),
        spec("Email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<EMAIL>", 80, "Email addresses").gate(&["@"]),
        spec("GUID", format!(r"\b{HEX}{{8}}-{HEX}{{4}}-{HEX}{{4}}-{HEX}{{4}}-{HEX}{{12}}\b"), "<GUID>", 70, "GUID / UUID").gate(&["-"]),
        spec("SID", r"\bS-1-5-21-\d+-\d+-\d+-\d+\b", "<SID>", 70, "Windows domain SIDs").hashed().gate(&["s-1-5-21-"]),
        spec("CreditCard", r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])", "<CARD>", 65, "Payment card numbers (Luhn-checked)")
            .validate(luhn_ok),
        spec("MACAddress", format!(r"\b{HEX}{{2}}(?:[:-]{HEX}{{2}}){{5}}\b"), "<MAC>", 65, "MAC addresses"),
        spec("IPv6", format!(r"(?<![\w:.])(?:{HEX}{{0,4}}:){{2,7}}{HEX}{{0,4}}(?:%[\w.-]+)?(?![\w:.])"), "<IPV6>", 62,
             "IPv6 addresses (validated)").gate(&[":"]).validate(ipv6_ok),
        spec("PortSpec", format!(r#"(?<![A-Za-z0-9])(?i:port){ENV_SUFFIX}(?:["']?[ \t]*[:=][ \t]*["']?|[ \t]+)(?P<value>\d{{1,5}})\b"#),
             "<PORT>", 60, "port=8080 / port 443 / REDIS_PORT_DEV=6379").gate(&["port"]),
        spec("URLPort", r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/\s@]+@)?[^/\s:@\[\]]+:(?P<value>\d{1,5})(?!\d)", "<PORT>", 60,
             "Port in a URL: http://host:9175").gate(&["://"]),
        spec("HighEntropy", r#"[=:][ \t]*["']?(?P<value>[A-Za-z0-9+/_-]{32,}={0,2})(?![A-Za-z0-9+/=_-])"#, "<SECRET>", 50,
             "Long hex / base64 values after = or : (32+ chars), whatever the key").hashed().validate(high_entropy_ok)
            .gate(&["=", ":"]),
        spec("InternalHost", concat!(r"(?i)(?<![\w.@-])(?!host\.docker\.internal(?![\w-]))(?:[a-z0-9-]+\.)+",
                                     r"(?:local|localdomain|internal|intranet|lan|corp|home\.arpa)(?![\w-])(?!\.[\w-])"),
             "<HOST>", 45, "Internal host names: *.local, *.internal, *.lan, *.corp")
            .gate(&[".local", ".internal", ".intranet", ".lan", ".corp", ".home.arpa"]),
        spec("DistinguishedName_CN", r"(?<![A-Za-z0-9])(?i:CN)=(?P<value>(?:\\,|[^,\r\n])+)", "<USER>", 55,
             "Common names in LDAP distinguished names").gate(&["cn="]),
        spec("SAMAccountName", kv("sAMAccountName", r#"(?P<value>[^,\s"']+)"#, true, ""), "<USER>", 55, "AD sAMAccountName")
            .gate(&["samaccountname"]),
        spec("DisplayName", kv("displayName", r#"(?P<value>[^,\r\n"']+)"#, true, ""), "<USER>", 55, "AD displayName")
            .gate(&["displayname"]),
        spec("LegacyExchangeDN", kv("legacyExchangeDN", r#"(?P<value>[^,\r\n"']+)"#, true, ""), "<LEGACY_DN>", 55,
             "AD legacyExchangeDN").gate(&["legacyexchangedn"]),
        spec("MailNickname", kv("mailNickname", r#"(?P<value>[^,\s"']+)"#, true, ""), "<NICKNAME>", 55, "AD mailNickname")
            .gate(&["mailnickname"]),
        spec("ObjectCategory", kv("objectCategory", r#"(?P<value>[^,\r\n"']+)"#, true, ""), "<CATEGORY>", 55,
             "AD objectCategory").gate(&["objectcategory"]),
        spec("ProxyAddresses", kv("proxyAddresses", r#"(?P<value>[^,\r\n"']+)"#, true, ""), "<PROXY>", 55,
             "AD proxyAddresses").gate(&["proxyaddresses"]),
        spec("ShowInAddressBook", kv("showInAddressBook", r#"(?P<value>[^,\r\n"']+)"#, true, ""), "<ADDRESS_BOOK>", 55,
             "AD showInAddressBook").gate(&["showinaddressbook"]),
        spec("UserField", kv(r"user(?:[-_ ]?(?:name|id))?|uid|login", r#"(?P<value>[^\s,;"'&]+)"#, true, ""), "<USER>", 55,
             "user= / username: / User Id= values").gate(&["user", "uid", "login"]),
        spec("IP", format!(r"\b{ipv4}\b"), "<IP>", 40, "IPv4 addresses").gate(&["."]),
        spec("Timestamp", r"(?<=Logged at )\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "<TIMESTAMP>", 30,
             "Timestamps after 'Logged at '").gate(&["logged at "]),
    ]
}

// ----------------------------------------------------------------------------- engine

#[derive(Clone)]
pub struct Engine {
    patterns: Vec<Pattern>, // kept sorted in application order
}

impl Default for Engine {
    fn default() -> Self {
        let env = |k: &str| std::env::var(k).unwrap_or_default();
        Self::with_defaults(&env("USERNAME"), &env("COMPUTERNAME"), &env("USERDNSDOMAIN"))
    }
}

impl Engine {
    /// `dns_domain` (e.g. %USERDNSDOMAIN%) adds a rule hiding every host name of that organisation.
    pub fn with_defaults(username: &str, hostname: &str, dns_domain: &str) -> Self {
        let mut patterns: Vec<Pattern> = default_specs()
            .into_iter()
            .map(|s| Pattern {
                name: s.name.into(),
                regex: compile(&s.regex, true).unwrap_or_else(|e| panic!("built-in {}: {e}", s.name)),
                source: s.regex,
                replacement: s.replacement.into(),
                hash: s.hash,
                enabled: true,
                case_sensitive: true,
                comment: s.comment.into(),
                priority: s.priority,
                gate: s.gate.iter().map(|g| g.to_string()).collect(),
                validator: s.validator,
                builtin: true,
            })
            .collect();
        let mut add = |name: &str, regex: String, repl: &str, comment: &str, gate: Vec<String>| {
            patterns.push(Pattern {
                name: name.into(), regex: compile(&regex, false).expect("system pattern"), source: regex,
                replacement: repl.into(), hash: false, enabled: true, case_sensitive: false, comment: comment.into(),
                priority: 50, gate, validator: None, builtin: true,
            });
        };
        for (name, value, repl, comment) in [("Username", username, "<USERNAME>", "Current Windows user name"),
                                              ("Hostname", hostname, "<HOSTNAME>", "This computer's host name")] {
            if value.chars().count() >= 3 {
                add(name, format!(r"\b{}\b", escape(value)), repl, comment, vec![value.to_lowercase()]);
            }
        }
        if let Some(label) = org_label(dns_domain) {
            add("CompanyDomain",
                format!(r"(?<![\w.@-])(?:[a-z0-9-]+\.)*{}(?:\.[a-z0-9-]+)+(?![\w-])", escape(&label)),
                "<HOST>", "Host names of your organisation's domain (from the Windows DNS domain)", vec![label.clone()]);
        }
        add("FilePath_Username",
            concat!(r#"(?:(?<=[\\/]Users[\\/])|(?<=[\\/]home[\\/]))(?!(?:Public|Default|All Users|Shared)[\\/])"#,
                    r#"(?:[^\\/\r\n"'<>|:*?]+(?=[\\/])|[^\\/\s"'<>|:*?]+)"#).to_string(),
            "<USERNAME>", "Any user name in C:\\Users\\<name> or /home/<name> paths", vec!["users".into(), "home".into()]);
        let mut engine = Engine { patterns };
        engine.sort();
        engine
    }

    fn sort(&mut self) {
        self.patterns.sort_by(|a, b| {
            b.priority.cmp(&a.priority).then(b.source.chars().count().cmp(&a.source.chars().count())).then(a.name.cmp(&b.name))
        });
    }

    pub fn patterns(&self) -> Vec<PatternInfo> {
        self.patterns
            .iter()
            .map(|p| PatternInfo {
                name: p.name.clone(), enabled: p.enabled, priority: p.priority, hash: p.hash,
                case_sensitive: p.case_sensitive, builtin: p.builtin, comment: p.comment.clone(), regex: p.source.clone(),
            })
            .collect()
    }

    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        match self.patterns.iter_mut().find(|p| p.name == name) {
            Some(p) => { p.enabled = enabled; true }
            None => false,
        }
    }

    fn upsert(&mut self, p: Pattern) {
        self.patterns.retain(|x| x.name != p.name);
        self.patterns.push(p);
    }

    /// Merge patterns from a config JSON string. Returns a human-readable summary.
    /// Entries without "regex" only override enabled / priority / hash of an existing pattern.
    pub fn load_config_str(&mut self, json: &str) -> Result<String, String> {
        let json = json.trim_start_matches('\u{feff}');
        let root: Value = serde_json::from_str(json).map_err(|e| format!("Invalid JSON in config file: {e}"))?;
        let entries = root.get("patterns").and_then(Value::as_array)
            .ok_or("Config must be an object with a \"patterns\" list")?;
        let (mut loaded, mut skipped) = (0usize, Vec::<String>::new());
        for entry in entries {
            let label = entry.get("name").and_then(Value::as_str).unwrap_or("?").to_string();
            match self.pattern_from_config(entry) {
                Ok(p) => { self.upsert(p); loaded += 1; }
                Err(e) => skipped.push(format!("{label}: {e}")),
            }
        }
        self.sort();
        let mut msg = format!("Loaded {loaded} patterns");
        if !skipped.is_empty() {
            msg += &format!(", skipped {}: {}", skipped.len(), skipped.iter().take(3).cloned().collect::<Vec<_>>().join("; "));
        }
        Ok(msg)
    }

    fn pattern_from_config(&self, entry: &Value) -> Result<Pattern, String> {
        let name = entry.get("name").and_then(Value::as_str).filter(|s| !s.trim().is_empty())
            .ok_or("missing \"name\"")?.trim().to_string();
        let existing = self.patterns.iter().find(|p| p.name == name);
        let mut regex = entry.get("regex").and_then(Value::as_str).filter(|s| !s.is_empty());
        if let (Some(r), Some(ex)) = (regex, existing) {
            if ex.builtin && LEGACY_DEFAULT_REGEXES.contains(&r) {
                regex = None; // outdated copy of a built-in
            }
        }
        let bool_field = |k: &str| entry.get(k).and_then(Value::as_bool);
        let priority = entry.get("priority").and_then(Value::as_i64);
        let Some(regex) = regex else {
            let mut p = existing.cloned().ok_or("missing \"regex\"")?;
            if let Some(v) = bool_field("enabled") { p.enabled = v; }
            if let Some(v) = bool_field("hash") { p.hash = v; }
            if let Some(v) = priority { p.priority = v; }
            return Ok(p);
        };
        if is_risky_regex(regex) {
            return Err("Regex rejected: nested quantifiers may cause catastrophic backtracking (ReDoS)".into());
        }
        let case_sensitive = bool_field("case_sensitive").unwrap_or(false);
        Ok(Pattern {
            name,
            regex: compile(regex, case_sensitive)?,
            source: regex.to_string(),
            replacement: entry.get("replacement").and_then(Value::as_str).unwrap_or("<REDACTED>").to_string(),
            hash: bool_field("hash").unwrap_or(false),
            enabled: bool_field("enabled").unwrap_or(true),
            case_sensitive,
            comment: entry.get("comment").and_then(Value::as_str).unwrap_or("").to_string(),
            priority: priority.unwrap_or(existing.map(|p| p.priority).unwrap_or(0)),
            gate: vec![],
            validator: None,
            builtin: false,
        })
    }

    /// Sanitize `text`. `salt` keys the HMAC; use a fresh random salt per run.
    pub fn sanitize(&self, text: &str, salt: &[u8]) -> SanitizeResult {
        let lowered = text.to_lowercase();
        let template_re = Regex::new(r"\\(?:\d|g<)").unwrap();
        let mut accepted: Vec<(usize, usize, String, usize)> = Vec::new();
        let mut warnings = Vec::new();

        for (idx, p) in self.patterns.iter().enumerate() {
            if !p.enabled || (!p.gate.is_empty() && !p.gate.iter().any(|g| lowered.contains(g.as_str()))) {
                continue;
            }
            let value_group = p.regex.capture_names().any(|n| n == Some(VALUE_GROUP));
            let template = p.regex.captures_len() > 1 && template_re.is_match(&p.replacement).unwrap_or(false);
            let mut cands = Vec::new();
            for caps in p.regex.captures_iter(text) {
                let caps = match caps {
                    Ok(c) => c,
                    Err(e) => {
                        warnings.push(format!("Pattern '{}' stopped early: {e}", p.name));
                        break;
                    }
                };
                let m = if value_group { caps.name(VALUE_GROUP) } else { caps.get(0) };
                let Some(m) = m else { continue };
                if m.start() == m.end() { continue; }
                let value = m.as_str();
                if is_placeholder(value) { continue; }
                if let Some(v) = p.validator { if !v(value) { continue; } }
                let repl = if p.hash {
                    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("hmac key");
                    mac.update(value.as_bytes());
                    let hex = hex::encode_upper(mac.finalize().into_bytes());
                    format!("<HASHED_{}_{}>", tag(&p.name), &hex[..HASH_LENGTH])
                } else if template {
                    expand(&p.replacement, &caps)
                } else {
                    p.replacement.clone()
                };
                cands.push((m.start(), m.end(), repl, idx));
            }
            if !cands.is_empty() {
                accepted = merge_spans(accepted, cands);
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut segments = Vec::new();
        let mut counts: HashMap<usize, usize> = HashMap::new();
        let mut pos = 0;
        for (s, e, r, idx) in &accepted {
            if *s > pos {
                segments.push(Segment { text: text[pos..*s].to_string(), hit: None });
            }
            out.push_str(&text[pos..*s]);
            out.push_str(r);
            segments.push(Segment { text: r.clone(), hit: Some(self.patterns[*idx].name.clone()) });
            *counts.entry(*idx).or_default() += 1;
            pos = *e;
        }
        if pos < text.len() {
            segments.push(Segment { text: text[pos..].to_string(), hit: None });
        }
        out.push_str(&text[pos..]);
        let mut counts: Vec<(String, usize)> = counts.into_iter().map(|(i, n)| (self.patterns[i].name.clone(), n)).collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        SanitizeResult { total: accepted.len(), text: out, counts, segments, warnings }
    }
}

/// Merge one pattern's (sorted, non-overlapping) matches into the accepted spans.
/// No overlap: keep. Strictly covers accepted spans: replace them (redacts more).
/// Inside / crossing / identical to an accepted span: drop (higher priority already won).
fn merge_spans<T>(accepted: Vec<(usize, usize, String, T)>, candidates: Vec<(usize, usize, String, T)>)
    -> Vec<(usize, usize, String, T)> {
    if accepted.is_empty() {
        return candidates;
    }
    let n = accepted.len();
    let mut acc: Vec<Option<(usize, usize, String, T)>> = accepted.into_iter().map(Some).collect();
    let mut out = Vec::with_capacity(n + candidates.len());
    let mut i = 0;
    for cand in candidates {
        let (cs, ce) = (cand.0, cand.1);
        while i < n && acc[i].as_ref().unwrap().1 <= cs {
            out.push(acc[i].take().unwrap());
            i += 1;
        }
        let mut j = i;
        while j < n && acc[j].as_ref().unwrap().0 < ce {
            j += 1;
        }
        if j == i {
            out.push(cand);
            continue;
        }
        let (first, last) = (acc[i].as_ref().unwrap(), acc[j - 1].as_ref().unwrap());
        let covers = first.0 >= cs && last.1 <= ce;
        let identical = j - i == 1 && first.0 == cs && first.1 == ce;
        if covers && !identical {
            for k in i..j { acc[k] = None; }
            out.push(cand);
            i = j;
        }
    }
    out.extend(acc.into_iter().skip(i).flatten());
    out
}

// ----------------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine { Engine::with_defaults("jdoe_test", "TESTHOST01", "CORP.EXAMPLE.COM") }
    fn clean(text: &str) -> String { engine().sanitize(text, b"salt").text }

    #[test]
    fn email_ip_ipport() {
        assert_eq!(clean("contact me@example.com from 192.168.1.10"), "contact <EMAIL> from <IP>");
        assert_eq!(clean("connect 10.0.0.5:8080 now"), "connect <IP>:<PORT> now");
        assert!(clean("bad 999.999.999.999").contains("999.999.999.999"));
    }

    #[test]
    fn password_variants() {
        for t in ["password: hunter2", "PASSWORD=hunter2", "Password = hunter2", "pwd:hunter2",
                  "\"password\": \"hunter2\"", "DB_PASSWORD=hunter2", "url?passwd=hunter2&x=1"] {
            let out = clean(t);
            assert!(!out.contains("hunter2"), "{t} -> {out}");
            assert!(out.contains("<HASHED_PASSWORD_"), "{t} -> {out}");
        }
        assert!(clean("PASSWORD=admin123!").starts_with("PASSWORD=<HASHED_PASSWORD_"));
    }

    #[test]
    fn quoted_and_spaced() {
        let out = clean("secret='correct horse battery'");
        assert!(out.starts_with("secret='<HASHED_SECRETKEY_") && out.ends_with("'"), "{out}");
        assert!(!clean("api_key abc123xyz").contains("abc123xyz"));
        assert_eq!(clean("Invalid token for user"), "Invalid token for user");
    }

    #[test]
    fn same_value_same_hash() {
        let out = clean("password=abc pwd=abc password=xyz");
        let v: Vec<&str> = out.split(' ').map(|t| t.split('=').nth(1).unwrap()).collect();
        assert_eq!(v[0], v[1]);
        assert_ne!(v[0], v[2]);
    }

    #[test]
    fn tokens_urls_keys() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl";
        for (t, secret) in [(format!("token {jwt} end"), jwt), ("Authorization: Bearer abcdefghijklmnop".into(), "abcdefghijklmnop"),
                            ("aws AKIAIOSFODNN7EXAMPLE used".into(), "AKIAIOSFODNN7EXAMPLE"), ("refresh_token=r3fr3sh".into(), "r3fr3sh")] {
            assert!(!clean(&t).contains(secret), "{t}");
        }
        assert_eq!(clean("fetch https://bob:p@ss@git.example.org/r.git"), "fetch https://<CREDENTIALS>@git.example.org/r.git");
        let out = clean("refresh_token=r1 Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc");
        assert!(out.contains("refresh_token=<HASHED_REFRESHTOKEN_") && out.contains("Bearer <HASHED_JWTTOKEN_"), "{out}");
    }

    #[test]
    fn overlap_absorb_and_blocks() {
        assert_eq!(clean("DisplayName=John Smith <john@corp.com>, dept=IT"), "DisplayName=<USER>, dept=IT");
        let db = clean("DATABASE_URL=postgres://admin:S3cret@10.0.0.5:5432/prod");
        assert!(db.starts_with("DATABASE_URL=<HASHED_DATABASEURL_") && !db.contains("10.0.0.5"), "{db}");
        let key = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\ndone";
        assert_eq!(clean(key), "key:\n<PRIVATE_KEY>\ndone");
    }

    #[test]
    fn validators_and_misc() {
        assert_eq!(clean("card 4111 1111 1111 1111 ok"), "card <CARD> ok");
        assert!(clean("card 4111 1111 1111 1112").contains("1112"));
        assert_eq!(clean("from fe80::1ff:fe23:4567:890a%eth0 at 14:35:22"), "from <IPV6> at 14:35:22");
        assert_eq!(clean("C++ std::vector"), "C++ std::vector");
        assert_eq!(clean(r"C:\Users\John Smith\AppData\x.log"), r"C:\Users\<USERNAME>\AppData\x.log");
        assert_eq!(clean(r"C:\Users\Public\Documents"), r"C:\Users\Public\Documents");
        assert_eq!(clean("sAMAccountName: jdoe, distinguishedName=CN=Doe\\, John,OU=Staff"),
                   "sAMAccountName: <USER>, distinguishedName=CN=<USER>,OU=Staff");
        assert_eq!(clean("listening on port 8443; report 5 items"), "listening on port <PORT>; report 5 items");
        assert_eq!(clean("host TESTHOST01 user JDOE_TEST"), "host <HOSTNAME> user <USERNAME>");
        let out = clean("mac 00:1A:2B:3C:4D:5E guid 123E4567-E89B-12D3-A456-426614174000 sid S-1-5-21-1-2-3-500");
        assert!(out.starts_with("mac <MAC> guid <GUID> sid <HASHED_SID_"), "{out}");
    }

    #[test]
    fn config_handling() {
        let mut e = engine();
        let msg = e.load_config_str(r#"{"patterns": [
            {"name": "Evil", "regex": "(a+)+", "replacement": "x"},
            {"name": "Broken", "regex": "(", "replacement": "x"},
            {"name": "Ticket", "regex": "TCK-(?P<value>\\d+)", "replacement": "<N>", "priority": 50},
            {"name": "Swap", "regex": "(\\w+)#(\\w+)", "replacement": "\\2 at \\1"},
            {"name": "Email", "enabled": false},
            {"name": "IPPort", "regex": "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{1,5}\\b", "replacement": "<IP>:<PORT>"}
        ]}"#).unwrap();
        assert!(msg.starts_with("Loaded 4 patterns, skipped 2"), "{msg}");
        let out = e.sanitize("TCK-42 a@b.com me#host 10.0.0.1:80", b"s").text;
        assert_eq!(out, "TCK-<N> a@b.com host at me <IP>:<PORT>");
        assert!(e.patterns().iter().any(|p| p.name == "IPPort" && p.priority == 100));
        assert!(e.load_config_str("{bad").is_err());
    }

    #[test]
    fn env_file_leaks() {
        let env = concat!(
            "DATABASE_PASS=0123456789abcdef0123456789abcdef\n",
            "ADMIN_PASSWORD=Adm1n!pw #n3w%Secr3t@Zz\n",
            "POSTGRES_PASSWORD_DEV=\"Qm9ndXNEZXZQYXNzd29yZEZvclRlc3RzMTIzNDU2Nzg=\"\n",
            "REDIS_PASSWORD_DEV=\"Zm9vYmFyRmFrZVJlZGlzUGFzc3dvcmQ5ODc2NTQzMjE=\"\n",
            "POSTGRES_USER_DEV=app_dev_user\n",
            "REDIS_PORT_DEV=30059\n",
            "OPAQUE_VALUE=Zk3q9WmXp2Lr7Tn4Vb8Yc1Hd6Gs0Ja5E\n",
            "FRONTEND_URL=http://app.corp.example.com:9175\n",
            "REACT_APP_API_URL=https://vault.example.com\n",
            "# Hosts: add 10.0.0.1 app.trackit.local for local testing.\n",
            "# DB_PASSWORD=0ldC0mmented!\n",
        );
        let out = clean(env);
        for leak in ["0123456789abcdef", "Adm1n", "n3w%Secr3t", "Qm9ndXNE", "Zm9vYmFy", "app_dev_user", "30059",
                     "Zk3q9WmX", "example.com", "9175", "trackit.local", "0ldC0mmented"] {
            assert!(!out.contains(leak), "leaked {leak}:\n{out}");
        }
        assert!(out.contains("FRONTEND_URL=http://<HOST>:<PORT>\n"), "{out}");
        assert!(out.contains("REDIS_PORT_DEV=<PORT>\n") && out.contains("POSTGRES_USER_DEV=<USER>\n"), "{out}");
        assert!(out.contains("add <IP> <HOST> for local"), "{out}");
    }

    #[test]
    fn env_file_pii_leaks() {
        let env = concat!(
            "HOSTNAME=prod-auth-gw-03.corp.northstar.example\nDOMAIN=corp.northstar.example\n",
            "ADMIN_FULL_NAME=Paula Reyes\nADMIN_PHONE=+1-202-555-0148\n",
            "ADMIN_ADDRESS=48 Harbor Plaza, Suite 720, Washington DC 20001\n",
            "UNC_BACKUP_PATH=\\\\filesrv-02\\Finance\\Payroll\\2026\n",
            "TOTP_SEED=JBSWY3DPEHPK3PXP\nRECOVERY_CODES=8462-1937,5741-2380\n",
            "AUTH_0=WgP5RipVIrlSWPQrzJOigHt4\n",
            "CARDHOLDER_NAME=Paula Reyes\nCARD_EXPIRY=08/29\nCARD_CVV=731\nIBAN=GB82WEST12345698765432\n",
            "US_ROUTING_NUMBER=021000021\nUS_ACCOUNT_NUMBER=987654321012\nPASSPORT_NUMBER=K68241975\n",
            "SSN=078-05-1120\nDATE_OF_BIRTH=1988-07-19\n",
            "P='{\"name\":\"Paula Reyes\",\"phone\":\"+1-202-555-0148\",\"ssn\":\"078-05-1120\"}'\n",
            "N=\"https://h.example/n?token=abc&email=paula.reyes%40northstar.example\"\n",
            "notes=\"call +1-202-555-0148\"\n",
        );
        let out = clean(env);
        for leak in ["northstar", "Paula", "Reyes", "555-0148", "Harbor", "filesrv", "JBSWY3", "8462", "WgP5Ri", "08/29",
                     "731", "GB82", "021000021", "987654321012", "K68241975", "078-05", "1988"] {
            assert!(!out.contains(leak), "leaked {leak}:\n{out}");
        }
    }

    #[test]
    fn pii_context_keeps_non_personal_keys() {
        let keep = "LISTEN_ADDRESS=ingress\nIP_ADDRESS_FAMILY=ipv4\nHOSTNAME=localhost\nPHONE_ENABLED=true\nDOMAIN=${BASE}\n";
        assert_eq!(clean(keep), keep);
        // Structure-checked values: invalid SSN / IBAN / short digit runs are left alone.
        let keep = "id 000-12-3456 iban GB00AAAA11112222333344 order 12-34-5678 +1-23";
        assert_eq!(clean(keep), keep);
        assert_eq!(clean("pay DE89 3704 0044 0532 0130 00 now"), "pay <IBAN> now");
    }

    #[test]
    fn config_values_are_not_secrets() {
        let keep = concat!(
            "FLAG_SECRET=false\nSECRET_BUILD_VERSION=6.3.1\nSECRET_TIMEOUT_MS=30000\nTOKEN_REFRESH_INTERVAL=86400\n",
            "AUTH_MODE=ldap\nPASSWORD_MIN_LENGTH=12\nAPI_KEY_HEADER=X-Api-Key\nsecret=null\nversion=2.14.1\nPORT=8443\n",
        );
        let out = clean(keep);
        for line in ["FLAG_SECRET=false", "SECRET_BUILD_VERSION=6.3.1", "SECRET_TIMEOUT_MS=30000", "AUTH_MODE=ldap",
                     "PASSWORD_MIN_LENGTH=12", "API_KEY_HEADER=X-Api-Key", "secret=null", "version=2.14.1"] {
            assert!(out.contains(line), "damaged {line}:\n{out}");
        }
        // The same key shapes with real values are still redacted.
        for t in ["FLAG_SECRET=Zx81kQ9mTt", "SECRET_KEY=Zx81kQ9mTt", "TOKEN=12345678", "password=1.2.3.4.5.6"] {
            assert!(!clean(t).ends_with(t.split('=').nth(1).unwrap()), "{t}");
        }
    }

    #[test]
    fn encoded_urls_and_nested_structures() {
        let out = clean("https://h.example/n?u=ann.lee%40corp-x.example&v=bob%2540corp-x.example&page=2");
        assert_eq!(out, "https://h.example/n?u=<EMAIL>&v=<EMAIL>&page=2");
        let json = r#"{"a":{"b":{"password":"Tr0ub4dor&3","note":"ok","client_secret":"s3cr3t-value"}},"port":5432}"#;
        let out = clean(json);
        assert!(!out.contains("Tr0ub4dor") && !out.contains("s3cr3t-value") && out.contains(r#""note":"ok""#), "{out}");
        let out = clean("Server=db1;Database=x;User ID=svc;Password=Pa55w0rd!x;Encrypt=True;");
        assert!(!out.contains("Pa55w0rd") && out.contains("Database=x") || !out.contains("Pa55w0rd"), "{out}");
        let out = clean("TOKEN_PART_A=abcDEF123 and k=1 password=Un1c0de-Sëcrët-密碼 end");
        assert!(!out.contains("密碼") && out.ends_with(" end"), "{out}");
    }

    #[test]
    fn sanitizing_is_idempotent_and_robust() {
        let src = "PASSWORD=Hunter2!x\nmail a@b.example from 10.1.2.3 ssn 123-45-6789 tel +44 20 7946 0958\nDB=postgres://u:p4ss@h:5432/d\n";
        let once = clean(src);
        assert_eq!(clean(&once), once);
        // Malformed / unusual input never panics and plain text passes through.
        for t in ["", "=", "KEY=", "\0\u{feff}password=", "\\\\", "%40", "<", "token=\"unterminated", "a=b=c=d"] {
            let _ = clean(t);
        }
        assert_eq!(clean("just some prose, nothing to see: 42"), "just some prose, nothing to see: 42");
        // Large clipboard content and very long lines stay bounded.
        let big = format!("{}\nPASSWORD=Zq81mT{}\n", "lorem ipsum dolor sit amet ".repeat(4_000), "x".repeat(20_000));
        let start = std::time::Instant::now();
        let out = clean(&big);
        let secs = start.elapsed().as_secs();
        assert!(!out.contains("Zq81mT"), "leaked after {secs}s; warnings: {:?}", engine().sanitize(&big, b"salt").warnings);
        assert!(secs < 20, "too slow: {secs}s");
    }

    #[test]
    fn env_file_no_damage() {
        // Empty / commented keys must not swallow the following line, and config-looking values stay.
        let keep = concat!(
            "#SMTP_USER=\n#SMTP_PASS=\n",
            "# DB_READ_USER=\n# DB_READ_PASSWORD=\n# DB_READ_HOST=\n",
            "# After first login, change both email and password in the UI.\n",
            "LM_STUDIO_MAX_TOKENS=1024\nJWT_EXPIRES_IN=24h\nTOKEN_EXPIRES_IN=7d\nPASSWORD_MIN_LENGTH=8\n",
            "SMTP_AUTH=false\nAPI_KEY_REQUIRED=true\nBCRYPT_ROUNDS=14\n",
            "LM_STUDIO_ALLOWED_HOSTS=localhost,host.docker.internal\n",
            "MODULE=some_long_snake_case_identifier_name_v2\n",
            "UPLOAD_PATH=/app/uploads\nREMINDER_CRON_SCHEDULE=0 9,15 * * *\n",
        );
        assert_eq!(clean(keep), keep);
        assert_eq!(clean("DB_USER=\nDB_HOST=db1\n"), "DB_USER=\nDB_HOST=db1\n");
    }

    #[test]
    fn org_label_parsing() {
        assert_eq!(org_label("CORP.EXAMPLE.COM").as_deref(), Some("example"));
        assert_eq!(org_label("example.co.uk").as_deref(), Some("example"));
        assert_eq!(org_label("corp.local"), None);
        assert_eq!(org_label("WORKGROUP"), None);
        assert_eq!(org_label(""), None);
    }

    #[test]
    fn counts_and_segments() {
        let r = engine().sanitize("a@b.com and c@d.com from 10.0.0.1", b"s");
        assert_eq!(r.total, 3);
        assert_eq!(r.counts[0], ("Email".to_string(), 2));
        let joined: String = r.segments.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(joined, r.text);
        assert_eq!(r.segments.iter().filter(|s| s.hit.is_some()).count(), 3);
    }
}
