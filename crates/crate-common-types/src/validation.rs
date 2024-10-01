use alloc::string::String;

use regex::Regex;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_EMAIL_LEN: usize = 318;
const MAX_PHONE_LEN: usize = 64;

pub fn validate_email(email: &str) -> bool {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(concat!(
            r"^[a-zA-Z0-9._%+-]{1,64}",
            r"@",
            r"(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*\.)+",
            r"[a-zA-Z]{2,}$"
        )).unwrap();
    }
    email.len() <= MAX_EMAIL_LEN && RE.is_match(email)
}

pub fn validate_domain(domain: &str) -> bool {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(concat!(
            r"(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*\.)+",
            r"[a-zA-Z]{2,}$"
        )).unwrap();
    }
    domain.len() <= MAX_DOMAIN_LEN && RE.is_match(domain)
}

pub fn validate_phone(phone: &str) -> bool {
    let Some(digits) = phone.strip_prefix('+') else {
        return false;
    };

    // E.164 specifies a max of 15 digits.
    if !matches!(digits.len(), 9..=15) {
        return false;
    }

    // A valid phone number will be entirely ASCII digits.  The first digit following the '+' must
    // not be '0' because no country code starts with '0'.
    phone.len() <= MAX_PHONE_LEN
        && matches!(digits.as_bytes(), [b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit))
}

pub fn validate_string(s: &str, min_len: usize, max_len: usize) -> bool {
    (min_len..=max_len).contains(&s.len())
}

pub fn validate_string_optional(s: &Option<String>, min_len: usize, max_len: usize) -> bool {
    match s {
        Some(s) => validate_string(s, min_len, max_len),
        None => true,
    }
}

pub fn validate_uri(uri: &str, max_len: usize) -> bool {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(r"^[[:word:]]+:/?/?[[:^space:]]+").unwrap();
    }
    validate_string(uri, 0, max_len) && RE.is_match(uri)
}

pub fn validate_uri_optional(uri: &Option<String>, max_len: usize) -> bool {
    match uri {
        Some(s) => validate_uri(s, max_len),
        None => true,
    }
}
