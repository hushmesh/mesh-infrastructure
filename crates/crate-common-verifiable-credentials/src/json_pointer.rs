use alloc::borrow::Cow;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use core::str::FromStr;

use common_types::MeshError;

/// JSON Pointer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug)]
#[repr(transparent)]
pub struct JsonPointer(str);

impl JsonPointer {
    /// Converts the given string into a JSON pointer.
    pub fn new(s: &str) -> Result<&Self, MeshError> {
        Self::validate(s)?;
        Ok(unsafe { Self::new_unchecked(s) })
    }

    /// Converts the given string into a JSON pointer without validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer.
    pub unsafe fn new_unchecked(s: &str) -> &Self {
        core::mem::transmute(s)
    }

    fn validate(s: &str) -> Result<(), MeshError> {
        if s.is_empty()
            || s.starts_with("/")
                && core::iter::from_fn({
                    let mut chars = s.chars();
                    move || Some(chars.next()? != '~' || matches!(chars.next(), Some('0' | '1')))
                })
                .all(core::convert::identity)
        {
            Ok(())
        } else {
            Err(MeshError::ParseError("Invalid JSON pointer".into()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn split_first(&self) -> Option<(&ReferenceToken, &Self)> {
        self.0.strip_prefix("/").map(|s| {
            let (left, right) = s.find("/").map(|idx| s.split_at(idx)).unwrap_or((s, ""));
            // Safety: the contents of self have been validated such that we can be assured that
            // these constructions are safe.
            let token = unsafe { ReferenceToken::new_unchecked(left) };
            let remaining = unsafe { Self::new_unchecked(right) };
            (token, remaining)
        })
    }

    pub fn iter(&self) -> JsonPointerIter {
        let mut tokens = self.0.split('/');
        tokens.next();
        JsonPointerIter(tokens)
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> IntoIterator for &'a JsonPointer {
    type Item = &'a ReferenceToken;
    type IntoIter = JsonPointerIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct JsonPointerIter<'a>(core::str::Split<'a, char>);

impl<'a> Iterator for JsonPointerIter<'a> {
    type Item = &'a ReferenceToken;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|s| unsafe { core::mem::transmute(s) })
    }
}

/// JSON Pointer buffer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug, Clone)]
pub struct JsonPointerBuf(String);

impl JsonPointerBuf {
    /// Converts the given string into an owned JSON pointer.
    pub fn new(value: String) -> Result<Self, MeshError> {
        JsonPointer::validate(&value)?;
        Ok(Self(value))
    }

    /// Converts the given byte string into an owned JSON pointer.
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, MeshError> {
        match String::from_utf8(value) {
            Ok(value) => {
                JsonPointer::validate(&value)?;
                Ok(Self(value))
            }
            Err(_) => Err(MeshError::ParseError("JSON pointer utf8 error".into())),
        }
    }
}

impl Deref for JsonPointerBuf {
    type Target = JsonPointer;

    fn deref(&self) -> &Self::Target {
        unsafe { JsonPointer::new_unchecked(&self.0) }
    }
}

impl FromStr for JsonPointerBuf {
    type Err = MeshError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl TryFrom<String> for JsonPointerBuf {
    type Error = MeshError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Display for JsonPointerBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for JsonPointerBuf {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ReferenceToken(str);

impl ReferenceToken {
    /// Converts the given string into a JSON pointer reference token without
    /// validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer reference token.
    pub unsafe fn new_unchecked(s: &str) -> &Self {
        core::mem::transmute(s)
    }

    pub fn is_escaped(&self) -> bool {
        self.0.contains('~')
    }

    pub fn to_str(&self) -> Cow<str> {
        if self.is_escaped() {
            Cow::Owned(self.decode())
        } else {
            Cow::Borrowed(&self.0)
        }
    }

    pub fn decode(&self) -> String {
        let mut buf = String::with_capacity(self.0.len());
        let mut chars = self.0.chars();
        buf.extend(core::iter::from_fn(|| {
            Some(match chars.next()? {
                '~' => match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => unreachable!(),
                },
                c => c,
            })
        }));
        buf
    }

    pub fn as_array_index(&self) -> Option<usize> {
        common_types::strict_uint(&self.0)
    }
}

impl fmt::Display for ReferenceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
