use alloc::string::String;
use alloc::vec::Vec;

use log::error;
use serde::Deserialize;
use serde::Serialize;

use crate::MeshError;

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct MeshVersionNumber {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct MeshVersionInfo {
    pub version_number: MeshVersionNumber,
    pub commit_sha: String,
    #[serde(default, with = "serde_bytes")]
    pub fingerprint: Vec<u8>,
}

impl From<MeshVersionNumber> for String {
    fn from(value: MeshVersionNumber) -> String {
        format!("{}.{}.{}", value.major, value.minor, value.patch)
    }
}

impl From<String> for MeshVersionNumber {
    fn from(value: String) -> MeshVersionNumber {
        value.as_str().into()
    }
}

impl From<&str> for MeshVersionNumber {
    fn from(value: &str) -> MeshVersionNumber {
        parse_version_number(value).unwrap_or_else(|err| {
            error!("{err}");
            MeshVersionNumber {
                major: 0,
                minor: 0,
                patch: 0,
            }
        })
    }
}

pub fn parse_version_number(value: &str) -> Result<MeshVersionNumber, MeshError> {
    let mut parts = value.split('.');

    if let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    {
        let major: Result<u32, _> = str::parse(major);
        let minor: Result<u32, _> = str::parse(minor);
        let patch: Result<u32, _> = str::parse(patch);
        match (major, minor, patch) {
            (Ok(major), Ok(minor), Ok(patch)) => {
                return Ok(MeshVersionNumber {
                    major,
                    minor,
                    patch,
                });
            }
            _ => {}
        }
    }
    Err(MeshError::ParseError(format!(
        "invalid version number {value:?}"
    )))
}
