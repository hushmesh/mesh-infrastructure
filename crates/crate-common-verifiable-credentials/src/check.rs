use alloc::string::ToString;

use chrono::DateTime;
use serde_json::Value;

use common_types::validation::validate_uri;
use common_types::MeshError;

use crate::Credential;
use crate::Presentation;
use crate::CREDENTIALS_CONTEXT_V1_URL;
use crate::CREDENTIALS_CONTEXT_V2_URL;

enum CredentialContextVersion {
    V1,
    V2,
}

fn check_context(value: Option<&Value>) -> Result<CredentialContextVersion, MeshError> {
    match value {
        Some(Value::String(context)) => {
            if matches!(context.as_str(), CREDENTIALS_CONTEXT_V1_URL) {
                return Ok(CredentialContextVersion::V1);
            } else if matches!(context.as_str(), CREDENTIALS_CONTEXT_V2_URL) {
                return Ok(CredentialContextVersion::V2);
            } else {
                return Err(MeshError::BadArgument(format!(
                    "{CREDENTIALS_CONTEXT_V1_URL} or {CREDENTIALS_CONTEXT_V2_URL} needs to be first in the list of contexts"
                )));
            }
        }
        Some(Value::Array(contexts)) => {
            if contexts.is_empty() {
                return Err(MeshError::BadArgument("Empty @context".to_string()));
            }
            let context = contexts[0].as_str().ok_or_else(|| {
                MeshError::BadArgument("First element of @context must be a string".to_string())
            })?;
            if matches!(context, CREDENTIALS_CONTEXT_V1_URL) {
                return Ok(CredentialContextVersion::V1);
            } else if matches!(context, CREDENTIALS_CONTEXT_V2_URL) {
                return Ok(CredentialContextVersion::V2);
            } else {
                return Err(MeshError::BadArgument(format!(
                    "{CREDENTIALS_CONTEXT_V1_URL} or {CREDENTIALS_CONTEXT_V2_URL} needs to be first in the list of contexts"
                )));
            }
        }
        _ => return Err(MeshError::BadArgument("Missing @context".to_string())),
    }
}

fn check_type(value: Option<&Value>, expected: &str) -> Result<(), MeshError> {
    match value {
        Some(Value::String(val)) if val == expected => Ok(()),
        Some(Value::Array(val)) if val.iter().any(|v| v == expected) => Ok(()),
        _ => Err(MeshError::BadArgument(format!(
            "\"type\" must include `{}`",
            expected
        ))),
    }
}

pub(crate) fn check_credential(
    credential: &Credential,
    unix_timestamp: i64,
) -> Result<(), MeshError> {
    let credential = &credential.0;
    let version = check_context(credential.pointer("/@context"))?;
    check_type(credential.pointer("/type"), "VerifiableCredential")?;
    if credential.pointer("/credentialSubject").is_none() {
        return Err(MeshError::BadArgument(
            "\"credentialSubject\" property is required".to_string(),
        ));
    }
    match credential.pointer("/credentialSubject/id") {
        Some(Value::String(id)) => {
            if !validate_uri(id, id.len()) {
                return Err(MeshError::BadArgument(
                    "\"credentialSubject.id\" must be a URI".to_string(),
                ));
            }
        }
        Some(_) => {
            return Err(MeshError::BadArgument(
                "\"credentialSubject.id\" must be a URI".to_string(),
            ));
        }
        _ => {}
    }
    match version {
        CredentialContextVersion::V1 => match credential.pointer("/issuanceDate") {
            Some(Value::String(date)) => {
                if let Ok(date) = DateTime::parse_from_rfc3339(&date) {
                    if unix_timestamp < date.timestamp() {
                        return Err(MeshError::BadArgument(
                            "\"issuanceDate\" must be in the past".to_string(),
                        ));
                    }
                } else {
                    return Err(MeshError::BadArgument(
                        "\"issuanceDate\" must be a valid RFC3339 date".to_string(),
                    ));
                }
            }
            _ => {
                return Err(MeshError::BadArgument(
                    "\"issuanceDate\" property is required".to_string(),
                ));
            }
        },
        CredentialContextVersion::V2 => match credential.pointer("/validFrom") {
            Some(Value::String(date)) => {
                if let Ok(date) = DateTime::parse_from_rfc3339(&date) {
                    if unix_timestamp < date.timestamp() {
                        return Err(MeshError::BadArgument(
                            "\"validFrom\" must be in the past".to_string(),
                        ));
                    }
                } else {
                    return Err(MeshError::BadArgument(
                        "\"validFrom\" must be a valid RFC3339 date".to_string(),
                    ));
                }
            }
            _ => {
                // validFrom property is optional in VC v2
            }
        },
    }
    match credential.pointer("/issuer") {
        Some(Value::String(issuer)) => {
            if !validate_uri(issuer, issuer.len()) {
                return Err(MeshError::BadArgument(
                    "\"issuer\" must be a URI".to_string(),
                ));
            }
        }
        Some(Value::Object(issuer)) => match issuer.get("id") {
            Some(Value::String(id)) => {
                if !validate_uri(id, id.len()) {
                    return Err(MeshError::BadArgument(
                        "\"issuer.id\" must be a URI".to_string(),
                    ));
                }
            }
            _ => {
                return Err(MeshError::BadArgument(
                    "\"issuer.id\" property is required".to_string(),
                ));
            }
        },
        _ => {
            return Err(MeshError::BadArgument(
                "\"issuer\" property is required".to_string(),
            ));
        }
    }
    match credential.pointer("/credentialStatus") {
        Some(Value::Object(status)) => {
            if status.get("id").is_none() {
                return Err(MeshError::BadArgument(
                    "\"credentialStatus.id\" property is required".to_string(),
                ));
            }
            if status.get("type").is_none() {
                return Err(MeshError::BadArgument(
                    "\"credentialStatus.type\" property is required".to_string(),
                ));
            }
        }
        Some(Value::Array(statuses)) => {
            if statuses
                .iter()
                .any(|status| status.pointer("/id").is_none())
            {
                return Err(MeshError::BadArgument(
                    "\"credentialStatus.id\" property is required".to_string(),
                ));
            }
            if statuses
                .iter()
                .any(|status| status.pointer("/type").is_none())
            {
                return Err(MeshError::BadArgument(
                    "\"credentialStatus.type\" property is required".to_string(),
                ));
            }
        }
        _ => {}
    }
    match credential.pointer("/evidence") {
        Some(Value::String(evidence)) => {
            if !validate_uri(evidence, evidence.len()) {
                return Err(MeshError::BadArgument(
                    "\"evidence\" must be a URI".to_string(),
                ));
            }
        }
        Some(Value::Object(map)) => {
            if let Some(Value::String(evidence)) = map.get("id") {
                if !validate_uri(evidence, evidence.len()) {
                    return Err(MeshError::BadArgument(
                        "\"evidence.id\" must be a URI".to_string(),
                    ));
                }
            }
        }
        Some(Value::Array(evidences)) => {
            for evidence in evidences {
                match evidence {
                    Value::String(evidence) => {
                        if !validate_uri(evidence, evidence.len()) {
                            return Err(MeshError::BadArgument(
                                "\"evidence\" must be a URI".to_string(),
                            ));
                        }
                    }
                    Value::Object(map) => {
                        if let Some(Value::String(evidence)) = map.get("id") {
                            if !validate_uri(evidence, evidence.len()) {
                                return Err(MeshError::BadArgument(
                                    "\"evidence.id\" must be a URI".to_string(),
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    match credential.pointer("/expirationDate") {
        Some(Value::String(date)) => {
            if let Ok(date) = DateTime::parse_from_rfc3339(&date) {
                if unix_timestamp > date.timestamp() {
                    return Err(MeshError::BadArgument(
                        "\"expirationDate\" must be in the future".to_string(),
                    ));
                }
            } else {
                return Err(MeshError::BadArgument(
                    "\"expirationDate\" must be a valid RFC3339 date".to_string(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn check_presentation(presentation: &Presentation) -> Result<(), MeshError> {
    let presentation = &presentation.0;
    check_context(presentation.pointer("/@context"))?;
    check_type(presentation.pointer("/type"), "VerifiablePresentation")?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use common_types::time::get_current_time_ms;
    use common_types::MeshError;
    use serde_json::Value;

    use crate::check_credential;
    use crate::Credential;

    #[test]
    fn test_check_credential() {
        let now = get_current_time_ms() / 1000;
        let credential_str = r#"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1", {
                    "ex1": "https://example.com/examples/v1",
                    "AlumniCredential": "ex1:AlumniCredential",
                    "alumniOf": "ex1:alumniOf"
                }
            ],
            "id": "http://example.edu/credentials/58473",
            "issuanceDate": "2010-01-01T19:23:24Z",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "alumniOf": "Example University"
            }
        }"#;
        let credential = Credential(serde_json::from_str(credential_str).unwrap());

        let mut cred = credential.clone();
        cred.0["issuer"] = Value::String("http://example.edu/credentials/58473".to_string());
        cred.0["credentialSubject"]["id"] = Value::String("12345".to_string());
        assert_eq!(
            check_credential(&cred, now),
            Err(MeshError::BadArgument(
                "\"credentialSubject.id\" must be a URI".to_string()
            ))
        );

        let mut cred = credential.clone();
        cred.0["issuer"] = Value::String("12345".to_string());
        assert_eq!(
            check_credential(&cred, now),
            Err(MeshError::BadArgument(
                "\"issuer\" must be a URI".to_string()
            ))
        );

        let mut cred = credential.clone();
        cred.0["issuer"] = Value::String("did:example:12345".to_string());
        cred.0["evidence"] = Value::String("12345".to_string());
        assert_eq!(
            check_credential(&cred, now),
            Err(MeshError::BadArgument(
                "\"evidence\" must be a URI".to_string()
            ))
        );

        let mut cred = credential.clone();
        cred.0["issuer"] = Value::String("did:example:12345".to_string());
        cred.0["expirationDate"] = Value::String("2020-05-31T19:21:25Z".to_string());
        assert_eq!(
            check_credential(&cred, now),
            Err(MeshError::BadArgument(
                "\"expirationDate\" must be in the future".to_string()
            ))
        );

        let mut cred = credential.clone();
        cred.0["issuer"] = Value::String("did:example:12345".to_string());
        cred.0["issuanceDate"] = Value::String("2020-05-31T19:21:25Z".to_string());
        assert_eq!(
            check_credential(&cred, 0),
            Err(MeshError::BadArgument(
                "\"issuanceDate\" must be in the past".to_string()
            ))
        );
    }
}
