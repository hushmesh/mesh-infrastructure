use alloc::collections::BTreeMap;
use alloc::string::ToString;

use json_ld::syntax::Parse;
use json_ld::syntax::Value;
use json_ld::IriBuf;
use json_ld::RemoteDocument;

pub fn new_permanent_resident_loader() -> BTreeMap<IriBuf, RemoteDocument> {
    lazy_static::lazy_static! {
        static ref LOADER: BTreeMap<IriBuf, RemoteDocument> = make_permanent_resident_loader();
    }
    LOADER.clone()
}

fn make_permanent_resident_loader() -> BTreeMap<IriBuf, RemoteDocument> {
    let mut map = BTreeMap::new();

    let iri = IriBuf::new("https://www.w3.org/2018/credentials/v1".to_string()).unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(WWW_W3_ORG_2018_CREDENTIALS_V1).unwrap().0,
        ),
    );

    let iri = IriBuf::new("https://www.w3.org/ns/credentials/v2".to_string()).unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(WWW_W3_ORG_NS_CREDENTIALS_V2).unwrap().0,
        ),
    );

    let iri = IriBuf::new("https://w3id.org/citizenship/v1".to_string()).unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(W3ID_ORG_CITIZENSHIP_V1).unwrap().0,
        ),
    );

    let iri = IriBuf::new("https://w3id.org/citizenship/v2".to_string()).unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(W3ID_ORG_CITIZENSHIP_V2).unwrap().0,
        ),
    );

    let iri = IriBuf::new("https://w3id.org/security/data-integrity/v2".to_string()).unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(W3ID_ORG_SECURITY_DATA_INTEGRITY_V2)
                .unwrap()
                .0,
        ),
    );

    map
}

const WWW_W3_ORG_2018_CREDENTIALS_V1: &str = r#"{
  "@context": {
    "@version": 1.1,
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "credentialSchema": {
          "@id": "cred:credentialSchema",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
          }
        },
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "refreshService": {
          "@id": "cred:refreshService",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "ManualRefreshService2018": "cred:ManualRefreshService2018"
          }
        },
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
      }
    },

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",

        "holder": {"@id": "cred:holder", "@type": "@id"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
      }
    },

    "EcdsaSecp256k1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "EcdsaSecp256r1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "Ed25519Signature2018": {
      "@id": "https://w3id.org/security#Ed25519Signature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "RsaSignature2018": {
      "@id": "https://w3id.org/security#RsaSignature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "proof": {"@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph"}
  }
}"#;

const W3ID_ORG_CITIZENSHIP_V1: &str = r#"{
  "@context": {
    "@version": 1.1,
    "@protected": true,

    "name": "http://schema.org/name",
    "description": "http://schema.org/description",
    "identifier": "http://schema.org/identifier",
    "image": {"@id": "http://schema.org/image", "@type": "@id"},

    "PermanentResidentCard": {
      "@id": "https://w3id.org/citizenship#PermanentResidentCard",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "description": "http://schema.org/description",
        "name": "http://schema.org/name",
        "identifier": "http://schema.org/identifier",
        "image": {"@id": "http://schema.org/image", "@type": "@id"}
      }
    },

    "PermanentResident": {
      "@id": "https://w3id.org/citizenship#PermanentResident",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "ctzn": "https://w3id.org/citizenship#",
        "schema": "http://schema.org/",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "birthCountry": "ctzn:birthCountry",
        "birthDate": {"@id": "schema:birthDate", "@type": "xsd:dateTime"},
        "commuterClassification": "ctzn:commuterClassification",
        "familyName": "schema:familyName",
        "gender": "schema:gender",
        "givenName": "schema:givenName",
        "lprCategory": "ctzn:lprCategory",
        "lprNumber": "ctzn:lprNumber",
        "residentSince": {"@id": "ctzn:residentSince", "@type": "xsd:dateTime"}
      }
    },

    "Person": "http://schema.org/Person"
  }
}"#;

const W3ID_ORG_SECURITY_DATA_INTEGRITY_V2: &str = r#"{
  "@context": {
    "id": "@id",
    "type": "@type",
    "@protected": true,
    "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}"#;

const WWW_W3_ORG_NS_CREDENTIALS_V2: &str = r#"{
  "@context": {
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "description": "https://schema.org/description",
    "digestMultibase": {
      "@id": "https://w3id.org/security#digestMultibase",
      "@type": "https://w3id.org/security#multibase"
    },
    "digestSRI": {
      "@id": "https://www.w3.org/2018/credentials#digestSRI",
      "@type": "https://www.w3.org/2018/credentials#sriString"
    },
    "mediaType": {
      "@id": "https://schema.org/encodingFormat"
    },
    "name": "https://schema.org/name",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "confidenceMethod": {
          "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
          "@type": "@id"
        },
        "credentialSchema": {
          "@id": "https://www.w3.org/2018/credentials#credentialSchema",
          "@type": "@id"
        },
        "credentialStatus": {
          "@id": "https://www.w3.org/2018/credentials#credentialStatus",
          "@type": "@id"
        },
        "credentialSubject": {
          "@id": "https://www.w3.org/2018/credentials#credentialSubject",
          "@type": "@id"
        },
        "description": "https://schema.org/description",
        "evidence": {
          "@id": "https://www.w3.org/2018/credentials#evidence",
          "@type": "@id"
        },
        "issuer": {
          "@id": "https://www.w3.org/2018/credentials#issuer",
          "@type": "@id"
        },
        "name": "https://schema.org/name",
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "refreshService": {
          "@id": "https://www.w3.org/2018/credentials#refreshService",
          "@type": "@id"
        },
        "relatedResource": {
          "@id": "https://www.w3.org/2018/credentials#relatedResource",
          "@type": "@id"
        },
        "renderMethod": {
          "@id": "https://www.w3.org/2018/credentials#renderMethod",
          "@type": "@id"
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        },
        "validFrom": {
          "@id": "https://www.w3.org/2018/credentials#validFrom",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "validUntil": {
          "@id": "https://www.w3.org/2018/credentials#validUntil",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        }
      }
    },

    "EnvelopedVerifiableCredential":
      "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "holder": {
          "@id": "https://www.w3.org/2018/credentials#holder",
          "@type": "@id"
        },
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        },
        "verifiableCredential": {
          "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
          "@type": "@id",
          "@container": "@graph",
          "@context": null
        }
      }
    },

    "EnvelopedVerifiablePresentation":
      "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",

    "JsonSchemaCredential":
      "https://www.w3.org/2018/credentials#JsonSchemaCredential",

    "JsonSchema": {
      "@id": "https://www.w3.org/2018/credentials#JsonSchema",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "jsonSchema": {
          "@id": "https://www.w3.org/2018/credentials#jsonSchema",
          "@type": "@json"
        }
      }
    },

    "BitstringStatusListCredential":
      "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",

    "BitstringStatusList": {
      "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "encodedList": {
          "@id": "https://www.w3.org/ns/credentials/status#encodedList",
          "@type": "https://w3id.org/security#multibase"
        },
        "statusMessage": {
          "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "message": "https://www.w3.org/ns/credentials/status#message",
            "status": "https://www.w3.org/ns/credentials/status#status"
          }
        },
        "statusPurpose":
          "https://www.w3.org/ns/credentials/status#statusPurpose",
        "statusReference": {
          "@id": "https://www.w3.org/ns/credentials/status#statusReference",
          "@type": "@id"
        },
        "statusSize": {
          "@id": "https://www.w3.org/ns/credentials/status#statusSize",
          "@type": "https://www.w3.org/2001/XMLSchema#positiveInteger"
        },
        "ttl": "https://www.w3.org/ns/credentials/status#ttl"
      }
    },

    "BitstringStatusListEntry": {
      "@id":
        "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "statusListCredential": {
          "@id":
            "https://www.w3.org/ns/credentials/status#statusListCredential",
          "@type": "@id"
        },
        "statusListIndex":
          "https://www.w3.org/ns/credentials/status#statusListIndex",
        "statusPurpose":
          "https://www.w3.org/ns/credentials/status#statusPurpose"
      }
    },

    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    },

    "...": {
      "@id": "https://www.iana.org/assignments/jwt#..."
    },
    "_sd": {
      "@id": "https://www.iana.org/assignments/jwt#_sd",
      "@type": "@json"
    },
    "_sd_alg": {
      "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
    },
    "aud": {
      "@id": "https://www.iana.org/assignments/jwt#aud",
      "@type": "@id"
    },
    "cnf": {
      "@id": "https://www.iana.org/assignments/jwt#cnf",
      "@context": {
        "@protected": true,

        "kid": {
          "@id": "https://www.iana.org/assignments/jwt#kid",
          "@type": "@id"
        },
        "jwk": {
          "@id": "https://www.iana.org/assignments/jwt#jwk",
          "@type": "@json"
        }
      }
    },
    "exp": {
      "@id": "https://www.iana.org/assignments/jwt#exp",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "iat": {
      "@id": "https://www.iana.org/assignments/jwt#iat",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "iss": {
      "@id": "https://www.iana.org/assignments/jose#iss",
      "@type": "@id"
    },
    "jku": {
      "@id": "https://www.iana.org/assignments/jose#jku",
      "@type": "@id"
    },
    "kid": {
      "@id": "https://www.iana.org/assignments/jose#kid",
      "@type": "@id"
    },
    "nbf": {
      "@id": "https://www.iana.org/assignments/jwt#nbf",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "sub": {
      "@id": "https://www.iana.org/assignments/jose#sub",
      "@type": "@id"
    },
    "x5u": {
      "@id": "https://www.iana.org/assignments/jose#x5u",
      "@type": "@id"
    }
  }
}"#;

const W3ID_ORG_CITIZENSHIP_V2: &str = r#"{
 "@context": {
    "@protected": true,

    "QuantitativeValue": {
      "@id": "https://schema.org/QuantitativeValue",
      "@context": {
        "@protected": true,

        "unitCode": "https://schema.org/unitCode",
        "value": "https://schema.org/value"
      }
    },

    "PostalAddress": {
      "@id": "https://schema.org/PostalAddress",
      "@context": {
        "@protected": true,

        "addressCountry": "https://schema.org/addressCountry",
        "addressLocality": "https://schema.org/addressLocality",
        "addressRegion": "https://schema.org/addressRegion"
      }
    },

    "Person": {
      "@id": "https://schema.org/Person",

      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "additionalName": "https://schema.org/additionalName",
        "birthCountry": "https://w3id.org/citizenship#birthCountry",
        "birthDate": {"@id": "https://schema.org/birthDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
        "familyName": "https://schema.org/familyName",
        "gender": "https://schema.org/gender",
        "givenName": "https://schema.org/givenName",
        "height": "https://schema.org/height",
        "image": {"@id": "https://schema.org/image", "@type": "@id"},
        "maritalStatus": "https://w3id.org/citizenship#maritalStatus",
        "marriageCertificateNumber": "https://w3id.org/citizenship#marriageCertificateNumber",
        "marriageLocation": {"@id": "https://w3id.org/citizenship#marriageLocation", "@type": "@id"}
      }
    },

    "PermanentResident": {
      "@id": "https://w3id.org/citizenship#PermanentResident",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "commuterClassification": "https://w3id.org/citizenship#commuterClassification",
        "formerNationality": "https://w3id.org/citizenship#formerNationality",
        "permanentResidentCard": {"@id": "https://w3id.org/citizenship#permanentResidentCard", "@type": "@id"},
        "residence": {"@id": "https://w3id.org/citizenship#residence", "@type": "@id"},
        "residentSince": {"@id": "https://w3id.org/citizenship#residentSince", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
      }
    },

    "PermanentResidentCard": {
      "@id": "https://w3id.org/citizenship#PermanentResidentCard",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
        "identifier": "https://schema.org/identifier",
        "lprCategory": "https://w3id.org/citizenship#lprCategory",
        "lprNumber": "https://w3id.org/citizenship#lprNumber",
        "mrzHash": {
          "@id": "https://w3id.org/citizenship#mrzHash",
          "@type": "https://w3id.org/security#multibase"
        }
      }
    },

    "PermanentResidentCardCredential": "https://w3id.org/citizenship#PermanentResidentCardCredential",

    "EmployablePerson": {
      "@id": "https://w3id.org/citizenship#EmployablePerson",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "commuterClassification": "https://w3id.org/citizenship#commuterClassification",
        "employmentAuthorizationDocument": {"@id": "https://w3id.org/citizenship#employmentAuthorizationDocument", "@type": "@id"},
        "formerNationality": "https://w3id.org/citizenship#formerNationality",
        "residence": {"@id": "https://w3id.org/citizenship#residence", "@type": "@id"},
        "residentSince": {"@id": "https://w3id.org/citizenship#residentSince", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
      }
    },

    "EmploymentAuthorizationDocument": {
      "@id": "https://w3id.org/citizenship#EmploymentAuthorizationDocument",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
        "identifier": "https://schema.org/identifier",
        "lprCategory": "https://w3id.org/citizenship#lprCategory",
        "lprNumber": "https://w3id.org/citizenship#lprNumber",
        "mrzHash": {
          "@id": "https://w3id.org/citizenship#mrzHash",
          "@type": "https://w3id.org/security#multibase"
        }
      }
    },

    "EmploymentAuthorizationDocumentCredential": "https://w3id.org/citizenship#EmploymentAuthorizationDocumentCredential",

    "NaturalizedPerson": {
      "@id": "https://w3id.org/citizenship#NaturalizedPerson",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "formerNationality": "https://w3id.org/citizenship#formerNationality",
        "certificateOfNaturalization": {"@id": "https://w3id.org/citizenship#certificateOfNaturalization", "@type": "@id"},
        "residence": {"@id": "https://w3id.org/citizenship#residence", "@type": "@id"},
        "residentSince": {"@id": "https://w3id.org/citizenship#residentSince", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
        "commuterClassification": "https://w3id.org/citizenship#commuterClassification"
      }
    },

    "CertificateOfNaturalization": {
      "@id": "https://w3id.org/citizenship#CertificateOfNaturalization",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "ceremonyDate": {"@id": "https://w3id.org/citizenship#ceremonyDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
        "ceremonyLocation": {"@id": "https://w3id.org/citizenship#ceremonyLocation", "@type": "@id"},
        "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
        "naturalizationLocation": {"@id": "https://w3id.org/citizenship#naturalizationLocation", "@type": "@id"},
        "naturalizedBy": "https://w3id.org/citizenship#naturalizedBy",
        "identifier": "https://schema.org/identifier",
        "insRegistrationNumber": "https://w3id.org/citizenship#insRegistrationNumber"
      }
    },

    "CertificateOfNaturalizationCredential": "https://w3id.org/citizenship#CertificateOfNaturalizationCredential",

    "Citizen": {
      "@id": "https://w3id.org/citizenship#Citizen",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "certificateOfCitizenship": {"@id": "https://w3id.org/citizenship#certificateOfCitizenship", "@type": "@id"}
      }
    },

    "CertificateOfCitizenship": {
      "@id": "https://w3id.org/citizenship#CertificateOfCitizenship",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "filingLocation": {"@id": "https://w3id.org/citizenship#filingLocation", "@type": "@id"},
        "identifier": "https://schema.org/identifier",
        "ceremonyDate": {"@id": "https://w3id.org/citizenship#ceremonyDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
        "ceremonyLocation": {"@id": "https://w3id.org/citizenship#ceremonyLocation", "@type": "@id"},
        "cisRegistrationNumber": "https://w3id.org/citizenship#cisRegistrationNumber"
      }
    },

    "CertificateOfCitizenshipCredential": "https://w3id.org/citizenship#CertificateOfCitizenshipCredential",
    "OpticalBarcodeCredential": "https://w3id.org/citizenship#OpticalBarcodeCredential",
    "TerseBitstringStatusListEntry": {
      "@id":
        "https://w3id.org/citizenship#TerseBitstringStatusListEntry",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "terseStatusListBaseUrl": {
          "@type": "@id",
          "@id": "https://w3id.org/citizenship#terseStatusListBaseUrl"
        },
        "terseStatusListIndex":
          "https://w3id.org/citizenship#terseStatusListIndex"
      }
    }
  }
}"#;
