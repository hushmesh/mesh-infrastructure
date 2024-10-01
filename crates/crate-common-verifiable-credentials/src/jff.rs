use alloc::collections::BTreeMap;

use json_ld::syntax::Parse;
use json_ld::syntax::Value;
use json_ld::IriBuf;
use json_ld::RemoteDocument;

pub(crate) fn new_jff_loader() -> BTreeMap<IriBuf, RemoteDocument> {
    let mut map = BTreeMap::new();

    let iri = IriBuf::new("https://www.w3.org/2018/credentials/v1".to_string()).unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(WWW_W3_ORG_CREDENTIALS_V1).unwrap().0,
        ),
    );

    let iri = IriBuf::new(
        "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json"
            .to_string(),
    )
    .unwrap();
    map.insert(
        iri.clone(),
        RemoteDocument::new(
            Some(iri),
            Some("application/ld+json".parse().unwrap()),
            Value::parse_str(PLUGFEST).unwrap().0,
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

const WWW_W3_ORG_CREDENTIALS_V1: &str = r#"{
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
}
"#;

const PLUGFEST: &str = r#"{
  "@context": {
    "id": "@id",
    "type": "@type",

    "xsd": "https://www.w3.org/2001/XMLSchema#",

    "OpenBadgeCredential": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential"
    },
    "Achievement": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Achievement",
      "@context": {
        "achievementType": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#achievementType",
          "@type": "xsd:string"
        },
        "alignment": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Alignment"
        },
        "creator": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Profile"
        },
        "creditsAvailable": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#creditsAvailable",
          "@type": "xsd:float"
        },
        "criteria": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#criteria", 
          "@type": "@id"
        },
        "fieldOfStudy": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#fieldOfStudy", 
          "@type": "xsd:string"
        },
        "humanCode": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#humanCode", 
          "@type": "xsd:string"
        },
        "specialization": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#specialization", 
          "@type": "xsd:string"
        },
        "tags": {
          "@id": "https://schema.org/keywords", 
          "@type": "xsd:string", 
          "@container": "@set"
        }
      }
    },
    "AchievementCredential": {
      "@id": "OpenBadgeCredential"
    },
    "AchievementSubject": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#AchievementSubject",
      "@context": {
        "achievement": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Achievement"
        },
        "identifier": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Identifier"
        },
        "result": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Result"
        }
      }
    },
    "Address": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Address",
      "@context": {
        "addressCountry": {
          "@id": "https://schema.org/addressCountry", 
          "@type": "xsd:string"
        },
        "addressCountryCode": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#CountryCode", 
          "@type": "xsd:string"
        },
        "addressLocality": {
          "@id": "https://schema.org/addresLocality", 
          "@type": "xsd:string"
        },
        "addressRegion": {
          "@id": "https://schema.org/addressRegion", 
          "@type": "xsd:string"
        },
        "geo": {
          "@id" : "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#GeoCoordinates"
        },
        "postOfficeBoxNumber": {
          "@id": "https://schema.org/postOfficeBoxNumber", 
          "@type": "xsd:string"
        },
        "postalCode": {
          "@id": "https://schema.org/postalCode", 
          "@type": "xsd:string"
        },
        "streetAddress": {
          "@id": "https://schema.org/streetAddress", 
          "@type": "xsd:string"
        }
      }
    },
    "Alignment": {
      "@id": "https://schema.org/Alignment",
      "@context": {
        "targetCode": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#targetCode", 
          "@type": "xsd:string"
        },
        "targetDescription": {
          "@id": "https://schema.org/targetDescription", 
          "@type": "xsd:string"
        },
        "targetFramework": {
          "@id": "https://schema.org/targetFramework", 
          "@type": "xsd:string"
        },
        "targetName": {
          "@id": "https://schema.org/targetName", 
          "@type": "xsd:string"
        }, 
        "targetType": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#targetType",
          "@type": "xsd:string"
        },     
        "targetUrl": {
          "@id": "https://schema.org/targetUrl",
          "@type": "xsd:anyURI"
        }
      }
    },
    "Criteria": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Criteria"
    },
    "EndorsementCredential": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#EndorsementCredential"
    },
    "EndorsementSubject": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#EndorsementSubject",
      "@context": {
        "endorsementComment": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#endorsementComment", 
          "@type": "xsd:string"
        }
      }
    },
    "Evidence": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Evidence",
      "@context": {
        "audience": {
          "@id": "https://schema.org/audience", 
          "@type": "xsd:string"
        },
        "genre": {
          "@id": "https://schema.org/genre",
          "@type": "xsd:string"
        }
      }
    },
    "GeoCoordinates": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#GeoCoordinates",
      "@context": {
        "latitude": {
          "@id": "https://schema.org/latitude", 
          "@type": "xsd:string"
        },
        "longitude": {
          "@id": "https://schema.org/longitude", 
          "@type": "xsd:string"
        }
      }
    },
    "IdentityObject": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#IdentityObject",
      "@context": {
        "hashed": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#hashed", 
          "@type": "xsd:boolean"
        },
        "identityHash": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#identityHash", 
          "@type": "xsd:string"
        },
        "salt":  {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#salt", 
          "@type": "xsd:string"
        }
      }
    },
    "Image": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#IdentityImage",
      "@context": {
        "caption": {
          "@id": "https://schema.org/caption",
          "@type": "xsd:string"
        }
      }
    },
    "Profile": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Profile",
      "@context": {
        "additionalName": {
          "@id": "https://schema.org/additionalName",
          "@type": "xsd:string"
        },
        "address": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Address"
        },
        "dateOfBirth": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#dateOfBirth",
          "@type": "xsd:date"
        },
        "email": {
          "@id": "https://schema.org/email", 
          "@type": "xsd:string"
        },
        "familyName": {
          "@id": "https://schema.org/familyName",
          "@type": "xsd:string"
        },
        "familyNamePrefix": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#familyNamePrefix",
          "@type": "xsd:string"
        },
        "givenName": {
          "@id": "https://schema.org/givenName",
          "@type": "xsd:string"
        },
        "honorificPrefix": {
          "@id": "https://schema.org/honorificPrefix",
          "@type": "xsd:string"
        },
        "honorificSuffix": {
          "@id": "https://schema.org/honorificSuffix",
          "@type": "xsd:string"
        },
        "parentOrg": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#parentOrg",
          "@type": "xsd:string"
        },
        "patronymicName": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#patronymicName",
          "@type": "xsd:string"
        },
        "phone": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#PhoneNumber", 
          "@type": "xsd:string"
        },
        "official": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#official",
          "@type": "xsd:string"
        },
        "sisSourcedId": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#sisSourcedId",
          "@type": "xsd:string"
        },
        "sourcedId": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#sourcedId",
          "@type": "xsd:string"
        }
      }
    },
    "Result": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Result",
      "@context": {
        "achievedLevel": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#achievedLevel", 
          "@type": "xsd:anyURI"
        },
        "resultDescription": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#resultDescription",
          "@type": "xsd:anyURI"
        },
        "status": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#status", 
          "@type": "xsd:string"
        },
        "value": {
          "@id": "https://schema.org/value", 
          "@type": "xsd:string"
        }
      }
    },
    "ResultDescription": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#ResultDescription",
      "@context": {
        "allowedValue": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#allowedValue", 
          "@type": "xsd:string"
        },
        "requiredLevel": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#requiredLevel", 
          "@type": "xsd:anyURI"
        },
        "requiredValue": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#requiredValue", 
          "@type": "xsd:string"
        },
        "resultType": {
          "@id":"https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#resultType",  
          "@type": "xsd:string"
        },
        "rubricCriterionLevel": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#RubricCriterionLevel",
        "valueMax": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#valueMax", 
          "@type": "xsd:string"
        },
        "valueMin": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#valueMin", 
          "@type": "xsd:string"
        }              
      }
    },
    "RubricCriterionLevel": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#RubricCriterionLevel",
      "@context": {
        "level": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#level", 
          "@type": "xsd:string"
        },
        "points": {
          "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#points", 
          "@type": "xsd:string"
        }
      }
    },
    "alignment": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#Alignment", 
      "@type": "@id"
    },    
    "description": {
      "@id": "https://schema.org/description", 
      "@type": "xsd:string"
    },
    "endorsement": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#endorsement", 
      "@type": "@id"
    },
    "image": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#image", 
      "@type": "@id"
    },
    "name": {
      "@id": "https://schema.org/name", 
      "@type": "xsd:string"
    },
    "narrative": {
      "@id": "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#narrative", 
      "@type": "xsd:string"
    },
    "url": {
      "@id": "https://schema.org/url", 
      "@type": "xsd:anyURI"
    }
  }
}
"#;

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
