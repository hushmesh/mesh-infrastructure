use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use zkryptium::bbsplus::ciphersuites::BbsCiphersuite;
use zkryptium::bbsplus::keys::BBSplusPublicKey;
use zkryptium::bbsplus::keys::BBSplusSecretKey;
use zkryptium::schemes::algorithms::BBSplus;
use zkryptium::schemes::algorithms::Ciphersuite;
use zkryptium::schemes::generics::Signature;

use crate::mesh_generate_id;
use crate::HmcDataType;
use crate::Sha256Writer;

pub fn bbs_generate_key_pair() -> ([u8; 32], [u8; 96]) {
    let rand = mesh_generate_id(64, HmcDataType::Raw).unwrap();
    let rand_bytes: &[u8; 64] = rand.as_slice().try_into().unwrap();

    let private = bls12_381_plus::Scalar::from_bytes_wide(rand_bytes);
    let public = bls12_381_plus::G2Affine::from(bls12_381_plus::G2Projective::GENERATOR * private);
    (private.to_be_bytes(), public.to_compressed())
}

#[derive(PartialEq, Eq)]
struct Bls12381Sha256;

// This is a copy of zkryptium's Bls12381Sha256, but with an Expander that uses our sha256 method.
impl BbsCiphersuite for Bls12381Sha256 {
    const ID: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const API_ID: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

    const MOCKED_SCALAR_DST: &[u8] =
        b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_";
    const API_ID_BLIND: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_";
    const COMMIT_DST: &[u8] =
        b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_";
    const BLIND_PROOF_DST: &[u8] =
        b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_";
    const GENERATOR_SIG_DST: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_DET_DST_";
    type Expander = elliptic_curve::hash2curve::ExpandMsgXmd<Sha256>;

    const P1: &str = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";
}

impl Ciphersuite for Bls12381Sha256 {
    type HashAlg = Sha256;
}

struct Sha256(Sha256Writer);

impl digest::HashMarker for Sha256 {}

impl digest::Update for Sha256 {
    fn update(&mut self, data: &[u8]) {
        self.0.write(data).unwrap()
    }
}

impl digest::core_api::BlockSizeUser for Sha256 {
    type BlockSize = digest::consts::U64;
}

impl digest::OutputSizeUser for Sha256 {
    type OutputSize = digest::consts::U32;
}

impl Default for Sha256 {
    fn default() -> Self {
        Self(Sha256Writer::new().unwrap())
    }
}

impl digest::FixedOutput for Sha256 {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let res: &mut [u8; 32] = out.as_mut_slice().try_into().unwrap();
        *res = self.0.finalize().unwrap();
    }

    fn finalize_fixed(self) -> digest::Output<Self> {
        self.0.finalize().unwrap().try_into().unwrap()
    }
}

pub fn bbs_sign(
    secret: &[u8; 32],
    public: &[u8; 96],
    bbs_header: &[u8; 64],
    messages: Option<&[Vec<u8>]>,
) -> Result<[u8; 80], String> {
    let sk = BBSplusSecretKey::from_bytes(secret).map_err(|e| e.to_string())?;
    let pk = BBSplusPublicKey::from_bytes(public).map_err(|e| e.to_string())?;
    let header = Some(bbs_header as &[u8]);

    match Signature::<BBSplus<Bls12381Sha256>>::sign(messages, &sk, &pk, header) {
        Ok(s) => Ok(s.to_bytes()),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_round_trip() {
        let (secret_bytes, public_bytes) = bbs_generate_key_pair();

        let key = BBSplusSecretKey::from_bytes(&secret_bytes).unwrap();
        assert_eq!(secret_bytes, key.to_bytes());

        let public = BBSplusPublicKey::from_bytes(&public_bytes).unwrap();
        assert_eq!(public_bytes, public.to_bytes());
    }

    #[test]
    fn signature() {
        use common_types::hex_array;

        const MESSAGES: &[&str] = &[
            "_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
        ];

        const HEADER: [u8; 64] = hex_array("3a5bbf25d34d90b18c35cd2357be6a6f42301e94fc9e52f77e93b773c5614bdf555de05f898817e31301bac187d0c3ff2b03e2cbdb4adb4d568c17de961f9a18");
        const PRIVATE: [u8; 32] =
            hex_array("66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0");
        const PUBLIC: [u8; 96] = hex_array("a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f");

        let messages = MESSAGES
            .into_iter()
            .map(|&s| Vec::from(s))
            .collect::<Vec<_>>();

        const EXPECTED: [u8; 80] = hex_array("8331f55ad458fe5c322420b2cb806f9a20ea6b2b8a29d51710026d71ace5da080064b488818efc75a439525bd031450822a6a332da781926e19360b90166431124efcf3d060fbc750c6122c714c07f71");

        let result = bbs_sign(&PRIVATE, &PUBLIC, &HEADER, Some(messages.as_slice())).unwrap();
        assert_eq!(result, EXPECTED);
    }
}
