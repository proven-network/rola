use radix_common::crypto::PublicKey;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub enum Curve {
    Curve25519,
    Secp256k1,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub enum Type {
    Account,
    Persona,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Proof {
    pub curve: Curve,
    pub public_key: PublicKey,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignedChallenge {
    pub address: String,
    pub challenge: String,
    pub proof: Proof,
    pub r#type: Type,
}
