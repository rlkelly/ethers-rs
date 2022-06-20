//! Specific helper functions for loading an offline K256 Private Key stored on disk
use super::Wallet;

use crate::wallet::mnemonic::MnemonicBuilderError;
use coins_bip32::Bip32Error;
use coins_bip39::MnemonicError;
#[cfg(not(target_arch = "wasm32"))]
use elliptic_curve::rand_core;
#[cfg(not(target_arch = "wasm32"))]
use eth_keystore::KeystoreError;
use ethers_core::{
    k256::ecdsa::{self, SigningKey},
    rand::{CryptoRng, Rng},
    utils::secret_key_to_address,
};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
/// Error thrown by the Wallet module
pub enum WalletError {
    /// Error propagated from the BIP-32 crate
    #[error(transparent)]
    Bip32Error(#[from] Bip32Error),
    /// Error propagated from the BIP-39 crate
    #[error(transparent)]
    Bip39Error(#[from] MnemonicError),
    /// Underlying eth keystore error
    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    EthKeystoreError(#[from] KeystoreError),
    /// Error propagated from k256's ECDSA module
    #[error(transparent)]
    EcdsaError(#[from] ecdsa::Error),
    /// Error propagated from the hex crate.
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    /// Error propagated by IO operations
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Error propagated from the mnemonic builder module.
    #[error(transparent)]
    MnemonicBuilderError(#[from] MnemonicBuilderError),
    /// Error type from Eip712Error message
    #[error("error encoding eip712 struct: {0:?}")]
    Eip712Error(String),
}

impl Clone for Wallet<SigningKey> {
    fn clone(&self) -> Self {
        Self {
            // TODO: Can we have a better way to clone here?
            signer: SigningKey::from_bytes(&*self.signer.to_bytes()).unwrap(),
            address: self.address,
            chain_id: self.chain_id,
        }
    }
}

impl Wallet<SigningKey> {
    /// Creates a new random encrypted JSON with the provided password and stores it in the
    /// provided directory. Returns a tuple (Wallet, String) of the wallet instance for the
    /// keystore with its random UUID. Accepts an optional name for the keystore file. If `None`,
    /// the keystore is stored as the stringified UUID.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_keystore<P, R, S>(
        dir: P,
        rng: &mut R,
        password: S,
        name: Option<&str>,
    ) -> Result<(Self, String), WalletError>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng + rand_core::CryptoRng,
        S: AsRef<[u8]>,
    {
        let (secret, uuid) = eth_keystore::new(dir, rng, password, name)?;
        let signer = SigningKey::from_bytes(secret.as_slice())?;
        let address = secret_key_to_address(&signer);
        Ok((Self { signer, address, chain_id: 1 }, uuid))
    }

    /// Decrypts an encrypted JSON from the provided path to construct a Wallet instance
    #[cfg(not(target_arch = "wasm32"))]
    pub fn decrypt_keystore<P, S>(keypath: P, password: S) -> Result<Self, WalletError>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let secret = eth_keystore::decrypt_key(keypath, password)?;
        let signer = SigningKey::from_bytes(secret.as_slice())?;
        let address = secret_key_to_address(&signer);
        Ok(Self { signer, address, chain_id: 1 })
    }

    /// Creates a new random keypair seeded with the provided RNG
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let signer = SigningKey::random(rng);
        let address = secret_key_to_address(&signer);
        Self { signer, address, chain_id: 1 }
    }
}

impl PartialEq for Wallet<SigningKey> {
    fn eq(&self, other: &Self) -> bool {
        self.signer.to_bytes().eq(&other.signer.to_bytes()) &&
            self.address == other.address &&
            self.chain_id == other.chain_id
    }
}

impl From<SigningKey> for Wallet<SigningKey> {
    fn from(signer: SigningKey) -> Self {
        let address = secret_key_to_address(&signer);

        Self { signer, address, chain_id: 1 }
    }
}

use ethers_core::k256::SecretKey as K256SecretKey;

impl From<K256SecretKey> for Wallet<SigningKey> {
    fn from(key: K256SecretKey) -> Self {
        let signer = key.into();
        let address = secret_key_to_address(&signer);

        Self { signer, address, chain_id: 1 }
    }
}

impl FromStr for Wallet<SigningKey> {
    type Err = WalletError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let src = hex::decode(src)?;
        let sk = SigningKey::from_bytes(&src)?;
        Ok(sk.into())
    }
}
