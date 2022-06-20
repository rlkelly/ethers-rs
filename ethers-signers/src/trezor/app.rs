#![allow(unused)]
use trezor_client::client::{AccessListItem as Trezor_AccessListItem, Trezor};

use futures_executor::block_on;
use futures_util::lock::Mutex;

use ethers_core::{
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, NameOrAddress, Signature, Transaction, TransactionRequest, TxHash, H256, U256,
    },
    utils::keccak256,
};
use home;
use std::{
    convert::TryFrom,
    env, fs,
    io::{Read, Write},
    path,
    path::PathBuf,
};
use thiserror::Error;

use super::types::*;

/// A Trezor Ethereum App.
///
/// This is a simple wrapper around the [Trezor transport](Trezor)
#[derive(Debug)]
pub struct TrezorEthereum {
    derivation: DerivationType,
    session_id: Vec<u8>,
    cache_dir: PathBuf,
    pub(crate) chain_id: u64,
    pub(crate) address: Address,
}

const FIRMWARE_MIN_VERSION: &str = ">=2.4.2";

// https://docs.trezor.io/trezor-firmware/common/communication/sessions.html
const SESSION_ID_LENGTH: usize = 32;
const SESSION_FILE_NAME: &str = "trezor.session";

impl TrezorEthereum {
    pub async fn new(
        derivation: DerivationType,
        chain_id: u64,
        cache_dir: Option<PathBuf>,
    ) -> Result<Self, TrezorError> {
        let cache_dir = (match cache_dir.or_else(home::home_dir) {
            Some(path) => path,
            None => match env::current_dir() {
                Ok(path) => path,
                Err(e) => return Err(TrezorError::CacheError(e.to_string())),
            },
        })
        .join(".ethers-rs")
        .join("trezor")
        .join("cache");

        let mut blank = Self {
            derivation: derivation.clone(),
            chain_id,
            cache_dir,
            address: Address::from([0_u8; 20]),
            session_id: vec![],
        };

        // Check if reachable
        blank.initate_session()?;
        blank.address = blank.get_address_with_path(&derivation).await?;
        Ok(blank)
    }

    fn check_version(version: String) -> Result<(), TrezorError> {
        let req = semver::VersionReq::parse(FIRMWARE_MIN_VERSION)?;
        let version = semver::Version::parse(&version)?;

        // Enforce firmware version is greater than FIRMWARE_MIN_VERSION
        if !req.matches(&version) {
            return Err(TrezorError::UnsupportedFirmwareVersion(FIRMWARE_MIN_VERSION.to_string()))
        }

        Ok(())
    }

    fn get_cached_session(&self) -> Result<Option<Vec<u8>>, TrezorError> {
        let mut session = [0; SESSION_ID_LENGTH];

        if let Ok(mut file) = fs::File::open(self.cache_dir.join(SESSION_FILE_NAME)) {
            file.read_exact(&mut session).map_err(|e| TrezorError::CacheError(e.to_string()))?;
            Ok(Some(session.to_vec()))
        } else {
            Ok(None)
        }
    }

    fn save_session(&mut self, session_id: Vec<u8>) -> Result<(), TrezorError> {
        fs::create_dir_all(&self.cache_dir).map_err(|e| TrezorError::CacheError(e.to_string()))?;

        let mut file = fs::File::create(self.cache_dir.join(SESSION_FILE_NAME))
            .map_err(|e| TrezorError::CacheError(e.to_string()))?;

        file.write_all(&session_id).map_err(|e| TrezorError::CacheError(e.to_string()))?;

        self.session_id = session_id;
        Ok(())
    }

    fn initate_session(&mut self) -> Result<(), TrezorError> {
        let mut client = trezor_client::unique(false)?;
        client.init_device(self.get_cached_session()?)?;

        let features = client.features().ok_or(TrezorError::FeaturesError)?;

        Self::check_version(format!(
            "{}.{}.{}",
            features.get_major_version(),
            features.get_minor_version(),
            features.get_patch_version()
        ))?;

        self.save_session(features.get_session_id().to_vec())?;

        Ok(())
    }

    /// You need to drop(client) once you're done with it
    fn get_client(&self, session_id: Vec<u8>) -> Result<Trezor, TrezorError> {
        let mut client = trezor_client::unique(false)?;
        client.init_device(Some(session_id))?;
        Ok(client)
    }

    /// Get the account which corresponds to our derivation path
    pub async fn get_address(&self) -> Result<Address, TrezorError> {
        self.get_address_with_path(&self.derivation).await
    }

    /// Gets the account which corresponds to the provided derivation path
    pub async fn get_address_with_path(
        &self,
        derivation: &DerivationType,
    ) -> Result<Address, TrezorError> {
        let mut client = self.get_client(self.session_id.clone())?;

        let address_str = client.ethereum_get_address(Self::convert_path(derivation))?;

        let mut address = [0; 20];
        address.copy_from_slice(&hex::decode(&address_str[2..])?);

        Ok(Address::from(address))
    }

    /// Signs an Ethereum transaction (requires confirmation on the Trezor)
    pub async fn sign_tx(&self, tx: &TypedTransaction) -> Result<Signature, TrezorError> {
        let mut client = self.get_client(self.session_id.clone())?;

        let arr_path = Self::convert_path(&self.derivation);

        let transaction = TrezorTransaction::load(tx)?;

        let chain_id = tx.chain_id().map(|id| id.as_u64()).unwrap_or(self.chain_id);

        let signature = match tx {
            TypedTransaction::Eip2930(_) | TypedTransaction::Legacy(_) => client.ethereum_sign_tx(
                arr_path,
                transaction.nonce,
                transaction.gas_price,
                transaction.gas,
                transaction.to,
                transaction.value,
                transaction.data,
                chain_id,
            )?,
            TypedTransaction::Eip1559(eip1559_tx) => client.ethereum_sign_eip1559_tx(
                arr_path,
                transaction.nonce,
                transaction.gas,
                transaction.to,
                transaction.value,
                transaction.data,
                chain_id,
                transaction.max_fee_per_gas,
                transaction.max_priority_fee_per_gas,
                transaction.access_list,
            )?,
        };

        Ok(Signature { r: signature.r, s: signature.s, v: signature.v })
    }

    /// Signs an ethereum personal message
    pub async fn sign_message<S: AsRef<[u8]>>(&self, message: S) -> Result<Signature, TrezorError> {
        let message = message.as_ref();
        let mut client = self.get_client(self.session_id.clone())?;
        let apath = Self::convert_path(&self.derivation);

        let signature = client.ethereum_sign_message(message.into(), apath)?;

        Ok(Signature { r: signature.r, s: signature.s, v: signature.v })
    }

    /// Signs an EIP712 encoded domain separator and message
    pub async fn sign_typed_struct<T>(&self, payload: &T) -> Result<Signature, TrezorError>
    where
        T: Eip712,
    {
        unimplemented!()
    }

    // helper which converts a derivation path to [u32]
    fn convert_path(derivation: &DerivationType) -> Vec<u32> {
        let derivation = derivation.to_string();
        let elements = derivation.split('/').skip(1).collect::<Vec<_>>();
        let depth = elements.len();

        let mut path = vec![];
        for derivation_index in elements {
            let hardened = derivation_index.contains('\'');
            let mut index = derivation_index.replace('\'', "").parse::<u32>().unwrap();
            if hardened {
                index |= 0x80000000;
            }
            path.push(index);
        }

        path
    }
}
