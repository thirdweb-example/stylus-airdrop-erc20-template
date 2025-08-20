//! this contract is not audited

#![cfg_attr(not(any(feature = "export-abi", test)), no_main)]
extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{b256, U64};
use alloy_sol_types::{sol, SolType};
use stylus_sdk::{
    alloy_primitives::{Address, B256, U256}, call::RawCall, crypto, prelude::*
};

// Compact error handling
#[derive(SolidityError)]
pub enum AirdropErrors {
    AirdropError(AirdropError),
}

// Error codes for compact error handling
pub const ERROR_LENGTH_MISMATCH: u8 = 1;
pub const ERROR_NO_MERKLE_ROOT: u8 = 2;
pub const ERROR_INVALID_PROOF: u8 = 3;
pub const ERROR_ALREADY_CLAIMED: u8 = 4;
pub const ERROR_REQUEST_EXPIRED: u8 = 5;
pub const ERROR_UID_ALREADY_USED: u8 = 6;
pub const ERROR_INVALID_SIGNATURE: u8 = 7;
pub const ERROR_NOT_OWNER: u8 = 8;

sol_interface! {
    interface IERC20 {
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }
}

sol! {

    struct AirdropContentERC20 {
        address recipient;
        uint256 amount;
    }

    struct AirdropRequestERC20 {
        bytes32 uid;
        address tokenAddress;
        uint256 expirationTimestamp;
        AirdropContentERC20[] contents;
    }

    // Compact error codes
    error AirdropError(uint8 code);
}

sol_storage! {
    #[entrypoint]
    pub struct StylusAirdropERC20 {
        address owner;

        mapping(address => uint64) tokenConditionId;
        mapping(address => bytes32) tokenMerkleRoot;
        mapping(bytes32 => bool) claimed; 

        mapping(bytes32  => bool) processed; 
    }
}

// keccak256("AirdropContentERC20(address recipient,uint256 amount)")
const CONTENT_TYPEHASH_ERC20:  B256 =
b256!("f6c72d100e33735bf51e80c28612aa8502ae41efe0a50e53461ab22ae8aa6def");

// keccak256("AirdropRequestERC20(bytes32 uid,address tokenAddress,uint256 expirationTimestamp,AirdropContentERC20[] contents)AirdropContentERC20(address recipient,uint256 amount)")
const REQUEST_TYPEHASH_ERC20:  B256 =
 b256!("32847426538f79017eb3c162a7d70952a635f4a2b0cf164b45d6399e76e2b4d3");

const EIP712_DOMAIN_TYPEHASH: B256 =
 b256!("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");

#[public]
impl StylusAirdropERC20 {
    #[constructor]
    pub fn constructor(&mut self, owner: Address) {
        let _ = self.owner.set(owner);
    }

    #[payable]
    pub fn airdrop(
        &mut self,
        token:      Address,
        recipients: Vec<Address>,
        amounts:    Vec<U256>,
    ) -> Result<(), AirdropErrors> {
        if recipients.len() != amounts.len() {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_LENGTH_MISMATCH }));
        }

        let erc20 = IERC20::from(token);
        let sender = self.vm().msg_sender();

        for i in 0..recipients.len() {
            let config = Call::new_mutating(self);
            erc20
                .transfer_from(self.vm(), config, sender, recipients[i], amounts[i])
                .expect("fail");
        }

        // TODO: emit log
        Ok(())
    }

    #[payable]
    pub fn claim(
        &mut self,
        token:   Address,
        amount:  U256,
        proofs:  Vec<B256>,
    ) -> Result<(), AirdropErrors> {
        let receiver = self.vm().msg_sender();

        // 1. root must exist
        let root = self.tokenMerkleRoot.get(token);
        if root == B256::ZERO {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_NO_MERKLE_ROOT }));
        }

        // 2. validate proof of (receiver, amount)
        let leaf = crypto::keccak(&(encode_pair(receiver, amount)));
        if !verify_proof(&proofs, root, leaf) {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_INVALID_PROOF }));
        }

        // 3. check claim not already used
        let round  = self.tokenConditionId.get(token);
        let round_u64: u64 = round.to::<u64>();
        let key    = crypto::keccak(&encode_claim_key(round_u64, receiver, token));
        if self.claimed.get(key) {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_ALREADY_CLAIMED }));
        }
        self.claimed.insert(key, true);

        // 4. transfer
        let erc20 = IERC20::from(token);
        let config = Call::new_mutating(self);
        let owner = self.owner.get();
        erc20
            .transfer_from(self.vm(), config, owner, receiver, amount)
            .expect("fail");

        // TODO: event
        Ok(())
    }

    #[payable]
    pub fn airdrop_erc20_with_sig(
        &mut self,
        req_raw: Vec<u8>,
        sig: [u8; 65],
    ) -> Result<(), AirdropErrors> {
        // 1. decode req from raw bytes
        let req_tuple: <AirdropRequestERC20 as SolType>::RustType = <AirdropRequestERC20 as SolType>::abi_decode(&req_raw)
        .unwrap();

        let req = AirdropRequestERC20 {
            uid:                 req_tuple.uid,
            tokenAddress:        req_tuple.tokenAddress,
            expirationTimestamp: req_tuple.expirationTimestamp,
            contents:            req_tuple.contents,
        };

        // 2. checks
        let expiry = req.expirationTimestamp; 
        let now = U256::from(self.vm().block_timestamp());
        if now > expiry {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_REQUEST_EXPIRED }));
        }

        let uid_used = self.processed.get(req.uid);
        if uid_used {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_UID_ALREADY_USED }));
        }

        let owner = self.owner.get();
        if !self.is_valid_sig(&req, &sig, owner) {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_INVALID_SIGNATURE }));
        }

        // 3. mark uid as processed
        self.processed.insert(req.uid, true);

        // 4. transfer
        let erc20 = IERC20::from(req.tokenAddress);

        for c in &req.contents {
            let config = Call::new_mutating(self);
            erc20
                .transfer_from(self.vm(), config, owner, c.recipient, c.amount)
                .expect("fail"); // transfer failed
        }

        // TODO: emit log
        Ok(())
    }

    pub fn set_merkle_root(
        &mut self,
        token: Address,
        root:  B256,
        reset: bool,
    ) -> Result<(), AirdropErrors> {
        self.only_owner();

        if reset || self.tokenConditionId.get(token) == U64::from(0) {
            let next = self.tokenConditionId.get(token) + U64::from(1u8);
            self.tokenConditionId.insert(token, next);
        }

        self.tokenMerkleRoot.insert(token, root);
        
        // TODO: emit log
        Ok(())
    }

    pub fn owner_addr(&self) -> Address { self.owner.get() }

    pub fn domain_separator(&self) -> B256 {
        let name_hash    = crypto::keccak(b"Airdrop");
        let version_hash = crypto::keccak(b"1");
        let chain_bytes: [u8; 32] = U256::from(self.vm().chain_id()).to_be_bytes::<32>();
        let verifying_word: [u8; 32] = address_word(&self.vm().contract_address());

        crypto::keccak(&[
            &EIP712_DOMAIN_TYPEHASH[..],
            &name_hash[..],
            &version_hash[..],
            &chain_bytes[..],
            &verifying_word[..],
        ].concat())
    }
}

impl StylusAirdropERC20 {
    #[inline(always)]
    fn only_owner(&self) -> Result<(), AirdropErrors> {
        if self.vm().msg_sender() != self.owner.get() {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_NOT_OWNER }));
        }

        Ok(())
    }

    fn is_valid_sig(&self, req: &AirdropRequestERC20, sig: &[u8; 65], owner: Address) -> bool {
        let content_hash = hash_content(&req.contents);
        let struct_hash  = hash_request(req, content_hash);

        let digest = crypto::keccak(&[
            b"\x19\x01",
            &self.domain_separator()[..],
            &struct_hash[..],
        ].concat());

        match ecrecover(digest, sig, &*self.vm()) {
            Some(addr) => addr == owner,
            None => false,
        }
    }
}

fn verify_proof(proof: &[B256], root: B256, mut hash: B256) -> bool {
    for p in proof {
        hash = if hash <= *p {
            crypto::keccak(&[hash.as_slice(), p.as_slice()].concat())
        } else {
            crypto::keccak(&[p.as_slice(), hash.as_slice()].concat())
        };
    }
    hash == root
}

/// abi.encodePacked(receiver, amount)
fn encode_pair(receiver: Address, amount: U256) -> [u8; 52] {
    let mut out = [0u8; 52];
    out[..20].copy_from_slice(receiver.as_slice());

    let amt_bytes: [u8; 32] = amount.to_be_bytes::<32>();
    out[20..].copy_from_slice(&amt_bytes);

    out
}

/// abi.encodePacked(round, receiver, token)
fn encode_claim_key(round: u64, receiver: Address, token: Address) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..8].copy_from_slice(&round.to_be_bytes());
    out[8..28].copy_from_slice(receiver.as_slice());
    out[28..48].copy_from_slice(token.as_slice());
    out
}

fn address_word(addr: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice()); // right-align 20 bytes
    out
}

fn hash_content(contents: &[AirdropContentERC20]) -> B256 {
    let mut buf = Vec::with_capacity(32 * contents.len());

    for c in contents {
        let leaf = crypto::keccak(
            &[
                CONTENT_TYPEHASH_ERC20.as_slice(),
                address_word(&c.recipient).as_slice(),
                c.amount.to_be_bytes::<32>().as_slice(),
            ]
            .concat(),
        );
        buf.extend_from_slice(
            &leaf.as_slice()[..]
        );
    }
    crypto::keccak(&buf)
}

fn hash_request(req: &AirdropRequestERC20, contents_hash: B256) -> B256 {
    let token_word = address_word(&req.tokenAddress);

    crypto::keccak(&[
        &REQUEST_TYPEHASH_ERC20[..],
        &req.uid[..],
        &token_word[..],
        &req.expirationTimestamp.to_be_bytes::<32>()[..],
        &contents_hash[..],
    ].concat())
}

fn ecrecover(digest: B256, sig: &[u8; 65], host: &dyn stylus_sdk::prelude::Host) -> Option<Address> {
    let (r, s, v) = (&sig[0..32], &sig[32..64], sig[64]);

    if v != 27 && v != 28 { return None }

    let mut input = [0u8; 128];
    input[..32].copy_from_slice(&digest.as_slice());
    input[63] = v;
    input[64..96].copy_from_slice(r);
    input[96..128].copy_from_slice(s);

    let precompile_addr = {
        let mut bytes = [0u8; 20];
        bytes[19] = 1; // ecrecover addr
        Address::from(bytes)
    };
    let out = unsafe {
        RawCall::new(host)
            .gas(25_000)                    
            .call(precompile_addr,
                  &input)
    }
    .ok()?;

    if out.len() < 32 { return None }
    let addr = Address::from_slice(&out[12..32]);
    if addr == Address::ZERO { None } else { Some(addr) }
}
