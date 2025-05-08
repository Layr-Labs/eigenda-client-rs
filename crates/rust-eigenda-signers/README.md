# rust-eigenda-signers

Centralized signer implementations.

It defines the `Sign` trait which defines a generic interface focused solely on the signing act:

```rs
async fn sign_digest(&self, message: &Message) -> Result<RecoverableSignature, Self::Error>
```

> Takes a pre-hashed Message (digest) prepared by the EigenDA client and returns a recoverable signature. The async nature supports external signers like KMS.

```rs
fn public_key(&self) -> PublicKey
```

> Returns the associated public key.

This crate provides a struct `Signer` which implements the `Sign` trait. This struct works with local private keys.

## Use

```toml
[dependencies]
rust-eigenda-v2-signers = "0.1.5"
```
