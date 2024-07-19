// Implementation based on Chapter 19 of: https://toc.cryptobook.us/

use curve25519_dalek::{ristretto, RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};

type SecretKey = Scalar;
type PublicKey = RistrettoPoint;

/// A KeyPair contains a secret key s which is an element of Z/lZ, and
/// its associated public key, which is a curve point equal to g^s.
#[derive(Copy, Clone)]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    /// Creates a new keypair.
    ///
    /// Returns the new keypair.
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        // Generate random secret key
        let mut secret = Scalar::default();

        while secret == Scalar::default() {
            let mut slice = [0 as u8; 32];
            rng.fill_bytes(&mut slice);

            let possible_secret = Scalar::from_canonical_bytes(slice);
            if possible_secret.is_some().into() {
                secret = possible_secret.unwrap();
            }
        }

        // Compute public key
        let public = ristretto::RistrettoPoint::mul_base(&secret);

        KeyPair { secret, public }
    }

    /// Creates a keypair starting from a secret key.
    /// Parameters:
    ///   - secret: secret key.
    ///
    /// Returns a keypair with the imported secret key and relative public key.
    pub fn from(secret: &SecretKey) -> Self {
        // Compute public key
        let public = ristretto::RistrettoPoint::mul_base(&secret);

        KeyPair {
            secret: *secret,
            public,
        }
    }

    /// Getter for the secret key
    pub fn secret(&self) -> SecretKey {
        self.secret
    }

    /// Getter for the public key
    pub fn public(&self) -> PublicKey {
        self.public
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn new_keypair() {
        let mut rng = StdRng::from_entropy();

        let keypair = KeyPair::new(&mut rng);
        print!(
            "Public: {:?} - Secret: {:?}",
            keypair.public, keypair.secret
        );
    }

    #[test]
    fn getters() {
        let mut rng = StdRng::from_entropy();

        let keypair = KeyPair::new(&mut rng);
        assert_eq!(keypair.public, keypair.public());
        assert_eq!(keypair.secret, keypair.secret());
    }
}
