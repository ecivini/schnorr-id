// Implementation based on Chapter 19 of: https://toc.cryptobook.us/

use curve25519_dalek::{constants, ristretto, RistrettoPoint, Scalar};
use rand::{rngs::StdRng, RngCore, SeedableRng};

type SecretKey = Scalar;
type PublicKey = RistrettoPoint;

pub const G: RistrettoPoint = constants::RISTRETTO_BASEPOINT_POINT;

/// A KeyPair contains a secret key s, which is a random element in Zq, and
/// its associated public key, which is equal to g^s.
#[derive(Copy, Clone)]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {

    /// Creates a new keypair.
    /// 
    /// Returns a new keypair.
    pub fn new() -> Self {
        let mut rng = StdRng::from_entropy();

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
    
        KeyPair {secret, public}
    }

    /// Creates a keypair starting from a secret key.
    /// Parameters:
    ///   - secret: secret key.
    /// 
    /// Returns a keypair with the imported secret key and relative public key.
    pub fn from(secret: &SecretKey) -> Self {
        // Compute public key
        let public = ristretto::RistrettoPoint::mul_base(&secret);
            
        KeyPair {secret: *secret, public}
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
    use super::*;

    #[test]
    fn new_keypair() {
        let keypair = KeyPair::new();
        print!("Public: {:?} - Secret: {:?}", keypair.public, keypair.secret);
    }

    #[test]
    fn getters() {
        let keypair = KeyPair::new();
        assert_eq!(keypair.public, keypair.public());
        assert_eq!(keypair.secret, keypair.secret());
    }

}
