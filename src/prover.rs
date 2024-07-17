// Implementation based on Chapter 19 of: https://toc.cryptobook.us/

use std::ops::{Add, Mul, Rem};

use curve25519_dalek::{ristretto, scalar, EdwardsPoint, RistrettoPoint, Scalar};
use crate::keypair::KeyPair;

/// A Prover P is something that needs to prove its identity id.
/// In the verification process, a new keypair ver_kp is generated and used
/// by a verifier V.
#[derive(Copy, Clone)]
pub struct Prover {
    id: KeyPair,
    ver_kp: Option<KeyPair>,
}

impl Prover {

    /// Creates a prover with a new identity
    pub fn new() -> Self {
        Prover {
            id: KeyPair::new(),
            ver_kp: None
        }
    }

    /// Creates a prover from an identity
    pub fn from(id: &KeyPair) -> Self {
        Prover {
            id: *id,
            ver_kp: None
        }
    }

    /// In the first step, a prover must generate a new keypair and send
    /// the new public key to the verifier.
    /// 
    /// Parameters: 
    ///   - q: group order.
    ///   - g: group generator.
    /// 
    /// Returns a new keypair used in the verification process.
    /// NOTE: this keypair is not the one that identifies the prover.
    /// pub fn new(q: u128, g: u128) -> Self {
    pub fn start_verification(&mut self) {
        self.ver_kp = Some(KeyPair::new());
    }

    /// In the third step, a prover must compute a value based on the 
    /// challenge parameter c provided by the verifier.
    /// 
    /// Parameters:
    ///   - c: challenge provided by the verifier.
    /// 
    /// Returns the alpha to be verified by the verifier.
    pub fn compute_challenge(self, c: Scalar) -> Option<Scalar> {
        let id_x_c = Scalar::mul(self.id.secret(), c);
        let alpha = Scalar::add(self.ver_kp?.secret(), id_x_c); 

        Some(alpha)
    }

    /// Getter for the id
    pub fn id(&self) -> RistrettoPoint {
        self.id.public()
    }

    /// Getter for the verification id
    pub fn verification_id(&self) -> Option<RistrettoPoint> {
        match self.ver_kp {
            Some(ver_kp) => Some(ver_kp.public()),
            None => None
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_prover() {
        let prover = Prover::new();

        println!("Public: {:?} - Secret: {:?}", prover.id(), prover.id.secret());
        assert!(prover.ver_kp.is_none());
    }

    #[test]
    fn prover_from_identity() {
        let id = KeyPair::new();
        let prover = Prover::from(&id);

        println!("Public: {:?} - Secret: {:?}", prover.id(), prover.id.secret());
        assert_eq!(prover.id.public(), id.public());
        assert_eq!(prover.id.secret(), id.secret());

        assert!(prover.ver_kp.is_none());
    }

    #[test]
    fn prover_start_challenge() {
        let mut prover = Prover::new();

        prover.start_verification();

        assert!(prover.ver_kp.is_some());

        println!("Public: {:?} - Secret: {:?}", prover.ver_kp.unwrap().public(), prover.ver_kp.unwrap().secret());
    }

}
