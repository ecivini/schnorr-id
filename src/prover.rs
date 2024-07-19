// Implementation based on Chapter 19 of: https://toc.cryptobook.us/

use std::ops::{Add, Mul};

use crate::keypair::KeyPair;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};

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
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Prover {
            id: KeyPair::new(rng),
            ver_kp: None,
        }
    }

    /// Creates a prover from an identity
    pub fn from(id: &KeyPair) -> Self {
        Prover {
            id: *id,
            ver_kp: None,
        }
    }

    /// In the first step, a prover must generate a new keypair and send
    /// the new public key to the verifier.
    ///
    /// Returns a new keypair used in the verification process.
    /// NOTE: this keypair is not the one that identifies the prover.
    pub fn start_verification<R: CryptoRng + RngCore>(&mut self, rng: &mut R) {
        self.ver_kp = Some(KeyPair::new(rng));
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
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn new_prover() {
        let mut rng = StdRng::from_entropy();
        let prover = Prover::new(&mut rng);

        println!(
            "Public: {:?} - Secret: {:?}",
            prover.id(),
            prover.id.secret()
        );
        assert!(prover.ver_kp.is_none());
    }

    #[test]
    fn prover_from_identity() {
        let mut rng = StdRng::from_entropy();
        let id = KeyPair::new(&mut rng);
        let prover = Prover::from(&id);

        println!(
            "Public: {:?} - Secret: {:?}",
            prover.id(),
            prover.id.secret()
        );
        assert_eq!(prover.id.public(), id.public());
        assert_eq!(prover.id.secret(), id.secret());

        assert!(prover.ver_kp.is_none());
    }

    #[test]
    fn prover_start_challenge() {
        let mut rng = StdRng::from_entropy();
        let mut prover = Prover::new(&mut rng);

        prover.start_verification(&mut rng);

        assert!(prover.ver_kp.is_some());

        println!(
            "Public: {:?} - Secret: {:?}",
            prover.ver_kp.unwrap().public(),
            prover.ver_kp.unwrap().secret()
        );
    }
}
