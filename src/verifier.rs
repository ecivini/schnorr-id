// Implementation based on Chapter 19 of: https://toc.cryptobook.us/

use std::ops::{Add, Mul};

use curve25519_dalek::{ristretto, RistrettoPoint, Scalar};
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// A Prover P is something that needs to prove its identity id.
/// In the verification process, a new keypair ver_kp is generated and used
/// by a verifier V.
#[derive(Copy, Clone)]
pub struct Verifier {
    id: RistrettoPoint, // Prover public key
    ver_pk: Option<RistrettoPoint>,
    challenge: Option<Scalar>,
}

impl Verifier {
    /// Creates a new verifier
    ///
    /// Parameters:
    ///   - id: prover public key.
    ///   - q: group order.
    ///   - g: group generator.
    pub fn new(id: RistrettoPoint) -> Self {
        Verifier {
            id,
            ver_pk: None,
            challenge: None,
        }
    }

    /// In the second step, a verifier generates a challenge by taking a random
    /// group element in Zq.
    ///
    /// Parameters:
    ///   - ver_pk: public key of the keypair generated in the first step by
    ///             the prover.
    ///
    /// Returns the challenge element to be used by the prover.
    pub fn create_challenge(&mut self, ver_pk: RistrettoPoint) -> Scalar {
        let mut rng = StdRng::from_entropy();

        let mut challenge = Scalar::default();
        while challenge == Scalar::default() {
            let mut slice = [0 as u8; 32];
            rng.fill_bytes(&mut slice);

            let possible_challenge = Scalar::from_canonical_bytes(slice);
            if possible_challenge.is_some().into() {
                challenge = possible_challenge.unwrap();
            }
        }

        self.challenge = Some(challenge);
        self.ver_pk = Some(ver_pk);

        challenge
    }

    /// In the fourth step, a verifier verifies the identity of the prover.
    ///
    /// Parameters:
    ///   - response: response provided by the prover.
    ///
    /// Returns the alpha to be verified by the verifier.
    pub fn verify(self, response: Scalar) -> bool {
        let challenge_available = self.challenge.is_some();

        // let g_to_resp = mod_pow(self.generator, response, self.order);
        let g_to_resp = ristretto::RistrettoPoint::mul_base(&response);

        let u_to_c = ristretto::RistrettoPoint::mul(self.id, self.challenge.unwrap());
        let us = ristretto::RistrettoPoint::add(self.ver_pk.unwrap(), u_to_c);

        println!("g^resp = {:?}", g_to_resp);
        println!("us = {:?}", us);
        //println!("VERIFIER RHS - Ver PUB: {:?} - Id pub: {:?} - c: {} - u^c: {} - us = {}", self.ver_pk.unwrap(), self.id, self.challenge.unwrap(), mod_pow(self.id, response, self.order), us);

        challenge_available && g_to_resp.eq(&us)
    }

    /// Getter for prover identity
    pub fn prover_id(&self) -> RistrettoPoint {
        self.id
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::prover::Prover;

    #[test]
    fn test_verify_correct() {
        let mut prover = Prover::new();
        let mut verifier = Verifier::new(prover.id());

        prover.start_verification();
        let challenge = verifier.create_challenge(prover.verification_id().unwrap());
        let response = prover.compute_challenge(challenge);
        let verified = verifier.verify(response.unwrap());

        assert!(verified);
    }

    #[test]
    fn test_verify_incorrect() {
        let mut prover = Prover::new();
        let mut verifier = Verifier::new(prover.id());

        prover.start_verification();
        let _ = verifier.create_challenge(prover.verification_id().unwrap());

        // craft likely invalid response
        let mut slice = [0 as u8; 32];
        slice[0] = 15;
        let response = Scalar::from_bytes_mod_order(slice);

        let verified = verifier.verify(response);

        assert!(!verified);
    }
}
