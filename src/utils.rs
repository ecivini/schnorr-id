use curve25519_dalek::{edwards, EdwardsPoint, Scalar};

// Internal modular exponentiation
pub fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 { return 0 }
    let mut result = 1;
    base = base % modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base % modulus;
        }
        exp = exp >> 1;
        base = base * base % modulus
    }
    result
}

pub fn to_scalar(val: u128) -> Scalar {
    let slice = to_slice(val);
    
    Scalar::from_bytes_mod_order(slice)
}

pub fn to_slice(val: u128) -> [u8; 32] {
    let mut slice = [0 as u8; 32];

    for i in 0..16 {
        slice[0] = ((val >> (8 * i)) & 0xFF) as u8;
    }
    
    slice
}
