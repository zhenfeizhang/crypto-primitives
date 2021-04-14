//! This module implements key derivation function as per section 6.2
//! of ISO/IEC 18033-2 <https://www.shoup.net/iso/std4.pdf>.
//! The concrete methods are recalled as follows:
//! 1. System parameters.
//!     KDF1 is a family of key derivation functions, parameterized a Hash function
//! 2. Specification.
//!     For an octet string `x` and a non-negative integer `l`, `KDF(x, l)` is defined to be the
//!     first `l` octets of
//!         `Hash.eval(x | I2OSP (0, 4)) | ... | Hash.eval(x | I2OSP (k − 1, 4))`
//!     where `k = ceil(l/Hash.len)`.
//!     Note. This function will fail if and only if `k > 2^32` or if `|x| + 4 > Hash.MaxInputLen`.
use crate::Error;
use crate::FixedLengthCRH;
use ark_ff::bytes::ToBytes;
use ark_std::hash::Hash;
use ark_std::marker::PhantomData;

pub trait KDF {
    type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
    type Hash: FixedLengthCRH;
    type HashParameters: Clone;

    /// evaluate the KDF over the input, with the given parameter;
    /// extract `output_len` bytes of keys
    fn evaluate(
        param: &Self::HashParameters,
        input: &[u8],
        output_len: usize,
    ) -> Result<Self::Output, Error>;
}

/// The ISO-KDF structure
#[derive(Default, Clone)]
pub struct ISOKDF<H> {
    hash: PhantomData<H>,
}

impl<H: FixedLengthCRH> KDF for ISOKDF<H> {
    type Output = Vec<u8>;
    type Hash = H;
    type HashParameters = H::Parameters;

    fn evaluate(
        param: &Self::HashParameters,
        input: &[u8],
        output_len: usize,
    ) -> Result<Self::Output, Error> {
        if (input.len() << 3) + 32 > H::INPUT_SIZE_BITS {
            // "Note. This function will fail if and only if `k > 2^32`
            //  or if `|x| + 4 > Hash.MaxInputLen`."
            return Err(format!("Input len ({}) exceed the hash capacity", input.len()).into());
        }

        let mut k = 0;
        let mut res: Vec<u8> = vec![];
        while res.len() < output_len {
            // compute `Hash(input | I2OSP (k, 4))` and
            // append it to the result
            Self::Hash::evaluate(&param, &[input, &i2osp(k as u32, 4)?].concat())?
                .write(&mut res)
                .unwrap();
            k += 1;
        }

        Ok(res[0..output_len].to_vec())
    }
}

// converting a u32 integer into an array of 4 bytes.
fn i2osp(integer: u32, len: usize) -> Result<[u8; 4], Error> {
    // for our KDF use case, the i2osp function always output an array of 4 bytes
    if len != 4 {
        return Err(format!("I2OSP length ({}) is not correct", len).into());
    }
    Ok([
        (integer >> 24 & 0xff) as u8,
        (integer >> 16 & 0xff) as u8,
        (integer >> 8 & 0xff) as u8,
        (integer & 0xff) as u8,
    ])
}

#[cfg(test)]
mod test {
    use crate::crh::FixedLengthCRH;
    use crate::kdf::{ISOKDF, KDF};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

    #[test]
    fn pedersen_kdf_test() {
        use crate::{crh::pedersen::Window, crh::pedersen};

        const PERDERSON_WINDOW_SIZE: usize = 4;
        const PERDERSON_WINDOW_NUM: usize = 256;

        #[derive(Clone)]
        struct PedersenWindow;
        impl Window for PedersenWindow {
            const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
            const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
        }
        type Hash = pedersen::CRH<JubJub, PedersenWindow>;

        let mut rng = &mut ark_std::test_rng();
        let param = Hash::setup(&mut rng).unwrap();

        <ISOKDF<Hash> as KDF>::evaluate(&param, b"test input", 1000).unwrap();
    }

    #[test]
    fn poseidon_kdf_test() {
        todo!()
    }
}
