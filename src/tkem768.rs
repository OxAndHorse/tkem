//! TKEM 768

use super::{constants::*, ind_cca::*, types::*, *}; // Ensure necessary items are imported

// --- Constants (Same as ML-KEM 768) ---
const RANK: usize = 3;
#[cfg(any(feature = "incremental", eurydice))]
const RANKED_BYTES_PER_RING_ELEMENT: usize = RANK * BITS_PER_RING_ELEMENT / 8;
const T_AS_NTT_ENCODED_SIZE: usize =
    (RANK * COEFFICIENTS_IN_RING_ELEMENT * BITS_PER_COEFFICIENT) / 8;
const VECTOR_U_COMPRESSION_FACTOR: usize = 10;
const C1_BLOCK_SIZE: usize = (COEFFICIENTS_IN_RING_ELEMENT * VECTOR_U_COMPRESSION_FACTOR) / 8;
const C1_SIZE: usize = C1_BLOCK_SIZE * RANK;
const VECTOR_V_COMPRESSION_FACTOR: usize = 4;
const C2_SIZE: usize = (COEFFICIENTS_IN_RING_ELEMENT * VECTOR_V_COMPRESSION_FACTOR) / 8;
const CPA_PKE_SECRET_KEY_SIZE: usize =
    (RANK * COEFFICIENTS_IN_RING_ELEMENT * BITS_PER_COEFFICIENT) / 8;
pub(crate) const CPA_PKE_PUBLIC_KEY_SIZE: usize = T_AS_NTT_ENCODED_SIZE + 32;
const CPA_PKE_CIPHERTEXT_SIZE: usize = C1_SIZE + C2_SIZE;
const SECRET_KEY_SIZE: usize =
    CPA_PKE_SECRET_KEY_SIZE + CPA_PKE_PUBLIC_KEY_SIZE + H_DIGEST_SIZE + SHARED_SECRET_SIZE;

const ETA1: usize = 2;
const ETA1_RANDOMNESS_SIZE: usize = ETA1 * 64;
const ETA2: usize = 2;
const ETA2_RANDOMNESS_SIZE: usize = ETA2 * 64;

const IMPLICIT_REJECTION_HASH_INPUT_SIZE: usize = SHARED_SECRET_SIZE + CPA_PKE_CIPHERTEXT_SIZE;
// --- End Constants ---

/// The TKEM 768 algorithms
pub struct Tkem768;

// Implement the standard KEM trait if applicable and not using hax/eurydice features that conflict
#[cfg(not(any(hax, eurydice)))]
// crate::impl_tkem_trait!(
//     Tkem768,
//     Tkem768PublicKey, // Assuming these aliases are updated below or elsewhere
//     Tkem768PrivateKey,
//     Tkem768Ciphertext,
//     Tag
// );

// --- Type Aliases (Renamed from MlKem* to Tkem*) ---
/// A TKEM 768 Ciphertext

pub type Tkem768Ciphertext = MlKemCiphertext<CPA_PKE_CIPHERTEXT_SIZE>;
/// A TKEM 768 Private key
pub type Tkem768PrivateKey = MlKemPrivateKey<SECRET_KEY_SIZE>;
/// A TKEM 768 Public key
pub type Tkem768PublicKey = MlKemPublicKey<CPA_PKE_PUBLIC_KEY_SIZE>;
/// A TKEM 768 Key pair
pub type Tkem768KeyPair = MlKemKeyPair<SECRET_KEY_SIZE, CPA_PKE_PUBLIC_KEY_SIZE>;

///A Tag
pub type Tag = [u8];
// --- End Type Aliases ---

// --- Macro to Instantiate Backend-Specific Modules ---
macro_rules! instantiate {
    ($modp:ident, $p:path, $doc:expr) => {
        #[doc = $doc]
        pub mod $modp {
            use super::*;
            use $p as p; // Import the specific backend path

            /// Validate a public key.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_public_key(public_key: &Tkem768PublicKey) -> bool {
                p::validate_public_key::<RANK, CPA_PKE_PUBLIC_KEY_SIZE>(&public_key.value)
            }

            /// Validate a private key.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_private_key(
                private_key: &Tkem768PrivateKey,
                ciphertext: &Tkem768Ciphertext,
            ) -> bool {
                p::validate_private_key::<RANK, SECRET_KEY_SIZE, CPA_PKE_CIPHERTEXT_SIZE>(
                    private_key,
                    ciphertext,
                )
            }

            /// Validate the private key only.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_private_key_only(private_key: &Tkem768PrivateKey) -> bool {
                p::validate_private_key_only::<RANK, SECRET_KEY_SIZE>(private_key)
            }

            /// Generate TKEM 768 Key Pair
            pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> Tkem768KeyPair {
                p::generate_keypair::<
                    RANK,
                    CPA_PKE_SECRET_KEY_SIZE,
                    SECRET_KEY_SIZE,
                    CPA_PKE_PUBLIC_KEY_SIZE,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                >(&randomness)
            }


            /// Encapsulate TKEM 768 with a tag
            ///
            /// Generates an ([`Tkem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
            /// The input is a reference to an [`Tkem768PublicKey`], a `tag` slice, and [`SHARED_SECRET_SIZE`]
            /// bytes of `randomness`.
            pub fn encapsulate_with_tag(
                public_key: &Tkem768PublicKey,
                randomness: [u8; SHARED_SECRET_SIZE],
                tag: &[u8], // <-- New tag parameter
            ) -> (Tkem768Ciphertext, MlKemSharedSecret) {
                // Call the corresponding backend's tkem implementation
                p::encapsulate_with_tag::<
                    RANK,
                    CPA_PKE_CIPHERTEXT_SIZE,
                    CPA_PKE_PUBLIC_KEY_SIZE,
                    T_AS_NTT_ENCODED_SIZE,
                    C1_SIZE,
                    C2_SIZE,
                    VECTOR_U_COMPRESSION_FACTOR,
                    VECTOR_V_COMPRESSION_FACTOR,
                    C1_BLOCK_SIZE,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                    ETA2,
                    ETA2_RANDOMNESS_SIZE,
                >(public_key, &randomness, tag) // Pass the tag
            }

            /// Decapsulate TKEM 768 with a tag
            ///
            /// Generates an [`MlKemSharedSecret`].
            /// The input is a reference to an [`MlKem768PrivateKey`] and an [`MlKem768Ciphertext`] and a tag.
            pub fn decapsulate_with_tag(
                private_key: &Tkem768PrivateKey,
                ciphertext: &Tkem768Ciphertext,
                tag:&[u8],
            ) -> MlKemSharedSecret {
                p::decapsulate_with_tag::<
                    RANK,
                    SECRET_KEY_SIZE,
                    CPA_PKE_SECRET_KEY_SIZE,
                    CPA_PKE_PUBLIC_KEY_SIZE,
                    CPA_PKE_CIPHERTEXT_SIZE,
                    T_AS_NTT_ENCODED_SIZE,
                    C1_SIZE,
                    C2_SIZE,
                    VECTOR_U_COMPRESSION_FACTOR,
                    VECTOR_V_COMPRESSION_FACTOR,
                    C1_BLOCK_SIZE,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                    ETA2,
                    ETA2_RANDOMNESS_SIZE,
                    IMPLICIT_REJECTION_HASH_INPUT_SIZE,
                >(private_key, ciphertext,tag)
            }


            /// Unpacked APIs that don't use serialized keys.
            pub mod unpacked {
                use super::*;

                /// An Unpacked TKEM 768 Public key
                pub type Tkem768PublicKeyUnpacked = p::unpacked::MlKemPublicKeyUnpacked<RANK>;

                /// An Unpacked TKEM 768 Key pair
                pub type Tkem768KeyPairUnpacked = p::unpacked::MlKemKeyPairUnpacked<RANK>;

                /// Create a new, empty unpacked key.
                pub fn init_key_pair() -> Tkem768KeyPairUnpacked {
                    Tkem768KeyPairUnpacked::default()
                }

                /// Create a new, empty unpacked public key.
                pub fn init_public_key() -> Tkem768PublicKeyUnpacked {
                    Tkem768PublicKeyUnpacked::default()
                }

                /// Get the serialized public key.
                #[hax_lib::requires(fstar!(r#"forall (i:nat). i < 3 ==>
                    Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index
                        ${public_key.ind_cpa_public_key.t_as_ntt} i)"#))]
                pub fn serialized_public_key(
                    public_key: &Tkem768PublicKeyUnpacked,
                    serialized: &mut Tkem768PublicKey,
                ) {
                    public_key.serialized_mut::<CPA_PKE_PUBLIC_KEY_SIZE>(serialized);
                }

                /// Get the serialized private key.
                pub fn key_pair_serialized_private_key(
                    key_pair: &Tkem768KeyPairUnpacked,
                ) -> Tkem768PrivateKey {
                    key_pair.serialized_private_key::<
                        CPA_PKE_SECRET_KEY_SIZE,
                        SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                    >()
                }

                /// Get the serialized private key.
                pub fn key_pair_serialized_private_key_mut(
                    key_pair: &Tkem768KeyPairUnpacked,
                    serialized: &mut Tkem768PrivateKey,
                ) {
                    key_pair.serialized_private_key_mut::<
                        CPA_PKE_SECRET_KEY_SIZE,
                        SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                    >(serialized);
                }

                /// Get the serialized public key.
                #[hax_lib::requires(fstar!(r#"(forall (i:nat). i < 3 ==>
                        Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index
                            ${key_pair.public_key.ind_cpa_public_key.t_as_ntt} i))"#))]
                pub fn key_pair_serialized_public_key_mut(
                    key_pair: &Tkem768KeyPairUnpacked,
                    serialized: &mut Tkem768PublicKey,
                ) {
                    key_pair.serialized_public_key_mut::<CPA_PKE_PUBLIC_KEY_SIZE>(serialized);
                }

                /// Get the serialized public key.
                #[hax_lib::requires(fstar!(r#"forall (i:nat). i < 3 ==>
                    Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index
                        ${key_pair.public_key.ind_cpa_public_key.t_as_ntt} i)"#))]
                pub fn key_pair_serialized_public_key(
                    key_pair: &Tkem768KeyPairUnpacked,
                ) -> Tkem768PublicKey {
                    key_pair.serialized_public_key::<CPA_PKE_PUBLIC_KEY_SIZE>()
                }

                /// Get an unpacked key from a private key.
                pub fn key_pair_from_private_mut(
                    private_key: &Tkem768PrivateKey,
                    key_pair: &mut Tkem768KeyPairUnpacked,
                ) {
                    p::unpacked::keypair_from_private_key::<
                        RANK,
                        SECRET_KEY_SIZE,
                        CPA_PKE_SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                        T_AS_NTT_ENCODED_SIZE,
                    >(private_key, key_pair);
                }

                /// Get the unpacked public key.
                pub fn public_key(key_pair: &Tkem768KeyPairUnpacked, pk: &mut Tkem768PublicKeyUnpacked) {
                    *pk = (*key_pair.public_key()).clone();
                }

                /// Get the unpacked public key from a serialized one.
                pub fn unpacked_public_key(
                    public_key: &Tkem768PublicKey,
                    unpacked_public_key: &mut Tkem768PublicKeyUnpacked,
                ) {
                    p::unpacked::unpack_public_key::<
                        RANK,
                        T_AS_NTT_ENCODED_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                    >(public_key, unpacked_public_key)
                }

                /// Generate TKEM 768 Key Pair in "unpacked" form.
                pub fn generate_key_pair(
                    randomness: [u8; KEY_GENERATION_SEED_SIZE],
                ) -> Tkem768KeyPairUnpacked {
                    let mut key_pair = Tkem768KeyPairUnpacked::default();
                    generate_key_pair_mut(randomness, &mut key_pair);
                    key_pair
                }

                /// Generate TKEM 768 Key Pair in "unpacked" form (mutable version).
                pub fn generate_key_pair_mut(
                    randomness: [u8; KEY_GENERATION_SEED_SIZE],
                    key_pair: &mut Tkem768KeyPairUnpacked,
                ) {
                    p::unpacked::generate_keypair::<
                        RANK,
                        CPA_PKE_SECRET_KEY_SIZE,
                        SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                    >(randomness, key_pair);
                }

                /// Encapsulate TKEM 768 (unpacked)
                ///
                /// Generates an ([`Tkem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
                /// The input is a reference to an unpacked public key of type [`Tkem768PublicKeyUnpacked`],
                /// the SHA3-256 hash of this public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
                #[cfg_attr(
                    hax,
                    hax_lib::fstar::before(
                        interface,
                        r#"
                let _ =
                (* This module has implicit dependencies, here we make them explicit. *)
                (* The implicit dependencies arise from typeclasses instances. *)
                let open Libcrux_ml_kem.Vector.Portable in
                let open Libcrux_ml_kem.Vector.Neon in
                ()"#
                    )
                )]
                pub fn encapsulate(
                    public_key: &Tkem768PublicKeyUnpacked,
                    randomness: [u8; SHARED_SECRET_SIZE],
                ) -> (Tkem768Ciphertext, MlKemSharedSecret) {
                    p::unpacked::encapsulate::<
                        RANK,
                        CPA_PKE_CIPHERTEXT_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                        T_AS_NTT_ENCODED_SIZE,
                        C1_SIZE,
                        C2_SIZE,
                        VECTOR_U_COMPRESSION_FACTOR,
                        VECTOR_V_COMPRESSION_FACTOR,
                        C1_BLOCK_SIZE,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                        ETA2,
                        ETA2_RANDOMNESS_SIZE,
                    >(public_key, &randomness)
                }

                 /// Encapsulate TKEM 768 (unpacked) with a tag
                ///
                /// Generates an ([`Tkem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
                /// The input is a reference to an unpacked public key of type [`Tkem768PublicKeyUnpacked`],
                /// a `tag` slice, the SHA3-256 hash of the original public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
                pub fn encapsulate_with_tag(
                    public_key: &Tkem768PublicKeyUnpacked,
                    randomness: &[u8; SHARED_SECRET_SIZE],
                    tag: &[u8], // <-- New tag parameter
                ) -> (Tkem768Ciphertext, MlKemSharedSecret) {
                    // Call the corresponding backend's unpacked tkem implementation
                     p::unpacked::encapsulate_with_tag::<
                        RANK,
                        CPA_PKE_CIPHERTEXT_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                        T_AS_NTT_ENCODED_SIZE,
                        C1_SIZE,
                        C2_SIZE,
                        VECTOR_U_COMPRESSION_FACTOR,
                        VECTOR_V_COMPRESSION_FACTOR,
                        C1_BLOCK_SIZE,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                        ETA2,
                        ETA2_RANDOMNESS_SIZE,
                    >(public_key, randomness, tag) // Pass the tag
                }

                /// Decapsulate TKEM 768 (unpacked)
                ///
                /// Generates an [`MlKemSharedSecret`].
                /// The input is a reference to an unpacked key pair of type [`Tkem768KeyPairUnpacked`]
                /// and an [`Tkem768Ciphertext`].
                pub fn decapsulate(
                    private_key: &Tkem768KeyPairUnpacked,
                    ciphertext: &Tkem768Ciphertext,
                ) -> MlKemSharedSecret {
                    p::unpacked::decapsulate::<
                        RANK,
                        SECRET_KEY_SIZE,
                        CPA_PKE_SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                        CPA_PKE_CIPHERTEXT_SIZE,
                        T_AS_NTT_ENCODED_SIZE,
                        C1_SIZE,
                        C2_SIZE,
                        VECTOR_U_COMPRESSION_FACTOR,
                        VECTOR_V_COMPRESSION_FACTOR,
                        C1_BLOCK_SIZE,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                        ETA2,
                        ETA2_RANDOMNESS_SIZE,
                        IMPLICIT_REJECTION_HASH_INPUT_SIZE,
                    >(private_key, ciphertext)
                }

                /// Decapsulate TKEM 768 (unpacked)
                ///
                /// Generates an [`MlKemSharedSecret`].
                /// The input is a reference to an unpacked key pair of type [`Tkem768KeyPairUnpacked`]
                /// and an [`Tkem768Ciphertext`] and a tag.
                pub fn decapsulate_with_tag(
                    private_key: &Tkem768KeyPairUnpacked,
                    ciphertext: &Tkem768Ciphertext,
                    tag:&[u8],
                ) -> MlKemSharedSecret {
                    p::unpacked::decapsulate_with_tag::<
                        RANK,
                        SECRET_KEY_SIZE,
                        CPA_PKE_SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                        CPA_PKE_CIPHERTEXT_SIZE,
                        T_AS_NTT_ENCODED_SIZE,
                        C1_SIZE,
                        C2_SIZE,
                        VECTOR_U_COMPRESSION_FACTOR,
                        VECTOR_V_COMPRESSION_FACTOR,
                        C1_BLOCK_SIZE,
                        ETA1,
                        ETA1_RANDOMNESS_SIZE,
                        ETA2,
                        ETA2_RANDOMNESS_SIZE,
                        IMPLICIT_REJECTION_HASH_INPUT_SIZE,
                    >(private_key, ciphertext,tag)
                }
            }
        }
    };
}
// --- End Macro ---

// --- Instantiate Backends ---
instantiate! { portable, ind_cca::instantiations::portable, "Portable TKEM 768" }
#[cfg(feature = "simd256")]
instantiate! { avx2, ind_cca::instantiations::avx2, "AVX2 Optimised TKEM 768" }
#[cfg(feature = "simd128")]
instantiate! { neon, ind_cca::instantiations::neon, "Neon Optimised TKEM 768" }
// --- End Instantiations ---

/// Validate a public key.
///
/// Returns `true` if valid, and `false` otherwise.
#[cfg(not(eurydice))]
pub fn validate_public_key(public_key: &Tkem768PublicKey) -> bool {
    multiplexing::validate_public_key::<RANK, CPA_PKE_PUBLIC_KEY_SIZE>(&public_key.value)
}

/// Validate a private key.
///
/// Returns `true` if valid, and `false` otherwise.
#[cfg(not(eurydice))]
pub fn validate_private_key(
    private_key: &Tkem768PrivateKey,
    ciphertext: &Tkem768Ciphertext,
) -> bool {
    multiplexing::validate_private_key::<RANK, SECRET_KEY_SIZE, CPA_PKE_CIPHERTEXT_SIZE>(
        private_key,
        ciphertext,
    )
}

/// Generate TKEM 768 Key Pair
///
/// Generate a TKEM key pair. The input is a byte array of size
/// [`KEY_GENERATION_SEED_SIZE`].
///
/// This function returns a [`Tkem768KeyPair`].
#[cfg(not(eurydice))]
pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> Tkem768KeyPair {
    multiplexing::generate_keypair::<
        RANK,
        CPA_PKE_SECRET_KEY_SIZE,
        SECRET_KEY_SIZE,
        CPA_PKE_PUBLIC_KEY_SIZE,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
    >(&randomness)
}


/// Encapsulate TKEM 768 with a tag
///
/// Generates an ([`Tkem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
/// The input is a reference to an [`Tkem768PublicKey`], a `tag` slice, and [`SHARED_SECRET_SIZE`]
/// bytes of `randomness`.
#[cfg(not(eurydice))]
pub fn encapsulate_with_tag(
    public_key: &Tkem768PublicKey,
    randomness: [u8; SHARED_SECRET_SIZE],
    tag: &[u8], // <-- New tag parameter
) -> (Tkem768Ciphertext, MlKemSharedSecret) {
    // Call the multiplexing layer's tkem implementation
    multiplexing::encapsulate_with_tag::<
        RANK,
        CPA_PKE_CIPHERTEXT_SIZE,
        CPA_PKE_PUBLIC_KEY_SIZE,
        T_AS_NTT_ENCODED_SIZE,
        C1_SIZE,
        C2_SIZE,
        VECTOR_U_COMPRESSION_FACTOR,
        VECTOR_V_COMPRESSION_FACTOR,
        C1_BLOCK_SIZE,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
    >(public_key, &randomness,tag) // Pass the tag
}

/// Decapsulate TKEM 768
///
/// Generates an [`MlKemSharedSecret`].
/// The input is a reference to an [`Tkem768PrivateKey`] and an [`Tkem768Ciphertext`].
#[cfg(not(eurydice))]
pub fn decapsulate_with_tag(
    private_key: &Tkem768PrivateKey,
    ciphertext: &Tkem768Ciphertext,
    tag:&[u8],
) -> MlKemSharedSecret {
    multiplexing::decapsulate_with_tag::<
        RANK,
        SECRET_KEY_SIZE,
        CPA_PKE_SECRET_KEY_SIZE,
        CPA_PKE_PUBLIC_KEY_SIZE,
        CPA_PKE_CIPHERTEXT_SIZE,
        T_AS_NTT_ENCODED_SIZE,
        C1_SIZE,
        C2_SIZE,
        VECTOR_U_COMPRESSION_FACTOR,
        VECTOR_V_COMPRESSION_FACTOR,
        C1_BLOCK_SIZE,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
        IMPLICIT_REJECTION_HASH_INPUT_SIZE,
    >(private_key, ciphertext, tag)
}


/// Randomized APIs
///
/// The functions in this module are equivalent to the one in the main module,
/// but sample their own randomness, provided a random number generator that
/// implements `CryptoRng`.
///
/// Decapsulation is not provided in this module as it does not require randomness.
#[cfg(all(not(eurydice), feature = "rand"))]
pub mod rand {
    use super::{
        Tkem768Ciphertext, Tkem768KeyPair, Tkem768PublicKey, MlKemSharedSecret,
        KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE,
    };
    use ::rand::CryptoRng;

    /// Generate TKEM 768 Key Pair
    ///
    /// The random number generator `rng` needs to implement `CryptoRng`
    /// to sample the required randomness internally.
    ///
    /// This function returns a [`Tkem768KeyPair`].
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> Tkem768KeyPair {
        let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut randomness);

        super::generate_key_pair(randomness)
    }


    /// Encapsulate TKEM 768 with a tag using randomness from `rng`
    ///
    /// Generates an ([`Tkem768Ciphertext`], [`MlKemSharedSecret`]) tuple.
    /// The input is a reference to an [`Tkem768PublicKey`] and a `tag` slice.
    /// The random number generator `rng` needs to implement `CryptoRng`
    /// to sample the required randomness internally.
    pub fn encapsulate_with_tag(
        public_key: &Tkem768PublicKey,
        
        rng: &mut impl CryptoRng,
        tag: &[u8], // <-- New tag parameter
    ) -> (Tkem768Ciphertext, MlKemSharedSecret) {
        let mut randomness = [0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut randomness);

        super::encapsulate_with_tag(public_key, randomness, tag) // Call the top-level function with tag
    }

}

// --- Tests (Optional, can remain largely unchanged) ---
#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, TryRngCore};

    use super::{
        tkem768::{generate_key_pair, validate_public_key}, // Updated import path/module name
        KEY_GENERATION_SEED_SIZE,
    };

    #[test]
    fn pk_validation() {
        let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        OsRng.try_fill_bytes(&mut randomness).unwrap();

        let key_pair = generate_key_pair(randomness);
        assert!(validate_public_key(&key_pair.pk));
    }
}
// --- End Tests ---