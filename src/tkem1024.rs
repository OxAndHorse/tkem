//! TKEM 1024 BY ML-KEM
use super::{constants::*, ind_cca::*, types::*, *};

const RANK: usize = 4;
#[cfg(any(feature = "incremental", eurydice))]
const RANKED_BYTES_PER_RING_ELEMENT: usize = RANK * BITS_PER_RING_ELEMENT / 8;
const T_AS_NTT_ENCODED_SIZE: usize =
    (RANK * COEFFICIENTS_IN_RING_ELEMENT * BITS_PER_COEFFICIENT) / 8;
const VECTOR_U_COMPRESSION_FACTOR: usize = 11;
const C1_BLOCK_SIZE: usize = (COEFFICIENTS_IN_RING_ELEMENT * VECTOR_U_COMPRESSION_FACTOR) / 8;
const C1_SIZE: usize = C1_BLOCK_SIZE * RANK;
const VECTOR_V_COMPRESSION_FACTOR: usize = 5;
const C2_SIZE: usize = (COEFFICIENTS_IN_RING_ELEMENT * VECTOR_V_COMPRESSION_FACTOR) / 8;
const CPA_PKE_SECRET_KEY_SIZE: usize =
    (RANK * COEFFICIENTS_IN_RING_ELEMENT * BITS_PER_COEFFICIENT) / 8;
pub(crate) const CPA_PKE_PUBLIC_KEY_SIZE: usize = T_AS_NTT_ENCODED_SIZE + 32;
const CPA_PKE_CIPHERTEXT_SIZE: usize = C1_SIZE + C2_SIZE;
pub(crate) const SECRET_KEY_SIZE: usize =
    CPA_PKE_SECRET_KEY_SIZE + CPA_PKE_PUBLIC_KEY_SIZE + H_DIGEST_SIZE + SHARED_SECRET_SIZE;

const ETA1: usize = 2;
const ETA1_RANDOMNESS_SIZE: usize = ETA1 * 64;
const ETA2: usize = 2;
const ETA2_RANDOMNESS_SIZE: usize = ETA2 * 64;

const IMPLICIT_REJECTION_HASH_INPUT_SIZE: usize = SHARED_SECRET_SIZE + CPA_PKE_CIPHERTEXT_SIZE;

// Implement the standard KEM trait if applicable and not using hax/eurydice features that conflict
#[cfg(not(any(hax, eurydice)))]
// crate::impl_tkem_trait!(
//     Tkem1024,
//     Tkem1024PublicKey, // Assuming these aliases are updated below or elsewhere
//     Tkem1024PrivateKey,
//     Tkem1024Ciphertext,
//     Tag
// );

// --- Type Aliases (Renamed from MlKem* to Tkem*) ---
/// A TKEM 1024 Ciphertext

pub type Tkem1024Ciphertext = MlKemCiphertext<CPA_PKE_CIPHERTEXT_SIZE>;
/// A TKEM 1024 Private key
pub type Tkem1024PrivateKey = MlKemPrivateKey<SECRET_KEY_SIZE>;
/// A TKEM 1024 Public key
pub type Tkem1024PublicKey = MlKemPublicKey<CPA_PKE_PUBLIC_KEY_SIZE>;
/// A TKEM 1024 Key pair
pub type Tkem1024KeyPair = MlKemKeyPair<SECRET_KEY_SIZE, CPA_PKE_PUBLIC_KEY_SIZE>;

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
            pub fn validate_public_key(public_key: &Tkem1024PublicKey) -> bool {
                p::validate_public_key::<RANK, CPA_PKE_PUBLIC_KEY_SIZE>(&public_key.value)
            }

            /// Validate a private key.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_private_key(
                private_key: &Tkem1024PrivateKey,
                ciphertext: &Tkem1024Ciphertext,
            ) -> bool {
                p::validate_private_key::<RANK, SECRET_KEY_SIZE, CPA_PKE_CIPHERTEXT_SIZE>(
                    private_key,
                    ciphertext,
                )
            }

            /// Validate the private key only.
            ///
            /// Returns `true` if valid, and `false` otherwise.
            pub fn validate_private_key_only(private_key: &Tkem1024PrivateKey) -> bool {
                p::validate_private_key_only::<RANK, SECRET_KEY_SIZE>(private_key)
            }

            /// Generate TKEM 1024 Key Pair
            pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> Tkem1024KeyPair {
                p::generate_keypair::<
                    RANK,
                    CPA_PKE_SECRET_KEY_SIZE,
                    SECRET_KEY_SIZE,
                    CPA_PKE_PUBLIC_KEY_SIZE,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                >(&randomness)
            }

            /// Generate Kyber 1024 Key Pair
            #[cfg(feature = "kyber")]
            #[cfg_attr(docsrs, doc(cfg(feature = "kyber")))]
            pub fn kyber_generate_key_pair(
                randomness: [u8; KEY_GENERATION_SEED_SIZE],
            ) -> Tkem1024KeyPair {
                p::kyber_generate_keypair::<
                    RANK,
                    CPA_PKE_SECRET_KEY_SIZE,
                    SECRET_KEY_SIZE,
                    CPA_PKE_PUBLIC_KEY_SIZE,
                    ETA1,
                    ETA1_RANDOMNESS_SIZE,
                >(&randomness)
            }


            /// Encapsulate TKEM 1024 with a tag
            ///
            /// Generates an ([`Tkem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
            /// The input is a reference to an [`Tkem1024PublicKey`], a `tag` slice, and [`SHARED_SECRET_SIZE`]
            /// bytes of `randomness`.
            pub fn encapsulate_with_tag(
                public_key: &Tkem1024PublicKey,
                randomness: [u8; SHARED_SECRET_SIZE],
                tag: &[u8], // <-- New tag parameter
            ) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
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

            /// Encapsulate Kyber1024 with a tag
            ///
            /// Generates an ([`Tkem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
            /// The input is a reference to an [`Tkem1024PublicKey`], a `tag` slice, and [`SHARED_SECRET_SIZE`]
            /// bytes of `randomness`.
            #[cfg(feature = "kyber")]
            #[cfg_attr(docsrs, doc(cfg(feature = "kyber")))]
            pub fn kyber_encapsulate_with_tag(
                public_key: &Tkem1024PublicKey,
                randomness: [u8; SHARED_SECRET_SIZE],
                tag:&[u8],
            ) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
                p::kyber_encapsulate_with_tag::<
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
                >(public_key, &randomness,tag)
            }

            /// Decapsulate TKEM 1024 with a tag
            ///
            /// Generates an [`MlKemSharedSecret`].
            /// The input is a reference to an [`MlKem1024PrivateKey`] and an [`MlKem1024Ciphertext`] and a tag.
            pub fn decapsulate_with_tag(
                private_key: &Tkem1024PrivateKey,
                ciphertext: &Tkem1024Ciphertext,
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

            /// Decapsulate kyber1024 with a tag
            ///
            /// Generates an [`MlKemSharedSecret`].
            /// The input is a reference to an [`MlKem1024PrivateKey`] and an [`MlKem1024Ciphertext`] and a tag.
            #[cfg(feature = "kyber")]
            #[cfg_attr(docsrs, doc(cfg(feature = "kyber")))]
            pub fn kyber_decapsulate_with_tag(
                private_key: &Tkem1024PrivateKey,
                ciphertext: &Tkem1024Ciphertext,
                tag:&[u8],
            ) -> MlKemSharedSecret {
                p::kyber_decapsulate_with_tag::<
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

                /// An Unpacked TKEM 1024 Public key
                pub type Tkem1024PublicKeyUnpacked = p::unpacked::MlKemPublicKeyUnpacked<RANK>;

                /// An Unpacked TKEM 1024 Key pair
                pub type Tkem1024KeyPairUnpacked = p::unpacked::MlKemKeyPairUnpacked<RANK>;

                /// Create a new, empty unpacked key.
                pub fn init_key_pair() -> Tkem1024KeyPairUnpacked {
                    Tkem1024KeyPairUnpacked::default()
                }

                /// Create a new, empty unpacked public key.
                pub fn init_public_key() -> Tkem1024PublicKeyUnpacked {
                    Tkem1024PublicKeyUnpacked::default()
                }

                /// Get the serialized public key.
                #[hax_lib::requires(fstar!(r#"forall (i:nat). i < 3 ==>
                    Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index
                        ${public_key.ind_cpa_public_key.t_as_ntt} i)"#))]
                pub fn serialized_public_key(
                    public_key: &Tkem1024PublicKeyUnpacked,
                    serialized: &mut Tkem1024PublicKey,
                ) {
                    public_key.serialized_mut::<CPA_PKE_PUBLIC_KEY_SIZE>(serialized);
                }

                /// Get the serialized private key.
                pub fn key_pair_serialized_private_key(
                    key_pair: &Tkem1024KeyPairUnpacked,
                ) -> Tkem1024PrivateKey {
                    key_pair.serialized_private_key::<
                        CPA_PKE_SECRET_KEY_SIZE,
                        SECRET_KEY_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                    >()
                }

                /// Get the serialized private key.
                pub fn key_pair_serialized_private_key_mut(
                    key_pair: &Tkem1024KeyPairUnpacked,
                    serialized: &mut Tkem1024PrivateKey,
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
                    key_pair: &Tkem1024KeyPairUnpacked,
                    serialized: &mut Tkem1024PublicKey,
                ) {
                    key_pair.serialized_public_key_mut::<CPA_PKE_PUBLIC_KEY_SIZE>(serialized);
                }

                /// Get the serialized public key.
                #[hax_lib::requires(fstar!(r#"forall (i:nat). i < 3 ==>
                    Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index
                        ${key_pair.public_key.ind_cpa_public_key.t_as_ntt} i)"#))]
                pub fn key_pair_serialized_public_key(
                    key_pair: &Tkem1024KeyPairUnpacked,
                ) -> Tkem1024PublicKey {
                    key_pair.serialized_public_key::<CPA_PKE_PUBLIC_KEY_SIZE>()
                }

                /// Get an unpacked key from a private key.
                pub fn key_pair_from_private_mut(
                    private_key: &Tkem1024PrivateKey,
                    key_pair: &mut Tkem1024KeyPairUnpacked,
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
                pub fn public_key(key_pair: &Tkem1024KeyPairUnpacked, pk: &mut Tkem1024PublicKeyUnpacked) {
                    *pk = (*key_pair.public_key()).clone();
                }

                /// Get the unpacked public key from a serialized one.
                pub fn unpacked_public_key(
                    public_key: &Tkem1024PublicKey,
                    unpacked_public_key: &mut Tkem1024PublicKeyUnpacked,
                ) {
                    p::unpacked::unpack_public_key::<
                        RANK,
                        T_AS_NTT_ENCODED_SIZE,
                        CPA_PKE_PUBLIC_KEY_SIZE,
                    >(public_key, unpacked_public_key)
                }

                /// Generate TKEM 1024 Key Pair in "unpacked" form.
                pub fn generate_key_pair(
                    randomness: [u8; KEY_GENERATION_SEED_SIZE],
                ) -> Tkem1024KeyPairUnpacked {
                    let mut key_pair = Tkem1024KeyPairUnpacked::default();
                    generate_key_pair_mut(randomness, &mut key_pair);
                    key_pair
                }

                /// Generate TKEM 1024 Key Pair in "unpacked" form (mutable version).
                pub fn generate_key_pair_mut(
                    randomness: [u8; KEY_GENERATION_SEED_SIZE],
                    key_pair: &mut Tkem1024KeyPairUnpacked,
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

                /// Encapsulate TKEM 1024 (unpacked)
                ///
                /// Generates an ([`Tkem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
                /// The input is a reference to an unpacked public key of type [`Tkem1024PublicKeyUnpacked`],
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
                    public_key: &Tkem1024PublicKeyUnpacked,
                    randomness: [u8; SHARED_SECRET_SIZE],
                ) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
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

                 /// Encapsulate TKEM 1024 (unpacked) with a tag
                ///
                /// Generates an ([`Tkem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
                /// The input is a reference to an unpacked public key of type [`Tkem1024PublicKeyUnpacked`],
                /// a `tag` slice, the SHA3-256 hash of the original public key, and [`SHARED_SECRET_SIZE`] bytes of `randomness`.
                pub fn encapsulate_with_tag(
                    public_key: &Tkem1024PublicKeyUnpacked,
                    randomness: &[u8; SHARED_SECRET_SIZE],
                    tag: &[u8], // <-- New tag parameter
                ) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
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

                /// Decapsulate TKEM 1024 (unpacked)
                ///
                /// Generates an [`MlKemSharedSecret`].
                /// The input is a reference to an unpacked key pair of type [`Tkem1024KeyPairUnpacked`]
                /// and an [`Tkem1024Ciphertext`].
                pub fn decapsulate(
                    private_key: &Tkem1024KeyPairUnpacked,
                    ciphertext: &Tkem1024Ciphertext,
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

                /// Decapsulate TKEM 1024 (unpacked)
                ///
                /// Generates an [`MlKemSharedSecret`].
                /// The input is a reference to an unpacked key pair of type [`Tkem1024KeyPairUnpacked`]
                /// and an [`Tkem1024Ciphertext`] and a tag.
                pub fn decapsulate_with_tag(
                    private_key: &Tkem1024KeyPairUnpacked,
                    ciphertext: &Tkem1024Ciphertext,
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
instantiate! { portable, ind_cca::instantiations::portable, "Portable TKEM 1024" }
#[cfg(feature = "simd256")]
instantiate! { avx2, ind_cca::instantiations::avx2, "AVX2 Optimised TKEM 1024" }
#[cfg(feature = "simd128")]
instantiate! { neon, ind_cca::instantiations::neon, "Neon Optimised TKEM 1024" }
// --- End Instantiations ---

/// Validate a public key.
///
/// Returns `true` if valid, and `false` otherwise.
#[cfg(not(eurydice))]
pub fn validate_public_key(public_key: &Tkem1024PublicKey) -> bool {
    multiplexing::validate_public_key::<RANK, CPA_PKE_PUBLIC_KEY_SIZE>(&public_key.value)
}

/// Validate a private key.
///
/// Returns `true` if valid, and `false` otherwise.
#[cfg(not(eurydice))]
pub fn validate_private_key(
    private_key: &Tkem1024PrivateKey,
    ciphertext: &Tkem1024Ciphertext,
) -> bool {
    multiplexing::validate_private_key::<RANK, SECRET_KEY_SIZE, CPA_PKE_CIPHERTEXT_SIZE>(
        private_key,
        ciphertext,
    )
}

/// Generate TKEM 1024 Key Pair
///
/// Generate a TKEM key pair. The input is a byte array of size
/// [`KEY_GENERATION_SEED_SIZE`].
///
/// This function returns a [`Tkem1024KeyPair`].
#[cfg(not(eurydice))]
pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> Tkem1024KeyPair {
    multiplexing::generate_keypair::<
        RANK,
        CPA_PKE_SECRET_KEY_SIZE,
        SECRET_KEY_SIZE,
        CPA_PKE_PUBLIC_KEY_SIZE,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
    >(&randomness)
}


/// Encapsulate TKEM 1024 with a tag
///
/// Generates an ([`Tkem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
/// The input is a reference to an [`Tkem1024PublicKey`], a `tag` slice, and [`SHARED_SECRET_SIZE`]
/// bytes of `randomness`.
#[cfg(not(eurydice))]
pub fn encapsulate_with_tag(
    public_key: &Tkem1024PublicKey,
    randomness: [u8; SHARED_SECRET_SIZE],
    tag: &[u8], // <-- New tag parameter
) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
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

/// Decapsulate TKEM 1024
///
/// Generates an [`MlKemSharedSecret`].
/// The input is a reference to an [`Tkem1024PrivateKey`] and an [`Tkem1024Ciphertext`].
#[cfg(not(eurydice))]
pub fn decapsulate_with_tag(
    private_key: &Tkem1024PrivateKey,
    ciphertext: &Tkem1024Ciphertext,
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
        Tkem1024Ciphertext, Tkem1024KeyPair, Tkem1024PublicKey, MlKemSharedSecret,
        KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE,
    };
    use ::rand::CryptoRng;

    /// Generate TKEM 1024 Key Pair
    ///
    /// The random number generator `rng` needs to implement `CryptoRng`
    /// to sample the required randomness internally.
    ///
    /// This function returns a [`Tkem1024KeyPair`].
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> Tkem1024KeyPair {
        let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
        rng.fill_bytes(&mut randomness);

        super::generate_key_pair(randomness)
    }


    /// Encapsulate TKEM 1024 with a tag using randomness from `rng`
    ///
    /// Generates an ([`Tkem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
    /// The input is a reference to an [`Tkem1024PublicKey`] and a `tag` slice.
    /// The random number generator `rng` needs to implement `CryptoRng`
    /// to sample the required randomness internally.
    pub fn encapsulate_with_tag(
        public_key: &Tkem1024PublicKey,
        
        rng: &mut impl CryptoRng,
        tag: &[u8], // <-- New tag parameter
    ) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
        let mut randomness = [0u8; SHARED_SECRET_SIZE];
        rng.fill_bytes(&mut randomness);

        super::encapsulate_with_tag(public_key, randomness, tag) // Call the top-level function with tag
    }

}

#[cfg(all(not(eurydice), feature = "kyber"))]
pub(crate) mod kyber {
    use super::*;

    /// The Kyber 1024 algorithms
    // pub struct Kyber1024;

    // crate::impl_kem_trait!(
    //     Kyber1024,
    //     MlKem1024PublicKey,
    //     MlKem1024PrivateKey,
    //     MlKem1024Ciphertext
    // );

    /// Generate Kyber 1024 Key Pair
    ///
    /// Generate a Kyber key pair. The input is a byte array of size
    /// [`KEY_GENERATION_SEED_SIZE`].
    ///
    /// This function returns an [`Tkem1024KeyPair`].
    pub fn generate_key_pair1(randomness: [u8; KEY_GENERATION_SEED_SIZE]) -> Tkem1024KeyPair {
        multiplexing::kyber_generate_keypair::<
            RANK,
            CPA_PKE_SECRET_KEY_SIZE,
            SECRET_KEY_SIZE,
            CPA_PKE_PUBLIC_KEY_SIZE,
            ETA1,
            ETA1_RANDOMNESS_SIZE,
        >(randomness)
    }

    /// Encapsulate Kyber 1024
    ///
    /// Generates an ([`MlKem1024Ciphertext`], [`MlKemSharedSecret`]) tuple.
    /// The input is a reference to an [`MlKem1024PublicKey`] and [`SHARED_SECRET_SIZE`]
    /// bytes of `randomness`.
    pub fn encapsulate_with_tag(
        public_key: &Tkem1024PublicKey,
        randomness: [u8; SHARED_SECRET_SIZE],
        tag:&[u8],
    ) -> (Tkem1024Ciphertext, MlKemSharedSecret) {
        multiplexing::kyber_encapsulate_with_tag::<
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
        >(public_key, randomness, tag)
    }

    /// Decapsulate ML-KEM 1024
    ///
    /// Generates an [`MlKemSharedSecret`].
    /// The input is a reference to an [`Tkem1024PrivateKey`] and an [`Tkem1024Ciphertext`].
    pub fn decapsulate_with_tag(
        private_key: &Tkem1024PrivateKey,
        ciphertext: &Tkem1024Ciphertext,
        tag:&[u8],
    ) -> MlKemSharedSecret {
        multiplexing::kyber_decapsulate_with_tag::<
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
}