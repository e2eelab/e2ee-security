project(pqclean C ASM)

set(PQCLEAN_COMMON_SRCS
    randombytes.c
    src/common/aes.c
    src/common/fips202.c
    src/common/nistseedexpander.c
    #src/common/randombytes.c
    src/common/sha2.c
    src/common/sp800-185.c
)

set(HQC_128_SRCS
    src/crypto_kem/hqc-128/clean/code.c
    src/crypto_kem/hqc-128/clean/fft.c
    src/crypto_kem/hqc-128/clean/gf.c
    src/crypto_kem/hqc-128/clean/gf2x.c
    src/crypto_kem/hqc-128/clean/hqc.c
    src/crypto_kem/hqc-128/clean/kem.c
    src/crypto_kem/hqc-128/clean/parsing.c
    src/crypto_kem/hqc-128/clean/reed_muller.c
    src/crypto_kem/hqc-128/clean/reed_solomon.c
    src/crypto_kem/hqc-128/clean/shake_ds.c
    src/crypto_kem/hqc-128/clean/shake_prng.c
    src/crypto_kem/hqc-128/clean/vector.c
)

set(HQC_192_SRCS
    src/crypto_kem/hqc-192/clean/code.c
    src/crypto_kem/hqc-192/clean/fft.c
    src/crypto_kem/hqc-192/clean/gf.c
    src/crypto_kem/hqc-192/clean/gf2x.c
    src/crypto_kem/hqc-192/clean/hqc.c
    src/crypto_kem/hqc-192/clean/kem.c
    src/crypto_kem/hqc-192/clean/parsing.c
    src/crypto_kem/hqc-192/clean/reed_muller.c
    src/crypto_kem/hqc-192/clean/reed_solomon.c
    src/crypto_kem/hqc-192/clean/shake_ds.c
    src/crypto_kem/hqc-192/clean/shake_prng.c
    src/crypto_kem/hqc-192/clean/vector.c
)

set(HQC_256_SRCS
    src/crypto_kem/hqc-256/clean/code.c
    src/crypto_kem/hqc-256/clean/fft.c
    src/crypto_kem/hqc-256/clean/gf.c
    src/crypto_kem/hqc-256/clean/gf2x.c
    src/crypto_kem/hqc-256/clean/hqc.c
    src/crypto_kem/hqc-256/clean/kem.c
    src/crypto_kem/hqc-256/clean/parsing.c
    src/crypto_kem/hqc-256/clean/reed_muller.c
    src/crypto_kem/hqc-256/clean/reed_solomon.c
    src/crypto_kem/hqc-256/clean/shake_ds.c
    src/crypto_kem/hqc-256/clean/shake_prng.c
    src/crypto_kem/hqc-256/clean/vector.c
)

set(MLKEM512_SRCS
    src/crypto_kem/ml-kem-512/clean/cbd.c
    src/crypto_kem/ml-kem-512/clean/indcpa.c
    src/crypto_kem/ml-kem-512/clean/kem.c
    src/crypto_kem/ml-kem-512/clean/ntt.c
    src/crypto_kem/ml-kem-512/clean/poly.c
    src/crypto_kem/ml-kem-512/clean/polyvec.c
    src/crypto_kem/ml-kem-512/clean/reduce.c
    src/crypto_kem/ml-kem-512/clean/symmetric-shake.c
    src/crypto_kem/ml-kem-512/clean/verify.c
)

set(MLKEM768_SRCS
    src/crypto_kem/ml-kem-768/clean/cbd.c
    src/crypto_kem/ml-kem-768/clean/indcpa.c
    src/crypto_kem/ml-kem-768/clean/kem.c
    src/crypto_kem/ml-kem-768/clean/ntt.c
    src/crypto_kem/ml-kem-768/clean/poly.c
    src/crypto_kem/ml-kem-768/clean/polyvec.c
    src/crypto_kem/ml-kem-768/clean/reduce.c
    src/crypto_kem/ml-kem-768/clean/symmetric-shake.c
    src/crypto_kem/ml-kem-768/clean/verify.c
)

set(MLKEM1024_SRCS
    src/crypto_kem/ml-kem-1024/clean/cbd.c
    src/crypto_kem/ml-kem-1024/clean/indcpa.c
    src/crypto_kem/ml-kem-1024/clean/kem.c
    src/crypto_kem/ml-kem-1024/clean/ntt.c
    src/crypto_kem/ml-kem-1024/clean/poly.c
    src/crypto_kem/ml-kem-1024/clean/polyvec.c
    src/crypto_kem/ml-kem-1024/clean/reduce.c
    src/crypto_kem/ml-kem-1024/clean/symmetric-shake.c
    src/crypto_kem/ml-kem-1024/clean/verify.c
)

set(MCELIECE348864_SRCS
    src/crypto_kem/mceliece348864/clean/aes256ctr.c
    src/crypto_kem/mceliece348864/clean/benes.c
    src/crypto_kem/mceliece348864/clean/bm.c
    src/crypto_kem/mceliece348864/clean/controlbits.c
    src/crypto_kem/mceliece348864/clean/crypto_int16.c
    src/crypto_kem/mceliece348864/clean/crypto_int32.c
    src/crypto_kem/mceliece348864/clean/crypto_uint16.c
    src/crypto_kem/mceliece348864/clean/crypto_uint32.c
    src/crypto_kem/mceliece348864/clean/crypto_uint64.c
    src/crypto_kem/mceliece348864/clean/decrypt.c
    src/crypto_kem/mceliece348864/clean/encrypt.c
    src/crypto_kem/mceliece348864/clean/gf.c
    src/crypto_kem/mceliece348864/clean/operations.c
    src/crypto_kem/mceliece348864/clean/pk_gen.c
    src/crypto_kem/mceliece348864/clean/root.c
    src/crypto_kem/mceliece348864/clean/sk_gen.c
    src/crypto_kem/mceliece348864/clean/synd.c
    src/crypto_kem/mceliece348864/clean/transpose.c
    src/crypto_kem/mceliece348864/clean/util.c
)

set(MCELIECE348864F_SRCS
    src/crypto_kem/mceliece348864f/clean/aes256ctr.c
    src/crypto_kem/mceliece348864f/clean/benes.c
    src/crypto_kem/mceliece348864f/clean/bm.c
    src/crypto_kem/mceliece348864f/clean/controlbits.c
    src/crypto_kem/mceliece348864f/clean/crypto_int16.c
    src/crypto_kem/mceliece348864f/clean/crypto_int32.c
    src/crypto_kem/mceliece348864f/clean/crypto_uint16.c
    src/crypto_kem/mceliece348864f/clean/crypto_uint32.c
    src/crypto_kem/mceliece348864f/clean/crypto_uint64.c
    src/crypto_kem/mceliece348864f/clean/decrypt.c
    src/crypto_kem/mceliece348864f/clean/encrypt.c
    src/crypto_kem/mceliece348864f/clean/gf.c
    src/crypto_kem/mceliece348864f/clean/operations.c
    src/crypto_kem/mceliece348864f/clean/pk_gen.c
    src/crypto_kem/mceliece348864f/clean/root.c
    src/crypto_kem/mceliece348864f/clean/sk_gen.c
    src/crypto_kem/mceliece348864f/clean/synd.c
    src/crypto_kem/mceliece348864f/clean/transpose.c
    src/crypto_kem/mceliece348864f/clean/util.c
)

set(MCELIECE460896_SRCS
    src/crypto_kem/mceliece460896/clean/aes256ctr.c
    src/crypto_kem/mceliece460896/clean/benes.c
    src/crypto_kem/mceliece460896/clean/bm.c
    src/crypto_kem/mceliece460896/clean/controlbits.c
    src/crypto_kem/mceliece460896/clean/crypto_int16.c
    src/crypto_kem/mceliece460896/clean/crypto_int32.c
    src/crypto_kem/mceliece460896/clean/crypto_uint16.c
    src/crypto_kem/mceliece460896/clean/crypto_uint32.c
    src/crypto_kem/mceliece460896/clean/crypto_uint64.c
    src/crypto_kem/mceliece460896/clean/decrypt.c
    src/crypto_kem/mceliece460896/clean/encrypt.c
    src/crypto_kem/mceliece460896/clean/gf.c
    src/crypto_kem/mceliece460896/clean/operations.c
    src/crypto_kem/mceliece460896/clean/pk_gen.c
    src/crypto_kem/mceliece460896/clean/root.c
    src/crypto_kem/mceliece460896/clean/sk_gen.c
    src/crypto_kem/mceliece460896/clean/synd.c
    src/crypto_kem/mceliece460896/clean/transpose.c
    src/crypto_kem/mceliece460896/clean/util.c
)

set(MCELIECE460896F_SRCS
    src/crypto_kem/mceliece460896f/clean/aes256ctr.c
    src/crypto_kem/mceliece460896f/clean/benes.c
    src/crypto_kem/mceliece460896f/clean/bm.c
    src/crypto_kem/mceliece460896f/clean/controlbits.c
    src/crypto_kem/mceliece460896f/clean/crypto_int16.c
    src/crypto_kem/mceliece460896f/clean/crypto_int32.c
    src/crypto_kem/mceliece460896f/clean/crypto_uint16.c
    src/crypto_kem/mceliece460896f/clean/crypto_uint32.c
    src/crypto_kem/mceliece460896f/clean/crypto_uint64.c
    src/crypto_kem/mceliece460896f/clean/decrypt.c
    src/crypto_kem/mceliece460896f/clean/encrypt.c
    src/crypto_kem/mceliece460896f/clean/gf.c
    src/crypto_kem/mceliece460896f/clean/operations.c
    src/crypto_kem/mceliece460896f/clean/pk_gen.c
    src/crypto_kem/mceliece460896f/clean/root.c
    src/crypto_kem/mceliece460896f/clean/sk_gen.c
    src/crypto_kem/mceliece460896f/clean/synd.c
    src/crypto_kem/mceliece460896f/clean/transpose.c
    src/crypto_kem/mceliece460896f/clean/util.c
)

set(MCELIECE6688128_SRCS
    src/crypto_kem/mceliece6688128/clean/aes256ctr.c
    src/crypto_kem/mceliece6688128/clean/benes.c
    src/crypto_kem/mceliece6688128/clean/bm.c
    src/crypto_kem/mceliece6688128/clean/controlbits.c
    src/crypto_kem/mceliece6688128/clean/crypto_int16.c
    src/crypto_kem/mceliece6688128/clean/crypto_int32.c
    src/crypto_kem/mceliece6688128/clean/crypto_uint16.c
    src/crypto_kem/mceliece6688128/clean/crypto_uint32.c
    src/crypto_kem/mceliece6688128/clean/crypto_uint64.c
    src/crypto_kem/mceliece6688128/clean/decrypt.c
    src/crypto_kem/mceliece6688128/clean/encrypt.c
    src/crypto_kem/mceliece6688128/clean/gf.c
    src/crypto_kem/mceliece6688128/clean/operations.c
    src/crypto_kem/mceliece6688128/clean/pk_gen.c
    src/crypto_kem/mceliece6688128/clean/root.c
    src/crypto_kem/mceliece6688128/clean/sk_gen.c
    src/crypto_kem/mceliece6688128/clean/synd.c
    src/crypto_kem/mceliece6688128/clean/transpose.c
    src/crypto_kem/mceliece6688128/clean/util.c
)

set(MCELIECE6688128F_SRCS
    src/crypto_kem/mceliece6688128f/clean/aes256ctr.c
    src/crypto_kem/mceliece6688128f/clean/benes.c
    src/crypto_kem/mceliece6688128f/clean/bm.c
    src/crypto_kem/mceliece6688128f/clean/controlbits.c
    src/crypto_kem/mceliece6688128f/clean/crypto_int16.c
    src/crypto_kem/mceliece6688128f/clean/crypto_int32.c
    src/crypto_kem/mceliece6688128f/clean/crypto_uint16.c
    src/crypto_kem/mceliece6688128f/clean/crypto_uint32.c
    src/crypto_kem/mceliece6688128f/clean/crypto_uint64.c
    src/crypto_kem/mceliece6688128f/clean/decrypt.c
    src/crypto_kem/mceliece6688128f/clean/encrypt.c
    src/crypto_kem/mceliece6688128f/clean/gf.c
    src/crypto_kem/mceliece6688128f/clean/operations.c
    src/crypto_kem/mceliece6688128f/clean/pk_gen.c
    src/crypto_kem/mceliece6688128f/clean/root.c
    src/crypto_kem/mceliece6688128f/clean/sk_gen.c
    src/crypto_kem/mceliece6688128f/clean/synd.c
    src/crypto_kem/mceliece6688128f/clean/transpose.c
    src/crypto_kem/mceliece6688128f/clean/util.c
)

set(MCELIECE6960119_SRCS
    src/crypto_kem/mceliece6960119/clean/aes256ctr.c
    src/crypto_kem/mceliece6960119/clean/benes.c
    src/crypto_kem/mceliece6960119/clean/bm.c
    src/crypto_kem/mceliece6960119/clean/controlbits.c
    src/crypto_kem/mceliece6960119/clean/crypto_int16.c
    src/crypto_kem/mceliece6960119/clean/crypto_int32.c
    src/crypto_kem/mceliece6960119/clean/crypto_uint16.c
    src/crypto_kem/mceliece6960119/clean/crypto_uint32.c
    src/crypto_kem/mceliece6960119/clean/crypto_uint64.c
    src/crypto_kem/mceliece6960119/clean/decrypt.c
    src/crypto_kem/mceliece6960119/clean/encrypt.c
    src/crypto_kem/mceliece6960119/clean/gf.c
    src/crypto_kem/mceliece6960119/clean/operations.c
    src/crypto_kem/mceliece6960119/clean/pk_gen.c
    src/crypto_kem/mceliece6960119/clean/root.c
    src/crypto_kem/mceliece6960119/clean/sk_gen.c
    src/crypto_kem/mceliece6960119/clean/synd.c
    src/crypto_kem/mceliece6960119/clean/transpose.c
    src/crypto_kem/mceliece6960119/clean/util.c
)

set(MCELIECE6960119F_SRCS
    src/crypto_kem/mceliece6960119f/clean/aes256ctr.c
    src/crypto_kem/mceliece6960119f/clean/benes.c
    src/crypto_kem/mceliece6960119f/clean/bm.c
    src/crypto_kem/mceliece6960119f/clean/controlbits.c
    src/crypto_kem/mceliece6960119f/clean/crypto_int16.c
    src/crypto_kem/mceliece6960119f/clean/crypto_int32.c
    src/crypto_kem/mceliece6960119f/clean/crypto_uint16.c
    src/crypto_kem/mceliece6960119f/clean/crypto_uint32.c
    src/crypto_kem/mceliece6960119f/clean/crypto_uint64.c
    src/crypto_kem/mceliece6960119f/clean/decrypt.c
    src/crypto_kem/mceliece6960119f/clean/encrypt.c
    src/crypto_kem/mceliece6960119f/clean/gf.c
    src/crypto_kem/mceliece6960119f/clean/operations.c
    src/crypto_kem/mceliece6960119f/clean/pk_gen.c
    src/crypto_kem/mceliece6960119f/clean/root.c
    src/crypto_kem/mceliece6960119f/clean/sk_gen.c
    src/crypto_kem/mceliece6960119f/clean/synd.c
    src/crypto_kem/mceliece6960119f/clean/transpose.c
    src/crypto_kem/mceliece6960119f/clean/util.c
)

set(MCELIECE8192128_SRCS
    src/crypto_kem/mceliece8192128/clean/aes256ctr.c
    src/crypto_kem/mceliece8192128/clean/benes.c
    src/crypto_kem/mceliece8192128/clean/bm.c
    src/crypto_kem/mceliece8192128/clean/controlbits.c
    src/crypto_kem/mceliece8192128/clean/crypto_int16.c
    src/crypto_kem/mceliece8192128/clean/crypto_int32.c
    src/crypto_kem/mceliece8192128/clean/crypto_uint16.c
    src/crypto_kem/mceliece8192128/clean/crypto_uint32.c
    src/crypto_kem/mceliece8192128/clean/crypto_uint64.c
    src/crypto_kem/mceliece8192128/clean/decrypt.c
    src/crypto_kem/mceliece8192128/clean/encrypt.c
    src/crypto_kem/mceliece8192128/clean/gf.c
    src/crypto_kem/mceliece8192128/clean/operations.c
    src/crypto_kem/mceliece8192128/clean/pk_gen.c
    src/crypto_kem/mceliece8192128/clean/root.c
    src/crypto_kem/mceliece8192128/clean/sk_gen.c
    src/crypto_kem/mceliece8192128/clean/synd.c
    src/crypto_kem/mceliece8192128/clean/transpose.c
    src/crypto_kem/mceliece8192128/clean/util.c
)

set(MCELIECE8192128F_SRCS
    src/crypto_kem/mceliece8192128f/clean/aes256ctr.c
    src/crypto_kem/mceliece8192128f/clean/benes.c
    src/crypto_kem/mceliece8192128f/clean/bm.c
    src/crypto_kem/mceliece8192128f/clean/controlbits.c
    src/crypto_kem/mceliece8192128f/clean/crypto_int16.c
    src/crypto_kem/mceliece8192128f/clean/crypto_int32.c
    src/crypto_kem/mceliece8192128f/clean/crypto_uint16.c
    src/crypto_kem/mceliece8192128f/clean/crypto_uint32.c
    src/crypto_kem/mceliece8192128f/clean/crypto_uint64.c
    src/crypto_kem/mceliece8192128f/clean/decrypt.c
    src/crypto_kem/mceliece8192128f/clean/encrypt.c
    src/crypto_kem/mceliece8192128f/clean/gf.c
    src/crypto_kem/mceliece8192128f/clean/operations.c
    src/crypto_kem/mceliece8192128f/clean/pk_gen.c
    src/crypto_kem/mceliece8192128f/clean/root.c
    src/crypto_kem/mceliece8192128f/clean/sk_gen.c
    src/crypto_kem/mceliece8192128f/clean/synd.c
    src/crypto_kem/mceliece8192128f/clean/transpose.c
    src/crypto_kem/mceliece8192128f/clean/util.c
)

set(MLDSA44_SRCS
    src/crypto_sign/ml-dsa-44/clean/ntt.c
    src/crypto_sign/ml-dsa-44/clean/packing.c
    src/crypto_sign/ml-dsa-44/clean/poly.c
    src/crypto_sign/ml-dsa-44/clean/polyvec.c
    src/crypto_sign/ml-dsa-44/clean/reduce.c
    src/crypto_sign/ml-dsa-44/clean/rounding.c
    src/crypto_sign/ml-dsa-44/clean/sign.c
    src/crypto_sign/ml-dsa-44/clean/symmetric-shake.c
)

set(MLDSA65_SRCS
    src/crypto_sign/ml-dsa-65/clean/ntt.c
    src/crypto_sign/ml-dsa-65/clean/packing.c
    src/crypto_sign/ml-dsa-65/clean/poly.c
    src/crypto_sign/ml-dsa-65/clean/polyvec.c
    src/crypto_sign/ml-dsa-65/clean/reduce.c
    src/crypto_sign/ml-dsa-65/clean/rounding.c
    src/crypto_sign/ml-dsa-65/clean/sign.c
    src/crypto_sign/ml-dsa-65/clean/symmetric-shake.c
)

set(MLDSA87_SRCS
    src/crypto_sign/ml-dsa-87/clean/ntt.c
    src/crypto_sign/ml-dsa-87/clean/packing.c
    src/crypto_sign/ml-dsa-87/clean/poly.c
    src/crypto_sign/ml-dsa-87/clean/polyvec.c
    src/crypto_sign/ml-dsa-87/clean/reduce.c
    src/crypto_sign/ml-dsa-87/clean/rounding.c
    src/crypto_sign/ml-dsa-87/clean/sign.c
    src/crypto_sign/ml-dsa-87/clean/symmetric-shake.c
)

set(FALCON_512_SRCS
    src/crypto_sign/falcon-512/clean/codec.c
    src/crypto_sign/falcon-512/clean/common.c
    src/crypto_sign/falcon-512/clean/fft.c
    src/crypto_sign/falcon-512/clean/fpr.c
    src/crypto_sign/falcon-512/clean/keygen.c
    src/crypto_sign/falcon-512/clean/pqclean.c
    src/crypto_sign/falcon-512/clean/rng.c
    src/crypto_sign/falcon-512/clean/sign.c
    src/crypto_sign/falcon-512/clean/vrfy.c
)

set(FALCON_1024_SRCS
    src/crypto_sign/falcon-1024/clean/codec.c
    src/crypto_sign/falcon-1024/clean/common.c
    src/crypto_sign/falcon-1024/clean/fft.c
    src/crypto_sign/falcon-1024/clean/fpr.c
    src/crypto_sign/falcon-1024/clean/keygen.c
    src/crypto_sign/falcon-1024/clean/pqclean.c
    src/crypto_sign/falcon-1024/clean/rng.c
    src/crypto_sign/falcon-1024/clean/sign.c
    src/crypto_sign/falcon-1024/clean/vrfy.c
)

set(SPHINCS_SHA2_128F_SRCS
    src/crypto_sign/sphincs-sha2-128f-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-128f-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_128S_SRCS
    src/crypto_sign/sphincs-sha2-128s-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-128s-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_192F_SRCS
    src/crypto_sign/sphincs-sha2-192f-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-192f-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_192S_SRCS
    src/crypto_sign/sphincs-sha2-192s-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-192s-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_256F_SRCS
    src/crypto_sign/sphincs-sha2-256f-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-256f-simple/clean/wotsx1.c
)

set(SPHINCS_SHA2_256S_SRCS
    src/crypto_sign/sphincs-sha2-256s-simple/clean/address.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/context_sha2.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/fors.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/hash_sha2.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/merkle.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/sign.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/thash_sha2_simple.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/utils.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/wots.c
    src/crypto_sign/sphincs-sha2-256s-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_128F_SRCS
    src/crypto_sign/sphincs-shake-128f-simple/clean/address.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-128f-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_128S_SRCS
    src/crypto_sign/sphincs-shake-128s-simple/clean/address.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-128s-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_192F_SRCS
    src/crypto_sign/sphincs-shake-192f-simple/clean/address.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-192f-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_192S_SRCS
    src/crypto_sign/sphincs-shake-192s-simple/clean/address.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-192s-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_256F_SRCS
    src/crypto_sign/sphincs-shake-256f-simple/clean/address.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-256f-simple/clean/wotsx1.c
)

set(SPHINCS_SHAKE_256S_SRCS
    src/crypto_sign/sphincs-shake-256s-simple/clean/address.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/context_shake.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/fors.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/hash_shake.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/merkle.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/sign.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/thash_shake_simple.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/utils.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/utilsx1.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/wots.c
    src/crypto_sign/sphincs-shake-256s-simple/clean/wotsx1.c
)

add_library(
    pqclean_common STATIC
    ${PQCLEAN_COMMON_SRCS}
)

target_include_directories(
    pqclean_common
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

add_library(
    hqc_128 STATIC
    ${HQC_128_SRCS}
)

target_include_directories(
    hqc_128
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/hqc-128/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    hqc_128
    PUBLIC pqclean_common
)

add_library(
    hqc_192 STATIC
    ${HQC_192_SRCS}
)

target_include_directories(
    hqc_192
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/hqc-192/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
        hqc_192
        PUBLIC pqclean_common
)


add_library(
    hqc_256 STATIC
    ${HQC_256_SRCS}
)

target_include_directories(
    hqc_256
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/hqc-256/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    hqc_256
    PUBLIC pqclean_common
)

add_library(
    mlkem512 STATIC
    ${MLKEM512_SRCS}
)

target_include_directories(
    mlkem512
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/ml-kem-512/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mlkem512
    PUBLIC pqclean_common
)

add_library(
    mlkem768 STATIC
    ${MLKEM768_SRCS}
)

target_include_directories(
    mlkem768
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/ml-kem-768/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mlkem768
    PUBLIC pqclean_common
)

add_library(
    mlkem1024 STATIC
    ${MLKEM1024_SRCS}
)

target_include_directories(
    mlkem1024
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/ml-kem-1024/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mlkem1024
    PUBLIC pqclean_common
)

add_library(
    mceliece348864 STATIC
    ${MCELIECE348864_SRCS}
)

target_include_directories(
    mceliece348864
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece348864/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece348864
    PUBLIC pqclean_common
)

add_library(
    mceliece348864f STATIC
    ${MCELIECE348864F_SRCS}
)

target_include_directories(
    mceliece348864f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece348864f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece348864f
    PUBLIC pqclean_common
)

add_library(
    mceliece460896 STATIC
    ${MCELIECE460896_SRCS}
)

target_include_directories(
    mceliece460896
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece460896/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece460896
    PUBLIC pqclean_common
)

add_library(
    mceliece460896f STATIC
    ${PQCLEAN_COMMON_SRCS}
    ${MCELIECE460896F_SRCS}
)

target_include_directories(
    mceliece460896f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece460896f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece460896f
    PUBLIC pqclean_common
)

add_library(
    mceliece6688128 STATIC
    ${MCELIECE6688128_SRCS}
)

target_include_directories(
    mceliece6688128
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6688128/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece6688128
    PUBLIC pqclean_common
)

add_library(
    mceliece6688128f STATIC
    ${MCELIECE6688128F_SRCS}
)

target_include_directories(
    mceliece6688128f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6688128f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece6688128f
    PUBLIC pqclean_common
)

add_library(
    mceliece6960119 STATIC
    ${MCELIECE6960119_SRCS}
)

target_include_directories(
    mceliece6960119
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6960119/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece6960119
    PUBLIC pqclean_common
)

add_library(
    mceliece6960119f STATIC
    ${MCELIECE6960119F_SRCS}
)

target_include_directories(
    mceliece6960119f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece6960119f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece6960119f
    PUBLIC pqclean_common
)

add_library(
    mceliece8192128 STATIC
    ${MCELIECE8192128_SRCS}
)

target_include_directories(
    mceliece8192128
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece8192128/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece8192128
    PUBLIC pqclean_common
)

add_library(
    mceliece8192128f STATIC
    ${MCELIECE8192128F_SRCS}
)

target_include_directories(
    mceliece8192128f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_kem/mceliece8192128f/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mceliece8192128f
    PUBLIC pqclean_common
)

add_library(
    mldsa44 STATIC
    ${MLDSA44_SRCS}
)

target_include_directories(
    mldsa44
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/ml-dsa-44/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mldsa44
    PUBLIC pqclean_common
)

add_library(
    mldsa65 STATIC
    ${MLDSA65_SRCS}
)

target_include_directories(
    mldsa65
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/ml-dsa-65/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    mldsa65
    PUBLIC pqclean_common
)

add_library(
    mldsa87 STATIC
    ${MLDSA87_SRCS}
)

target_include_directories(
    mldsa87
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/ml-dsa-87/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
        mldsa87
        PUBLIC pqclean_common
)

add_library(
    falcon512 STATIC
    ${FALCON_512_SRCS}
)

target_include_directories(
    falcon512
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/falcon-512/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    falcon512
    PUBLIC pqclean_common
)

add_library(
    falcon1024 STATIC
    ${FALCON_1024_SRCS}
)

target_include_directories(
    falcon1024
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/falcon-1024/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    falcon1024
    PUBLIC pqclean_common
)

add_library(
    sphincs_sha2_128f STATIC
    ${SPHINCS_SHA2_128F_SRCS}
)

target_include_directories(
    sphincs_sha2_128f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-128f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_sha2_128f
    PUBLIC pqclean_common
)

add_library(
    sphincs_sha2_128s STATIC
    ${SPHINCS_SHA2_128S_SRCS}
)

target_include_directories(
    sphincs_sha2_128s
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-128s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_sha2_128s
    PUBLIC pqclean_common
)

add_library(
    sphincs_sha2_192f STATIC
    ${SPHINCS_SHA2_192F_SRCS}
)

target_include_directories(
    sphincs_sha2_192f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-192f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_sha2_192f
    PUBLIC pqclean_common
)

add_library(
    sphincs_sha2_192s STATIC
    ${SPHINCS_SHA2_192S_SRCS}
)

target_include_directories(
    sphincs_sha2_192s
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-192s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
        sphincs_sha2_192s
        PUBLIC pqclean_common
)

add_library(
    sphincs_sha2_256f STATIC
    ${SPHINCS_SHA2_256F_SRCS}
)

target_include_directories(
    sphincs_sha2_256f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-256f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_sha2_256f
    PUBLIC pqclean_common
)

add_library(
    sphincs_sha2_256s STATIC
    ${SPHINCS_SHA2_256S_SRCS}
)

target_include_directories(
    sphincs_sha2_256s
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-sha2-256s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_sha2_256s
    PUBLIC pqclean_common
)

add_library(
    sphincs_shake_128f STATIC
    ${SPHINCS_SHAKE_128F_SRCS}
)

target_include_directories(
    sphincs_shake_128f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-128f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_shake_128f
    PUBLIC pqclean_common
)

add_library(
    sphincs_shake_128s STATIC
    ${SPHINCS_SHAKE_128S_SRCS}
)

target_include_directories(
    sphincs_shake_128s
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-128s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
        sphincs_shake_128s
        PUBLIC pqclean_common
)

add_library(
    sphincs_shake_192f STATIC
    ${SPHINCS_SHAKE_192F_SRCS}
)

target_include_directories(
    sphincs_shake_192f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-192f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_shake_192f
    PUBLIC pqclean_common
)

add_library(
    sphincs_shake_192s STATIC
    ${SPHINCS_SHAKE_192S_SRCS}
)

target_include_directories(
    sphincs_shake_192s
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-192s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_shake_192s
    PUBLIC pqclean_common
)

add_library(
    sphincs_shake_256f STATIC
    ${SPHINCS_SHAKE_256F_SRCS}
)

target_include_directories(
    sphincs_shake_256f
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-256f-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_shake_256f
    PUBLIC pqclean_common
)

add_library(sphincs_shake_256s STATIC
    ${SPHINCS_SHAKE_256S_SRCS}
)

target_include_directories(
    sphincs_shake_256s
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_sign/sphincs-shake-256s-simple/clean>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
)

target_link_libraries(
    sphincs_shake_256s
    PUBLIC pqclean_common
)

add_library(
    pqclean INTERFACE
)

target_link_libraries(
    pqclean INTERFACE
    hqc_128 hqc_192 hqc_256 mlkem512 mlkem768 mlkem1024
    mceliece348864 mceliece348864f mceliece460896 mceliece460896f mceliece6688128 mceliece6688128f
    mceliece6960119 mceliece6960119f mceliece8192128 mceliece8192128f
    mldsa44 mldsa65 mldsa87 falcon512 falcon1024
    sphincs_sha2_128f sphincs_sha2_128s sphincs_sha2_192f sphincs_sha2_192s sphincs_sha2_256f sphincs_sha2_256s
    sphincs_shake_128f sphincs_shake_128s sphincs_shake_192f sphincs_shake_192s sphincs_shake_256f sphincs_shake_256s
)

install(TARGETS pqclean hqc_128 hqc_192 hqc_256 mlkem512 mlkem768 mlkem1024
        mceliece348864 mceliece348864f mceliece460896 mceliece460896f mceliece6688128 mceliece6688128f
        mceliece6960119 mceliece6960119f mceliece8192128 mceliece8192128f
        mldsa44 mldsa65 mldsa87 falcon512 falcon1024
        sphincs_sha2_128f sphincs_sha2_128s sphincs_sha2_192f sphincs_sha2_192s sphincs_sha2_256f sphincs_sha2_256s
        sphincs_shake_128f sphincs_shake_128s sphincs_shake_192f sphincs_shake_192s sphincs_shake_256f sphincs_shake_256s
  CONFIGURATIONS ${CMAKE_BUILD_TYPE}
  EXPORT pqcleanTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
