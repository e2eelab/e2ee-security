/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdbool.h>
#include <string.h>

#include <PQClean/src/crypto_kem/hqc-128/clean/api.h>
#include <PQClean/src/crypto_kem/hqc-192/clean/api.h>
#include <PQClean/src/crypto_kem/hqc-256/clean/api.h>
#include <PQClean/src/crypto_kem/ml-kem-512/clean/api.h>
#include <PQClean/src/crypto_kem/ml-kem-768/clean/api.h>
#include <PQClean/src/crypto_kem/ml-kem-1024/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece348864/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece348864f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece460896/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece460896f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6688128/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6688128f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6960119/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece6960119f/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece8192128/clean/api.h>
#include <PQClean/src/crypto_kem/mceliece8192128f/clean/api.h>

#include "e2ees/cipher.h"

static crypto_kem_param_t hqc128_param = {
    true,
    PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t hqc192_param = {
    true,
    PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t hqc256_param = {
    true,
    PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mlkem512_param = {
    true,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mlkem768_param = {
    true,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mlkem1024_param = {
    true,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece348864_param = {
    true,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece348864f_param = {
    true,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece460896_param = {
    true,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece460896f_param = {
    true,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6688128_param = {
    true,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6688128f_param = {
    true,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6960119_param = {
    true,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece6960119f_param = {
    true,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece8192128_param = {
    true,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t mceliece8192128f_param = {
    true,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES
};

static crypto_kem_param_t crypto_kem_params_hqc128() {
    return hqc128_param;
}

static crypto_kem_param_t crypto_kem_params_hqc192() {
    return hqc192_param;
}

static crypto_kem_param_t crypto_kem_params_hqc256() {
    return hqc256_param;
}

static crypto_kem_param_t crypto_kem_params_mlkem512() {
    return mlkem512_param;
}

static crypto_kem_param_t crypto_kem_params_mlkem768() {
    return mlkem768_param;
}

static crypto_kem_param_t crypto_kem_params_mlkem1024() {
    return mlkem1024_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece348864() {
    return mceliece348864_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece348864f() {
    return mceliece348864f_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece460896() {
    return mceliece460896_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece460896f() {
    return mceliece460896f_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece6688128() {
    return mceliece6688128_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece6688128f() {
    return mceliece6688128f_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece6960119() {
    return mceliece6960119_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece6960119f() {
    return mceliece6960119f_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece8192128() {
    return mceliece8192128_param;
}

static crypto_kem_param_t crypto_kem_params_mceliece8192128f() {
    return mceliece8192128f_param;
}

static int crypto_kem_asym_key_gen_hqc128(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_hqc192(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_hqc256(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mlkem512(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mlkem768(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mlkem1024(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece348864(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece348864f(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece460896(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece460896f(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece6688128(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece6688128f(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece6960119(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece6960119f(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece8192128(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_asym_key_gen_mceliece8192128f(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pub_key->data, priv_key->data);
}

static int crypto_kem_encaps_hqc128(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_hqc192(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_hqc256(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mlkem512(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mlkem768(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mlkem1024(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece348864(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece348864f(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece460896(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece460896f(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece6688128(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece6688128f(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece6960119(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece6960119f(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece8192128(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_encaps_mceliece8192128f(
    uint8_t *shared_secret,
    ProtobufCBinaryData *ciphertext,
    const ProtobufCBinaryData *their_key
) {
    ciphertext->data = (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ciphertext->len = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ciphertext->data, shared_secret, their_key->data);
}

static int crypto_kem_decaps_hqc128(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_hqc192(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_hqc256(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mlkem512(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mlkem768(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mlkem1024(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece348864(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece348864f(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece460896(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece460896f(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece6688128(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece6688128f(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece6960119(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece6960119f(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece8192128(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

static int crypto_kem_decaps_mceliece8192128f(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(shared_secret, ciphertext->data, our_key->data);
}

// default kem suites with pqc

struct kem_suite_t E2EES_KEM_HQC128 = {
    crypto_kem_params_hqc128,
    crypto_kem_asym_key_gen_hqc128,
    crypto_kem_encaps_hqc128,
    crypto_kem_decaps_hqc128
};

struct kem_suite_t E2EES_KEM_HQC192 = {
    crypto_kem_params_hqc192,
    crypto_kem_asym_key_gen_hqc192,
    crypto_kem_encaps_hqc192,
    crypto_kem_decaps_hqc192
};

struct kem_suite_t E2EES_KEM_HQC256 = {
    crypto_kem_params_hqc256,
    crypto_kem_asym_key_gen_hqc256,
    crypto_kem_encaps_hqc256,
    crypto_kem_decaps_hqc256
};

struct kem_suite_t E2EES_KEM_MLKEM512 = {
    crypto_kem_params_mlkem512,
    crypto_kem_asym_key_gen_mlkem512,
    crypto_kem_encaps_mlkem512,
    crypto_kem_decaps_mlkem512
};

struct kem_suite_t E2EES_KEM_MLKEM768 = {
    crypto_kem_params_mlkem768,
    crypto_kem_asym_key_gen_mlkem768,
    crypto_kem_encaps_mlkem768,
    crypto_kem_decaps_mlkem768
};

struct kem_suite_t E2EES_KEM_MLKEM1024 = {
    crypto_kem_params_mlkem1024,
    crypto_kem_asym_key_gen_mlkem1024,
    crypto_kem_encaps_mlkem1024,
    crypto_kem_decaps_mlkem1024
};

struct kem_suite_t E2EES_KEM_MCELIECE348864 = {
    crypto_kem_params_mceliece348864,
    crypto_kem_asym_key_gen_mceliece348864,
    crypto_kem_encaps_mceliece348864,
    crypto_kem_decaps_mceliece348864
};

struct kem_suite_t E2EES_KEM_MCELIECE348864F = {
    crypto_kem_params_mceliece348864f,
    crypto_kem_asym_key_gen_mceliece348864f,
    crypto_kem_encaps_mceliece348864f,
    crypto_kem_decaps_mceliece348864f
};

struct kem_suite_t E2EES_KEM_MCELIECE460896 = {
    crypto_kem_params_mceliece460896,
    crypto_kem_asym_key_gen_mceliece460896,
    crypto_kem_encaps_mceliece460896,
    crypto_kem_decaps_mceliece460896
};

struct kem_suite_t E2EES_KEM_MCELIECE460896F = {
    crypto_kem_params_mceliece460896f,
    crypto_kem_asym_key_gen_mceliece460896f,
    crypto_kem_encaps_mceliece460896f,
    crypto_kem_decaps_mceliece460896f
};

struct kem_suite_t E2EES_KEM_MCELIECE6688128 = {
    crypto_kem_params_mceliece6688128,
    crypto_kem_asym_key_gen_mceliece6688128,
    crypto_kem_encaps_mceliece6688128,
    crypto_kem_decaps_mceliece6688128
};

struct kem_suite_t E2EES_KEM_MCELIECE6688128F = {
    crypto_kem_params_mceliece6688128f,
    crypto_kem_asym_key_gen_mceliece6688128f,
    crypto_kem_encaps_mceliece6688128f,
    crypto_kem_decaps_mceliece6688128f
};

struct kem_suite_t E2EES_KEM_MCELIECE6960119 = {
    crypto_kem_params_mceliece6960119,
    crypto_kem_asym_key_gen_mceliece6960119,
    crypto_kem_encaps_mceliece6960119,
    crypto_kem_decaps_mceliece6960119
};

struct kem_suite_t E2EES_KEM_MCELIECE6960119F = {
    crypto_kem_params_mceliece6960119f,
    crypto_kem_asym_key_gen_mceliece6960119f,
    crypto_kem_encaps_mceliece6960119f,
    crypto_kem_decaps_mceliece6960119f
};

struct kem_suite_t E2EES_KEM_MCELIECE8192128 = {
    crypto_kem_params_mceliece8192128,
    crypto_kem_asym_key_gen_mceliece8192128,
    crypto_kem_encaps_mceliece8192128,
    crypto_kem_decaps_mceliece8192128
};

struct kem_suite_t E2EES_KEM_MCELIECE8192128F = {
    crypto_kem_params_mceliece8192128f,
    crypto_kem_asym_key_gen_mceliece8192128f,
    crypto_kem_encaps_mceliece8192128f,
    crypto_kem_decaps_mceliece8192128f
};
