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

#include <PQClean/src/crypto_sign/falcon-1024/clean/api.h>
#include <PQClean/src/crypto_sign/falcon-512/clean/api.h>
#include <PQClean/src/crypto_sign/ml-dsa-44/clean/api.h>
#include <PQClean/src/crypto_sign/ml-dsa-65/clean/api.h>
#include <PQClean/src/crypto_sign/ml-dsa-87/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-sha2-128f-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-sha2-128s-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-sha2-192f-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-sha2-192s-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-sha2-256f-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-sha2-256s-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-shake-128f-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-shake-128s-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-shake-192f-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-shake-192s-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-shake-256f-simple/clean/api.h>
#include <PQClean/src/crypto_sign/sphincs-shake-256s-simple/clean/api.h>

#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"

static crypto_ds_param_t mldsa44_param           = { true,
                                                     PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                     PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
                                                     PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES };

static crypto_ds_param_t mldsa65_param           = { true,
                                                     PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                     PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
                                                     PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES };

static crypto_ds_param_t mldsa87_param           = { true,
                                                     PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                     PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
                                                     PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES };

static crypto_ds_param_t falcon512_param         = { true,
                                                     PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                     PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES,
                                                     PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES };

static crypto_ds_param_t falcon1024_param        = { true,
                                                     PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                     PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                                                     PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES };

static crypto_ds_param_t sphincs_sha2_128f_param = {
    true,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_128s_param = {
    true,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_192f_param = {
    true,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_192s_param = {
    true,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_256f_param = {
    true,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_sha2_256s_param = {
    true,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_128f_param = {
    true,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_128s_param = {
    true,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_192f_param = {
    true,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_192s_param = {
    true,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_256f_param = {
    true,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t sphincs_shake_256s_param = {
    true,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES
};

static crypto_ds_param_t crypto_ds_params_mldsa44() { return mldsa44_param; }

static crypto_ds_param_t crypto_ds_params_mldsa65() { return mldsa65_param; }

static crypto_ds_param_t crypto_ds_params_mldsa87() { return mldsa87_param; }

static crypto_ds_param_t crypto_ds_params_falcon512() { return falcon512_param; }

static crypto_ds_param_t crypto_ds_params_falcon1024() { return falcon1024_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_sha2_128f() { return sphincs_sha2_128f_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_sha2_128s() { return sphincs_sha2_128s_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_sha2_192f() { return sphincs_sha2_192f_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_sha2_192s() { return sphincs_sha2_192s_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_sha2_256f() { return sphincs_sha2_256f_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_sha2_256s() { return sphincs_sha2_256s_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_shake_128f() { return sphincs_shake_128f_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_shake_128s() { return sphincs_shake_128s_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_shake_192f() { return sphincs_shake_192f_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_shake_192s() { return sphincs_shake_192s_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_shake_256f() { return sphincs_shake_256f_param; }

static crypto_ds_param_t crypto_ds_params_sphincs_shake_256s() { return sphincs_shake_256s_param; }

static int crypto_ds_key_gen_mldsa44(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int crypto_ds_key_gen_mldsa65(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int crypto_ds_key_gen_mldsa87(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_falcon512(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_falcon1024(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data =
        (uint8_t *)malloc(sizeof(uint8_t) * PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_sha2_128f(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data = (uint8_t *)malloc(
        sizeof(uint8_t) * PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    priv_key->len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(
        sizeof(uint8_t) * PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);
    pub_key->len = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES;

    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_sha2_128s(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_sha2_192f(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_sha2_192s(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_sha2_256f(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_sha2_256s(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_shake_128f(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_shake_128s(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_shake_192f(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_shake_192s(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_shake_256f(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

static int
crypto_ds_key_gen_sphincs_shake_256s(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    malloc_protobuf(priv_key, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES);
    malloc_protobuf(pub_key, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);

    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pub_key->data, priv_key->data);
}

// default digital signature suites with pqc

struct ds_suite_t E2EES_DS_MLDSA44           = { crypto_ds_params_mldsa44,
                                                 crypto_ds_key_gen_mldsa44,
                                                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature,
                                                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify };

struct ds_suite_t E2EES_DS_MLDSA65           = { crypto_ds_params_mldsa65,
                                                 crypto_ds_key_gen_mldsa65,
                                                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature,
                                                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify };

struct ds_suite_t E2EES_DS_MLDSA87           = { crypto_ds_params_mldsa87,
                                                 crypto_ds_key_gen_mldsa87,
                                                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature,
                                                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify };

struct ds_suite_t E2EES_DS_FALCON512         = { crypto_ds_params_falcon512,
                                                 crypto_ds_key_gen_falcon512,
                                                 PQCLEAN_FALCON512_CLEAN_crypto_sign_signature,
                                                 PQCLEAN_FALCON512_CLEAN_crypto_sign_verify };

struct ds_suite_t E2EES_DS_FALCON1024        = { crypto_ds_params_falcon1024,
                                                 crypto_ds_key_gen_falcon1024,
                                                 PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature,
                                                 PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify };

struct ds_suite_t E2EES_DS_SPHINCS_SHA2_128F = {
    crypto_ds_params_sphincs_sha2_128f,
    crypto_ds_key_gen_sphincs_sha2_128f,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHA2_128S = {
    crypto_ds_params_sphincs_sha2_128s,
    crypto_ds_key_gen_sphincs_sha2_128s,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHA2_192F = {
    crypto_ds_params_sphincs_sha2_192f,
    crypto_ds_key_gen_sphincs_sha2_192f,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHA2_192S = {
    crypto_ds_params_sphincs_sha2_192s,
    crypto_ds_key_gen_sphincs_sha2_192s,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHA2_256F = {
    crypto_ds_params_sphincs_sha2_256f,
    crypto_ds_key_gen_sphincs_sha2_256f,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHA2_256S = {
    crypto_ds_params_sphincs_sha2_256s,
    crypto_ds_key_gen_sphincs_sha2_256s,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_128F = {
    crypto_ds_params_sphincs_shake_128f,
    crypto_ds_key_gen_sphincs_shake_128f,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_128S = {
    crypto_ds_params_sphincs_shake_128s,
    crypto_ds_key_gen_sphincs_shake_128s,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_192F = {
    crypto_ds_params_sphincs_shake_192f,
    crypto_ds_key_gen_sphincs_shake_192f,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_192S = {
    crypto_ds_params_sphincs_shake_192s,
    crypto_ds_key_gen_sphincs_shake_192s,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_256F = {
    crypto_ds_params_sphincs_shake_256f,
    crypto_ds_key_gen_sphincs_shake_256f,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify
};

struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_256S = {
    crypto_ds_params_sphincs_shake_256s,
    crypto_ds_key_gen_sphincs_shake_256s,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature,
    PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify
};
