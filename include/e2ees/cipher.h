/**
 * @file
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
#ifndef CIPHER_H_
#define CIPHER_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/**
 * @brief Type definition of digital signature algorithm parameters.
 */
typedef struct crypto_ds_param_t {
    bool pqc_param;
    uint32_t sign_pub_key_len;
    uint32_t sign_priv_key_len;
    uint32_t sig_len;
} crypto_ds_param_t;

/**
 * @brief Type definition of kem algorithm parameters.
 */
typedef struct crypto_kem_param_t {
    bool pqc_param;
    uint32_t asym_pub_key_len;
    uint32_t asym_priv_key_len;
    uint32_t kem_ciphertext_len;
    uint32_t shared_secret_len;
} crypto_kem_param_t;

/**
 * @brief Type definition of symmetric encryption algorithm parameters.
 */
typedef struct crypto_se_param_t {
    uint32_t aead_key_len;
    uint32_t aead_iv_len;
    uint32_t aead_tag_len;
} crypto_se_param_t;

/**
 * @brief Type definition of hash function parameters.
 */
typedef struct crypto_hf_param_t {
    uint32_t hf_len;
} crypto_hf_param_t;

/**
 * @brief Type definition of digital signature algorithm suite.
 */
typedef struct ds_suite_t {
    /**
     * @brief Get the parameters of this digital signature algorithm suite.
     * @return crypto_ds_param_t
     */
    struct crypto_ds_param_t (*get_param)(void);

    /**
     * @brief Generate a random key pair that will be used to generate or verify a signature.
     *
     * @param pub_key
     * @param priv_key
     * @return value < 0 for error
     */
    int (*ds_key_gen)(
        ProtobufCBinaryData *pub_key,
        ProtobufCBinaryData *priv_key
    );

    /**
     * @brief Sign a message.
     *
     * @param signature_out
     * @param signature_out_len
     * @param msg
     * @param msg_len
     * @param private_key
     * @return value < 0 for error
     */
    int (*sign)(
        uint8_t *signature_out, size_t *signature_out_len,
        const uint8_t *msg, size_t msg_len,
        const uint8_t *private_key
    );

    /**
     * @brief Verify a signature with a given message.
     *
     * @param signature_in
     * @param signature_in_len
     * @param msg
     * @param msg_len
     * @param public_key
     * @return value < 0 for error
     */
    int (*verify)(
        const uint8_t *signature_in, size_t signature_in_len,
        const uint8_t *msg, size_t msg_len,
        const uint8_t *public_key
    );
} ds_suite_t;

/**
 * @brief Type definition of kem algorithm suite.
 */
typedef struct kem_suite_t {
    /**
     * @brief Get the parameters of this kem suite.
     * @return crypto_kem_param_t
     */
    struct crypto_kem_param_t (*get_param)(void);

    /**
     * @brief Generate a random key pair that will be used to calculate shared secret keys.
     *
     * @param pub_key
     * @param priv_key
     */
    int (*asym_key_gen)(
        ProtobufCBinaryData *pub_key,
        ProtobufCBinaryData *priv_key
    );

    /**
    * @brief Encapsulation.
    *
    * @param shared_secret
    * @param ciphertext
    * @param their_key
    * @return value < 0 for error.
    */
    int (*encaps)(
        uint8_t *shared_secret,
        ProtobufCBinaryData *ciphertext,
        const ProtobufCBinaryData *their_key
    );

    /**
    * @brief Decapsulation.
    *
    * @param shared_secret
    * @param our_key
    * @param ciphertext
    * @return value < 0 for error.
    */
    int (*decaps)(
        uint8_t *shared_secret,
        const ProtobufCBinaryData *our_key,
        const ProtobufCBinaryData *ciphertext
    );
} kem_suite_t;

/**
 * @brief Type definition of symmetric encryption algorithm suite.
 */
typedef struct se_suite_t {
    /**
     * @brief Get the parameters of this symmetric encryption suite.
     * @return crypto_se_param_t
     */
    struct crypto_se_param_t (*get_param)(void);

    /**
     * @brief Encrypt a given plaintext.
     *
     * @param ad The associated data
     * @param key The secret key
     * @param plaintext_data The plaintext to encrypt
     * @param plaintext_data_len The plaintext length
     * @param ciphertext_data The output ciphertext
     * @param ciphertext_data_len The output ciphertext length
     * @return Success or not
     */
    int (*encrypt)(
        const ProtobufCBinaryData *,
        const uint8_t *,
        const uint8_t *, size_t,
        uint8_t **, size_t *
    );

    /**
     * @brief Decrypt a given ciphertext.
     *
     * @param decrypted_data_out The output plaintext
     * @param decrypted_data_len_out The output plaintext length
     * @param ad The associated data
     * @param key The secret key
     * @param ciphertext_data The ciphertext to decrypt
     * @param ciphertext_data_len The ciphertext length
     * @return 0 if success or -1 for decryption error
     */
    int (*decrypt)(
        uint8_t **, size_t *,
        const ProtobufCBinaryData *,
        const uint8_t *,
        const uint8_t *, size_t
    );
} se_suite_t;

/**
 * @brief Type definition of hash function suite.
 */
typedef struct hf_suite_t {
    /**
     * @brief Get the parameters of this hash function suite.
     * @return crypto_hf_param_t
     */
    struct crypto_hf_param_t (*get_param)(void);

    /**
     * @brief HMAC-based key derivation function.
     *
     * @param input
     * @param input_len
     * @param salt
     * @param salt_len
     * @param info
     * @param info_len
     * @param output
     * @param output_len
     * @return 0 if success
     */
    int (*hkdf)(
        const uint8_t *input, size_t input_len,
        const uint8_t *salt, size_t salt_len,
        const uint8_t *info, size_t info_len,
        uint8_t *output, size_t output_len
    );

    /**
     * @brief Keyed-Hashing for message authentication.
     *
     * @param key
     * @param key_len
     * @param input
     * @param input_len
     * @param output
     * @return 0 if success
     */
    int (*hmac)(
        const uint8_t *key, size_t key_len,
        const uint8_t *input, size_t input_len,
        uint8_t *output
    );

    /**
     * @brief Hash function.
     *
     * @param msg
     * @param msg_len
     * @param hash_out
     * @return 0 if success
     */
    int (*hash)(
        const uint8_t *msg,
        size_t msg_len,
        uint8_t *hash_out
    );
} hf_suite_t;

/**
 * @brief Type definition of cipher suite.
 */
typedef struct cipher_suite_t {
    ds_suite_t *ds_suite;
    kem_suite_t *kem_suite;
    se_suite_t *se_suite;
    hf_suite_t *hf_suite;
} cipher_suite_t;

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_H_ */
