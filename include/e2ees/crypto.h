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
#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/** length of a sha256 hash */
#define SHA256_OUTPUT_LENGTH 32

/** length of a public or private Curve25519 key */
#define CURVE25519_KEY_LENGTH 32

/** length of a Curve25519 signature */
#define CURVE_SIGNATURE_LENGTH 64

/** length of an aes256 key */
#define AES256_KEY_LENGTH 32

/** length of an aes256 initialisation vector */
#define AES256_IV_LENGTH 16

/** length of an aes256 gcm tag */
#define AES256_GCM_TAG_LENGTH 16

/** length of an aes256 initialisation vector for file encryption */
#define AES256_DATA_IV_LENGTH 12

/** amount of random data required to create a Curve25519 keypair */
#define CURVE25519_RANDOM_LENGTH CURVE25519_KEY_LENGTH

#define AES256_FILE_AD "E2EES ---> file encryption with AES256/GCM/Nopadding algorithm"
#define AES256_FILE_AD_LEN 64
#define AES256_FILE_KDF_INFO "FILE"

#define AES256_DATA_AD "E2EES ---> data encryption with AES256/GCM/Nopadding algorithm"
#define AES256_DATA_AD_LEN 64

/** buffer length for file encryption/decryption */
#define FILE_ENCRYPTION_BUFFER_LENGTH 8192

/**
 * @brief Generate a random key pair for Curve25519 digital signature.
 * @param pub_key The generated public key.
 * @param priv_key The generated private key.
 * @return 0 if success.
 */
int crypto_ds_key_gen_curve25519(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key);

/**
 * @brief Generate a random key pair for Curve25519 KEM.
 * @param pub_key The generated public key.
 * @param priv_key The generated private key.
 * @return 0 if success.
 */
int crypto_kem_asym_key_gen_curve25519(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key);

/**
 * @brief Sign a message using Curve25519.
 * @param signature_out Output signature buffer.
 * @param signature_out_len Output signature length.
 * @param msg The message to sign.
 * @param msg_len The message length.
 * @param private_key The private key.
 * @return 0 if success.
 */
int crypto_ds_sign_curve25519(
    uint8_t *signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key
);

/**
 * @brief Verify a signature using Curve25519.
 * @param signature_in The signature to verify.
 * @param signature_in_len The signature length.
 * @param msg The message.
 * @param msg_len The message length.
 * @param public_key The public key.
 * @return 0 if success, non-zero on failure.
 */
int crypto_ds_verify_curve25519(
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key
);

/**
 * @brief Decapsulate a shared secret using Curve25519 KEM.
 * @param shared_secret Buffer to store the decapsulated secret.
 * @param our_key Our private key.
 * @param ciphertext The incoming ciphertext.
 * @return 0 if success.
 */
int crypto_kem_decaps_curve25519(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
);

/**
 * @brief Sign a message using Curve25519 (raw form).
 * @param private_key The private key.
 * @param msg The message.
 * @param msg_len The message length.
 * @param signature_out The generated signature.
 */
void crypto_sign_curve25519(uint8_t *private_key,
    uint8_t *msg, size_t msg_len, uint8_t *signature_out
);

/**
 * @brief Verify a signature using Curve25519 (raw form).
 * @param signature_in The signature to verify.
 * @param public_key The public key.
 * @param msg The message.
 * @param msg_len The message length.
 * @return 0 if success, non-zero on failure.
 */
int crypto_verify_curve25519(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
);

/**
 * @brief HMAC-based Key Derivation Function (HKDF).
 * https://tools.ietf.org/html/rfc5869
 * Derives key material from the input bytes.
 *
 * @param input
 * @param input_len
 * @param salt
 * @param salt_len
 * @param info
 * @param info_len
 * @param output
 * @param output_len
 */
int crypto_hf_hkdf_sha256(
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *output, size_t output_len
);

/**
 * @brief Keyed-Hashing for Message Authentication (HMAC).
 * http://tools.ietf.org/html/rfc2104
 * Computes HMAC-SHA-256 of the input for the key.
 * The output buffer must be at least SHA256_OUTPUT_LENGTH (32) bytes long.
 *
 * @param key
 * @param key_len
 * @param input
 * @param input_len
 * @param output
 */
int crypto_hf_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
);

/**
 * @brief Secure Hash Algorithms (SHAs)
 * https://www.rfc-editor.org/rfc/rfc6234
 * Computes HMAC-SHA-256 of the input for the key.
 * The output buffer must be at least SHA256_OUTPUT_LENGTH (32) bytes long.
 *
 * @param msg
 * @param msg_len
 * @param hash_out
 */
int crypto_hf_sha256(
    const uint8_t *msg, size_t msg_len,
    uint8_t *hash_out
);

/**
 * @brief AES256 encrypt function in GCM mode.
 * @see [AES256 GCM mode](https://datatracker.ietf.org/doc/html/rfc5288)
 * @param plaintext_data
 * @param plaintext_data_len
 * @param aes_key
 * @param iv
 * @param add
 * @param add_len
 * @param ciphertext_data
 */
int crypto_aes_encrypt_gcm(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *ciphertext_data
);

/**
 * @brief AES256 decrypt function in GCM mode.
 * @see [AES256 GCM mode](https://datatracker.ietf.org/doc/html/rfc5288)
 *
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param aes_key
 * @param iv
 * @param add
 * @param add_len
 * @param plaintext_data
 * @param plaintext_data_len
 * @return size_t plaintext data length
 */
int crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *plaintext_data, size_t *plaintext_data_len
);

/**
 * @brief Calculate ciphertext data len for AES GCM.
 *
 * @param plaintext_data_length
 * @return size_t length of ciphertext data
 */
size_t crypto_aes256_gcm_ciphertext_data_len(size_t plaintext_data_length);

/**
 * @brief Calculate plaintext data len for AES GCM.
 *
 * @param ciphertext_data_len
 * @return size_t length of plaintext data
 */
size_t crypto_aes256_gcm_plaintext_data_len(size_t ciphertext_data_len);

/**
 * @brief AES256 encrypt data in GCM mode.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param aes_key
 * @param iv
 * @param ciphertext_data
 * @return
 */
size_t crypto_encrypt_aes_data_with_iv(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **ciphertext_data
);

/**
 * @brief AES256 encrypt data in GCM mode.
 * The initial vector iv is designated to zeros.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param aes_key
 * @param ciphertext_data
 * @return size_t ciphertext data length
 */
size_t crypto_encrypt_aes_data(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **ciphertext_data
);

/**
 *  @brief AES256 decrypt data in GCM mode.
 *
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param aes_key
 * @param iv
 * @param plaintext_data
 * @return
 */
size_t crypto_decrypt_aes_data_with_iv(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **plaintext_data
);

/**
 * @brief AES256 decrypt data in GCM mode.
 * The initial vector iv is designated to zeros.
 *
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @param aes_key
 * @param plaintext_data
 * @return size_t plaintext data length
 */
size_t crypto_decrypt_aes_data(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **plaintext_data
);

/**
 * @brief AES256 encrypt file in GCM mode.
 * The initial vector iv is designated to zeros.
 *
 * @param in_file_path
 * @param out_file_path
 * @param aes_key
 * @return int 0 for success
 */
int crypto_encrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
);

/**
 * @brief AES256 decrypt file in GCM mode.
 * The initial vector iv is designated to zeros.
 *
 * @param in_file_path
 * @param out_file_path
 * @param aes_key
 * @return int 0 for success
 */
int crypto_decrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
);

/**
 * @brief AES256 encrypt file in GCM mode.
 * The initial vector iv is designated to zeros.
 * The password is an arbitrary vector with non-zero length.
 *
 * @param in_file_path
 * @param out_file_path
 * @param password
 * @param password_len
 * @return int 0 for success
 */
int crypto_encrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
);

/**
 * @brief AES256 decrypt file in GCM mode.
 * The initial vector iv is designated to zeros.
 * The password is an arbitrary vector with non-zero length.
 *
 * @param in_file_path
 * @param out_file_path
 * @param password
 * @param password_len
 * @return int 0 for success
 */
int crypto_decrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
);

/**
 * @brief Encode to base64 string.
 *
 * @param msg
 * @param msg_len
 * @return char*
 */
char *crypto_base64_encode(const uint8_t *msg, size_t msg_len);

/**
 * @brief Decode from base64 string.
 *
 * @param base64_data
 * @param base64_data_len
 * @return char*
 */
size_t crypto_base64_decode(uint8_t **msg_out, const unsigned char *base64_str);

/**
 * @brief Calculate hash with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ees_pack_id_raw
 * @param msg
 * @param msg_len
 * @param hash_out
 * @param hash_out_len
 * @return value < 0 for error
 */
int crypto_hash_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    const uint8_t *msg, size_t msg_len,
    uint8_t **hash_out, size_t *hash_out_len
);

/**
 * @brief Generate a random key pair that will be used to generate or verify a signature
 * with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ees_pack_id_raw
 * @param pub_key
 * @param priv_key
 * @return value < 0 for error
 */
int crypto_ds_key_gen_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    ProtobufCBinaryData *pub_key,
    ProtobufCBinaryData *priv_key
);

/**
 * @brief Sign a message
 * with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ees_pack_id_raw
 * @param signature_out
 * @param signature_out_len
 * @param msg
 * @param msg_len
 * @param private_key
 * @param private_key_len
 * @return value < 0 for error
 */
int crypto_ds_sign_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    uint8_t **signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key, size_t private_key_len
);

/**
 * @brief Verify a signature with a given message
 * with respect to the specific e2ee pack ID raw number.
 *
 * @param e2ees_pack_id_raw
 * @param signature_in
 * @param signature_in_len
 * @param msg
 * @param msg_len
 * @param public_key
 * @param public_key_len
 * @return value < 0 for error
 */
int crypto_ds_verify_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key, size_t public_key_len
);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H_ */
