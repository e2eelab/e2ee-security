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
#ifndef E2EES_CRYPTO_H_
#define E2EES_CRYPTO_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encrypts data using AES-256-GCM.
 * @param plaintext The data to encrypt.
 * @param plaintext_len The length of the plaintext.
 * @param password The encryption key.
 * @param iv The initialization vector.
 * @param add Additional authenticated data.
 * @param add_len The length of the additional authenticated data.
 * @param ciphertext The output buffer for the encrypted data. The caller must free this buffer.
 * @return The length of the ciphertext.
 */
size_t e2ees_encrypt_gcm(
    const uint8_t *plaintext, const size_t plaintext_len,
    const uint8_t *password, const uint8_t *iv,
    const uint8_t *add, const size_t add_len,
    uint8_t **ciphertext
);

/**
 * @brief Decrypts data using AES-256-GCM.
 * @param ciphertext The data to decrypt.
 * @param ciphertext_len The length of the ciphertext.
 * @param password The decryption key.
 * @param iv The initialization vector.
 * @param add Additional authenticated data.
 * @param add_len The length of the additional authenticated data.
 * @param plaintext The output buffer for the decrypted data. The caller must free this buffer.
 * @return The length of the plaintext.
 */
size_t e2ees_decrypt_gcm(
    const uint8_t *ciphertext, const size_t ciphertext_len,
    const uint8_t *password, const uint8_t *iv,
    const uint8_t *add, const size_t add_len,
    uint8_t **plaintext
);

/**
 * @brief Encrypts data with a password.
 * @param plaintext The data to encrypt.
 * @param plaintext_len The length of the plaintext.
 * @param password The encryption key.
 * @param password_len The length of the password.
 * @param ciphertext The output buffer for the encrypted data. The caller must free this buffer.
 * @return The length of the ciphertext, or 0 on failure.
 */
size_t e2ees_encrypt_data(
    const uint8_t *plaintext, const size_t plaintext_len,
    const uint8_t *password, const size_t password_len,
    uint8_t **ciphertext
);

/**
 * @brief Decrypts data with a password.
 * @param ciphertext_data The data to decrypt.
 * @param ciphertext_data_len The length of the ciphertext.
 * @param password The decryption key.
 * @param password_len The length of the password.
 * @param plaintext The output buffer for the decrypted data. The caller must free this buffer.
 * @return The length of the plaintext, or 0 on failure.
 */
size_t e2ees_decrypt_data(
    const uint8_t *ciphertext_data, const size_t ciphertext_data_len,
    const uint8_t *password, const size_t password_len,
    uint8_t **plaintext
);

/**
 * @brief Encrypts a file.
 * @param password The encryption key.
 * @param password_len The length of the password.
 * @param in_file_path The path to the input file.
 * @param out_file_path The path to the output (encrypted) file.
 * @return true on success, false on failure.
 */
bool e2ees_encrypt_file(
    const uint8_t *password, const size_t password_len,
    const char *in_file_path, const char *out_file_path
);

/**
 * @brief Decrypts a file.
 * @param password The decryption key.
 * @param password_len The length of the password.
 * @param in_file_path The path to the input (encrypted) file.
 * @param out_file_path The path to the output (decrypted) file.
 * @return true on success, false on failure.
 */
bool e2ees_decrypt_file(
    const uint8_t *password, const size_t password_len,
    const char *in_file_path, const char *out_file_path
);

/**
 * @brief Computes a hash of a message.
 * @param e2ees_pack_id The e2ee package id to determine the hash algorithm.
 * @param msg The message to hash.
 * @param msg_len The length of the message.
 * @param hash_out The output buffer for the hash. The caller must free this buffer.
 * @return The length of the hash, or 0 on failure.
 */
size_t e2ees_hash(
    uint32_t e2ees_pack_id, const uint8_t *msg, size_t msg_len, uint8_t **hash_out
);

/**
 * @brief Generates a digital signature key pair.
 * @param e2ees_pack_id The e2ee package id to determine the algorithm.
 * @param keypair_out The output buffer for the serialized key pair. The caller must free this buffer.
 * @return The length of the serialized key pair, or 0 on failure.
 */
size_t e2ees_ds_gen_key_pair(uint32_t e2ees_pack_id, uint8_t **keypair_out);

/**
 * @brief Creates a digital signature for a message.
 * @param e2ees_pack_id The e2ee package id to determine the algorithm.
 * @param msg The message to sign.
 * @param msg_len The length of the message.
 * @param private_key The private key for signing.
 * @param private_key_len The length of the private key.
 * @param signature_out The output buffer for the signature. The caller must free this buffer.
 * @return The length of the signature, or 0 on failure.
 */
size_t e2ees_ds_sign(
    uint32_t e2ees_pack_id, const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key, size_t private_key_len, uint8_t **signature_out
);

/**
 * @brief Verifies a digital signature.
 * @param e2ees_pack_id The e2ee package id to determine the algorithm.
 * @param signature_in The signature to verify.
 * @param signature_in_len The length of the signature.
 * @param msg The original message.
 * @param msg_len The length of the message.
 * @param public_key The public key for verification.
 * @param public_key_len The length of the public key.
 * @return 0 on successful verification, non-zero otherwise.
 */
int e2ees_ds_verify(
    uint32_t e2ees_pack_id, const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *public_key, size_t public_key_len
);

/**
 * @brief Generates a KEM key pair.
 * @param e2ees_pack_id The e2ee package id to determine the algorithm.
 * @param keypair_out The output buffer for the serialized key pair. The caller must free this buffer.
 * @return The length of the serialized key pair, or 0 on failure.
 */
size_t e2ees_kem_gen_key_pair(uint32_t e2ees_pack_id, uint8_t **keypair_out);

/**
 * @brief Encapsulates a shared secret.
 * @param e2ees_pack_id The e2ee package id to determine the algorithm.
 * @param shared_secret_out The output buffer for the shared secret. The caller must free this buffer.
 * @param ciphertext_out The output buffer for the ciphertext. The caller must free this buffer.
 * @param public_key The public key for encapsulation.
 * @param public_key_len The length of the public key.
 * @return The length of the ciphertext, or 0 on failure.
 */
size_t e2ees_kem_encaps(
    uint32_t e2ees_pack_id, uint8_t **shared_secret_out, uint8_t **ciphertext_out,
    const uint8_t *public_key, size_t public_key_len
);

/**
 * @brief Decapsulates a shared secret.
 * @param e2ees_pack_id The e2ee package id to determine the algorithm.
 * @param shared_secret_out The output buffer for the shared secret. The caller must free this buffer.
 * @param ciphertext The ciphertext to decapsulate.
 * @param ciphertext_len The length of the ciphertext.
 * @param private_key The private key for decapsulation.
 * @param private_key_len The length of the private key.
 * @return The length of the shared secret, or 0 on failure.
 */
size_t e2ees_kem_decaps(
    uint32_t e2ees_pack_id, uint8_t **shared_secret_out,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *private_key, size_t private_key_len
);

#ifdef __cplusplus
}
#endif

#endif /* E2EES_CRYPTO_H_ */