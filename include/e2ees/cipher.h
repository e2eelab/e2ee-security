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

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/**
 * The context strings that are used by the HKDF
 * for deriving next root key and chain key.
 */
#define KDF_INFO_ROOT "ROOT"
#define KDF_INFO_RATCHET "RATCHET"

/**
 * @brief Calculate ciphertext data len for AES GCM.
 *
 * @param plaintext_data_length
 * @return size_t length of ciphertext data
 */
size_t aes256_gcm_ciphertext_data_len(size_t plaintext_data_length);

/**
 * @brief Calculate plaintext data len for AES GCM.
 *
 * @param ciphertext_data_len
 * @return size_t length of plaintext data
 */
size_t aes256_gcm_plaintext_data_len(size_t ciphertext_data_len);

/**
 * @brief Encrypt plaintext with AES GCM.
 *
 * @param ad
 * @param aes_key
 * @param plaintext_data
 * @param plaintext_data_len
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @return 0 if success
 */
int aes256_gcm_encrypt(
    const ProtobufCBinaryData *ad, const uint8_t *aes_key,
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    uint8_t **ciphertext_data, size_t *ciphertext_data_len
);

/**
 * @brief Decrypt a ciphertext with AES GCM.
 *
 * @param decrypted_data_out
 * @param decrypted_data_len_out
 * @param ad
 * @param aes_key
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @return The length of plaintext_data or -1 for decryption error
 */
int aes256_gcm_decrypt(
    uint8_t **decrypted_data_out, size_t *decrypted_data_len_out,
    const ProtobufCBinaryData *ad, const uint8_t *aes_key,
    const uint8_t *ciphertext_data, size_t ciphertext_data_len
);

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_H_ */
