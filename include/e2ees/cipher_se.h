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
#ifndef CIPHER_SE_H_
#define CIPHER_SE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

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
int crypto_se_encrypt_aes256_gcm(
    const ProtobufCBinaryData *ad,
    const uint8_t *aes_key,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len,
    uint8_t **ciphertext_data,
    size_t *ciphertext_data_len);

/**
 * @brief Decrypt a ciphertext with AES GCM.
 *
 * @param decrypted_data_out
 * @param decrypted_data_len_out
 * @param ad
 * @param aes_key
 * @param ciphertext_data
 * @param ciphertext_data_len
 * @return 0 if success or -1 for decryption error
 */
int crypto_se_decrypt_aes256_gcm(
    uint8_t **decrypted_data_out,
    size_t *decrypted_data_len_out,
    const ProtobufCBinaryData *ad,
    const uint8_t *aes_key,
    const uint8_t *ciphertext_data,
    size_t ciphertext_data_len);

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_SE_H_ */
