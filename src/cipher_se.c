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
#include "e2ees/cipher_se.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "e2ees/cipher.h"
#include "e2ees/crypto.h"
#include "e2ees/mem_util.h"

static crypto_se_param_t aes256_param = { AES256_KEY_LENGTH,
                                          AES256_IV_LENGTH,
                                          AES256_GCM_TAG_LENGTH };

static crypto_se_param_t crypto_se_params_aes256_gcm() { return aes256_param; }

int crypto_se_encrypt_aes256_gcm(
    const ProtobufCBinaryData *ad,
    const uint8_t *aes_key,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len,
    uint8_t **ciphertext_data,
    size_t *ciphertext_data_len) {
    int ret              = E2EES_RESULT_SUCC;

    uint8_t *iv          = (uint8_t *)aes_key + AES256_KEY_LENGTH;
    *ciphertext_data_len = crypto_aes256_gcm_ciphertext_data_len(plaintext_data_len);
    *ciphertext_data     = (uint8_t *)malloc(*ciphertext_data_len);
    ret                  = crypto_aes_encrypt_gcm(
        plaintext_data, plaintext_data_len, aes_key, iv, ad->data, ad->len, *ciphertext_data);

    return ret;
}

int crypto_se_decrypt_aes256_gcm(
    uint8_t **decrypted_data_out,
    size_t *decrypted_data_len_out,
    const ProtobufCBinaryData *ad,
    const uint8_t *aes_key,
    const uint8_t *ciphertext_data,
    size_t ciphertext_data_len) {
    int ret                   = E2EES_RESULT_SUCC;

    uint8_t *iv               = (uint8_t *)aes_key + AES256_KEY_LENGTH;
    size_t plaintext_data_len = crypto_aes256_gcm_plaintext_data_len(ciphertext_data_len);
    uint8_t *plaintext_data   = (uint8_t *)malloc(plaintext_data_len);
    ret                       = crypto_aes_decrypt_gcm(
        ciphertext_data,
        ciphertext_data_len,
        aes_key,
        iv,
        ad->data,
        ad->len,
        plaintext_data,
        decrypted_data_len_out);
    if (*decrypted_data_len_out > 0) {
        *decrypted_data_out = plaintext_data;
    } else {
        *decrypted_data_out = NULL;
        free_mem((void **)&plaintext_data, plaintext_data_len);
    }

    return ret;
}

// default symmetric encryption suite

const struct se_suite_t E2EES_SE_AES256_SHA256 = {
    crypto_se_params_aes256_gcm,
    crypto_se_encrypt_aes256_gcm,
    crypto_se_decrypt_aes256_gcm,
};
