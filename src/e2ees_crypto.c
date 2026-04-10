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
#include "e2ees/e2ees_crypto.h"

#include <stdio.h>
#include <string.h>

#include "e2ees/e2ees.h"
#include "e2ees/crypto.h"
#include "e2ees/mem_util.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t e2ees_encrypt_gcm(
    const uint8_t *plaintext, const size_t plaintext_len,
    const uint8_t *password, const uint8_t *iv,
    const uint8_t *add, const size_t add_len,
    uint8_t **ciphertext
) {
    size_t out_data_len = crypto_aes256_gcm_ciphertext_data_len(plaintext_len);
    *ciphertext = (uint8_t *)malloc(out_data_len);
    crypto_aes_encrypt_gcm(plaintext, plaintext_len, password, iv, add, add_len, *ciphertext);

    return out_data_len;
}

size_t e2ees_decrypt_gcm(
    const uint8_t *ciphertext, const size_t ciphertext_len,
    const uint8_t *password, const uint8_t *iv,
    const uint8_t *add, const size_t add_len,
    uint8_t **plaintext
) {
    size_t plaintext_len = crypto_aes256_gcm_plaintext_data_len(ciphertext_len);
    *plaintext = (uint8_t *)malloc(plaintext_len);
    size_t out_data_len;
    crypto_aes_decrypt_gcm(
        ciphertext, ciphertext_len, password, iv, add, add_len, *plaintext, &out_data_len
    );

    return out_data_len;
}

size_t e2ees_encrypt_data(
    const uint8_t *plaintext, const size_t plaintext_len,
    const uint8_t *password, const size_t password_len,
    uint8_t **ciphertext
)  {
    if (password_len != AES256_KEY_LENGTH)
        return 0;

    size_t out_data_len = crypto_encrypt_aes_data(plaintext, plaintext_len, password, ciphertext);
    return out_data_len;
}

size_t e2ees_decrypt_data(
    const uint8_t *ciphertext_data, const size_t ciphertext_data_len,
    const uint8_t *password, const size_t password_len,
    uint8_t **plaintext
) {
    if (password_len != AES256_KEY_LENGTH)
        return 0;

    size_t out_data_len = crypto_decrypt_aes_data(ciphertext_data, ciphertext_data_len, password, plaintext);
    return out_data_len;
}

bool e2ees_encrypt_file(
    const uint8_t *password,
    const size_t password_len,
    const char *in_file_path, const char *out_file_path
) {
    printf("<c> e2ees_encryptFile: password: %s    in_file_path: %s    out_file_path: %s\n", password, in_file_path, out_file_path);
    int succ = crypto_encrypt_file(in_file_path, out_file_path, password, password_len);
    return succ == 0;
}

bool e2ees_decrypt_file(
    const uint8_t *password,
    const size_t password_len,
    const char *in_file_path, const char *out_file_path
) {
    printf("<c> e2ees_decryptFile: password: %s    in_file_path: %s    out_file_path: %s\n", password, in_file_path, out_file_path);
    int succ = crypto_decrypt_file(in_file_path, out_file_path, password, password_len);
    return succ == 0;
}

size_t e2ees_hash(uint32_t e2ees_pack_id, const uint8_t *msg, size_t msg_len, uint8_t **hash_out) {
    size_t hash_out_len;
    int result = crypto_hash_by_e2ees_pack_id(
        e2ees_pack_id,
        msg, msg_len,
        hash_out, &hash_out_len
    );
    if (result >= 0) {
        return hash_out_len;
    } else {
        return 0;
    }
}

size_t e2ees_ds_gen_key_pair(uint32_t e2ees_pack_id, uint8_t **keypair_out) {
    *keypair_out = NULL;
    E2ees__KeyPair key_pair = E2EES__KEY_PAIR__INIT;
    int result = crypto_ds_key_gen_by_e2ees_pack_id(
        e2ees_pack_id,
        &(key_pair.public_key), &(key_pair.private_key)
    );
    if (result >= 0) {
        // pack key_pair to keypair_out
        size_t keypair_out_len = e2ees__key_pair__get_packed_size(&key_pair);
        *keypair_out = (uint8_t *)malloc(sizeof(uint8_t) * keypair_out_len);
        e2ees__key_pair__pack(&key_pair, *keypair_out);
        // release
        free_protobuf(&(key_pair.public_key));
        free_protobuf(&(key_pair.private_key));
        return keypair_out_len;
    } else {
        // release
        free_protobuf(&(key_pair.public_key));
        free_protobuf(&(key_pair.private_key));
        return 0;
    }
}

size_t e2ees_ds_sign(uint32_t e2ees_pack_id, const uint8_t *msg, size_t msg_len, const uint8_t *private_key, size_t private_key_len, uint8_t **signature_out){
    *signature_out = NULL;
    size_t signature_out_len;
    int result = crypto_ds_sign_by_e2ees_pack_id(
        e2ees_pack_id,
        signature_out, &signature_out_len,
        msg, msg_len,
        private_key, private_key_len
    );
    if (result >= 0) {
        return signature_out_len;
    } else {
        return 0;
    }
}

int e2ees_ds_verify(uint32_t e2ees_pack_id, const uint8_t *signature_in, size_t signature_in_len, const uint8_t *msg, size_t msg_len, const uint8_t *public_key, size_t public_key_len) {
    int result = crypto_ds_verify_by_e2ees_pack_id(
        e2ees_pack_id,
        signature_in, signature_in_len,
        msg, msg_len,
        public_key, public_key_len
    );
    return result;
}

size_t e2ees_kem_gen_key_pair(uint32_t e2ees_pack_id, uint8_t **keypair_out) {
    *keypair_out = NULL;
    E2ees__KeyPair key_pair = E2EES__KEY_PAIR__INIT;
    int result = crypto_kem_key_gen_by_e2ees_pack_id(
        e2ees_pack_id,
        &(key_pair.public_key), &(key_pair.private_key)
    );
    if (result >= 0) {
        // pack key_pair to keypair_out
        size_t keypair_out_len = e2ees__key_pair__get_packed_size(&key_pair);
        *keypair_out = (uint8_t *)malloc(sizeof(uint8_t) * keypair_out_len);
        e2ees__key_pair__pack(&key_pair, *keypair_out);
        // release
        free_protobuf(&(key_pair.public_key));
        free_protobuf(&(key_pair.private_key));
        return keypair_out_len;
    } else {
        // release
        free_protobuf(&(key_pair.public_key));
        free_protobuf(&(key_pair.private_key));
        return 0;
    }
}

size_t e2ees_kem_encaps(
    uint32_t e2ees_pack_id, uint8_t **shared_secret_out, uint8_t **ciphertext_out,
    const uint8_t *public_key, size_t public_key_len
) {
    size_t ciphertext_len;
    int result = crypto_kem_encaps_by_e2ees_pack_id(
        e2ees_pack_id,
        shared_secret_out, ciphertext_out, &ciphertext_len,
        public_key, public_key_len
    );
    if (result >= 0) {
        return ciphertext_len;
    } else {
        return 0;
    }
}

size_t e2ees_kem_decaps(
    uint32_t e2ees_pack_id, uint8_t **shared_secret_out,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *private_key, size_t private_key_len
) {
    e2ees_pack_id_t e2ees_pack_id_st = raw_to_e2ees_pack_id(e2ees_pack_id);
    kem_suite_t *kem_suite            = get_kem_suite(e2ees_pack_id_st.kem);
    if (kem_suite == NULL) {
        return 0;
    }

    int result = crypto_kem_decaps_by_e2ees_pack_id(
        e2ees_pack_id,
        shared_secret_out,
        private_key, private_key_len,
        ciphertext, ciphertext_len
    );
    if (result >= 0) {
        return kem_suite->get_param().shared_secret_len;
    } else {
        return 0;
    }
}



#ifdef __cplusplus
}
#endif

