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
#include "e2ees/crypto.h"

#include <errno.h>
#include <string.h>

#include "additions/curve_sigs.h"
#include "curve25519-donna.h"

#include "gcm.h"
#include "hkdf.h"
#include "md.h"
#include "platform.h"
#include "sha256.h"
#include "base64.h"

#include "e2ees/account.h"
#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"

static const uint8_t CURVE25519_BASEPOINT[32] = {9};

static void crypto_generate_private_key_curve25519(uint8_t *private_key) {
    uint8_t random[CURVE25519_RANDOM_LENGTH];
    e2ees_randombytes(random, sizeof(random));

    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    memcpy(private_key, random, CURVE25519_KEY_LENGTH);
}

int crypto_ds_key_gen_curve25519(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    int result;

    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    uint8_t msg[10] = {0};
    uint8_t signature[CURVE_SIGNATURE_LENGTH];

    while (true) {
        crypto_generate_private_key_curve25519(priv_key->data);

        curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
        crypto_sign_curve25519(priv_key->data, msg, 10, signature);
        result = crypto_verify_curve25519(signature, pub_key->data, msg, 10);
        if (result != 0) {
            // verify failed, regenerate the key pair
            e2ees_notify_log(
                NULL,
                BAD_SIGNATURE,
                "crypto_generate_private_key_curve25519() verify failed, regenerate the key pair."
            );
        } else {
            // success
            break;
        }
        // TODO in case of long running
    }

    return result;
}

int crypto_kem_asym_key_gen_curve25519(ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    crypto_generate_private_key_curve25519(priv_key->data);

    return curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
}

int crypto_ds_sign_curve25519(
    uint8_t *signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key
) {
    *signature_out_len = CURVE_SIGNATURE_LENGTH;
    uint8_t nonce[*signature_out_len];
    e2ees_randombytes(nonce, sizeof(nonce));
    return curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

int crypto_ds_verify_curve25519(
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

int crypto_kem_decaps_curve25519(
    uint8_t *shared_secret,
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *ciphertext
) {
    return curve25519_donna(shared_secret, our_key->data, ciphertext->data);
}

void crypto_sign_curve25519(
    uint8_t *private_key,
    uint8_t *msg, size_t msg_len,
    uint8_t *signature_out
) {
    uint8_t nonce[CURVE_SIGNATURE_LENGTH];
    e2ees_randombytes(nonce, sizeof(nonce));
    curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

int crypto_verify_curve25519(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

int crypto_aes_encrypt_gcm(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *ciphertext_data
) {
    int ret = E2EES_RESULT_SUCC;

    mbedtls_gcm_context ctx;
    unsigned char *tag_buf = ciphertext_data + plaintext_data_len;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int key_len = AES256_KEY_LENGTH * 8;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_data_len, iv,
            AES256_IV_LENGTH, add, add_len, plaintext_data,
            ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }

    mbedtls_gcm_free(&ctx);

    return ret;
}

int crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *plaintext_data, size_t *plaintext_data_len
) {
    int ret = E2EES_RESULT_SUCC;

    mbedtls_gcm_context ctx;
    unsigned char *input_tag_buf =
        (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int key_len = AES256_KEY_LENGTH * 8;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_DECRYPT,
            ciphertext_data_len - AES256_GCM_TAG_LENGTH, iv,
            AES256_IV_LENGTH, add, add_len, ciphertext_data,
            plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }
    mbedtls_gcm_free(&ctx);

    // verify tag in "constant-time"
    int diff = 0, i;
    for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
        diff |= input_tag_buf[i] ^ tag_buf[i];
    if (diff == 0) {
        *plaintext_data_len = ciphertext_data_len - AES256_GCM_TAG_LENGTH;
    } else {
        *plaintext_data_len = 0;
        ret = E2EES_RESULT_FAIL;
    }

    return ret;
}

size_t crypto_encrypt_aes_data_with_iv(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **ciphertext_data
) {
    size_t ciphertext_data_len = crypto_aes256_gcm_ciphertext_data_len(plaintext_data_len);
    *ciphertext_data = (uint8_t *)malloc(ciphertext_data_len);

    mbedtls_gcm_context ctx;
    unsigned char *tag_buf = *ciphertext_data + plaintext_data_len;
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_DATA_AD_LEN] = AES256_DATA_AD;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_data_len, iv,
            AES256_DATA_IV_LENGTH, AD, AES256_DATA_AD_LEN, plaintext_data,
            *ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }

    mbedtls_gcm_free(&ctx);

    // done
    if (ret == E2EES_RESULT_SUCC) {
        return ciphertext_data_len;
    } else {
        free_mem((void **)ciphertext_data, ciphertext_data_len);
        *ciphertext_data = NULL;
        return 0;
    }
}

size_t crypto_encrypt_aes_data(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **ciphertext_data
) {
    uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
    return crypto_encrypt_aes_data_with_iv(plaintext_data, plaintext_data_len, aes_key, iv, ciphertext_data);
}

size_t crypto_aes256_gcm_ciphertext_data_len(size_t plaintext_data_length) {
    return plaintext_data_length + AES256_GCM_TAG_LENGTH;
}

size_t crypto_aes256_gcm_plaintext_data_len(size_t ciphertext_data_len) {
    return ciphertext_data_len - AES256_GCM_TAG_LENGTH;
}

size_t crypto_decrypt_aes_data_with_iv(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    const uint8_t iv[AES256_DATA_IV_LENGTH],
    uint8_t **plaintext_data
) {
    size_t plaintext_data_len = crypto_aes256_gcm_plaintext_data_len(ciphertext_data_len);
    *plaintext_data = (uint8_t *)malloc(plaintext_data_len);

    mbedtls_gcm_context ctx;
    unsigned char *input_tag_buf =
            (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_DATA_AD_LEN] = AES256_DATA_AD;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_DECRYPT,
            plaintext_data_len, iv,
            AES256_DATA_IV_LENGTH, AD, AES256_DATA_AD_LEN, ciphertext_data,
            *plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }
    mbedtls_gcm_free(&ctx);

    // verify tag in "constant-time"
    int diff = 0, i;
    for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
        diff |= input_tag_buf[i] ^ tag_buf[i];
    if (diff == 0) {
        return plaintext_data_len;
    } else {
        free_mem((void **)plaintext_data, plaintext_data_len);
        *plaintext_data = NULL;
        return 0;
    }
}

size_t crypto_decrypt_aes_data(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **plaintext_data
) {
    uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
    return crypto_decrypt_aes_data_with_iv(ciphertext_data, ciphertext_data_len, aes_key, iv, plaintext_data);
}

int crypto_encrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
) {
    FILE *infile, *outfile;
    infile = fopen(in_file_path, "r");
    if (infile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_ENCRYPTION,
            "crypto_encrypt_aes_file() in_file_path: %s, with errorno: %d.", in_file_path, errno);
        return -1;
    }

    outfile = fopen(out_file_path, "w");
    if (outfile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_ENCRYPTION,
            "crypto_encrypt_aes_file() out_file_path: %s, with errorno: %d.", out_file_path, errno);
        // release
        fclose(infile);
        return -1;
    }

    fseek(infile, 0, SEEK_END);
    long size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    int max_plaintext_size = FILE_ENCRYPTION_BUFFER_LENGTH;
    unsigned char in_buffer[max_plaintext_size];
    unsigned char out_buffer[FILE_ENCRYPTION_BUFFER_LENGTH];

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_FILE_AD_LEN] = AES256_FILE_AD;

    int times = size / max_plaintext_size;
    int rest = size % max_plaintext_size;

    mbedtls_gcm_context ctx;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int ret;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, AES256_DATA_IV_LENGTH, AD, AES256_FILE_AD_LEN);
    }

    if (ret == E2EES_RESULT_SUCC) {
        int i;
        for (i = 0; i < times; i++) {
            fread(in_buffer, sizeof(char), max_plaintext_size, infile);
            if ((ret = mbedtls_gcm_update(&ctx, max_plaintext_size, in_buffer, out_buffer)) != 0)
                break;
            fwrite(out_buffer, sizeof(char), max_plaintext_size, outfile);
        }
    }
    if (ret == E2EES_RESULT_SUCC) {
        if (rest > 0) {
            fread(in_buffer, sizeof(char), rest, infile);
            if ((ret = mbedtls_gcm_update(&ctx, rest, in_buffer, out_buffer)) == 0) {
                fwrite(out_buffer, sizeof(char), rest, outfile);
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        uint8_t tag[AES256_GCM_TAG_LENGTH];
        if ((ret = mbedtls_gcm_finish(&ctx, tag, AES256_GCM_TAG_LENGTH)) == 0) {
            fwrite(tag, sizeof(char), AES256_GCM_TAG_LENGTH, outfile);
        }
    }

    mbedtls_gcm_free(&ctx);

    fclose(outfile);
    fclose(infile);

    return ret;
}

int crypto_decrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
) {
    FILE *infile, *outfile;
    infile = fopen(in_file_path, "r+");
    if (infile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_DECRYPTION,
            "crypto_decrypt_aes_file() in_file_path: %s, with errorno: %d.", in_file_path, errno);
        return -1;
    }

    outfile = fopen(out_file_path, "w");
    if (outfile == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_FILE_DECRYPTION,
            "crypto_decrypt_aes_file() out_file_path: %s, with errorno: %d.", out_file_path, errno);
        // release
        fclose(infile);
        return -1;
    }

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_FILE_AD_LEN] = AES256_FILE_AD;

    fseek(infile, 0, SEEK_END);
    long size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    int max_ciphertext_size = FILE_ENCRYPTION_BUFFER_LENGTH;
    unsigned char in_buffer[max_ciphertext_size];
    unsigned char out_buffer[FILE_ENCRYPTION_BUFFER_LENGTH];

    int times = (size - AES256_GCM_TAG_LENGTH) / max_ciphertext_size;
    int rest = (size - AES256_GCM_TAG_LENGTH) % max_ciphertext_size;

    mbedtls_gcm_context ctx;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int ret;
    int i;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == E2EES_RESULT_SUCC) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, iv, AES256_DATA_IV_LENGTH, AD, AES256_FILE_AD_LEN);
    }

    if (ret == E2EES_RESULT_SUCC) {
        for (i = 0; i < times; i++) {
            fread(in_buffer, sizeof(char), max_ciphertext_size, infile);
            if ((ret = mbedtls_gcm_update(&ctx, max_ciphertext_size, in_buffer, out_buffer)) != 0)
                break;
            fwrite(out_buffer, sizeof(char), max_ciphertext_size, outfile);
        }
    }
    if (ret == E2EES_RESULT_SUCC) {
        if (rest > 0) {
            fread(in_buffer, sizeof(char), rest, infile);
            if ((ret = mbedtls_gcm_update(&ctx, rest, in_buffer, out_buffer)) == 0) {
                fwrite(out_buffer, sizeof(char), rest, outfile);
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        uint8_t tag[AES256_GCM_TAG_LENGTH];
        if ((ret = mbedtls_gcm_finish(&ctx, tag, AES256_GCM_TAG_LENGTH)) == 0) {
            // fwrite(tag, sizeof(char), AES256_GCM_TAG_LENGTH, outfile);
            // verify tag
            uint8_t input_tag[AES256_GCM_TAG_LENGTH];
            fread(input_tag, sizeof(uint8_t), AES256_GCM_TAG_LENGTH, infile);

            // verify tag in "constant-time"
            int diff = 0;
            for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
                diff |= input_tag[i] ^ tag[i];
            if (diff == 0) {
                ret = E2EES_RESULT_SUCC;
            } else {
                ret = E2EES_RESULT_FAIL;
            }
        }
    }

    mbedtls_gcm_free(&ctx);

    fclose(outfile);
    fclose(infile);

    return ret;
}

int crypto_encrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
) {
    // prepare aes_key
    size_t salt_len = 0;
    uint8_t salt[salt_len];
    uint8_t aes_key[AES256_KEY_LENGTH];

    crypto_hf_hkdf_sha256(
        password, password_len,
        salt, salt_len,
        (uint8_t *)AES256_FILE_KDF_INFO, sizeof(AES256_FILE_KDF_INFO) - 1,
        aes_key, AES256_KEY_LENGTH
    );

    // perform aes encryption
    return crypto_encrypt_aes_file(in_file_path, out_file_path, aes_key);
}

int crypto_decrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
) {
    // prepare aes_key
    size_t salt_len = 0;
    uint8_t salt[salt_len];
    uint8_t aes_key[AES256_KEY_LENGTH];

    crypto_hf_hkdf_sha256(
        password, password_len,
        salt, salt_len,
        (uint8_t *)AES256_FILE_KDF_INFO, sizeof(AES256_FILE_KDF_INFO) - 1,
        aes_key, AES256_KEY_LENGTH
    );

    // perform aes decryption
    return crypto_decrypt_aes_file(in_file_path, out_file_path, aes_key);
}

int crypto_hf_hkdf_sha256(
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len, uint8_t *output,
    size_t output_len
) {
    const mbedtls_md_info_t *sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(sha256_info, salt, salt_len, input, input_len, info, info_len, output, output_len);
}

int crypto_hf_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
) {
    int ret = E2EES_RESULT_SUCC;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    ret = mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, key_len);
    ret = mbedtls_md_hmac_update(&ctx, (const unsigned char *)input, input_len);
    ret = mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);

    return ret;
}

int crypto_hf_sha256(const uint8_t *msg, size_t msg_len, uint8_t *hash_out) {
    int ret = E2EES_RESULT_SUCC;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    ret = mbedtls_sha256_update_ret(&ctx, msg, msg_len);
    ret = mbedtls_sha256_finish_ret(&ctx, hash_out);
    mbedtls_sha256_free(&ctx);

    return ret;
}

char *crypto_base64_encode(const uint8_t *msg, size_t msg_len) {
    size_t len = 4 * ((msg_len + 2) / 3) + 1;
    char *output = (char *)malloc(sizeof(char) * len);
    mbedtls_base64_encode((unsigned char *)output, len, &len, (const unsigned char *)msg, msg_len);
    return output;
}

size_t crypto_base64_decode(uint8_t **msg_out, const unsigned char *base64_str) {
    size_t base64_str_len = strlen((const char *)base64_str);
    int pad = base64_str_len > 0 && (base64_str_len % 4 || base64_str[base64_str_len - 1] == '=');
    size_t len = ((base64_str_len + 3) / 4 - pad) * 4;
    unsigned char buffer[len + 1];
    size_t msg_out_len;
    int ret = mbedtls_base64_decode(buffer, len + 1, &msg_out_len, base64_str, base64_str_len);

    if (msg_out_len > (len + 1)) {
        // something wrong with the length
        return 0;
    }
    *msg_out = (uint8_t *)malloc(sizeof(uint8_t) * msg_out_len);
    memcpy(*msg_out, buffer, msg_out_len);

    unset(buffer, len + 1);

    return msg_out_len;
}

int crypto_hash_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    const uint8_t *msg, size_t msg_len,
    uint8_t **hash_out, size_t *hash_out_len
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    hf_suite_t *hf_suite = get_hf_suite(e2ees_pack_id.hash);
    if (hf_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_hash_by_e2ees_pack_id() hf_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }

    uint32_t hf_len = hf_suite->get_param().hf_len;
    *hash_out_len = hf_len;
    *hash_out = (uint8_t *)malloc(sizeof(uint8_t) * hf_len);
    hf_suite->hash(msg, msg_len, *hash_out);
    return 0;
}

int crypto_ds_key_gen_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    ProtobufCBinaryData *pub_key,
    ProtobufCBinaryData *priv_key
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    ds_suite_t *digital_signature_suite = get_ds_suite(e2ees_pack_id.ds);
    if (digital_signature_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_ds_key_gen_by_e2ees_pack_id() digital_signature_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }

    int result = digital_signature_suite->ds_key_gen(pub_key, priv_key);
    if (result < 0) {
        e2ees_notify_log(
            NULL,
            BAD_KEY_PAIR,
            "crypto_ds_key_gen_by_e2ees_pack_id() gen key failed."
        );
        free_protobuf(pub_key);
        free_protobuf(priv_key);
    }

    return result;
}

int crypto_ds_sign_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    uint8_t **signature_out, size_t *signature_out_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *private_key, size_t private_key_len
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    ds_suite_t *digital_signature_suite = get_ds_suite(e2ees_pack_id.ds);
    if (digital_signature_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_ds_sign_by_e2ees_pack_id() digital_signature_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }
    if (private_key == NULL || private_key_len != digital_signature_suite->get_param().sign_priv_key_len) {
        e2ees_notify_log(
            NULL,
            BAD_PRIVATE_KEY,
            "crypto_ds_sign_by_e2ees_pack_id() private_key wrong."
        );
        return -1;
    }

    size_t sig_len = digital_signature_suite->get_param().sig_len;
    *signature_out = (uint8_t *)malloc(sizeof(uint8_t) * sig_len);
    int result = digital_signature_suite->sign(*signature_out, signature_out_len, msg, msg_len, private_key);
    if (result < 0) {
        e2ees_notify_log(
            NULL,
            BAD_SIGNATURE,
            "crypto_ds_sign_by_e2ees_pack_id() sign failed."
        );
        free_mem((void **)signature_out, sig_len);
    }

    return result;
}

int crypto_ds_verify_by_e2ees_pack_id(
    uint32_t e2ees_pack_id_raw,
    const uint8_t *signature_in, size_t signature_in_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *public_key, size_t public_key_len
) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);
    ds_suite_t *digital_signature_suite = get_ds_suite(e2ees_pack_id.ds);
    if (digital_signature_suite == NULL) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "crypto_ds_verify_by_e2ees_pack_id() digital_signature_suite not found: %d.", e2ees_pack_id_raw
        );
        return -1;
    }
    if (public_key == NULL || public_key_len != digital_signature_suite->get_param().sign_pub_key_len) {
        e2ees_notify_log(
            NULL,
            BAD_PUBLIC_KEY,
            "crypto_ds_sign_by_e2ees_pack_id() public_key wrong."
        );
        return -1;
    }

    int result = digital_signature_suite->verify(signature_in, signature_in_len, msg, msg_len, public_key);
    if (result < 0) {
        e2ees_notify_log(
            NULL,
            BAD_SIGNATURE,
            "crypto_ds_verify_by_e2ees_pack_id() verify failed."
        );
    }

    return result;
}
