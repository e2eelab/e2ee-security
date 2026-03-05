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
#include "e2ees/account.h"

#include <string.h>

#include "e2ees/account_cache.h"
#include "e2ees/account_manager.h"
#include "e2ees/cipher.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/mem_util.h"
#include "e2ees/validation.h"

void account_begin() {
    int ret = E2EES_RESULT_SUCC;

    // load accounts that may be null
    E2ees__Account **accounts = NULL;
    size_t account_num = get_e2ees_plugin()->db_handler.load_accounts(&accounts);

    E2ees__Account *cur_account = NULL;
    size_t i;
    for (i = 0; i < account_num; i++) {
        cur_account = accounts[i];

        if (is_valid_registered_account(cur_account)) {
            // store into cache
            store_account_into_cache(cur_account);
        }

        // release
        if (cur_account != NULL) {
            e2ees__account__free_unpacked(cur_account, NULL);
            cur_account = NULL;
        }
    }

    // release
    if (accounts != NULL) {
        free_mem((void **)&accounts, sizeof(E2ees__Account *) * account_num);
    }
}

void account_end() {
    free_account_cacheer_list();
}

int create_account(E2ees__Account **account_out, uint32_t e2ees_pack_id) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Account *account = NULL;
    E2ees__IdentityKey *identity_key = NULL;
    E2ees__SignedPreKey *signed_pre_key = NULL;
    uint32_t cur_spk_id = 0;
    E2ees__OneTimePreKey **one_time_pre_key_list = NULL;
    size_t number_of_keys = E2EES_ONE_TIME_PRE_KEY_INITIAL_NUM;
    uint32_t cur_opk_id = 1;

    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;
    if (!is_valid_cipher_suite(cipher_suite)) {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "create_account() invalid cipher suite with e2ees_pack_id = %d", e2ees_pack_id);
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // generate the identity key pair
        ret = generate_identity_key(&identity_key, e2ees_pack_id);
    }

    if (ret == E2EES_RESULT_SUCC) {
        // generate a signed pre-key pair
        ret = generate_signed_pre_key(&signed_pre_key, e2ees_pack_id, cur_spk_id, identity_key->sign_key_pair->private_key.data);
    }

    if (ret == E2EES_RESULT_SUCC) {
        // generate 100 one-time pre-key pairs
        ret = generate_opks(&one_time_pre_key_list, number_of_keys, e2ees_pack_id, cur_opk_id);
    }

    if (ret == E2EES_RESULT_SUCC) {
        account = (E2ees__Account *)malloc(sizeof(E2ees__Account));
        e2ees__account__init(account);

        // set the version, e2ees_pack_id
        account->version = strdup(E2EES_PROTOCOL_VERSION);
        account->e2ees_pack_id = e2ees_pack_id;

        account->identity_key = identity_key;
        account->signed_pre_key = signed_pre_key;
        insert_opks(account, one_time_pre_key_list, number_of_keys);

        *account_out = account;
    } else {
        if (identity_key != NULL) {
            e2ees__identity_key__free_unpacked(identity_key, NULL);
            identity_key = NULL;
        }
        if (signed_pre_key != NULL) {
            e2ees__signed_pre_key__free_unpacked(signed_pre_key, NULL);
            signed_pre_key = NULL;
        }
        if (one_time_pre_key_list != NULL) {
            size_t i;
            for (i = 0; i < number_of_keys; i++) {
                if (one_time_pre_key_list[i] != NULL) {
                    e2ees__one_time_pre_key__free_unpacked(one_time_pre_key_list[i], NULL);
                    one_time_pre_key_list[i] = NULL;
                }
            }
            free_mem((void **)&one_time_pre_key_list, sizeof(E2ees__OneTimePreKey *) * number_of_keys);
        }
    }

    return ret;
}

int generate_identity_key(
    E2ees__IdentityKey **identity_key_out,
    uint32_t e2ees_pack_id
) {
    int ret = E2EES_RESULT_SUCC;

    uint32_t asym_pub_key_len = 0;
    uint32_t asym_priv_key_len = 0;
    uint32_t sign_pub_key_len = 0;
    uint32_t sign_priv_key_len = 0;
    E2ees__IdentityKey *identity_key = NULL;
    E2ees__KeyPair *asym_key_pair = NULL;
    E2ees__KeyPair *sign_key_pair = NULL;

    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;
    if (is_valid_cipher_suite(cipher_suite)) {
        asym_pub_key_len = cipher_suite->kem_suite->get_param().asym_pub_key_len;
        asym_priv_key_len = cipher_suite->kem_suite->get_param().asym_priv_key_len;
        sign_pub_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;
        sign_priv_key_len = cipher_suite->ds_suite->get_param().sign_priv_key_len;
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "generate_identity_key() invalid cipher suite with e2ees_pack_id = %d", e2ees_pack_id);
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        asym_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
        e2ees__key_pair__init(asym_key_pair);
        ret = cipher_suite->kem_suite->asym_key_gen(&(asym_key_pair->public_key), &(asym_key_pair->private_key));

        if (!accurate_key_pair(asym_key_pair, asym_pub_key_len, asym_priv_key_len)) {
            e2ees_notify_log(NULL, BAD_KEY_PAIR, "generate_identity_key() bad asym_key_pair");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        sign_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
        e2ees__key_pair__init(sign_key_pair);
        ret = cipher_suite->ds_suite->ds_key_gen(&(sign_key_pair->public_key), &(sign_key_pair->private_key));

        if (!accurate_key_pair(sign_key_pair, sign_pub_key_len, sign_priv_key_len)) {
            e2ees_notify_log(NULL, BAD_KEY_PAIR, "generate_identity_key() bad sign_key_pair");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        identity_key = (E2ees__IdentityKey *)malloc(sizeof(E2ees__IdentityKey));
        e2ees__identity_key__init(identity_key);

        identity_key->asym_key_pair = asym_key_pair;
        identity_key->sign_key_pair = sign_key_pair;

        *identity_key_out = identity_key;
    } else {
        if (asym_key_pair != NULL) {
            e2ees__key_pair__free_unpacked(asym_key_pair, NULL);
            asym_key_pair = NULL;
        }
        if (sign_key_pair != NULL) {
            e2ees__key_pair__free_unpacked(sign_key_pair, NULL);
            sign_key_pair = NULL;
        }
    }

    return ret;
}

int generate_signed_pre_key(
    E2ees__SignedPreKey **signed_pre_key_out,
    uint32_t e2ees_pack_id, uint32_t cur_spk_id,
    const uint8_t *identity_private_key
) {
    int ret = E2EES_RESULT_SUCC;

    uint32_t asym_pub_key_len = 0;
    uint32_t asym_priv_key_len = 0;
    uint32_t sig_len = 0;
    E2ees__SignedPreKey *signed_pre_key = NULL;
    E2ees__KeyPair *key_pair = NULL;
    uint8_t *signature_data = NULL;
    size_t signature_data_len = 0;

    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;
    if (is_valid_cipher_suite(cipher_suite)) {
        asym_pub_key_len = cipher_suite->kem_suite->get_param().asym_pub_key_len;
        asym_priv_key_len = cipher_suite->kem_suite->get_param().asym_priv_key_len;
        sig_len = cipher_suite->ds_suite->get_param().sig_len;
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "generate_signed_pre_key() invalid cipher suite with e2ees_pack_id = %d", e2ees_pack_id);
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // generate a signed pre-key pair
        key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
        e2ees__key_pair__init(key_pair);
        ret = cipher_suite->kem_suite->asym_key_gen(&(key_pair->public_key), &(key_pair->private_key));

        if (!accurate_key_pair(key_pair, asym_pub_key_len, asym_priv_key_len)) {
            e2ees_notify_log(NULL, BAD_KEY_PAIR, "generate_signed_pre_key() bad signed pre-key pair");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        signature_data = (uint8_t *)malloc(sizeof(uint8_t) * sig_len);
        // generate a signature
        ret = cipher_suite->ds_suite->sign(
            signature_data, &signature_data_len,
            key_pair->public_key.data, asym_pub_key_len,
            identity_private_key
        );

        // what if sig_len > signature_data_len?
        if (sig_len < signature_data_len) {
            e2ees_notify_log(NULL, BAD_SIGNATURE, "generate_signed_pre_key() bad signature");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        signed_pre_key = (E2ees__SignedPreKey *)malloc(sizeof(E2ees__SignedPreKey));
        e2ees__signed_pre_key__init(signed_pre_key);

        signed_pre_key->key_pair = key_pair;
        copy_protobuf_from_array(&(signed_pre_key->signature), signature_data, signature_data_len);

        signed_pre_key->spk_id = cur_spk_id + 1;

        int64_t now = get_e2ees_plugin()->common_handler.gen_ts();
        signed_pre_key->ttl = now + E2EES_SIGNED_PRE_KEY_EXPIRATION_MS;

        *signed_pre_key_out = signed_pre_key;
    } else {
        if (key_pair != NULL) {
            e2ees__key_pair__free_unpacked(key_pair, NULL);
            key_pair = NULL;
        }
    }
    
    // release
    if (signature_data != NULL) {
        free_mem((void **)&signature_data, sizeof(uint8_t) * sig_len);
    }

    return ret;
}

void purge_signed_pre_key(E2ees__Account *account) {
    int ret = E2EES_RESULT_SUCC;

    // the account will be saved only after consume_register_response
    if (account->saved == false) return;

    // check if the signed pre-key expired
    int64_t now = get_e2ees_plugin()->common_handler.gen_ts();
    if (now > account->signed_pre_key->ttl) {
        uint32_t e2ees_pack_id = account->e2ees_pack_id;
        uint32_t cur_spk_id = account->signed_pre_key->spk_id;
        E2ees__SignedPreKey *signed_pre_key = NULL;
        uint8_t *identity_private_key = account->identity_key->sign_key_pair->private_key.data;
        // generate a new pair of signed pre-key
        ret = generate_signed_pre_key(&signed_pre_key, e2ees_pack_id, cur_spk_id, identity_private_key);

        if (ret == E2EES_RESULT_SUCC) {
            // release the old signed pre-key
            e2ees__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
            account->signed_pre_key = signed_pre_key;

            E2ees__PublishSpkResponse *response = NULL;
            ret = publish_spk_internal(&response, e2ees_pack_id, account->address, signed_pre_key);
            // release
            if (response != NULL) {
                e2ees__publish_spk_response__free_unpacked(response, NULL);
                response = NULL;
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        // check and remove signed pre-keys (keep last two)
        get_e2ees_plugin()->db_handler.remove_expired_signed_pre_key(account->address);
    }
}

E2ees__OneTimePreKey *lookup_one_time_pre_key(E2ees__Account *account, uint32_t one_time_pre_key_id) {
    E2ees__OneTimePreKey **cur = account->one_time_pre_key_list;
    if (cur == NULL) {
        // there is no one-tme pre-keys in the account
        e2ees_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "lookup_one_time_pre_key() opk not found");
        return NULL;
    }

    size_t i;
    for (i = 0; i < account->n_one_time_pre_key_list; i++) {
        if (cur[i] != NULL) {
            if (cur[i]->opk_id == one_time_pre_key_id) {
                return cur[i];
            }
        } else {
            e2ees_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "lookup_one_time_pre_key() the number of opks does not match");
            break;
        }
    }
    return NULL;
}

int generate_opks(
    E2ees__OneTimePreKey ***one_time_pre_key_out, size_t number_of_keys,
    uint32_t e2ees_pack_id, uint32_t cur_opk_id
) {
    int ret = E2EES_RESULT_SUCC;

    uint32_t asym_pub_key_len = 0;
    uint32_t asym_priv_key_len = 0;
    E2ees__OneTimePreKey **one_time_pre_key_list = NULL;
    E2ees__KeyPair *key_pair = NULL;
    size_t i;

    const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;
    if (is_valid_cipher_suite(cipher_suite)) {
        asym_pub_key_len = cipher_suite->kem_suite->get_param().asym_pub_key_len;
        asym_priv_key_len = cipher_suite->kem_suite->get_param().asym_priv_key_len;
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "generate_opks() invalid cipher suite with e2ees_pack_id = %d", e2ees_pack_id);
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        one_time_pre_key_list = (E2ees__OneTimePreKey **)malloc(sizeof(E2ees__OneTimePreKey *) * number_of_keys);
        for (i = 0; i < number_of_keys; i++) {
            key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
            e2ees__key_pair__init(key_pair);
            ret = cipher_suite->kem_suite->asym_key_gen(&(key_pair->public_key), &(key_pair->private_key));

            if (!accurate_key_pair(key_pair, asym_pub_key_len, asym_priv_key_len)) {
                e2ees_notify_log(NULL, BAD_KEY_PAIR, "generate_opks() bad one-time pre-key pair");
                ret = E2EES_RESULT_FAIL;
            }

            if (ret == E2EES_RESULT_SUCC) {
                one_time_pre_key_list[i] = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
                e2ees__one_time_pre_key__init(one_time_pre_key_list[i]);
                copy_key_pair_from_key_pair(&(one_time_pre_key_list[i]->key_pair), key_pair);
                one_time_pre_key_list[i]->opk_id = cur_opk_id + i;
                one_time_pre_key_list[i]->used = false;

                // release
                e2ees__key_pair__free_unpacked(key_pair, NULL);
                key_pair = NULL;
            } else {
                // release
                e2ees__key_pair__free_unpacked(key_pair, NULL);
                key_pair = NULL;

                // if there is something wrong with the newly generated key pair, then we break the procedure
                break;
            }
        }

        if (ret == E2EES_RESULT_SUCC) {
            *one_time_pre_key_out = one_time_pre_key_list;
        } else {
            // if ret != 0, then release the whole one_time_pre_key_list
            if (one_time_pre_key_list != NULL) {
                for (i = 0; i < number_of_keys; i++) {
                    if (one_time_pre_key_list[i] != NULL) {
                        e2ees__one_time_pre_key__free_unpacked(one_time_pre_key_list[i], NULL);
                        one_time_pre_key_list[i] = NULL;
                    }
                }
                free_mem((void **)&one_time_pre_key_list, sizeof(E2ees__OneTimePreKey *) * number_of_keys);
            }
        }
    }

    return ret;
}

int insert_opks(E2ees__Account *account, E2ees__OneTimePreKey **src, size_t src_num) {
    int ret = E2EES_RESULT_SUCC;

    size_t i, j;
    size_t old_opk_num = 0;
    size_t new_opk_num = 0;
    E2ees__OneTimePreKey **temp_one_time_pre_key_list = NULL;
    E2ees__OneTimePreKey **cur_one_time_pre_key_list = NULL;
    E2ees__OneTimePreKey *cur_one_time_pre_key = NULL;
    E2ees__KeyPair *cur_key_pair = NULL;

    if (is_valid_one_time_pre_key_list(account->one_time_pre_key_list, account->n_one_time_pre_key_list)) {
        old_opk_num = account->n_one_time_pre_key_list;
        new_opk_num = old_opk_num + src_num;
    } else {
        e2ees_notify_log(NULL, BAD_ONE_TIME_PRE_KEY, "insert_opks(): invalid one-time pre-key list");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        if (old_opk_num == 0) {
            // there is no one-tme pre-keys in the account
            account->one_time_pre_key_list = src;
            account->n_one_time_pre_key_list = src_num;
            account->next_one_time_pre_key_id = src[src_num - 1]->opk_id + 1;
        } else {
            // there are several one-time pre-keys in the account
            temp_one_time_pre_key_list = (E2ees__OneTimePreKey **)malloc(sizeof(E2ees__OneTimePreKey *) * new_opk_num);

            cur_one_time_pre_key_list = account->one_time_pre_key_list;
            for (i = 0; i < old_opk_num; i++) {
                temp_one_time_pre_key_list[i] = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
                e2ees__one_time_pre_key__init(temp_one_time_pre_key_list[i]);

                cur_one_time_pre_key = cur_one_time_pre_key_list[i];
                temp_one_time_pre_key_list[i]->opk_id = cur_one_time_pre_key->opk_id;
                temp_one_time_pre_key_list[i]->used = cur_one_time_pre_key->used;
                temp_one_time_pre_key_list[i]->key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
                cur_key_pair = temp_one_time_pre_key_list[i]->key_pair;
                e2ees__key_pair__init(cur_key_pair);
                copy_protobuf_from_protobuf(&(cur_key_pair->private_key), &(cur_one_time_pre_key->key_pair->private_key));
                copy_protobuf_from_protobuf(&(cur_key_pair->public_key), &(cur_one_time_pre_key->key_pair->public_key));

                // release the old data
                e2ees__one_time_pre_key__free_unpacked(cur_one_time_pre_key, NULL);
                cur_one_time_pre_key = NULL;
            }
            free_mem((void **)&(cur_one_time_pre_key_list), sizeof(E2ees__OneTimePreKey *) * old_opk_num);

            for (i = 0; i < src_num; i++) {
                j = old_opk_num + i;
                temp_one_time_pre_key_list[j] = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
                e2ees__one_time_pre_key__init(temp_one_time_pre_key_list[j]);

                cur_one_time_pre_key = src[i];
                temp_one_time_pre_key_list[j]->opk_id = cur_one_time_pre_key->opk_id;
                temp_one_time_pre_key_list[j]->used = cur_one_time_pre_key->used;
                temp_one_time_pre_key_list[j]->key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
                cur_key_pair = temp_one_time_pre_key_list[j]->key_pair;
                e2ees__key_pair__init(cur_key_pair);
                copy_protobuf_from_protobuf(&(cur_key_pair->private_key), &(cur_one_time_pre_key->key_pair->private_key));
                copy_protobuf_from_protobuf(&(cur_key_pair->public_key), &(cur_one_time_pre_key->key_pair->public_key));
            }

            account->one_time_pre_key_list = temp_one_time_pre_key_list;
            account->n_one_time_pre_key_list = new_opk_num;
            account->next_one_time_pre_key_id = src[src_num - 1]->opk_id + 1;
        }
    }

    return ret;
}

int mark_opk_as_used(E2ees__Account *account, uint32_t id) {
    E2ees__OneTimePreKey **cur = account->one_time_pre_key_list;
    if (cur == NULL) {
        // there is no one-tme pre-keys in the account
        e2ees_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "mark_opk_as_used() opk not found");
        return -1;
    }

    size_t i;
    for (i = 0; i < account->n_one_time_pre_key_list; i++) {
        if (cur[i] != NULL) {
            if (cur[i]->opk_id == id) {
                cur[i]->used = true;
                return cur[i]->opk_id;
            }
        } else {
            e2ees_notify_log(account->address, BAD_ONE_TIME_PRE_KEY, "mark_opk_as_used() the number of opks does not match");
            break;
        }
    }

    e2ees_notify_log(account->address, BAD_REMOVE_OPK, "mark_opk_as_used() opk id not found");
    return -1;
}

static void copy_one_time_pre_key_list(E2ees__OneTimePreKey **dest, E2ees__OneTimePreKey **src, size_t num) {
    size_t i;
    for (i = 0; i < num; i++) {
        dest[i] = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
        e2ees__one_time_pre_key__init(dest[i]);
        dest[i]->opk_id = src[i]->opk_id;
        dest[i]->used = src[i]->used;
        dest[i]->key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
        e2ees__key_pair__init(dest[i]->key_pair);
        copy_protobuf_from_protobuf(&(dest[i]->key_pair->private_key), &(src[i]->key_pair->private_key));
        copy_protobuf_from_protobuf(&(dest[i]->key_pair->public_key), &(src[i]->key_pair->public_key));
    }
}

void purge_one_time_pre_key(E2ees__Account *account) {
    size_t used_num = 0;
    size_t new_num = 0;
    size_t i;
    if (account->one_time_pre_key_list) {
        for (i = 0; i < account->n_one_time_pre_key_list; i++) {
            if (account->one_time_pre_key_list[i]) {
                if (account->one_time_pre_key_list[i]->used == true) {
                    used_num++;
                } else {
                    // we use the one-time pre-keys from ahead
                    break;
                }
            }
        }
        // we release the "used" one-time pre-keys if there are many
        if (used_num >= 60) {
            new_num = account->n_one_time_pre_key_list - used_num;
            E2ees__OneTimePreKey **new_one_time_pre_key_list = NULL;
            if (new_num > 0) {
                new_one_time_pre_key_list = (E2ees__OneTimePreKey **)malloc(sizeof(E2ees__OneTimePreKey *) * new_num);
                E2ees__OneTimePreKey **temp = &(account->one_time_pre_key_list[used_num]);
                copy_one_time_pre_key_list(new_one_time_pre_key_list, temp, new_num);
            }
            for (i = 0; i < account->n_one_time_pre_key_list; i++) {
                get_e2ees_plugin()->db_handler.remove_one_time_pre_key(account->address, account->one_time_pre_key_list[i]->opk_id);
                e2ees__one_time_pre_key__free_unpacked(account->one_time_pre_key_list[i], NULL);
                account->one_time_pre_key_list[i] = NULL;
            }
            free_mem((void **)&(account->one_time_pre_key_list), sizeof(E2ees__OneTimePreKey *) * account->n_one_time_pre_key_list);
            if (new_num > 0) {
                account->one_time_pre_key_list = new_one_time_pre_key_list;
            }
            account->n_one_time_pre_key_list = new_num;
        }
    }
}
