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
#include "e2ees/ratchet.h"

#include <stdio.h>
#include <string.h>

#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"
#include "e2ees/validation.h"

static const char MESSAGE_KEY_SEED[] = "MessageKeys";
static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const size_t MAX_SKIPPED_MESSAGE_KEY_NODES = 512;

static void free_skipped_message_key(E2ees__SkippedMsgKeyNode ***src, size_t num) {
    size_t i;
    for (i = 0; i < num; i++) {
        if ((*src)[i] != NULL) {
            e2ees__skipped_msg_key_node__free_unpacked((*src)[i], NULL);
            (*src)[i] = NULL;
        }
    }
    free_mem((void **)src, sizeof(E2ees__SkippedMsgKeyNode *) * num);
    *src = NULL;
}

static int create_chain_key(const cipher_suite_t *cipher_suite, const ProtobufCBinaryData root_key, const ProtobufCBinaryData *our_private_key, const ProtobufCBinaryData *their_key,
                            ProtobufCBinaryData *new_root_key, E2ees__ChainKey *new_chain_key, ProtobufCBinaryData *ratchet_public_key) {
    int ret = E2EES_RESULT_SUCC;

    bool pqc_param;

    if (is_valid_cipher_suite(cipher_suite)) {
        if ((our_private_key == NULL && ratchet_public_key == NULL) || (our_private_key != NULL && ratchet_public_key != NULL)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (our_private_key != NULL) {
            if (!is_valid_protobuf(our_private_key)) {
                ret = E2EES_RESULT_FAIL;
            }
        }
        if (ratchet_public_key != NULL) {
            // ratchet_public_key should be {0, NULL}
            if (ratchet_public_key->len != 0 || ratchet_public_key->data != NULL) {
                ret = E2EES_RESULT_FAIL;
            }
        }
        if (!is_valid_protobuf(&(root_key))) {
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_protobuf(their_key)) {
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "create_chain_key() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        pqc_param = cipher_suite->kem_suite->get_param().pqc_param;

        int shared_key_len = cipher_suite->hf_suite->get_param().hf_len;
        int shared_secret_len = cipher_suite->kem_suite->get_param().shared_secret_len;

        uint8_t secret[shared_secret_len];
        memset(secret, 0, shared_secret_len);
        ProtobufCBinaryData ciphertext = {0, NULL};
        if (our_private_key == NULL) {
            cipher_suite->kem_suite->encaps(secret, &ciphertext, their_key);
            uint32_t ciphertext_len = ciphertext.len;
            ratchet_public_key->data = (uint8_t *)malloc(sizeof(uint8_t) * ciphertext_len);
            memcpy(ratchet_public_key->data, ciphertext.data, ciphertext_len);
            ratchet_public_key->len = ciphertext_len;
        } else {
            cipher_suite->kem_suite->decaps(secret, our_private_key, their_key);
        }
        uint8_t derived_secrets[2 * shared_key_len];
        cipher_suite->hf_suite->hkdf(secret, sizeof(secret), root_key.data, root_key.len, (uint8_t *)KDF_INFO_RATCHET, sizeof(KDF_INFO_RATCHET) - 1, derived_secrets, sizeof(derived_secrets));

        if (new_root_key->data) {
            overwrite_protobuf_from_array(new_root_key, derived_secrets);
        } else {
            copy_protobuf_from_array(new_root_key, derived_secrets, shared_key_len);
        }

        new_chain_key->index = 0;
        if (new_chain_key->shared_key.data) {
            overwrite_protobuf_from_array(&(new_chain_key->shared_key), derived_secrets + shared_key_len);
        } else {
            copy_protobuf_from_array(&(new_chain_key->shared_key), derived_secrets + shared_key_len, shared_key_len);
        }

        free_protobuf(&ciphertext);
        unset(derived_secrets, sizeof(derived_secrets));
        unset(secret, sizeof(secret));
    }

    return ret;
}

static int advance_chain_key(const cipher_suite_t *cipher_suite, E2ees__ChainKey *chain_key) {
    int ret = E2EES_RESULT_SUCC;

    if (is_valid_cipher_suite(cipher_suite)) {
        if (!is_valid_chain_key(chain_key)) {
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "advance_chain_key() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        int shared_key_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t shared_key[shared_key_len];
        memset(shared_key, 0, shared_key_len);
        cipher_suite->hf_suite->hmac(chain_key->shared_key.data, chain_key->shared_key.len, CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED), shared_key);

        chain_key->index = chain_key->index + 1;
        overwrite_protobuf_from_array(&(chain_key->shared_key), shared_key);
    }

    return ret;
}

static int create_msg_keys(const cipher_suite_t *cipher_suite, const E2ees__ChainKey *chain_key, E2ees__MsgKey **msg_key_out) {
    int ret = E2EES_RESULT_SUCC;
    E2ees__MsgKey *msg_key = NULL;
    uint8_t *output = NULL;
    int msg_key_len = 0;
    int hf_len = 0;

    if (is_valid_cipher_suite(cipher_suite)) {
        if (!is_valid_chain_key(chain_key)) {
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "create_msg_keys() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        msg_key_len = cipher_suite->se_suite->get_param().aead_key_len + cipher_suite->se_suite->get_param().aead_iv_len;
        output = (uint8_t *)malloc(sizeof(uint8_t) * msg_key_len);
        hf_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t salt[hf_len];
        memset(salt, 0, hf_len);
        ret =
            cipher_suite->hf_suite->hkdf(chain_key->shared_key.data, chain_key->shared_key.len, salt, sizeof(salt), (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1, output, msg_key_len);
    }

    if (ret == E2EES_RESULT_SUCC) {
        msg_key = (E2ees__MsgKey *)malloc(sizeof(E2ees__MsgKey));
        e2ees__msg_key__init(msg_key);

        msg_key->derived_key.data = output;
        msg_key->derived_key.len = msg_key_len;
        msg_key->index = chain_key->index;

        *msg_key_out = msg_key;
    } else {
        free_mem((void **)&output, sizeof(uint8_t) * msg_key_len);
    }

    return ret;
}

static int verify_and_decrypt(uint8_t **decrypted_data_out, size_t *decrypted_data_len_out, const cipher_suite_t *cipher_suite, ProtobufCBinaryData ad, const E2ees__MsgKey *message_key,
                              const E2ees__One2oneMsgPayload *payload) {
    int ret = E2EES_RESULT_SUCC;

    if (is_valid_cipher_suite(cipher_suite)) {
        if (!is_valid_protobuf(&ad)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_msg_key(message_key)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_one2one_msg_payload(payload)) {
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "verify_and_decrypt() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = cipher_suite->se_suite->decrypt(decrypted_data_out, decrypted_data_len_out, &ad, message_key->derived_key.data, payload->ciphertext.data, payload->ciphertext.len);
    }

    if (ret < 0)
        e2ees_notify_log(NULL, BAD_MESSAGE_DECRYPTION, "verify_and_decrypt()");

    return ret;
}

static int verify_and_decrypt_for_existing_chain(uint8_t **decrypted_data_out, size_t *decrypted_data_len_out, const cipher_suite_t *cipher_suite, ProtobufCBinaryData ad,
                                                 const E2ees__ChainKey *chain, const E2ees__One2oneMsgPayload *payload) {
    int ret = E2EES_RESULT_SUCC;

    if (is_valid_cipher_suite(cipher_suite)) {
        if (!is_valid_protobuf(&ad)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_chain_key(chain)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_one2one_msg_payload(payload)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (ret == E2EES_RESULT_SUCC) {
            if (payload->sequence < chain->index) {
                e2ees_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "verify_and_decrypt_for_existing_chain()");
                ret = E2EES_RESULT_FAIL;
            }
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "verify_and_decrypt_for_existing_chain() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        E2ees__ChainKey *new_chain = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
        e2ees__chain_key__init(new_chain);
        new_chain->index = chain->index;
        copy_protobuf_from_protobuf(&(new_chain->shared_key), &(chain->shared_key));

        while (new_chain->index < payload->sequence) {
            advance_chain_key(cipher_suite, new_chain);
        }

        E2ees__MsgKey *mk = NULL;
        create_msg_keys(cipher_suite, new_chain, &mk);

        ret = verify_and_decrypt(decrypted_data_out, decrypted_data_len_out, cipher_suite, ad, mk, payload);

        e2ees__chain_key__free_unpacked(new_chain, NULL);
        e2ees__msg_key__free_unpacked(mk, NULL);
    }

    return ret;
}

static size_t verify_and_decrypt_for_new_chain(uint8_t **decrypted_data_out, size_t *decrypted_data_len_out, const cipher_suite_t *cipher_suite, const E2ees__Ratchet *ratchet,
                                               ProtobufCBinaryData ad, const E2ees__One2oneMsgPayload *payload) {
    int ret = E2EES_RESULT_SUCC;

    bool pqc_param;
    uint32_t coming_root_sequence = 0;
    uint32_t our_root_sequence = 0;

    if (is_valid_cipher_suite(cipher_suite)) {
        pqc_param = cipher_suite->kem_suite->get_param().pqc_param;
        if (!is_valid_protobuf(&ad)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (is_valid_ratchet(ratchet)) {
            our_root_sequence = ratchet->root_sequence;
        } else {
            ret = E2EES_RESULT_FAIL;
        }
        if (is_valid_one2one_msg_payload(payload)) {
            coming_root_sequence = payload->root_sequence;
            // coming_root_sequence should be positive
            if (coming_root_sequence == 0) {
                e2ees_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "verify_and_decrypt_for_new_chain()");
                ret = E2EES_RESULT_FAIL;
            }
            // the length of the ratchet key should be correct
            if (pqc_param) {
                if (payload->ratchet_key.len != cipher_suite->kem_suite->get_param().kem_ciphertext_len) {
                    ret = E2EES_RESULT_FAIL;
                }
            } else {
                if (payload->ratchet_key.len != cipher_suite->kem_suite->get_param().asym_pub_key_len) {
                    ret = E2EES_RESULT_FAIL;
                }
            }
        } else {
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "verify_and_decrypt_for_new_chain() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ProtobufCBinaryData new_root_key = {0, NULL};
        E2ees__ReceiverChainNode new_chain;

        e2ees__receiver_chain_node__init(&new_chain);
        new_chain.chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
        e2ees__chain_key__init(new_chain.chain_key);

        uint32_t i;
        copy_protobuf_from_protobuf(&new_root_key, &(ratchet->root_key));
        ProtobufCBinaryData *our_private_key = &(ratchet->receiver_chain->our_ratchet_private_key);
        for (i = our_root_sequence; i < coming_root_sequence; i++) {
            create_chain_key(cipher_suite, new_root_key, our_private_key, &(payload->ratchet_key), &new_root_key, new_chain.chain_key, NULL);
        }

        ret = verify_and_decrypt_for_existing_chain(decrypted_data_out, decrypted_data_len_out, cipher_suite, ad, new_chain.chain_key, payload);

        free_protobuf(&new_root_key);
        unset((void volatile *)&new_root_key, sizeof(ProtobufCBinaryData));
        free_protobuf(&(new_chain.chain_key->shared_key));
        e2ees__chain_key__free_unpacked(new_chain.chain_key, NULL);
        new_chain.chain_key = NULL;
        unset((void volatile *)&new_chain, sizeof(E2ees__ReceiverChainNode));
    }

    return ret;
}

static void prune_bloated_skipped_keys(E2ees__Ratchet *ratchet) {
    /* * Sanity check: Do nothing if the ratchet is NULL or the number of skipped keys
     * is within our defined safety limit.
     */
    if (ratchet == NULL || ratchet->n_skipped_msg_key_list <= MAX_SKIPPED_MESSAGE_KEY_NODES) {
        return;
    }

    // Calculate the number of excess keys that need to be purged
    size_t excess_count = ratchet->n_skipped_msg_key_list - MAX_SKIPPED_MESSAGE_KEY_NODES;

    /*
     * Step 1: Surgical removal.
     * Free the oldest, obsolete keys at the front of the array.
     * Since we append new keys to the end, indices 0 to (excess_count - 1)
     * represent the oldest historical legacy data.
     */
    size_t i;
    for (i = 0; i < excess_count; i++) {
        if (ratchet->skipped_msg_key_list[i] != NULL) {
            e2ees__skipped_msg_key_node__free_unpacked(ratchet->skipped_msg_key_list[i], NULL);
            ratchet->skipped_msg_key_list[i] = NULL;
        }
    }

    /*
     * Step 2: Prepare a new home.
     * Allocate a new array exactly the size of our maximum allowed limit.
     */
    E2ees__SkippedMsgKeyNode **new_list = (E2ees__SkippedMsgKeyNode **)malloc(sizeof(E2ees__SkippedMsgKeyNode *) * MAX_SKIPPED_MESSAGE_KEY_NODES);

    /*
     * Step 3: Relocation.
     * Move the remaining "newest" and valid keys to the front of the new array.
     */
    for (i = 0; i < MAX_SKIPPED_MESSAGE_KEY_NODES; i++) {
        new_list[i] = ratchet->skipped_msg_key_list[excess_count + i];
    }

    /*
     * Step 4: Destroy the old array.
     * Note: We CANNOT call free_skipped_message_key() here because we are
     * still keeping the latest nodes! We only need to free the large array
     * that previously held the pointers.
     */
    free_mem((void **)&(ratchet->skipped_msg_key_list), sizeof(E2ees__SkippedMsgKeyNode *) * ratchet->n_skipped_msg_key_list);

    /*
     * Step 5: Update the Ratchet state. The slimming process is complete!
     */
    ratchet->skipped_msg_key_list = new_list;
    ratchet->n_skipped_msg_key_list = MAX_SKIPPED_MESSAGE_KEY_NODES;

    // Log the event to show how much memory was salvaged
    // e2ees_notify_log(NULL, DEBUG_LOG, "prune_bloated_skipped_keys(): Successfully pruned %zu obsolete keys!", excess_count);
}

int initialise_as_bob(E2ees__Ratchet **ratchet_out, const cipher_suite_t *cipher_suite, const uint8_t *shared_secret, size_t shared_secret_len, const E2ees__KeyPair *our_ratchet_key,
                      ProtobufCBinaryData *their_ratchet_key) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Ratchet *ratchet = NULL;
    bool pqc_param;
    int shared_key_len = 0;
    int hf_len = 0;
    uint8_t *derived_secrets = NULL;
    size_t derived_secrets_len = 0;
    ProtobufCBinaryData ciphertext = {0, NULL};

    if (is_valid_cipher_suite(cipher_suite)) {
        pqc_param = cipher_suite->kem_suite->get_param().pqc_param;
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "initialise_as_bob() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }
    if (shared_secret == NULL)
        ret = E2EES_RESULT_FAIL;
    if (shared_secret_len == 0)
        ret = E2EES_RESULT_FAIL;
    if (!is_valid_key_pair(our_ratchet_key)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_protobuf(their_ratchet_key)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // the ssk will be 64 bytes
        shared_key_len = cipher_suite->hf_suite->get_param().hf_len;
        derived_secrets_len = shared_key_len * 2;
        derived_secrets = (uint8_t *)malloc(sizeof(uint8_t) * derived_secrets_len);
        hf_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t salt[hf_len];
        memset(salt, 0, hf_len);
        ret = cipher_suite->hf_suite->hkdf(shared_secret, shared_secret_len, salt, sizeof(salt), (uint8_t *)KDF_INFO_ROOT, sizeof(KDF_INFO_ROOT) - 1, derived_secrets, derived_secrets_len);
    }

    if (ret == E2EES_RESULT_SUCC) {
        int temp_shared_key_len = cipher_suite->kem_suite->get_param().shared_secret_len;
        uint8_t temp_secret[temp_shared_key_len];
        ret = cipher_suite->kem_suite->encaps(temp_secret, &ciphertext, their_ratchet_key);

        unset(temp_secret, sizeof(temp_secret));
    }

    if (ret == E2EES_RESULT_SUCC) {
        ratchet = (E2ees__Ratchet *)malloc(sizeof(E2ees__Ratchet));
        e2ees__ratchet__init(ratchet);

        ratchet->receiver_chain = (E2ees__ReceiverChainNode *)malloc(sizeof(E2ees__ReceiverChainNode));
        E2ees__ReceiverChainNode *receiver_chain = ratchet->receiver_chain;
        e2ees__receiver_chain_node__init(receiver_chain);
        copy_protobuf_from_protobuf(&(receiver_chain->our_ratchet_private_key), &(our_ratchet_key->private_key));

        ratchet->sender_chain = (E2ees__SenderChainNode *)malloc(sizeof(E2ees__SenderChainNode));
        E2ees__SenderChainNode *sender_chain = ratchet->sender_chain;
        e2ees__sender_chain_node__init(sender_chain);
        sender_chain->chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
        e2ees__chain_key__init(sender_chain->chain_key);
        sender_chain->chain_key->index = 0;

        /** The first half of the derived_secrets will be the root key,
         *  and the second half will be the sender chain key */
        copy_protobuf_from_array(&(ratchet->root_key), derived_secrets, shared_key_len);

        copy_protobuf_from_array(&(sender_chain->chain_key->shared_key), derived_secrets + shared_key_len, shared_key_len);

        copy_protobuf_from_protobuf(&(sender_chain->their_ratchet_public_key), their_ratchet_key);

        if (cipher_suite->kem_suite->get_param().pqc_param == false) {
            // ECC mode
            copy_protobuf_from_protobuf(&(sender_chain->our_ratchet_public_key), &(our_ratchet_key->public_key));
        } else {
            // PQC mode
            copy_protobuf_from_protobuf(&(sender_chain->our_ratchet_public_key), &ciphertext);
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        *ratchet_out = ratchet;
    } else {
        free_proto(ratchet);
    }

    // release
    if (derived_secrets != NULL) {
        free_mem((void **)&derived_secrets, sizeof(uint8_t) * derived_secrets_len);
    }
    if (ciphertext.data != NULL) {
        free_mem((void **)&(ciphertext.data), sizeof(uint8_t) * ciphertext.len);
    }

    return ret;
}

int initialise_as_alice(E2ees__Ratchet **ratchet_out, const cipher_suite_t *cipher_suite, const uint8_t *shared_secret, size_t shared_secret_len, const E2ees__KeyPair *our_ratchet_key,
                        ProtobufCBinaryData *their_ratchet_key, ProtobufCBinaryData *their_encaps_ciphertext) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Ratchet *ratchet = NULL;
    bool pqc_param;
    int shared_key_len = 0;
    int hf_len = 0;
    uint8_t *derived_secrets = NULL;
    size_t derived_secrets_len = 0;

    if (is_valid_cipher_suite(cipher_suite)) {
        pqc_param = cipher_suite->kem_suite->get_param().pqc_param;
        if (pqc_param) {
            if (!is_valid_protobuf(their_encaps_ciphertext))
                ret = E2EES_RESULT_FAIL;
        } else {
            if (their_encaps_ciphertext != NULL)
                ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "initialise_as_alice() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }
    if (shared_secret == NULL)
        ret = E2EES_RESULT_FAIL;
    if (shared_secret_len == 0)
        ret = E2EES_RESULT_FAIL;
    if (!is_valid_key_pair(our_ratchet_key)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_protobuf(their_ratchet_key))
        ret = E2EES_RESULT_FAIL;

    if (ret == E2EES_RESULT_SUCC) {
        // the length of derived_secrets will be 64 bytes
        shared_key_len = cipher_suite->hf_suite->get_param().hf_len;
        derived_secrets_len = shared_key_len * 2;
        derived_secrets = (uint8_t *)malloc(sizeof(uint8_t) * derived_secrets_len);
        hf_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t salt[hf_len];
        memset(salt, 0, hf_len);
        // shared_secret_len may be 128 or 96
        ret = cipher_suite->hf_suite->hkdf(shared_secret, shared_secret_len, salt, sizeof(salt), (uint8_t *)KDF_INFO_ROOT, sizeof(KDF_INFO_ROOT) - 1, derived_secrets, derived_secrets_len);
    }

    if (ret == E2EES_RESULT_SUCC) {
        ratchet = (E2ees__Ratchet *)malloc(sizeof(E2ees__Ratchet));
        e2ees__ratchet__init(ratchet);
        ratchet->receiver_chain = (E2ees__ReceiverChainNode *)malloc(sizeof(E2ees__ReceiverChainNode));
        E2ees__ReceiverChainNode *receiver_chain = ratchet->receiver_chain;
        e2ees__receiver_chain_node__init(receiver_chain);
        receiver_chain->chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
        e2ees__chain_key__init(receiver_chain->chain_key);

        /** The first half of the derived_secrets will be the root key,
         *  and the second half will be the receiver chain key */
        copy_protobuf_from_array(&(ratchet->root_key), derived_secrets, shared_key_len);

        copy_protobuf_from_array(&(receiver_chain->chain_key->shared_key), derived_secrets + shared_key_len, shared_key_len);

        copy_protobuf_from_protobuf(&(receiver_chain->our_ratchet_private_key), &(our_ratchet_key->private_key));
        if (pqc_param == false) {
            // ECC mode
            copy_protobuf_from_protobuf(&(receiver_chain->their_ratchet_public_key), their_ratchet_key);
        } else {
            // PQC mode
            copy_protobuf_from_protobuf(&(receiver_chain->their_ratchet_public_key), their_encaps_ciphertext);
        }

        // generate a new root key and a sender chain key
        ratchet->sender_chain = (E2ees__SenderChainNode *)malloc(sizeof(E2ees__SenderChainNode));
        E2ees__SenderChainNode *sender_chain = ratchet->sender_chain;
        e2ees__sender_chain_node__init(sender_chain);

        sender_chain->chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
        e2ees__chain_key__init(sender_chain->chain_key);

        if (pqc_param == false) {
            // ECC mode
            create_chain_key(cipher_suite, ratchet->root_key, &(our_ratchet_key->private_key), their_ratchet_key, &(ratchet->root_key), sender_chain->chain_key, NULL);
            copy_protobuf_from_protobuf(&(sender_chain->our_ratchet_public_key), &(our_ratchet_key->public_key));
            copy_protobuf_from_protobuf(&(sender_chain->their_ratchet_public_key), their_ratchet_key);
        } else {
            // PQC mode
            create_chain_key(cipher_suite, ratchet->root_key, NULL, their_ratchet_key, &(ratchet->root_key), sender_chain->chain_key, &(sender_chain->our_ratchet_public_key));
            copy_protobuf_from_protobuf(&(sender_chain->their_ratchet_public_key), their_ratchet_key);
        }

        // inviter's initial root sequence
        ratchet->root_sequence = 1;
    }

    if (ret == E2EES_RESULT_SUCC) {
        *ratchet_out = ratchet;
    } else {
        free_proto(ratchet);
    }

    // release
    if (derived_secrets != NULL) {
        free_mem((void **)&derived_secrets, sizeof(uint8_t) * derived_secrets_len);
    }

    return ret;
}

int encrypt_ratchet(E2ees__One2oneMsgPayload **payload_out, const cipher_suite_t *cipher_suite, E2ees__Ratchet *ratchet, ProtobufCBinaryData ad, const uint8_t *plaintext_data,
                    size_t plaintext_data_len) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__SenderChainNode *sender_chain = NULL;
    E2ees__ChainKey *chain_key = NULL;

    if (!is_valid_cipher_suite(cipher_suite)) {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "encrypt_ratchet() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }
    if (ratchet != NULL) {
        if (is_valid_sender_chain(ratchet->sender_chain)) {
            sender_chain = ratchet->sender_chain;
            chain_key = sender_chain->chain_key;
        } else {
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        ret = E2EES_RESULT_FAIL;
    }
    if (plaintext_data == NULL)
        ret = E2EES_RESULT_FAIL;

    if (ret == E2EES_RESULT_SUCC) {
        E2ees__MsgKey *msg_key = NULL;
        create_msg_keys(cipher_suite, chain_key, &msg_key);
        advance_chain_key(cipher_suite, chain_key);

        (ratchet->sending_message_sequence)++;

        uint32_t sequence = msg_key->index;

        *payload_out = (E2ees__One2oneMsgPayload *)malloc(sizeof(E2ees__One2oneMsgPayload));
        e2ees__one2one_msg_payload__init(*payload_out);
        (*payload_out)->sequence = sequence;
        copy_protobuf_from_protobuf(&((*payload_out)->ratchet_key), &(sender_chain->our_ratchet_public_key));
        (*payload_out)->root_sequence = ratchet->root_sequence;
        (*payload_out)->sending_message_sequence = ratchet->sending_message_sequence;
        ret = cipher_suite->se_suite->encrypt(&ad, msg_key->derived_key.data, plaintext_data, plaintext_data_len, &((*payload_out)->ciphertext.data), &((*payload_out)->ciphertext.len));

        if (ret != E2EES_RESULT_SUCC) {
            e2ees__one2one_msg_payload__free_unpacked(*payload_out, NULL);
            *payload_out = NULL;
        }

        // release
        e2ees__msg_key__free_unpacked(msg_key, NULL);
    }

    // done
    return ret;
}

int decrypt_ratchet(uint8_t **decrypted_data_out, size_t *decrypted_data_len_out, const cipher_suite_t *cipher_suite, E2ees__Ratchet *ratchet, ProtobufCBinaryData ad,
                    E2ees__One2oneMsgPayload *payload) {
    int ret = E2EES_RESULT_SUCC;

    bool pqc_param;
    int ratchet_key_len = 0;
    uint32_t coming_root_sequence = 0;
    uint32_t our_root_sequence = 0;
    E2ees__ReceiverChainNode *corresponding_receiver_chain = NULL;
    bool skipped_message = false;

    if (is_valid_cipher_suite(cipher_suite)) {
        // the cipher suite should exist and be safe
        pqc_param = cipher_suite->kem_suite->get_param().pqc_param;
        if (pqc_param == false) {
            ratchet_key_len = cipher_suite->kem_suite->get_param().asym_pub_key_len;
        } else {
            ratchet_key_len = cipher_suite->kem_suite->get_param().kem_ciphertext_len;
        }
        if (is_valid_one2one_msg_payload(payload)) {
            if (payload->ratchet_key.len != ratchet_key_len) {
                // the ratchet key length should be equal
                ret = E2EES_RESULT_FAIL;
            }
        } else {
            // something wrong with the payload
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_protobuf(&ad)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (!is_valid_ratchet(ratchet)) {
            ret = E2EES_RESULT_FAIL;
        }
        if (ret == E2EES_RESULT_SUCC) {
            if (ratchet->root_sequence == 0) {
                if (payload->sending_message_sequence < payload->sequence) {
                    ret = E2EES_RESULT_FAIL;
                }
            }
        }
        if (ret == E2EES_RESULT_SUCC) {
            // compare the root sequences of each other
            coming_root_sequence = payload->root_sequence;
            our_root_sequence = ratchet->root_sequence;
            if (coming_root_sequence != our_root_sequence) {
                if (coming_root_sequence < our_root_sequence) {
                    if (coming_root_sequence == our_root_sequence - 1) {
                        if (compare_protobuf(&(ratchet->receiver_chain->their_ratchet_public_key), &(payload->ratchet_key))) {
                            // the current chain
                            corresponding_receiver_chain = ratchet->receiver_chain;
                            if (corresponding_receiver_chain->chain_key->index > payload->sequence) {
                                skipped_message = true;
                            }
                        } else {
                            e2ees_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "decrypt_ratchet()");
                            ret = E2EES_RESULT_FAIL;
                        }
                    } else {
                        // the chain before the current one
                        skipped_message = true;
                    }
                } else {
                    /**
                     * If their root sequence is bigger than ours, then only one condition can be satisfied:
                     * coming_root_sequence = our_root_sequence + 1
                     */
                    if (coming_root_sequence != our_root_sequence + 1) {
                        e2ees_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "decrypt_ratchet() coming_root_sequence: %d, our_root_sequence: %d", coming_root_sequence, our_root_sequence);
                        ret = E2EES_RESULT_FAIL;
                    }
                }
            } else {
                // the root sequences of each other cannot be the same
                e2ees_notify_log(NULL, BAD_MESSAGE_SEQUENCE, "decrypt_ratchet() coming_root_sequence: %d, our_root_sequence: %d", coming_root_sequence, our_root_sequence);
                ret = E2EES_RESULT_FAIL;
            }
        }
    } else {
        e2ees_notify_log(NULL, BAD_CIPHER_SUITE, "decrypt_ratchet() invalid cipher suite");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        if (skipped_message == true) {
            /* receiver_chain already advanced beyond the key for this message
             * Check if the message keys are in the skipped key list. */
            ret = E2EES_RESULT_FAIL;
            size_t i, j;
            for (i = 0; i < ratchet->n_skipped_msg_key_list; i++) {
                if (payload->sequence == ratchet->skipped_msg_key_list[i]->msg_key->index &&
                    0 == memcmp(ratchet->skipped_msg_key_list[i]->ratchet_key_public.data, payload->ratchet_key.data, ratchet_key_len)) {
                    ret = verify_and_decrypt(decrypted_data_out, decrypted_data_len_out, cipher_suite, ad, ratchet->skipped_msg_key_list[i]->msg_key, payload);

                    if (ret == E2EES_RESULT_SUCC) {
                        // decryption success, so we need to eliminate the skipped message
                        if (ratchet->n_skipped_msg_key_list == 1) {
                            /*
                             * Edge case: If there is only 1 skipped message key left in the list,
                             * and we have just successfully used it for decryption, the list should now be empty.
                             * We free the memory and explicitly set the pointer to NULL.
                             * This prevents the dangerous malloc(0) behavior in the else-block
                             * and ensures it passes the strict is_valid_ratchet() validation.
                             */
                            free_skipped_message_key(&(ratchet->skipped_msg_key_list), ratchet->n_skipped_msg_key_list);
                            ratchet->skipped_msg_key_list = NULL;
                            ratchet->n_skipped_msg_key_list = 0;
                        } else {
                            /*
                             * Normal case: There are multiple skipped message keys.
                             * We simply free the used key, shift the remaining array elements left,
                             * and optionally shrink the array to save memory.
                             */
                            e2ees__skipped_msg_key_node__free_unpacked(ratchet->skipped_msg_key_list[i], NULL);

                            if (i < ratchet->n_skipped_msg_key_list - 1) {
                                memmove(&(ratchet->skipped_msg_key_list[i]), &(ratchet->skipped_msg_key_list[i + 1]),
                                        sizeof(E2ees__SkippedMsgKeyNode *) * (ratchet->n_skipped_msg_key_list - i - 1));
                            }

                            (ratchet->n_skipped_msg_key_list)--;
                            E2ees__SkippedMsgKeyNode **temp_skipped_message_keys =
                                (E2ees__SkippedMsgKeyNode **)realloc(ratchet->skipped_msg_key_list, sizeof(E2ees__SkippedMsgKeyNode *) * ratchet->n_skipped_msg_key_list);
                            if (temp_skipped_message_keys != NULL) {
                                ratchet->skipped_msg_key_list = temp_skipped_message_keys;
                            }
                        }

                        break;
                    } else {
                        // the decryption failed
                        e2ees_notify_log(NULL, BAD_MESSAGE_DECRYPTION, "verify_and_decrypt() in decrypt_ratchet()");
                    }
                }
            }
            if (ret != 0) {
                // the corresponding message key not found or the decryption failed
                e2ees_notify_log(NULL, BAD_MESSAGE_KEY, "decrypt_ratchet()");
            }
        } else {
            if (corresponding_receiver_chain == NULL) {
                /* They have started using a new ephemeral ratchet key.
                 * We will check if we can decrypt the message correctly.
                 * We will not store our new chain key now.
                 * We will store our new chain key later when decrypting the message correctly. */
                ret = verify_and_decrypt_for_new_chain(decrypted_data_out, decrypted_data_len_out, cipher_suite, ratchet, ad, payload);
                if (ret != 0) {
                    // the decryption failed
                    e2ees_notify_log(NULL, BAD_MESSAGE_DECRYPTION, "verify_and_decrypt_for_new_chain() in decrypt_ratchet()");
                }
            } else {
                /* They use the same ratchet key. The sequence of the payload(incoming message)
                 * may be bigger than or equal to the index of our receiver chain. */
                ret = verify_and_decrypt_for_existing_chain(decrypted_data_out, decrypted_data_len_out, cipher_suite, ad, corresponding_receiver_chain->chain_key, payload);
                if (ret != 0) {
                    // the decryption failed
                    e2ees_notify_log(NULL, BAD_MESSAGE_DECRYPTION, "verify_and_decrypt_for_existing_chain() in decrypt_ratchet()");
                }
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        // if the decryption is success, we will update our ratchet state if neccessary
        if (corresponding_receiver_chain == NULL) {
            if (skipped_message == false) {
                /* They have started using a new ephemeral ratchet key.
                 * We need to derive a new set of chain keys.
                 * We can discard our previous empheral ratchet key.
                 * We will generate a new key when we send the next message. */

                if (payload->sending_message_sequence - ratchet->received_message_sequence > payload->sequence + 1) {
                    // we skipped some messages in the previous ratchet
                    size_t skipped_num = payload->sending_message_sequence - ratchet->received_message_sequence - (payload->sequence + 1);
                    // check the limit
                    if (ratchet->n_skipped_msg_key_list + skipped_num > MAX_SKIPPED_MESSAGE_KEY_NODES) {
                        e2ees_notify_log(NULL, DEBUG_LOG, "decrypt_ratchet(): Too many skipped keys in previous chain! Bomb defused.");
                        ret = E2EES_RESULT_FAIL;
                    } else {
                        if (ratchet->skipped_msg_key_list == NULL) {
                            ratchet->skipped_msg_key_list = (E2ees__SkippedMsgKeyNode **)malloc(sizeof(E2ees__SkippedMsgKeyNode *) * skipped_num);
                        } else {
                            E2ees__SkippedMsgKeyNode **temp_skipped_message_keys =
                                (E2ees__SkippedMsgKeyNode **)realloc(ratchet->skipped_msg_key_list, sizeof(E2ees__SkippedMsgKeyNode *) * (ratchet->n_skipped_msg_key_list + skipped_num));
                            if (temp_skipped_message_keys != NULL) {
                                ratchet->skipped_msg_key_list = temp_skipped_message_keys;
                            }
                        }
                        size_t cur_seq;
                        for (cur_seq = 0; cur_seq < skipped_num; cur_seq++) {
                            // insert data
                            E2ees__SkippedMsgKeyNode *key = (E2ees__SkippedMsgKeyNode *)malloc(sizeof(E2ees__SkippedMsgKeyNode));
                            e2ees__skipped_msg_key_node__init(key);
                            key->msg_key = NULL;
                            create_msg_keys(cipher_suite, ratchet->receiver_chain->chain_key, &(key->msg_key));
                            copy_protobuf_from_protobuf(&(key->ratchet_key_public), &(ratchet->receiver_chain->their_ratchet_public_key));

                            ratchet->skipped_msg_key_list[ratchet->n_skipped_msg_key_list] = key;
                            (ratchet->n_skipped_msg_key_list)++;
                            advance_chain_key(cipher_suite, ratchet->receiver_chain->chain_key);
                        }
                    }
                }

                E2ees__KeyPair *new_ratchet_key_pair = NULL;

                E2ees__ReceiverChainNode *new_receiver_chain = (E2ees__ReceiverChainNode *)malloc(sizeof(E2ees__ReceiverChainNode));
                e2ees__receiver_chain_node__init(new_receiver_chain);

                // copy their ratchet key
                copy_protobuf_from_protobuf(&(new_receiver_chain->their_ratchet_public_key), &(payload->ratchet_key));

                // create a new receiver chain key
                new_receiver_chain->chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
                e2ees__chain_key__init(new_receiver_chain->chain_key);
                create_chain_key(cipher_suite, ratchet->root_key, &(ratchet->receiver_chain->our_ratchet_private_key), &(new_receiver_chain->their_ratchet_public_key), &(ratchet->root_key),
                                 new_receiver_chain->chain_key, NULL);

                corresponding_receiver_chain = new_receiver_chain;

                // create a new sender chain
                E2ees__SenderChainNode *new_sender_chain = (E2ees__SenderChainNode *)malloc(sizeof(E2ees__SenderChainNode));
                e2ees__sender_chain_node__init(new_sender_chain);

                new_sender_chain->chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
                e2ees__chain_key__init(new_sender_chain->chain_key);
                if (cipher_suite->kem_suite->get_param().pqc_param == false) {
                    // ECC mode
                    new_ratchet_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
                    e2ees__key_pair__init(new_ratchet_key_pair);
                    cipher_suite->kem_suite->asym_key_gen(&new_ratchet_key_pair->public_key, &new_ratchet_key_pair->private_key);

                    copy_protobuf_from_protobuf(&(new_receiver_chain->our_ratchet_private_key), &(new_ratchet_key_pair->private_key));

                    copy_protobuf_from_protobuf(&(new_sender_chain->our_ratchet_public_key), &(new_ratchet_key_pair->public_key));
                    copy_protobuf_from_protobuf(&(new_sender_chain->their_ratchet_public_key), &(new_receiver_chain->their_ratchet_public_key));
                    create_chain_key(cipher_suite, ratchet->root_key, &(new_ratchet_key_pair->private_key), &(new_sender_chain->their_ratchet_public_key), &(ratchet->root_key),
                                     new_sender_chain->chain_key, NULL);

                    e2ees__key_pair__free_unpacked(new_ratchet_key_pair, NULL);
                } else {
                    // PQC mode
                    copy_protobuf_from_protobuf(&(new_receiver_chain->our_ratchet_private_key), &(ratchet->receiver_chain->our_ratchet_private_key));

                    copy_protobuf_from_protobuf(&(new_sender_chain->their_ratchet_public_key), &(ratchet->sender_chain->their_ratchet_public_key));
                    create_chain_key(cipher_suite, ratchet->root_key, NULL, &(new_sender_chain->their_ratchet_public_key), &(ratchet->root_key), new_sender_chain->chain_key,
                                     &(new_sender_chain->our_ratchet_public_key));
                }

                e2ees__receiver_chain_node__free_unpacked(ratchet->receiver_chain, NULL);
                ratchet->receiver_chain = new_receiver_chain;
                (ratchet->root_sequence)++;

                e2ees__sender_chain_node__free_unpacked(ratchet->sender_chain, NULL);
                ratchet->sender_chain = new_sender_chain;
                (ratchet->root_sequence)++;
            }
        }

        if (corresponding_receiver_chain != NULL) {
            if (corresponding_receiver_chain->chain_key->index < payload->sequence) {
                /* We skipped some messages.
                 * We will generate the corresponding message keys and store them
                 * together with their ratchet key in the skipped message key list. */
                size_t skipped_num = payload->sequence - corresponding_receiver_chain->chain_key->index;
                // check the limit
                if (ratchet->n_skipped_msg_key_list + skipped_num > MAX_SKIPPED_MESSAGE_KEY_NODES) {
                    e2ees_notify_log(NULL, DEBUG_LOG, "decrypt_ratchet(): Too many skipped keys in current chain! Bomb defused.");
                    ret = E2EES_RESULT_FAIL;
                } else {
                    if (ratchet->skipped_msg_key_list == NULL) {
                        ratchet->skipped_msg_key_list = (E2ees__SkippedMsgKeyNode **)malloc(sizeof(E2ees__SkippedMsgKeyNode *) * skipped_num);
                    } else {
                        E2ees__SkippedMsgKeyNode **temp_skipped_message_keys =
                            (E2ees__SkippedMsgKeyNode **)realloc(ratchet->skipped_msg_key_list, sizeof(E2ees__SkippedMsgKeyNode *) * (ratchet->n_skipped_msg_key_list + skipped_num));
                        if (temp_skipped_message_keys != NULL) {
                            ratchet->skipped_msg_key_list = temp_skipped_message_keys;
                        }
                    }
                    while (corresponding_receiver_chain->chain_key->index < payload->sequence) {
                        // insert data
                        E2ees__SkippedMsgKeyNode *key = (E2ees__SkippedMsgKeyNode *)malloc(sizeof(E2ees__SkippedMsgKeyNode));
                        e2ees__skipped_msg_key_node__init(key);
                        key->msg_key = NULL;
                        create_msg_keys(cipher_suite, corresponding_receiver_chain->chain_key, &(key->msg_key));
                        copy_protobuf_from_protobuf(&(key->ratchet_key_public), &(corresponding_receiver_chain->their_ratchet_public_key));

                        ratchet->skipped_msg_key_list[ratchet->n_skipped_msg_key_list] = key;
                        (ratchet->n_skipped_msg_key_list)++;
                        advance_chain_key(cipher_suite, corresponding_receiver_chain->chain_key);
                    }
                }
            }

            if (corresponding_receiver_chain->chain_key->index == payload->sequence) {
                /* If we decrypt the incoming message by a skipped message key,
                 * we will not need to advance the chain key. */
                advance_chain_key(cipher_suite, corresponding_receiver_chain->chain_key);
            }

            // update received_message_sequence
            if (payload->sending_message_sequence > ratchet->received_message_sequence) {
                ratchet->received_message_sequence = payload->sending_message_sequence;
            }
        }
    }

    if (ratchet != NULL) {
        prune_bloated_skipped_keys(ratchet);
    }

    return ret;
}
