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
#include "e2ees/group_session.h"

#include <string.h>

#include "e2ees/account_cache.h"
#include "e2ees/cipher.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/group_session_manager.h"
#include "e2ees/mem_util.h"
#include "e2ees/validation.h"
#include "e2ees/session.h"
#include "e2ees/session_manager.h"

#define SEED_SECRET_LEN 32

static const char ROOT_SEED[] = "ROOT";
static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const char MESSAGE_KEY_SEED[] = "MessageKeys";

void advance_group_chain_key(const cipher_suite_t *cipher_suite, ProtobufCBinaryData *chain_key) {
    uint32_t group_shared_key_len = cipher_suite->hf_suite->get_param().hf_len;
    uint8_t shared_key[group_shared_key_len];
    cipher_suite->hf_suite->hmac(
        chain_key->data, chain_key->len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    overwrite_protobuf_from_array(chain_key, shared_key);
}

void advance_group_chain_key_by_welcome(
    const cipher_suite_t *cipher_suite, const ProtobufCBinaryData *src_chain_key, ProtobufCBinaryData **dest_chain_key
) {
    uint32_t hf_len = cipher_suite->hf_suite->get_param().hf_len;
    uint8_t salt[] = "welcome";

    *dest_chain_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    (*dest_chain_key)->len = hf_len;
    (*dest_chain_key)->data = (uint8_t *)malloc(sizeof(uint8_t) * hf_len);

    cipher_suite->hf_suite->hkdf(
        src_chain_key->data, src_chain_key->len,
        salt, sizeof(salt) - 1,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        (*dest_chain_key)->data, (*dest_chain_key)->len
    );
}

void advance_group_chain_key_by_add(
    const cipher_suite_t *cipher_suite, const ProtobufCBinaryData *src_chain_key, ProtobufCBinaryData *dest_chain_key
) {
    uint32_t hf_len = cipher_suite->hf_suite->get_param().hf_len;
    uint8_t salt[] = "add";

    ProtobufCBinaryData *new_chain_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    new_chain_key->len = hf_len;
    new_chain_key->data = (uint8_t *)malloc(sizeof(uint8_t) * hf_len);

    cipher_suite->hf_suite->hkdf(
        src_chain_key->data, src_chain_key->len,
        salt, sizeof(salt) - 1,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        new_chain_key->data, new_chain_key->len
    );

    overwrite_protobuf_from_array(dest_chain_key, new_chain_key->data);

    // release
    free_mem((void **)&(new_chain_key->data), sizeof(uint8_t) * hf_len);
    free_mem((void **)&new_chain_key, sizeof(ProtobufCBinaryData));
}

void create_group_message_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    E2ees__MsgKey *msg_key
) {
    uint32_t group_msg_key_len = cipher_suite->se_suite->get_param().aead_key_len + cipher_suite->se_suite->get_param().aead_iv_len;

    free_protobuf(&(msg_key->derived_key));
    msg_key->derived_key.data = (uint8_t *)malloc(sizeof(uint8_t) * group_msg_key_len);
    msg_key->derived_key.len = group_msg_key_len;

    uint32_t hf_len = cipher_suite->hf_suite->get_param().hf_len;
    uint8_t salt[hf_len];
    memset(salt, 0, hf_len);
    cipher_suite->hf_suite->hkdf(
        chain_key->data, chain_key->len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        msg_key->derived_key.data, msg_key->derived_key.len
    );
}

static void pack_group_pre_key(
    E2ees__GroupPreKeyBundle *group_pre_key_bundle,
    uint8_t **group_pre_key_plaintext_data,
    size_t *group_pre_key_plaintext_data_len
) {
    E2ees__Plaintext *plaintext = (E2ees__Plaintext *)malloc(sizeof(E2ees__Plaintext));
    e2ees__plaintext__init(plaintext);
    plaintext->version = strdup(E2EES_PLAINTEXT_VERSION);
    plaintext->payload_case = E2EES__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE;
    plaintext->group_pre_key_bundle = group_pre_key_bundle;

    size_t len = e2ees__plaintext__get_packed_size(plaintext);
    *group_pre_key_plaintext_data_len = len;
    *group_pre_key_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    e2ees__plaintext__pack(plaintext, *group_pre_key_plaintext_data);

    // release
    // group_pre_key_bundle will also be released
    e2ees__plaintext__free_unpacked(plaintext, NULL);
}

size_t pack_group_pre_key_plaintext(
    E2ees__GroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext_data,
    char *old_session_id
) {
    E2ees__GroupPreKeyBundle *group_pre_key_bundle = (E2ees__GroupPreKeyBundle *)malloc(sizeof(E2ees__GroupPreKeyBundle));
    e2ees__group_pre_key_bundle__init(group_pre_key_bundle);

    group_pre_key_bundle->version = strdup(outbound_group_session->version);

    group_pre_key_bundle->e2ees_pack_id = outbound_group_session->e2ees_pack_id;

    group_pre_key_bundle->session_id = strdup(outbound_group_session->session_id);

    if (old_session_id != NULL) {
        group_pre_key_bundle->old_session_id = strdup(old_session_id);
    }

    copy_address_from_address(&(group_pre_key_bundle->sender), outbound_group_session->sender);

    copy_group_info(&(group_pre_key_bundle->group_info), outbound_group_session->group_info);

    group_pre_key_bundle->sequence = outbound_group_session->sequence;
    copy_protobuf_from_protobuf(&(group_pre_key_bundle->group_seed), &(outbound_group_session->group_seed));

    // pack the group_pre_key_bundle
    size_t group_pre_key_plaintext_data_len;
    pack_group_pre_key(
        group_pre_key_bundle,
        group_pre_key_plaintext_data, &group_pre_key_plaintext_data_len
    );

    // release
    // group_pre_key_bundle is released in pack_group_pre_key()

    // done
    return group_pre_key_plaintext_data_len;
}

static void pack_group_ratchet_state(
    E2ees__GroupUpdateKeyBundle *group_update_key_bundle,
    uint8_t **group_ratchet_state_plaintext_data,
    size_t *group_ratchet_state_plaintext_data_len
) {
    E2ees__Plaintext *plaintext = (E2ees__Plaintext *)malloc(sizeof(E2ees__Plaintext));
    e2ees__plaintext__init(plaintext);
    plaintext->version = strdup(E2EES_PLAINTEXT_VERSION);
    plaintext->payload_case = E2EES__PLAINTEXT__PAYLOAD_GROUP_UPDATE_KEY_BUNDLE;
    plaintext->group_update_key_bundle = group_update_key_bundle;

    size_t len = e2ees__plaintext__get_packed_size(plaintext);
    *group_ratchet_state_plaintext_data_len = len;
    *group_ratchet_state_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    e2ees__plaintext__pack(plaintext, *group_ratchet_state_plaintext_data);

    // release
    // group_update_key_bundle will also be released
    e2ees__plaintext__free_unpacked(plaintext, NULL);
}

size_t pack_group_ratchet_state_plaintext(
    E2ees__GroupSession *outbound_group_session,
    uint8_t **group_ratchet_state_plaintext_data,
    bool adding,
    ProtobufCBinaryData *identity_public_key,
    size_t n_adding_member_info_list,
    E2ees__GroupMemberInfo **adding_member_info_list
) {
    E2ees__GroupUpdateKeyBundle *group_update_key_bundle = (E2ees__GroupUpdateKeyBundle *)malloc(sizeof(E2ees__GroupUpdateKeyBundle));
    e2ees__group_update_key_bundle__init(group_update_key_bundle);

    group_update_key_bundle->version = strdup(outbound_group_session->version);
    group_update_key_bundle->e2ees_pack_id = outbound_group_session->e2ees_pack_id;

    group_update_key_bundle->session_id = strdup(outbound_group_session->session_id);

    copy_address_from_address(&(group_update_key_bundle->sender), outbound_group_session->sender);

    group_update_key_bundle->adding = adding;

    copy_group_info(&(group_update_key_bundle->group_info), outbound_group_session->group_info);

    group_update_key_bundle->sequence = outbound_group_session->sequence;

    copy_protobuf_from_protobuf(&(group_update_key_bundle->chain_key), &(outbound_group_session->chain_key));

    copy_protobuf_from_protobuf(&(group_update_key_bundle->sign_public_key), identity_public_key);

    group_update_key_bundle->n_adding_member_info_list = n_adding_member_info_list;
    copy_group_member_ids(&(group_update_key_bundle->adding_member_info_list), adding_member_info_list, n_adding_member_info_list);

    // pack
    size_t group_ratchet_state_plaintext_data_len;
    pack_group_ratchet_state(
        group_update_key_bundle,
        group_ratchet_state_plaintext_data, &group_ratchet_state_plaintext_data_len
    );

    // release
    // group_update_key_bundle is released in pack_group_ratchet_state()

    // done
    return group_ratchet_state_plaintext_data_len;
}

static void insert_outbound_group_session_data(
    E2ees__GroupSession *outbound_group_session,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    const char *group_name,
    E2ees__E2eeAddress *group_address,
    const char *session_id,
    E2ees__GroupMember **group_member_list,
    size_t group_members_num,
    const uint8_t *identity_public_key
) {
    const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;
    uint32_t sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

    outbound_group_session->version = strdup(E2EES_PROTOCOL_VERSION);
    outbound_group_session->e2ees_pack_id = e2ees_pack_id;

    copy_address_from_address(&(outbound_group_session->sender), user_address);
    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    if (session_id == NULL)
        outbound_group_session->session_id = generate_uuid_str();
    else
        outbound_group_session->session_id = strdup(session_id);

    outbound_group_session->group_info = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = outbound_group_session->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup(group_name);
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = group_members_num;
    copy_group_members(&(group_info->group_member_list), group_member_list, group_members_num);

    outbound_group_session->sequence = 0;

    // combine seed secret and ID
    size_t secret_len = SEED_SECRET_LEN + sign_key_len;
    uint8_t *secret = (uint8_t *)malloc(sizeof(uint8_t) * secret_len);
    memcpy(secret, outbound_group_session->group_seed.data, SEED_SECRET_LEN);
    memcpy(secret + SEED_SECRET_LEN, identity_public_key, sign_key_len);

    // generate a chain key
    uint32_t hf_len = cipher_suite->hf_suite->get_param().hf_len;
    uint8_t salt[hf_len];
    memset(salt, 0, hf_len);
    outbound_group_session->chain_key.len = hf_len;
    outbound_group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    cipher_suite->hf_suite->hkdf(
        secret, secret_len,
        salt, sizeof(salt),
        (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
        outbound_group_session->chain_key.data, outbound_group_session->chain_key.len
    );

    size_t ad_len = 2 * sign_key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, identity_public_key, sign_key_len);
    memcpy((outbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

    // release
    free_mem((void **)&secret, sizeof(uint8_t) * secret_len);
}

static void insert_inbound_group_session_data(
    E2ees__GroupMemberInfo *group_member_id,
    E2ees__GroupSession *other_group_session,
    E2ees__GroupSession *inbound_group_session
) {
    inbound_group_session->e2ees_pack_id = other_group_session->e2ees_pack_id;
    copy_address_from_address(&(inbound_group_session->session_owner), other_group_session->session_owner);

    inbound_group_session->version = strdup(other_group_session->version);
    inbound_group_session->session_id = strdup(other_group_session->session_id);

    copy_address_from_address(&(inbound_group_session->sender), group_member_id->member_address);

    copy_group_info(&(inbound_group_session->group_info), other_group_session->group_info);
}

int new_outbound_group_session_by_sender(
    size_t n_member_info_list,
    E2ees__GroupMemberInfo **member_info_list,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    const char *group_name,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupMember **group_member_list,
    size_t group_members_num,
    char *old_session_id
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Account *account = NULL;
    char *auth = NULL;
    E2ees__IdentityKey *identity_key = NULL;
    uint8_t *identity_public_key = NULL;
    E2ees__GroupSession *outbound_group_session = NULL;
    E2ees__GroupInfo *group_info = NULL;
    uint8_t *group_pre_key_plaintext_data = NULL;
    size_t group_pre_key_plaintext_data_len;
    char *cur_user_id = NULL, *cur_user_domain = NULL;
    E2ees__Session **outbound_sessions = NULL;
    size_t outbound_sessions_num;
    E2ees__Session *outbound_session = NULL;
    E2ees__SendOne2oneMsgResponse *response = NULL;
    E2ees__InviteResponse **invite_response_list = NULL;
    size_t invite_response_num = 0;
    size_t i, j;

    if (!is_valid_e2ees_pack_id(e2ees_pack_id)) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "new_outbound_group_session_by_sender() invalid e2ees pack id with e2ees_pack_id = %d", e2ees_pack_id
        );
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(user_address)) {
        e2ees_notify_log(NULL, BAD_ADDRESS, "new_outbound_group_session_by_sender()");
        ret = E2EES_RESULT_FAIL;
    } else {
        load_identity_key_from_cache(&identity_key, user_address);

        if (identity_key == NULL) {
            get_e2ees_plugin()->db_handler.load_account_by_address(user_address, &account);
            if (account == NULL) {
                e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_sender()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = get_identity_public_key_ds_uint8_from_account(account);
                if (identity_public_key == NULL) {
                    e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_sender()");
                    ret = E2EES_RESULT_FAIL;
                } else {
                    auth = strdup(account->auth);
                }
            }
        } else {
            load_auth_from_cache(&auth, user_address);

            if (auth == NULL) {
                e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_sender()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = identity_key->sign_key_pair->public_key.data;
            }
        }
    }

    if (!is_valid_group_member_info_list((const E2ees__GroupMemberInfo **)member_info_list, n_member_info_list)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "new_outbound_group_session_by_sender()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(group_name)) {
        e2ees_notify_log(NULL, BAD_GROUP_NAME, "new_outbound_group_session_by_sender()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(group_address)) {
        e2ees_notify_log(NULL, BAD_GROUP_ADDRESS, "new_outbound_group_session_by_sender()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_list(group_member_list, group_members_num)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBERS, "new_outbound_group_session_by_sender()");
        ret = E2EES_RESULT_FAIL;
    }
    if ((group_members_num == 0) || (n_member_info_list == 0) || (group_members_num > n_member_info_list)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBERS, "new_outbound_group_session_by_sender()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        outbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(outbound_group_session);

        // the sender needs to generate a random seed secret
        outbound_group_session->group_seed.len = SEED_SECRET_LEN;
        outbound_group_session->group_seed.data = (uint8_t *)malloc(sizeof(uint8_t) * outbound_group_session->group_seed.len);
        e2ees_randombytes(outbound_group_session->group_seed.data, outbound_group_session->group_seed.len);

        insert_outbound_group_session_data(
            outbound_group_session, e2ees_pack_id,
            user_address, group_name, group_address, NULL,
            group_member_list, group_members_num, identity_public_key
        );

        // only the group creator needs to send the group pre-key bundle to others
        group_pre_key_plaintext_data_len = pack_group_pre_key_plaintext(
            outbound_group_session, &group_pre_key_plaintext_data, old_session_id
        );

        group_info = outbound_group_session->group_info;
        // send the group pre-key message to the members in the group
        for (i = 0; i < group_info->n_group_member_list; i++) {
            // the ith group member
            cur_user_id = group_info->group_member_list[i]->user_id;
            cur_user_domain = group_info->group_member_list[i]->domain;
            outbound_sessions_num = get_e2ees_plugin()->db_handler.load_outbound_sessions(
                outbound_group_session->session_owner, cur_user_id, cur_user_domain, &outbound_sessions
            );

            if (outbound_sessions_num > 0 && outbound_sessions != NULL) {
                for (j = 0; j < outbound_sessions_num; j++) {
                    outbound_session = outbound_sessions[j];
                    if (compare_address(outbound_session->their_address, outbound_group_session->session_owner))
                        continue;
                    if (outbound_session->responded) {
                        response = send_one2one_msg_internal(
                            outbound_session,
                            E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION,
                            group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
                        );
                        e2ees__send_one2one_msg_response__free_unpacked(response, NULL);
                    } else {
                        /** Since the other has not responded, we store the group pre-key first so that
                         *  we can send it right after receiving the other's accept message.
                         */
                        store_pending_common_plaintext_data_internal(
                            outbound_session->our_address,
                            outbound_session->their_address,
                            group_pre_key_plaintext_data,
                            group_pre_key_plaintext_data_len,
                            E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                        );
                    }
                }
            } else {
                /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
                int invite_response_ret = get_pre_key_bundle_internal(
                    &invite_response_list,
                    &invite_response_num,
                    outbound_group_session->session_owner,
                    auth,
                    cur_user_id, cur_user_domain,
                    NULL, true,
                    group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
                );
                // release
                free_invite_response_list(&invite_response_list, invite_response_num);
            }
        }

        // create the inbound group sessions
        for (i = 0; i < n_member_info_list; i++) {
            if (!compare_address(member_info_list[i]->member_address, user_address))
                new_and_complete_inbound_group_session(member_info_list[i], outbound_group_session);
        }

        // we do not store the seed secret in the session
        free_protobuf(&(outbound_group_session->group_seed));

        // store
        get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);
    }

    // release
    free_proto(account);
    free_string(auth);
    free_proto(identity_key);
    e2ees__group_session__free_unpacked(outbound_group_session, NULL);
    free_mem((void **)&group_pre_key_plaintext_data, sizeof(uint8_t) * group_pre_key_plaintext_data_len);
    for (j = 0; j < outbound_sessions_num; j++) {
        e2ees__session__free_unpacked(outbound_sessions[j], NULL);
        outbound_sessions[j] = NULL;
    }
    free_mem((void **)&outbound_sessions, sizeof(E2ees__Session *) * outbound_sessions_num);

    return ret;
}

int new_outbound_group_session_by_receiver(
    const ProtobufCBinaryData *group_seed,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    const char *group_name,
    E2ees__E2eeAddress *group_address,
    const char *session_id,
    E2ees__GroupMember **group_member_list,
    size_t group_members_num
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Account *account = NULL;
    E2ees__IdentityKey *identity_key = NULL;
    uint8_t *identity_public_key = NULL;
    E2ees__GroupSession *outbound_group_session = NULL;

    if (!is_valid_e2ees_pack_id(e2ees_pack_id)) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "new_outbound_group_session_by_receiver() invalid e2ees pack id with e2ees_pack_id = %d", e2ees_pack_id
        );
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(user_address)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_by_receiver()");
        ret = E2EES_RESULT_FAIL;
    } else {
        load_identity_key_from_cache(&identity_key, user_address);

        if (identity_key == NULL) {
            get_e2ees_plugin()->db_handler.load_account_by_address(user_address, &account);
            if (account == NULL) {
                e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_receiver()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = get_identity_public_key_ds_uint8_from_account(account);
                if (identity_public_key == NULL) {
                    e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_receiver()");
                    ret = E2EES_RESULT_FAIL;
                }
            }
        } else {
            identity_public_key = identity_key->sign_key_pair->public_key.data;
        }
    }

    if (!is_valid_protobuf(group_seed)) {
        e2ees_notify_log(NULL, BAD_GROUP_SEED, "new_outbound_group_session_by_receiver()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(group_name)) {
        e2ees_notify_log(NULL, BAD_GROUP_NAME, "new_outbound_group_session_by_receiver()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(group_address)) {
        e2ees_notify_log(NULL, BAD_GROUP_ADDRESS, "new_outbound_group_session_by_receiver()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(session_id)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION_ID, "new_outbound_group_session_by_receiver()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_list(group_member_list, group_members_num)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBERS, "new_outbound_group_session_by_receiver()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        outbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(outbound_group_session);

        // the receiver gets the seed secret from the sender
        outbound_group_session->group_seed.len = group_seed->len;
        outbound_group_session->group_seed.data = (uint8_t *)malloc(sizeof(uint8_t) * outbound_group_session->group_seed.len);
        memcpy(outbound_group_session->group_seed.data, group_seed->data, group_seed->len);

        insert_outbound_group_session_data(
            outbound_group_session, e2ees_pack_id,
            user_address, group_name, group_address, session_id,
            group_member_list, group_members_num, identity_public_key
        );

        // we do not store the seed secret in the session
        free_protobuf(&(outbound_group_session->group_seed));

        // store
        get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);
    }

    // release
    free_proto(account);
    free_proto(identity_key);
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    return ret;
}

int new_outbound_group_session_invited(
    E2ees__GroupUpdateKeyBundle *group_update_key_bundle,
    E2ees__E2eeAddress *user_address
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Account *account = NULL;
    E2ees__IdentityKey *identity_key = NULL;
    uint8_t *identity_public_key = NULL;
    E2ees__GroupSession *outbound_group_session = NULL;
    uint32_t sign_key_len;
    uint32_t ad_len;
    size_t n_adding_member_info_list;
    ProtobufCBinaryData *sender_chain_key = NULL;
    ProtobufCBinaryData **adding_members_chain_key = NULL;
    size_t i;

    if (!is_valid_address(user_address)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_invited()");
        ret = E2EES_RESULT_FAIL;
    } else {
        load_identity_key_from_cache(&identity_key, user_address);

        if (identity_key == NULL) {
            get_e2ees_plugin()->db_handler.load_account_by_address(user_address, &account);
            if (account == NULL) {
                e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_invited()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = get_identity_public_key_ds_uint8_from_account(account);
                if (identity_public_key == NULL) {
                    e2ees_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_invited()");
                    ret = E2EES_RESULT_FAIL;
                }
            }
        } else {
            identity_public_key = identity_key->sign_key_pair->public_key.data;
        }
    }
    if (is_valid_group_update_key_bundle(group_update_key_bundle)) {
        n_adding_member_info_list = group_update_key_bundle->n_adding_member_info_list;
        sender_chain_key = &(group_update_key_bundle->chain_key);
    } else {
        e2ees_notify_log(NULL, BAD_GROUP_UPDATE_KEY_BUNDLE, "new_outbound_group_session_invited()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(group_update_key_bundle->e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        outbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(outbound_group_session);

        outbound_group_session->version = strdup(group_update_key_bundle->version);
        outbound_group_session->e2ees_pack_id = group_update_key_bundle->e2ees_pack_id;

        copy_address_from_address(&(outbound_group_session->sender), user_address);
        copy_address_from_address(&(outbound_group_session->session_owner), user_address);
        outbound_group_session->session_id = strdup(group_update_key_bundle->session_id);

        copy_group_info(&(outbound_group_session->group_info), group_update_key_bundle->group_info);

        ad_len = 2 * sign_key_len;
        outbound_group_session->associated_data.len = ad_len;
        outbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(outbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((outbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        adding_members_chain_key = (ProtobufCBinaryData **)malloc(sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
        for (i = 0; i < n_adding_member_info_list; i++) {
            // generate the chain keys, including the sender's and new members'
            advance_group_chain_key_by_welcome(cipher_suite, sender_chain_key, &(adding_members_chain_key[i]));
            advance_group_chain_key_by_add(cipher_suite, adding_members_chain_key[i], sender_chain_key);

            if (compare_address(group_update_key_bundle->adding_member_info_list[i]->member_address, user_address)) {
                // insert the chain key
                copy_protobuf_from_protobuf(&(outbound_group_session->chain_key), adding_members_chain_key[i]);
                outbound_group_session->sequence = 0;
            } else {
                // create an inbound group session corresponding to other new members
                new_and_complete_inbound_group_session_with_chain_key(
                    group_update_key_bundle->adding_member_info_list[i],
                    outbound_group_session,
                    adding_members_chain_key[i]
                );
            }
        }

        // store
        get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);
    }

    // release
    free_proto(account);
    free_proto(identity_key);
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }
    if (adding_members_chain_key != NULL) {
        for (i = 0; i < n_adding_member_info_list; i++) {
            free_protobuf(adding_members_chain_key[i]);
            free_mem((void **)&adding_members_chain_key[i], sizeof(ProtobufCBinaryData));
        }
        free_mem((void **)&adding_members_chain_key, sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
    }

    return ret;
}

int new_inbound_group_session_by_pre_key_bundle(
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    E2ees__GroupPreKeyBundle *group_pre_key_bundle
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupSession *inbound_group_session = NULL;
    ProtobufCBinaryData *group_seed = NULL;

    if (!is_valid_e2ees_pack_id(e2ees_pack_id)) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "new_inbound_group_session_by_pre_key_bundle() invalid e2ees pack id with e2ees_pack_id = %d", e2ees_pack_id
        );
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(user_address)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "new_inbound_group_session_by_pre_key_bundle()");
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_group_pre_key_bundle(group_pre_key_bundle)) {
        group_seed = &(group_pre_key_bundle->group_seed);
    } else {
        e2ees_notify_log(NULL, BAD_GROUP_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        inbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(inbound_group_session);

        inbound_group_session->e2ees_pack_id = e2ees_pack_id;
        copy_address_from_address(&(inbound_group_session->session_owner), user_address);

        inbound_group_session->version = strdup(group_pre_key_bundle->version);
        inbound_group_session->session_id = strdup(group_pre_key_bundle->session_id);

        copy_address_from_address(&(inbound_group_session->sender), group_pre_key_bundle->sender);

        copy_group_info(&(inbound_group_session->group_info), group_pre_key_bundle->group_info);

        inbound_group_session->sequence = group_pre_key_bundle->sequence;

        inbound_group_session->group_seed.len = group_seed->len;
        inbound_group_session->group_seed.data = (uint8_t *)malloc(sizeof(uint8_t) * inbound_group_session->group_seed.len);
        memcpy(inbound_group_session->group_seed.data, group_seed->data, group_seed->len);

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    return ret;
}

int new_inbound_group_session_by_member_id(
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    E2ees__GroupMemberInfo *group_member_id,
    E2ees__GroupInfo *group_info
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupSession *inbound_group_session = NULL;
    uint32_t sign_key_len;
    uint32_t ad_len;

    if (!is_valid_e2ees_pack_id(e2ees_pack_id)) {
        e2ees_notify_log(
            NULL,
            BAD_E2EES_PACK,
            "new_inbound_group_session_by_member_id() invalid e2ees pack id with e2ees_pack_id = %d", e2ees_pack_id
        );
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(user_address)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "new_inbound_group_session_by_member_id()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_info(group_member_id)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "new_inbound_group_session_by_member_id()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_info(group_info)) {
        e2ees_notify_log(NULL, BAD_GROUP_INFO, "new_inbound_group_session_by_member_id()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        inbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(inbound_group_session);

        inbound_group_session->e2ees_pack_id = e2ees_pack_id;
        copy_address_from_address(&(inbound_group_session->session_owner), user_address);

        copy_address_from_address(&(inbound_group_session->sender), group_member_id->member_address);
        copy_group_info(&(inbound_group_session->group_info), group_info);

        ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, group_member_id->sign_public_key.data, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, group_member_id->sign_public_key.data, sign_key_len);

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    return ret;
}

int complete_inbound_group_session_by_pre_key_bundle(
    E2ees__GroupSession *inbound_group_session,
    E2ees__GroupPreKeyBundle *group_pre_key_bundle
) {
    int ret = E2EES_RESULT_SUCC;

    uint8_t *secret = NULL;
    uint32_t sign_key_len;
    size_t secret_len;
    uint32_t hf_len;

    if (!is_valid_group_session_by_member_id(inbound_group_session)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "complete_inbound_group_session_by_pre_key_bundle()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_pre_key_bundle(group_pre_key_bundle)) {
        e2ees_notify_log(NULL, BAD_GROUP_PRE_KEY_BUNDLE, "complete_inbound_group_session_by_pre_key_bundle()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_group_session->e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        secret_len = SEED_SECRET_LEN + sign_key_len;
        secret = (uint8_t *)malloc(sizeof(uint8_t) * secret_len);

        inbound_group_session->version = strdup(group_pre_key_bundle->version);
        inbound_group_session->session_id = strdup(group_pre_key_bundle->session_id);

        inbound_group_session->sequence = group_pre_key_bundle->sequence;

        // combine seed secret and ID
        memcpy(secret, group_pre_key_bundle->group_seed.data, SEED_SECRET_LEN);
        memcpy(secret + SEED_SECRET_LEN, inbound_group_session->associated_data.data, sign_key_len);  // only copy the first half

        // generate a chain key
        hf_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t salt[hf_len];
        memset(salt, 0, hf_len);
        inbound_group_session->chain_key.len = hf_len;
        inbound_group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * inbound_group_session->chain_key.len);
        cipher_suite->hf_suite->hkdf(
            secret, secret_len,
            salt, sizeof(salt),
            (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
            inbound_group_session->chain_key.data, inbound_group_session->chain_key.len
        );

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    free_mem((void **)&secret, secret_len);

    return ret;
}

int complete_inbound_group_session_by_member_id(
    E2ees__GroupSession *inbound_group_session,
    E2ees__GroupMemberInfo *group_member_id
) {
    int ret = E2EES_RESULT_SUCC;

    uint8_t *secret = NULL;
    uint32_t sign_key_len;
    uint32_t ad_len;
    size_t secret_len;
    uint32_t hf_len;

    if (!is_valid_group_session_by_pre_key_bundle(inbound_group_session)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "complete_inbound_group_session_by_member_id()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_info(group_member_id)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "complete_inbound_group_session_by_member_id()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_group_session->e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        secret_len = SEED_SECRET_LEN + sign_key_len;
        secret = (uint8_t *)malloc(sizeof(uint8_t) * secret_len);

        ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, group_member_id->sign_public_key.data, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, group_member_id->sign_public_key.data, sign_key_len);

        // combine seed secret and ID
        memcpy(secret, inbound_group_session->group_seed.data, SEED_SECRET_LEN);
        memcpy(secret + SEED_SECRET_LEN, group_member_id->sign_public_key.data, sign_key_len);

        // we do not store the seed secret in the session
        free_protobuf(&(inbound_group_session->group_seed));

        // generate a chain key
        hf_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t salt[hf_len];
        memset(salt, 0, hf_len);
        inbound_group_session->chain_key.len = hf_len;
        inbound_group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * inbound_group_session->chain_key.len);
        cipher_suite->hf_suite->hkdf(
            secret, secret_len,
            salt, sizeof(salt),
            (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
            inbound_group_session->chain_key.data, inbound_group_session->chain_key.len
        );

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    free_mem((void **)&secret, secret_len);

    return ret;
}

int new_and_complete_inbound_group_session(
    E2ees__GroupMemberInfo *group_member_id,
    E2ees__GroupSession *other_group_session
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupSession *inbound_group_session = NULL;
    uint8_t *secret = NULL;
    uint8_t *identity_public_key = NULL;
    ProtobufCBinaryData *group_seed = NULL;
    uint32_t sign_key_len;
    uint32_t ad_len;
    size_t secret_len;
    uint32_t hf_len;

    if (is_valid_group_member_info(group_member_id)) {
        identity_public_key = group_member_id->sign_public_key.data;
    } else {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "new_and_complete_inbound_group_session()");
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_group_session_by_pre_key_bundle(other_group_session)) {
        group_seed = &(other_group_session->group_seed);
    } else {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        inbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(inbound_group_session);

        insert_inbound_group_session_data(group_member_id, other_group_session, inbound_group_session);

        const cipher_suite_t *cipher_suite = get_e2ees_pack(other_group_session->e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        secret_len = SEED_SECRET_LEN + sign_key_len;
        secret = (uint8_t *)malloc(sizeof(uint8_t) * secret_len);

        // combine seed secret and ID
        memcpy(secret, group_seed->data, SEED_SECRET_LEN);
        memcpy(secret + SEED_SECRET_LEN, identity_public_key, sign_key_len);

        // generate a chain key
        hf_len = cipher_suite->hf_suite->get_param().hf_len;
        uint8_t salt[hf_len];
        memset(salt, 0, hf_len);
        inbound_group_session->chain_key.len = hf_len;
        inbound_group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * inbound_group_session->chain_key.len);
        cipher_suite->hf_suite->hkdf(
            secret, secret_len,
            salt, sizeof(salt),
            (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
            inbound_group_session->chain_key.data, inbound_group_session->chain_key.len
        );
        inbound_group_session->sequence = 0;

        ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }
    free_mem((void **)&secret, sizeof(uint8_t) * secret_len);

    return ret;
}

int new_and_complete_inbound_group_session_with_chain_key(
    E2ees__GroupMemberInfo *group_member_info,
    E2ees__GroupSession *other_group_session,
    ProtobufCBinaryData *their_chain_key
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupSession *inbound_group_session = NULL;
    uint8_t *identity_public_key = NULL;
    uint32_t sign_key_len;
    uint32_t ad_len;

    if (is_valid_group_member_info(group_member_info)) {
        identity_public_key = group_member_info->sign_public_key.data;
    } else {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "new_and_complete_inbound_group_session_with_chain_key()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_session_no_chain_key(other_group_session)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session_with_chain_key()");
        ret = E2EES_RESULT_FAIL;
    }
    if (their_chain_key == NULL) {
        e2ees_notify_log(NULL, BAD_GROUP_CHAIN_KEY, "new_and_complete_inbound_group_session_with_chain_key()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        inbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(inbound_group_session);

        insert_inbound_group_session_data(group_member_info, other_group_session, inbound_group_session);

        const cipher_suite_t *cipher_suite = get_e2ees_pack(other_group_session->e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), their_chain_key);
        inbound_group_session->sequence = 0;

        ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);

        memcpy(inbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    return ret;
}

int new_and_complete_inbound_group_session_with_ratchet_state(
    E2ees__GroupUpdateKeyBundle *group_update_key_bundle,
    E2ees__E2eeAddress *user_address
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupSession *inbound_group_session = NULL;
    uint8_t *identity_public_key = NULL;
    uint32_t sign_key_len;
    uint32_t ad_len;

    if (!is_valid_address(user_address)) {
        e2ees_notify_log(NULL, BAD_ADDRESS, "new_and_complete_inbound_group_session_with_ratchet_state()");
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_group_update_key_bundle(group_update_key_bundle)) {
        identity_public_key = group_update_key_bundle->sign_public_key.data;
    } else {
        e2ees_notify_log(NULL, BAD_GROUP_UPDATE_KEY_BUNDLE, "new_and_complete_inbound_group_session_with_ratchet_state()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        inbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
        e2ees__group_session__init(inbound_group_session);

        inbound_group_session->version = strdup(group_update_key_bundle->version);
        inbound_group_session->e2ees_pack_id = group_update_key_bundle->e2ees_pack_id;
        inbound_group_session->session_id = strdup(group_update_key_bundle->session_id);

        const cipher_suite_t *cipher_suite = get_e2ees_pack(group_update_key_bundle->e2ees_pack_id)->cipher_suite;

        copy_address_from_address(&(inbound_group_session->sender), group_update_key_bundle->sender);

        copy_address_from_address(&(inbound_group_session->session_owner), user_address);

        copy_group_info(&(inbound_group_session->group_info), group_update_key_bundle->group_info);

        /** We have generated the sender's chain key in new_outbound_group_session_invited(),
         *  so we just need to generate others' chain key.
         */
        if (group_update_key_bundle->adding == false) {
            advance_group_chain_key_by_add(cipher_suite, &(group_update_key_bundle->chain_key), &(group_update_key_bundle->chain_key));
        }
        copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), &(group_update_key_bundle->chain_key));
        inbound_group_session->sequence = 0;

        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    return ret;
}

int renew_outbound_group_session_by_welcome_and_add(
    E2ees__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    E2ees__E2eeAddress *sender_address,
    size_t n_adding_member_info_list,
    E2ees__GroupMemberInfo **adding_member_info_list,
    size_t adding_group_members_num,
    E2ees__GroupMember **adding_group_members
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Account *account = NULL;
    char *auth = NULL;
    E2ees__IdentityKey *identity_key = NULL;
    ProtobufCBinaryData *identity_public_key = NULL;
    E2ees__GroupInfo *old_group_info = NULL;
    char *cur_user_id = NULL, *cur_user_domain = NULL;
    uint8_t *group_ratchet_state_plaintext_data = NULL;
    size_t group_ratchet_state_plaintext_data_len;
    E2ees__Session **outbound_sessions = NULL;
    size_t outbound_sessions_num;
    E2ees__Session *outbound_session = NULL;
    E2ees__SendOne2oneMsgResponse *response = NULL;
    ProtobufCBinaryData **their_chain_keys = NULL;
    E2ees__GroupSession **inbound_group_sessions = NULL;
    size_t inbound_group_sessions_num;
    size_t i, j;

    if (!is_valid_group_session(outbound_group_session)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
        ret = E2EES_RESULT_FAIL;
    } else {
        load_identity_key_from_cache(&identity_key, outbound_group_session->session_owner);

        if (identity_key == NULL) {
            get_e2ees_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
            if (account == NULL) {
                e2ees_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_outbound_group_session_by_welcome_and_add()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = get_identity_public_key_ds_bytes_from_account(account);
                if (identity_public_key == NULL) {
                    e2ees_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_outbound_group_session_by_welcome_and_add()");
                    ret = E2EES_RESULT_FAIL;
                } else {
                    auth = strdup(account->auth);
                }
            }
        } else {
            load_auth_from_cache(&auth, outbound_group_session->session_owner);
            if (auth == NULL) {
                e2ees_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_outbound_group_session_by_welcome_and_add()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = &(identity_key->sign_key_pair->public_key);
            }
        }
    }
    if (!is_valid_address(sender_address)) {
        e2ees_notify_log(NULL, BAD_ADDRESS, "renew_outbound_group_session_by_welcome_and_add()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_info_list((const E2ees__GroupMemberInfo **)adding_member_info_list, n_adding_member_info_list)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "renew_outbound_group_session_by_welcome_and_add()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_list(adding_group_members, adding_group_members_num)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBERS, "renew_outbound_group_session_by_welcome_and_add()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(outbound_group_session->e2ees_pack_id)->cipher_suite;

        // renew the group members
        copy_group_info(&old_group_info, outbound_group_session->group_info);
        e2ees__group_info__free_unpacked(outbound_group_session->group_info, NULL);

        add_group_members_to_group_info(
            &(outbound_group_session->group_info), old_group_info, adding_group_members, adding_group_members_num
        );

        // pack the group ratchet state
        group_ratchet_state_plaintext_data_len = pack_group_ratchet_state_plaintext(
            outbound_group_session, &group_ratchet_state_plaintext_data,
            sender_chain_key == NULL, identity_public_key,
            n_adding_member_info_list, adding_member_info_list
        );

        // send the current ratchet state to the new group members
        for (i = 0; i < adding_group_members_num; i++) {
            cur_user_id = adding_group_members[i]->user_id;
            cur_user_domain = adding_group_members[i]->domain;

            outbound_sessions_num = get_e2ees_plugin()->db_handler.load_outbound_sessions(
                outbound_group_session->session_owner, cur_user_id, cur_user_domain, &outbound_sessions
            );

            if (outbound_sessions_num > 0 && outbound_sessions != NULL) {
                for (j = 0; j < outbound_sessions_num; j++) {
                    outbound_session = outbound_sessions[j];
                    if (compare_address(outbound_session->their_address, outbound_group_session->session_owner))
                        continue;
                    if (outbound_session->responded) {
                        response = send_one2one_msg_internal(
                            outbound_session,
                            E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION,
                            group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
                        );
                    } else {
                        /** Since the other has not responded, we store the group pre-key first so that
                         *  we can send it right after receiving the other's accept message.
                         */
                        store_pending_common_plaintext_data_internal(
                            outbound_session->our_address,
                            outbound_session->their_address,
                            group_ratchet_state_plaintext_data,
                            group_ratchet_state_plaintext_data_len,
                            E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                        );
                    }
                }
            } else {
                /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
                E2ees__InviteResponse **invite_response_list = NULL;
                size_t invite_response_num = 0;
                int invite_response_ret = get_pre_key_bundle_internal(
                    &invite_response_list,
                    &invite_response_num,
                    outbound_group_session->session_owner,
                    auth,
                    cur_user_id, cur_user_domain,
                    NULL, true,
                    group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
                );
                // release
                free_invite_response_list(&invite_response_list, invite_response_num);
            }
        }

        their_chain_keys = (ProtobufCBinaryData **)malloc(sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
        // advance the chain key
        if (sender_chain_key == NULL) {
            // the sender
            for (i = 0; i < n_adding_member_info_list; i++) {
                advance_group_chain_key_by_welcome(cipher_suite, &(outbound_group_session->chain_key), &their_chain_keys[i]);
                advance_group_chain_key_by_add(cipher_suite, their_chain_keys[i], &(outbound_group_session->chain_key));
            }
        } else {
            // the receiver
            for (i = 0; i < n_adding_member_info_list; i++) {
                advance_group_chain_key_by_welcome(cipher_suite, sender_chain_key, &their_chain_keys[i]);
                advance_group_chain_key_by_add(cipher_suite, their_chain_keys[i], sender_chain_key);
            }
            advance_group_chain_key_by_add(cipher_suite, &(outbound_group_session->chain_key), &(outbound_group_session->chain_key));
        }

        // reset the sequence
        outbound_group_session->sequence = 0;

        // store
        get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);

        // renew existed inbound group sessions
        inbound_group_sessions_num = get_e2ees_plugin()->db_handler.load_group_sessions(
            outbound_group_session->session_owner, outbound_group_session->group_info->group_address, &inbound_group_sessions
        );

        if (inbound_group_sessions_num > 0 && inbound_group_sessions != NULL) {
            for (i = 0; i < inbound_group_sessions_num; i++) {
                // there is one outbound group session in inbound_group_sessions, so we need to ignore it
                if (!compare_address(outbound_group_session->session_owner, inbound_group_sessions[i]->sender)) {
                    if (compare_address(sender_address, inbound_group_sessions[i]->sender)) {
                        renew_inbound_group_session_by_welcome_and_add(
                            sender_chain_key,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    } else {
                        renew_inbound_group_session_by_welcome_and_add(
                            NULL,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    }
                    e2ees_notify_log(
                        outbound_group_session->session_owner,
                        DEBUG_LOG,
                        "renew_outbound_group_session_by_welcome_and_add() renew the inbound group sessions: sender_address:[%s:%s], inbound_group_sessions[%zu of %zu]->sender:[%s:%s]", 
                        sender_address->user->user_id,
                        sender_address->user->device_id,
                        i+1, inbound_group_sessions_num,
                        inbound_group_sessions[i]->sender->user->user_id,
                        inbound_group_sessions[i]->sender->user->device_id
                    );
                }
            }
        } else {
            e2ees_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_outbound_group_session_by_welcome_and_add(), no existed inbound group sessions, renew the inbound group sessions skipped"
            );
        }

        // create new inbound group sessions to the adding members
        for (i = 0; i < n_adding_member_info_list; i++) {
            new_and_complete_inbound_group_session_with_chain_key(adding_member_info_list[i], outbound_group_session, their_chain_keys[i]);
        }
    }

    // release
    free_proto(account);
    free_string(auth);
    free_proto(identity_key);
    if (old_group_info != NULL) {
        e2ees__group_info__free_unpacked(old_group_info, NULL);
        old_group_info = NULL;
    }
    free_mem((void **)&group_ratchet_state_plaintext_data, sizeof(uint8_t) * group_ratchet_state_plaintext_data_len);
    for (j = 0; j < outbound_sessions_num; j++) {
        e2ees__session__free_unpacked(outbound_sessions[j], NULL);
        outbound_sessions[j] = NULL;
    }
    free_mem((void **)&outbound_sessions, sizeof(E2ees__Session *) * outbound_sessions_num);
    if (their_chain_keys != NULL) {
        for (i = 0; i < n_adding_member_info_list; i++) {
            free_protobuf(their_chain_keys[i]);
            free_mem((void **)&(their_chain_keys[i]), sizeof(ProtobufCBinaryData));
        }
        free_mem((void **)&their_chain_keys, sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
    }
    if (response != NULL) {
        e2ees__send_one2one_msg_response__free_unpacked(response, NULL);
        response = NULL;
    }
    for (i = 0; i < inbound_group_sessions_num; i++) {
        e2ees__group_session__free_unpacked(inbound_group_sessions[i], NULL);
        inbound_group_sessions[i] = NULL;
    }
    free_mem((void **)&inbound_group_sessions, sizeof(E2ees__Session *) * inbound_group_sessions_num);

    return ret;
}

int renew_inbound_group_session_by_welcome_and_add(
    ProtobufCBinaryData *sender_chain_key,
    E2ees__GroupSession *inbound_group_session,
    E2ees__GroupInfo *new_group_info
) {
    int ret = E2EES_RESULT_SUCC;

    if (!is_valid_group_session(inbound_group_session)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "renew_inbound_group_session_by_welcome_and_add()");
        ret = E2EES_RESULT_FAIL;
    }
    if (new_group_info == NULL) {
        e2ees_notify_log(NULL, BAD_GROUP_INFO, "renew_inbound_group_session_by_welcome_and_add()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        e2ees_notify_log(
            inbound_group_session->session_owner,
            DEBUG_LOG,
            "renew_inbound_group_session_by_welcome_and_add() sender_chain_key is Null: %s",
            sender_chain_key == NULL ? "true" : "false"
        );

        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_group_session->e2ees_pack_id)->cipher_suite;

        e2ees__group_info__free_unpacked(inbound_group_session->group_info, NULL);
        copy_group_info(&(inbound_group_session->group_info), new_group_info);

        if (sender_chain_key != NULL) {
            free_mem((void **)&(inbound_group_session->chain_key.data), inbound_group_session->chain_key.len);

            copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), sender_chain_key);
        } else {
            advance_group_chain_key_by_add(cipher_suite, &(inbound_group_session->chain_key), &(inbound_group_session->chain_key));
        }

        inbound_group_session->sequence = 0;

        // store
        get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    return ret;
}

int renew_group_sessions_with_new_device(
    E2ees__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *new_device_address,
    E2ees__GroupMemberInfo *adding_member_device_info
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__Account *account = NULL;
    char *auth = NULL;
    E2ees__IdentityKey *identity_key = NULL;
    ProtobufCBinaryData *identity_public_key = NULL;
    char *cur_user_id = NULL, *cur_user_domain = NULL;
    char *cur_user_device_id = NULL;
    uint8_t *group_ratchet_state_plaintext_data = NULL;
    size_t group_ratchet_state_plaintext_data_len;
    E2ees__Session *outbound_session = NULL;
    E2ees__SendOne2oneMsgResponse *response = NULL;
    ProtobufCBinaryData *their_chain_keys = NULL;
    E2ees__GroupSession **inbound_group_sessions = NULL;
    size_t inbound_group_sessions_num;
    size_t i, j;

    if (!is_valid_group_session(outbound_group_session)) {
        e2ees_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
        ret = E2EES_RESULT_FAIL;
    } else {
        load_identity_key_from_cache(&identity_key, outbound_group_session->session_owner);

        if (identity_key == NULL) {
            get_e2ees_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
            if (account == NULL) {
                e2ees_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_group_sessions_with_new_device()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = get_identity_public_key_ds_bytes_from_account(account);
                if (identity_public_key == NULL) {
                    e2ees_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_group_sessions_with_new_device()");
                    ret = E2EES_RESULT_FAIL;
                } else {
                    auth = strdup(account->auth);
                }
            }
        } else {
            load_auth_from_cache(&auth, outbound_group_session->session_owner);

            if (auth == NULL) {
                e2ees_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_group_sessions_with_new_device()");
                ret = E2EES_RESULT_FAIL;
            } else {
                identity_public_key = &(identity_key->sign_key_pair->public_key);
            }
        }
    }
    if (!is_valid_address(sender_address)) {
        e2ees_notify_log(NULL, BAD_ADDRESS, "renew_group_sessions_with_new_device()");
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_address(new_device_address)) {
        cur_user_id = new_device_address->user->user_id;
        cur_user_domain = new_device_address->domain;
        cur_user_device_id = new_device_address->user->device_id;
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "renew_group_sessions_with_new_device()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_info(adding_member_device_info)) {
        e2ees_notify_log(NULL, BAD_GROUP_MEMBER_INFO, "renew_group_sessions_with_new_device()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        e2ees_notify_log(
            outbound_group_session->session_owner,
            DEBUG_LOG,
            "renew_group_sessions_with_new_device() owner address: [%s:%s] sender address: [%s:%s] member address: [%s:%s]",
            outbound_group_session->session_owner->user->user_id,
            outbound_group_session->session_owner->user->device_id,
            sender_address->user->user_id,
            sender_address->user->device_id,
            adding_member_device_info->member_address->user->user_id,
            adding_member_device_info->member_address->user->device_id
        );

        // renew outbound group session
        const cipher_suite_t *cipher_suite = get_e2ees_pack(outbound_group_session->e2ees_pack_id)->cipher_suite;

        group_ratchet_state_plaintext_data_len = pack_group_ratchet_state_plaintext(
            outbound_group_session, &group_ratchet_state_plaintext_data,
            sender_chain_key == NULL, identity_public_key,
            1, &adding_member_device_info
        );

        get_e2ees_plugin()->db_handler.load_outbound_session(
            outbound_group_session->session_owner, new_device_address, &outbound_session
        );

        if (outbound_session != NULL) {
            if (outbound_session->responded) {
                response = send_one2one_msg_internal(
                    outbound_session,
                    E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION,
                    group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
                );
            } else {
                e2ees_notify_log(
                    outbound_group_session->session_owner,
                    DEBUG_LOG,
                    "renew_group_sessions_with_new_device() outbound_session found and is not responded"
                );
                /** Since the other has not responded, we store the group pre-key first so that
                 *  we can send it right after receiving the other's accept message.
                 */
                store_pending_common_plaintext_data_internal(
                    outbound_session->our_address,
                    outbound_session->their_address,
                    group_ratchet_state_plaintext_data,
                    group_ratchet_state_plaintext_data_len,
                    E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                );                
            }
        } else {
            e2ees_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device() outbound_session not found"
            );
            /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
            E2ees__InviteResponse **invite_response_list = NULL;
            size_t invite_response_num = 0;
            int invite_response_ret = get_pre_key_bundle_internal(
                &invite_response_list,
                &invite_response_num,
                outbound_group_session->session_owner,
                auth,
                cur_user_id, cur_user_domain,
                cur_user_device_id, false,
                group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
            );
            // release
            free_invite_response_list(&invite_response_list, invite_response_num);
        }

        // advance the chain key
        if (sender_chain_key == NULL) {
            // the sender
            advance_group_chain_key_by_welcome(cipher_suite, &(outbound_group_session->chain_key), &their_chain_keys);
            advance_group_chain_key_by_add(cipher_suite, their_chain_keys, &(outbound_group_session->chain_key));
            e2ees_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device() sender_chain_key is the case of null, create their_chain_keys"
            );
        } else {
            // the receiver
            advance_group_chain_key_by_welcome(cipher_suite, sender_chain_key, &their_chain_keys);
            advance_group_chain_key_by_add(cipher_suite, their_chain_keys, sender_chain_key);
            advance_group_chain_key_by_add(cipher_suite, &(outbound_group_session->chain_key), &(outbound_group_session->chain_key));
            e2ees_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device() sender_chain_key is the case of not null, create their_chain_keys"
            );
        }

        // reset the sequence
        outbound_group_session->sequence = 0;

        // store
        get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);

        // renew the inbound group sessions
        inbound_group_sessions_num = get_e2ees_plugin()->db_handler.load_group_sessions(
            outbound_group_session->session_owner, outbound_group_session->group_info->group_address, &inbound_group_sessions
        );
        if (inbound_group_sessions_num > 0 && inbound_group_sessions != NULL) {
            for (i = 0; i < inbound_group_sessions_num; i++) {
                // there is one outbound group session in inbound_group_sessions, so we need to ignore it
                if (!compare_address(outbound_group_session->session_owner, inbound_group_sessions[i]->sender)) {
                    if (compare_address(sender_address, inbound_group_sessions[i]->sender)) {
                        renew_inbound_group_session_by_welcome_and_add(
                            sender_chain_key,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    } else {
                        renew_inbound_group_session_by_welcome_and_add(
                            NULL,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    }
                    e2ees_notify_log(
                        outbound_group_session->session_owner,
                        DEBUG_LOG,
                        "renew_group_sessions_with_new_device() renew the inbound group sessions: sender_address:[%s:%s], inbound_group_sessions[%zu of %zu]->sender:[%s:%s]", 
                        sender_address->user->user_id,
                        sender_address->user->device_id,
                        i + 1,
                        inbound_group_sessions_num,
                        inbound_group_sessions[i]->sender->user->user_id,
                        inbound_group_sessions[i]->sender->user->device_id
                    );
                }
            }

            // create the inbound group session for new device
            new_and_complete_inbound_group_session_with_chain_key(adding_member_device_info, outbound_group_session, their_chain_keys);
        } else {
            e2ees_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device(), no inbound group sessions, renew the inbound group sessions skipped"
            );
        }
    }

    // release
    free_proto(account);
    free_string(auth);
    free_proto(identity_key);
    free_mem((void **)&group_ratchet_state_plaintext_data, sizeof(uint8_t) * group_ratchet_state_plaintext_data_len);
    if (outbound_session != NULL) {
        e2ees__session__free_unpacked(outbound_session, NULL);
        outbound_session = NULL;
    }
    if (response != NULL) {
        e2ees__send_one2one_msg_response__free_unpacked(response, NULL);
        response = NULL;
    }
    if (their_chain_keys != NULL) {
        free_mem((void **)&(their_chain_keys->data), sizeof(uint8_t) * their_chain_keys->len);
        free_mem((void **)&their_chain_keys, sizeof(ProtobufCBinaryData));
    }
    for (i = 0; i < inbound_group_sessions_num; i++) {
        e2ees__group_session__free_unpacked(inbound_group_sessions[i], NULL);
        inbound_group_sessions[i] = NULL;
    }
    free_mem((void **)&inbound_group_sessions, sizeof(E2ees__Session *) * inbound_group_sessions_num);

    return ret;
}
