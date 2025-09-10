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
#include "e2ees/session_manager.h"

#include <stdio.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/account_cache.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/ratchet.h"
#include "e2ees/validation.h"
#include "e2ees/session.h"

typedef struct group_address_node {
    E2ees__E2eeAddress *group_address;
    struct group_address_node *next;
} group_address_node;

static void send_pending_plaintext_data(E2ees__Session *outbound_session) {
    // load pending plaintext data(may be the group pre-key or the common plaintext)
    uint32_t pending_plaintext_data_list_num;
    char **pending_plaintext_id_list;
    uint8_t **pending_plaintext_data_list;
    size_t *pending_plaintext_data_len_list;
    E2ees__NotifLevel *notif_level_list;
    pending_plaintext_data_list_num =
        get_e2ees_plugin()->db_handler.load_pending_plaintext_data(
            outbound_session->our_address,
            outbound_session->their_address,
            &pending_plaintext_id_list,
            &pending_plaintext_data_list,
            &pending_plaintext_data_len_list,
            &notif_level_list
        );
    if (pending_plaintext_data_list_num > 0) {
        e2ees_notify_log(
            outbound_session->our_address,
            DEBUG_LOG,
            "send_pending_plaintext_data(): list num = %d",
            pending_plaintext_data_list_num
        );
        uint32_t i;
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            E2ees__SendOne2oneMsgResponse *response = send_one2one_msg_internal(
                outbound_session,
                notif_level_list[i],
                pending_plaintext_data_list[i],
                pending_plaintext_data_len_list[i]
            );
            // always unload
            get_e2ees_plugin()->db_handler.unload_pending_plaintext_data(
                outbound_session->our_address, outbound_session->their_address, pending_plaintext_id_list[i]
            );
            // release
            if (response != NULL) {
                e2ees__send_one2one_msg_response__free_unpacked(response, NULL);
            }
        }

        // release
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            free_mem((void **)&(pending_plaintext_data_list[i]), pending_plaintext_data_len_list[i]);
            free(pending_plaintext_id_list[i]);
        }
        free_mem((void **)&pending_plaintext_id_list, sizeof(char *) * pending_plaintext_data_list_num);
        free_mem((void **)&pending_plaintext_data_list, sizeof(uint8_t *) * pending_plaintext_data_list_num);
        free_mem((void **)&pending_plaintext_data_len_list, sizeof(size_t) * pending_plaintext_data_list_num);
        free_mem((void **)&notif_level_list, sizeof(E2ees__NotifLevel) * pending_plaintext_data_list_num);
    }
}

int produce_get_pre_key_bundle_request(
    E2ees__GetPreKeyBundleRequest **request_out,
    const char *to_user_id,
    const char *to_domain,
    const char *to_device_id,
    bool active
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GetPreKeyBundleRequest *request = NULL;

    if (!is_valid_string(to_user_id)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(to_domain)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        request = (E2ees__GetPreKeyBundleRequest *)malloc(sizeof(E2ees__GetPreKeyBundleRequest));
        e2ees__get_pre_key_bundle_request__init(request);
        request->domain = strdup(to_domain);
        request->user_id = strdup(to_user_id);
        if (to_device_id != NULL) {
            // the device ID may be empty or nonempty
            request->device_id = strdup(to_device_id);
        }

        *request_out = request;
    }

    return ret;
}

int consume_get_pre_key_bundle_response(
    E2ees__InviteResponse ***invite_response_list_out,
    size_t *invite_response_num,
    E2ees__E2eeAddress *from,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len,
    E2ees__GetPreKeyBundleResponse *get_pre_key_bundle_response
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__PreKeyBundle **their_pre_key_bundles = NULL;
    size_t n_pre_key_bundles;
    E2ees__PreKeyBundle *cur_pre_key_bundle = NULL;
    E2ees__E2eeAddress *to_address = NULL;
    uint32_t e2ees_pack_id;
    E2ees__InviteResponse **invite_response_list = NULL;
    size_t invite_response_list_len = 0;
    E2ees__InviteResponse *cur_invite_response = NULL;
    int invite_response_ret = E2EES_RESULT_SUCC;    // this parameter may be useful
    int server_check = E2EES_RESULT_SUCC;
    ProtobufCBinaryData server_public_key = {0, NULL};
    bool is_self = false;
    char *from_user_id = NULL;
    size_t i;

    if (is_valid_address(from)) {
        from_user_id = from->user->user_id;
        if (is_valid_get_pre_key_bundle_response(get_pre_key_bundle_response)) {
            their_pre_key_bundles = get_pre_key_bundle_response->pre_key_bundles;
            n_pre_key_bundles = get_pre_key_bundle_response->n_pre_key_bundles;

            if (safe_strcmp(from_user_id, get_pre_key_bundle_response->user_id)) {
                if (n_pre_key_bundles > 1) {
                    // pre-key bundles from this and other devices, but we need not invite this device
                    is_self = true;
                    invite_response_list_len = n_pre_key_bundles - 1;
                    invite_response_list = (E2ees__InviteResponse **)malloc(sizeof(E2ees__InviteResponse *) * invite_response_list_len);
                } else if (n_pre_key_bundles == 1) {
                    if (!compare_address(from, their_pre_key_bundles[0]->user_address)) {
                        invite_response_list_len = 1;
                        invite_response_list = (E2ees__InviteResponse **)malloc(sizeof(E2ees__InviteResponse *));
                    } else {
                        ret = E2EES_RESULT_FAIL;
                    }
                } else {
                    e2ees_notify_log(NULL, BAD_GET_PRE_KEY_BUNDLE_RESPONSE, "consume_get_pre_key_bundle_response()");
                    ret = E2EES_RESULT_FAIL;
                }
            } else {
                invite_response_list_len = n_pre_key_bundles;
                invite_response_list = (E2ees__InviteResponse **)malloc(sizeof(E2ees__InviteResponse *) * invite_response_list_len);
            }
        } else {
            e2ees_notify_log(NULL, BAD_GET_PRE_KEY_BUNDLE_RESPONSE, "consume_get_pre_key_bundle_response()");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        for (i = 0; i < n_pre_key_bundles; i++) {
            cur_pre_key_bundle = their_pre_key_bundles[i];
            e2ees_pack_id = cur_pre_key_bundle->e2ees_pack_id;
            to_address = cur_pre_key_bundle->user_address;
            // skip if the pre-key bundle is from this device
            if (is_self) {
                if (compare_address(from, to_address)) {
                    continue;
                }
            }

            if (is_valid_server_signed_signature(cur_pre_key_bundle->signature)) {
                load_server_public_key_from_cache(&server_public_key, from);
                if (server_public_key.data != NULL) {
                    ds_suite_t *digital_signature_suite = get_ds_suite(cur_pre_key_bundle->signature->signing_alg);
                    server_check = digital_signature_suite->verify(
                        cur_pre_key_bundle->signature->signature.data,
                        cur_pre_key_bundle->signature->signature.len,
                        cur_pre_key_bundle->signature->msg_fingerprint.data,
                        cur_pre_key_bundle->signature->msg_fingerprint.len,
                        server_public_key.data
                    );
                    // release
                    free_mem((void **)&(server_public_key.data), server_public_key.len);
                } else {
                    server_check = E2EES_RESULT_FAIL;
                }

                if (server_check < E2EES_RESULT_SUCC) {
                    e2ees_notify_log(NULL, BAD_SERVER_SIGNATURE, "consume_get_pre_key_bundle_response()");
                    ret = E2EES_RESULT_FAIL;
                }
            } else {
                e2ees_notify_log(NULL, BAD_SERVER_SIGNATURE, "consume_get_pre_key_bundle_response()");
                ret = E2EES_RESULT_FAIL;
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        int insert_pos = 0;
        for (i = 0; i < n_pre_key_bundles; i++) {
            cur_pre_key_bundle = their_pre_key_bundles[i];
            e2ees_pack_id = cur_pre_key_bundle->e2ees_pack_id;
            to_address = cur_pre_key_bundle->user_address;
            // skip if the pre-key bundle is from this device
            if (is_self) {
                if (compare_address(from, to_address)) {
                    continue;
                }
            }
            // store the group pre-keys if necessary
            if (group_pre_key_plaintext_data != NULL) {
                e2ees_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() store the group pre-keys");
                char *pending_plaintext_id = generate_uuid_str();
                get_e2ees_plugin()->db_handler.store_pending_plaintext_data(
                    from,
                    to_address,
                    pending_plaintext_id,
                    group_pre_key_plaintext_data,
                    group_pre_key_plaintext_data_len,
                    E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                );
                // release
                free(pending_plaintext_id);
                pending_plaintext_id = NULL;
            }
            // create an outbound session
            const session_suite_t *session_suite = get_e2ees_pack(e2ees_pack_id)->session_suite;
            invite_response_ret = session_suite->new_outbound_session(&(invite_response_list[insert_pos]), from, cur_pre_key_bundle);
            insert_pos++;
        }
        *invite_response_list_out = invite_response_list;
        *invite_response_num = n_pre_key_bundles;
    } else {
        // release
        if (invite_response_list != NULL) {
            for (i = 0; i < invite_response_list_len; i++) {
                cur_invite_response = invite_response_list[i];
                if (cur_invite_response != NULL) {
                    e2ees__invite_response__free_unpacked(cur_invite_response, NULL);
                    cur_invite_response = NULL;
                }
            }
            free_mem((void **)&invite_response_list, sizeof(E2ees__InviteResponse *) * invite_response_list_len);
        }
    }

    // done
    return ret;
}

int produce_send_one2one_msg_request(
    E2ees__SendOne2oneMsgRequest **request_out,
    E2ees__Session *outbound_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__One2oneMsgPayload *payload_out = NULL;

    if (outbound_session != NULL) {
        if (outbound_session->session_id == NULL)
            ret = E2EES_RESULT_FAIL;
        if (outbound_session->our_address == NULL)
            ret = E2EES_RESULT_FAIL;
        if (outbound_session->their_address == NULL)
            ret = E2EES_RESULT_FAIL;
        if (outbound_session->ratchet == NULL)
            ret = E2EES_RESULT_FAIL;
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(outbound_session->e2ees_pack_id)->cipher_suite;
        ret = encrypt_ratchet(
            &payload_out, cipher_suite,
            outbound_session->ratchet, outbound_session->associated_data,
            plaintext_data, plaintext_data_len
        );
    }

    if (ret == E2EES_RESULT_SUCC) {
        // prepare an e2ee message
        E2ees__E2eeMsg *e2ee_msg = (E2ees__E2eeMsg *)malloc(sizeof(E2ees__E2eeMsg));
        e2ees__e2ee_msg__init(e2ee_msg);

        e2ee_msg->version = strdup(E2EES_PROTOCOL_VERSION);
        e2ee_msg->session_id = strdup(outbound_session->session_id);
        copy_address_from_address(&(e2ee_msg->from), outbound_session->our_address);
        copy_address_from_address(&(e2ee_msg->to), outbound_session->their_address);
        e2ee_msg->msg_id = generate_uuid_str();
        e2ee_msg->notif_level = notif_level;
        e2ee_msg->payload_case = E2EES__E2EE_MSG__PAYLOAD_ONE2ONE_MSG;
        e2ee_msg->one2one_msg = payload_out;

        E2ees__SendOne2oneMsgRequest *request = (E2ees__SendOne2oneMsgRequest *)malloc(sizeof(E2ees__SendOne2oneMsgRequest));
        e2ees__send_one2one_msg_request__init(request);
        request->msg = e2ee_msg;

        *request_out = request;
    } else {
        *request_out = NULL;
    }

    return ret;
}

bool consume_send_one2one_msg_response(
    E2ees__Session *outbound_session,
    E2ees__SendOne2oneMsgResponse *response
) {
    bool succ = false;
    bool remove_session = false;
    if (response != NULL) {
        if (response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            succ = true;
        } else if (response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
            // user device is removed, we remove outbound_sessions
            remove_session = true;
            succ = true;
        } else {
            succ = false;
        }
    } else {
        succ = false;
    }
    // store sesson state
    if (remove_session) {
        get_e2ees_plugin()->db_handler.unload_session(outbound_session->our_address, outbound_session->their_address);
    } else {
        get_e2ees_plugin()->db_handler.store_session(outbound_session);
    }
    // done
    return succ;
}

bool consume_one2one_msg(E2ees__E2eeAddress *receiver_address, E2ees__E2eeMsg *e2ee_msg) {
    int ret = E2EES_RESULT_SUCC;
    // e2ees_notify_log(receiver_address, DEBUG_LOG, "consume_one2one_msg(): from [%s:%s], to [%s:%s]", e2ee_msg->from->user->user_id, e2ee_msg->from->user->device_id, e2ee_msg->to->user->user_id, e2ee_msg->to->user->device_id);
    if (e2ee_msg->session_id == NULL) {
        e2ees_notify_log(receiver_address, BAD_SESSION_ID, "consume_one2one_msg(), wrong session_id");
        // wrong session_id, just consume it
        return true;
    }

    // load the corresponding inbound session
    E2ees__Session *inbound_session = NULL;
    get_e2ees_plugin()->db_handler.load_session(e2ee_msg->session_id, receiver_address, &inbound_session);
    if (inbound_session == NULL) {
        e2ees_notify_log(receiver_address, BAD_SESSION, "consume_one2one_msg() inbound session not found, just consume it");
        // no inbound session, just consume it
        return true;
    }

    // e2ees_notify_log(receiver_address, DEBUG_LOG, "consume_one2one_msg(), session_id: %s, from: [%s:%s], to: [%s:%s]", e2ee_msg->session_id, e2ee_msg->from->user->user_id, e2ee_msg->from->user->device_id, e2ee_msg->to->user->user_id, e2ee_msg->to->user->device_id);
    E2ees__One2oneMsgPayload *payload = NULL;
    if (e2ee_msg->payload_case == E2EES__E2EE_MSG__PAYLOAD_ONE2ONE_MSG) {
        payload = e2ee_msg->one2one_msg;
    }
    if (payload != NULL) {
        uint8_t *decrypted_data_out = NULL;
        size_t decrypted_data_len_out;
        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_session->e2ees_pack_id)->cipher_suite;
        ret = decrypt_ratchet(&decrypted_data_out, &decrypted_data_len_out, cipher_suite, inbound_session->ratchet, inbound_session->associated_data, payload);

        // store session state
        get_e2ees_plugin()->db_handler.store_session(inbound_session);

        // delete old sessions if necessary
        get_e2ees_plugin()->db_handler.unload_old_session(receiver_address, e2ee_msg->from, inbound_session->invite_t);

        if (decrypted_data_out != NULL && decrypted_data_len_out > 0) {
            E2ees__Plaintext *plaintext = e2ees__plaintext__unpack(NULL, decrypted_data_len_out, decrypted_data_out);
            if (plaintext != NULL) {
                if (plaintext->payload_case == E2EES__PLAINTEXT__PAYLOAD_COMMON_MSG) {
                    e2ees_notify_one2one_msg(receiver_address, e2ee_msg->from, e2ee_msg->to, plaintext->common_msg.data, plaintext->common_msg.len);
                } else if (plaintext->payload_case == E2EES__PLAINTEXT__PAYLOAD_USER_DEVICES_BUNDLE) {
                    E2ees__UserDevicesBundle *their_device_id_list = plaintext->user_devices_bundle;

                    char *to_user_id = their_device_id_list->user_id;
                    char *to_domain = their_device_id_list->domain;

                    char *auth = NULL;
                    load_auth_from_cache(&auth, receiver_address);

                    if (auth == NULL) {
                        e2ees_notify_log(
                            receiver_address, BAD_ACCOUNT, "invite() from [%s:%s] to [%s@%s]",
                            receiver_address->user->user_id,
                            receiver_address->user->device_id,
                            to_user_id,
                            to_domain
                        );
                        return true;
                    }

                    E2ees__InviteResponse *invite_response = NULL;
                    E2ees__InviteResponse **invite_response_list = NULL;
                    size_t invite_response_num = 0;
                    size_t their_devices_num = their_device_id_list->n_device_id_list;
                    size_t i;
                    if (their_devices_num == 0) {
                        // this paragraph may be useless
                        ret = get_pre_key_bundle_internal(
                            &invite_response_list,
                            &invite_response_num,
                            receiver_address,
                            auth,
                            to_user_id,
                            to_domain,
                            NULL,
                            false,
                            NULL, 0
                        );
                        // release
                        free_invite_response_list(&invite_response_list, invite_response_num);
                    } else {
                        char *cur_device_id = NULL;
                        for (i = 0; i < their_devices_num; i++) {
                            cur_device_id = their_device_id_list->device_id_list[i];
                            ret = get_pre_key_bundle_internal(
                                &invite_response_list,
                                &invite_response_num,
                                receiver_address,
                                auth,
                                to_user_id,
                                to_domain,
                                cur_device_id,
                                false,
                                NULL, 0
                            );
                            // release
                            free_invite_response_list(&invite_response_list, invite_response_num);
                        }
                    }
                    // release
                    free_string(auth);
                } else if (plaintext->payload_case == E2EES__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG) {
                    e2ees_notify_other_device_msg(receiver_address, e2ee_msg->from, e2ee_msg->to, plaintext->common_sync_msg.data, plaintext->common_sync_msg.len);
                } else if (plaintext->payload_case == E2EES__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE) {
                    E2ees__GroupPreKeyBundle *group_pre_key_bundle = plaintext->group_pre_key_bundle;

                    // unload the old outbound and inbound group sessions
                    if ((group_pre_key_bundle->old_session_id)[0] != '\0') {
                        get_e2ees_plugin()->db_handler.unload_group_session_by_id(receiver_address, group_pre_key_bundle->old_session_id);
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "unload the old outbound and inbound group sessions session_id: %s, session_owner: [%s:%s]",
                            group_pre_key_bundle->old_session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    }

                    // try to load the new group sessions
                    E2ees__GroupInfo *cur_group_info = group_pre_key_bundle->group_info;
                    E2ees__GroupSession **inbound_group_sessions = NULL;
                    size_t inbound_group_sessions_num = get_e2ees_plugin()->db_handler.load_group_sessions(
                        receiver_address, group_pre_key_bundle->group_info->group_address, &inbound_group_sessions
                    );
                    e2ees_notify_log(
                        receiver_address,
                        DEBUG_LOG,
                        "consume_one2one_msg() E2EES__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE : inbound_group_sessions_num: %d, inbound_group_sessions: %p",
                        inbound_group_sessions_num,
                        inbound_group_sessions
                    );
                    if (inbound_group_sessions_num > 0 && inbound_group_sessions != NULL) {
                        size_t i;
                        for (i = 0; i < inbound_group_sessions_num; i++) {
                            if (compare_address(receiver_address, inbound_group_sessions[i]->sender)) {
                                // skip
                                continue;
                            }
                            complete_inbound_group_session_by_pre_key_bundle(inbound_group_sessions[i], group_pre_key_bundle);
                            e2ees_notify_log(
                                receiver_address,
                                DEBUG_LOG,
                                "complete_inbound_group_session_by_pre_key_bundle: %s, session_owner: [%s:%s]",
                                group_pre_key_bundle->session_id,
                                receiver_address->user->user_id,
                                receiver_address->user->device_id
                            );

                            // release inbound_group_sessions[i]
                            e2ees__group_session__free_unpacked(inbound_group_sessions[i], NULL);
                        }
                        // release inbound_group_sessions
                        free_mem((void **)&inbound_group_sessions, sizeof(E2ees__Session *) * inbound_group_sessions_num);

                        new_outbound_group_session_by_receiver(
                            &(group_pre_key_bundle->group_seed),
                            group_pre_key_bundle->e2ees_pack_id,
                            receiver_address,
                            cur_group_info->group_name,
                            cur_group_info->group_address,
                            group_pre_key_bundle->session_id,
                            cur_group_info->group_member_list,
                            cur_group_info->n_group_member_list
                        );
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "new_outbound_group_session_by_receiver: %s, session_owner: [%s:%s]",
                            group_pre_key_bundle->session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    } else {
                        new_inbound_group_session_by_pre_key_bundle(group_pre_key_bundle->e2ees_pack_id, receiver_address, group_pre_key_bundle);
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "new_inbound_group_session_by_pre_key_bundle: %s, session_owner: [%s:%s]",
                            group_pre_key_bundle->session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    }
                } else if (plaintext->payload_case == E2EES__PLAINTEXT__PAYLOAD_GROUP_UPDATE_KEY_BUNDLE) {
                    E2ees__GroupUpdateKeyBundle *group_update_key_bundle = plaintext->group_update_key_bundle;

                    if (group_update_key_bundle->adding == true) {
                        // create the outbound group session
                        new_outbound_group_session_invited(group_update_key_bundle, receiver_address);
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "new_outbound_group_session_invited: %s, session_owner: [%s:%s]",
                            group_update_key_bundle->session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    }
                    new_and_complete_inbound_group_session_with_ratchet_state(group_update_key_bundle, receiver_address);
                    e2ees_notify_log(
                        receiver_address,
                        DEBUG_LOG,
                        "new_and_complete_inbound_group_session_with_ratchet_state: %s, session_owner: [%s:%s]",
                        group_update_key_bundle->session_id,
                        receiver_address->user->user_id,
                        receiver_address->user->device_id
                    );
                }
                e2ees__plaintext__free_unpacked(plaintext, NULL);
                // success
            } else {
                e2ees_notify_log(receiver_address, BAD_PLAINTEXT, "consume_one2one_msg(), plaintext data unpack error");
                // error
            }
            // release
            free_mem((void **)&decrypted_data_out, decrypted_data_len_out);
        } else {
            e2ees_notify_log(receiver_address, BAD_MESSAGE_DECRYPTION, "consume_one2one_msg() wrong plaintext data");
        }
    }

    // release
    e2ees__session__free_unpacked(inbound_session, NULL);

    // done
    // just consume it
    return true;
}

bool consume_add_user_device_msg(E2ees__E2eeAddress *receiver_address, E2ees__AddUserDeviceMsg *msg) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__E2eeAddress *new_user_address = NULL;
    E2ees__E2eeAddress **old_address_list = NULL;
    size_t old_address_list_number;
    group_address_node *group_address_list = NULL;
    group_address_node *cur_group_address_node = NULL;
    group_address_node *tail_group_address_node = NULL;
    E2ees__E2eeAddress **group_addresses = NULL;
    size_t group_address_num;
    size_t i, j;

    if (!is_valid_address(receiver_address)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_add_user_device_msg(msg)) {
        new_user_address = msg->user_address;
        old_address_list = msg->old_address_list;
        old_address_list_number = msg->n_old_address_list;
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_FAIL) {
        return true;
    }

    for (i = 0; i < old_address_list_number; i++) {
        // load all outbound group addresses
        group_address_num = get_e2ees_plugin()->db_handler.load_group_addresses(old_address_list[i], receiver_address, &group_addresses);

        if (group_address_num == 0)
            continue;

        for (j = 0; j < group_address_num; j++) {
            if (group_address_list != NULL) {
                cur_group_address_node = group_address_list;
                tail_group_address_node = NULL;
                while (cur_group_address_node != NULL) {
                    if (compare_address(cur_group_address_node->group_address, group_addresses[j])) {
                        break;
                    }
                    if (cur_group_address_node->next == NULL) {
                        tail_group_address_node = cur_group_address_node;
                    }
                    cur_group_address_node = cur_group_address_node->next;
                }
                if (tail_group_address_node != NULL) {
                    tail_group_address_node->next = (group_address_node *)malloc(sizeof(group_address_node));
                    copy_address_from_address(&(tail_group_address_node->next->group_address), group_addresses[j]);
                    tail_group_address_node->next->next = NULL;
                }
            } else {
                group_address_list = (group_address_node *)malloc(sizeof(group_address_node));
                copy_address_from_address(&(group_address_list->group_address), group_addresses[j]);
                group_address_list->next = NULL;
            }
        }

        // release
        for (j = 0; j < group_address_num; j++) {
            e2ees__e2ee_address__free_unpacked(group_addresses[j], NULL);
            group_addresses[j] = NULL;
        }
        if (group_addresses != NULL) {
            free_mem((void **)&group_addresses, sizeof(E2ees__E2eeAddress *) * group_address_num);
            group_addresses = NULL;
        }
    }

    if (group_address_list != NULL) {
        cur_group_address_node = group_address_list;
        while (cur_group_address_node != NULL) {
            E2ees__AddGroupMemberDeviceResponse *add_group_member_device_response = NULL;
            ret = add_group_member_device_internal(
                &add_group_member_device_response, receiver_address, cur_group_address_node->group_address, new_user_address
            );

            // release
            free_proto(add_group_member_device_response);

            cur_group_address_node = cur_group_address_node->next;
        }
    }

    // done
    return true;
}

bool consume_remove_user_device_msg(E2ees__E2eeAddress *receiver_address, E2ees__RemoveUserDeviceMsg *msg) {
    if (!is_valid_address(receiver_address)) {
        return true;
    }
    if (!is_valid_remove_user_device_msg(msg)) {
        return true;
    }
    // delete the corresponding session
    get_e2ees_plugin()->db_handler.unload_session(receiver_address, msg->user_address);

    return true;
}

int produce_invite_request(
    E2ees__InviteRequest **request_out,
    E2ees__Session *outbound_session
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__InviteRequest *request = NULL;
    E2ees__InviteMsg *msg = NULL;

    if (!is_valid_uncompleted_session(outbound_session)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        msg = (E2ees__InviteMsg *)malloc(sizeof(E2ees__InviteMsg));
        e2ees__invite_msg__init(msg);

        msg->version = strdup(outbound_session->version);
        msg->e2ees_pack_id = outbound_session->e2ees_pack_id;
        msg->session_id = strdup(outbound_session->session_id);
        copy_address_from_address(&(msg->from), outbound_session->our_address);
        copy_address_from_address(&(msg->to), outbound_session->their_address);

        msg->n_pre_shared_input_list = outbound_session->n_pre_shared_input_list;
        msg->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData) * msg->n_pre_shared_input_list);
        size_t i;
        for (i = 0; i < msg->n_pre_shared_input_list; i++) {
            init_protobuf(&(msg->pre_shared_input_list[i]));
            copy_protobuf_from_protobuf(&(msg->pre_shared_input_list[i]), &(outbound_session->pre_shared_input_list[i]));
        }

        copy_protobuf_from_protobuf(&(msg->alice_base_key), &(outbound_session->alice_base_key->public_key));

        msg->bob_signed_pre_key_id = outbound_session->bob_signed_pre_key_id;
        msg->bob_one_time_pre_key_id = outbound_session->bob_one_time_pre_key_id;

        msg->invite_t = outbound_session->invite_t;

        request = (E2ees__InviteRequest *)malloc(sizeof(E2ees__InviteRequest));
        e2ees__invite_request__init(request);
        request->msg = msg;

        *request_out = request;
    }

    return ret;
}

int consume_invite_response(
    E2ees__E2eeAddress *user_address,
    E2ees__InviteResponse *response
) {
    int ret = E2EES_RESULT_SUCC;

    if (is_valid_address(user_address)) {
        if (!is_valid_invite_response(response)) {
            e2ees_notify_log(NULL, BAD_INVITE_RESPONSE, "consume_invite_response()");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // load the corresponding inbound session
        E2ees__Session *inbound_session = NULL;
        get_e2ees_plugin()->db_handler.load_session(response->session_id, user_address, &inbound_session);
        if (inbound_session != NULL) {
            // update invite_t
            inbound_session->invite_t = response->invite_t;
            get_e2ees_plugin()->db_handler.store_session(inbound_session);
        } else {
            e2ees_notify_log(NULL, BAD_SESSION, "consume_invite_response()");
            ret = E2EES_RESULT_FAIL;
        }
    }

    return ret;
}

bool consume_invite_msg(E2ees__E2eeAddress *receiver_address, E2ees__InviteMsg *invite_msg) {
    if (!is_valid_address(receiver_address)) {
        return true;
    }
    if (!is_valid_invite_msg(invite_msg)) {
        return true;
    }

    e2ees_notify_log(
        receiver_address, DEBUG_LOG, "consume_invite_msg(): from [%s:%s], to [%s:%s]",
        invite_msg->from->user->user_id,
        invite_msg->from->user->device_id,
        invite_msg->to->user->user_id,
        invite_msg->to->user->device_id
    );

    uint32_t e2ees_pack_id = invite_msg->e2ees_pack_id;
    E2ees__E2eeAddress *from = invite_msg->from;
    E2ees__E2eeAddress *to = invite_msg->to;
    char *version = invite_msg->version;
    char *session_id = invite_msg->session_id;

    if (!compare_address(receiver_address, to)) {
        e2ees_notify_log(receiver_address, BAD_ADDRESS, "consume_invite_msg() wrong receiver_address, just consume it");
        // just consume it
        return true;
    }

    // check if session ID has been used
    E2ees__Session *inbound_session = NULL;
    get_e2ees_plugin()->db_handler.load_session(session_id, receiver_address, &inbound_session);
    if (inbound_session != NULL) {
        e2ees_notify_log(receiver_address, BAD_SESSION, "consume_invite_msg() session ID has been used, just consume it");
        // release
        e2ees__session__free_unpacked(inbound_session, NULL);
        // just consume it
        return true;
    }

    // notify
    e2ees_notify_inbound_session_invited(receiver_address, from);

    // automatic create inbound session and send accept request
    E2ees__Account *account = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(to, &account);
    if (account == NULL) {
        e2ees_notify_log(receiver_address, BAD_ACCOUNT, "consume_invite_msg()");
        return true;
    }

    inbound_session = NULL;
    const session_suite_t *session_suite = get_e2ees_pack(e2ees_pack_id)->session_suite;
    // create a new inbound session
    int result = session_suite->new_inbound_session(&inbound_session, account, invite_msg);

    if (result != E2EES_RESULT_SUCC
        || safe_strcmp(inbound_session->session_id, invite_msg->session_id) == false
    ) {
        e2ees_notify_log(receiver_address, BAD_SESSION, "consume_invite_msg()");
        result = E2EES_RESULT_FAIL;
    } else {
        // notify
        e2ees_notify_inbound_session_ready(receiver_address, inbound_session);
    }
    // release
    free_proto(account);
    if (inbound_session != NULL) {
        e2ees__session__free_unpacked(inbound_session, NULL);
        inbound_session = NULL;
    }

    // done
    return true;
}

int produce_accept_request(
    E2ees__AcceptRequest **request_out,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    char *session_id,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__AcceptRequest *request = NULL;
    E2ees__AcceptMsg *msg = NULL;

    if (!is_valid_e2ees_pack_id(e2ees_pack_id)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(from)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(to)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(session_id)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (ciphertext_1 != NULL) {
        if (!is_valid_protobuf(ciphertext_1)) {
            ret = E2EES_RESULT_FAIL;
        }
    }
    if (!is_valid_protobuf(our_ratchet_key)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        msg = (E2ees__AcceptMsg *)malloc(sizeof(E2ees__AcceptMsg));
        e2ees__accept_msg__init(msg);

        msg->e2ees_pack_id = e2ees_pack_id;
        msg->session_id = strdup(session_id);
        copy_address_from_address(&(msg->from), from);
        copy_address_from_address(&(msg->to), to);

        if (ciphertext_1 != NULL) {
            copy_protobuf_from_protobuf(&(msg->encaps_ciphertext), ciphertext_1);
        }

        copy_protobuf_from_protobuf(&(msg->ratchet_key), our_ratchet_key);

        request = (E2ees__AcceptRequest *)malloc(sizeof(E2ees__AcceptRequest));
        e2ees__accept_request__init(request);
        request->msg = msg;

        *request_out = request;
    }

    return ret;
}

int consume_accept_response(E2ees__E2eeAddress *user_address, E2ees__AcceptResponse *response) {
    int ret = E2EES_RESULT_SUCC;

    if (is_valid_address(user_address)) {
        if (!is_valid_accept_response(response)) {
            e2ees_notify_log(NULL, BAD_ACCEPT_RESPONSE, "consume_accept_response()");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    // if (response != NULL) {
    //     e2ees_notify_log(user_address, DEBUG_LOG, "consume_accept_response() response code: %d", response->code);
    //     if (response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK
    //         || response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
    //         return true;
    //     }
    // }

    return ret;
}

bool consume_accept_msg(E2ees__E2eeAddress *receiver_address, E2ees__AcceptMsg *accept_msg) {
    if (!is_valid_address(receiver_address)) {
        // just consume it
        return true;
    }
    if (!is_valid_accept_msg(accept_msg)) {
        // just consume it
        return true;
    }

    e2ees_notify_log(
        receiver_address, DEBUG_LOG, "consume_accept_msg(): from [%s:%s], to [%s:%s]", 
        accept_msg->from->user->user_id,
        accept_msg->from->user->device_id,
        accept_msg->to->user->user_id,
        accept_msg->to->user->device_id
    );

    if (!compare_address(receiver_address, accept_msg->to)) {
        e2ees_notify_log(receiver_address, BAD_ADDRESS, "consume_accept_msg()");
        // just consume it
        return true;
    }

    E2ees__Session *outbound_session = NULL;
    const session_suite_t *session_suite = get_e2ees_pack(accept_msg->e2ees_pack_id)->session_suite;
    int result = session_suite->complete_outbound_session(&outbound_session, accept_msg);

    if (result == E2EES_RESULT_SUCC) {
        // notify
        e2ees_notify_outbound_session_ready(receiver_address, outbound_session);

        // try to send group pre-keys if necessary
        send_pending_plaintext_data(outbound_session);

        // release
        e2ees__session__free_unpacked(outbound_session, NULL);
        outbound_session = NULL;

        // session built, consume accept_msg
        return true;
    } else {
        e2ees_notify_log(
            receiver_address,
            DEBUG_LOG,
            "consume_accept_msg(): complete_outbound_session error, just consume the accept_msg"
        );
        // just consume it
        return true;
    }
}
