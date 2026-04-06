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
#include "e2ees/e2ees_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/account_cache.h"
#include "e2ees/account_manager.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/group_session.h"
#include "e2ees/group_session_manager.h"
#include "e2ees/mem_util.h"
#include "e2ees/session.h"
#include "e2ees/session_manager.h"
#include "e2ees/validation.h"

int register_user(
    E2ees__RegisterUserResponse **response_out,
    uint32_t e2ees_pack_id,
    const char *user_name,
    const char *user_id,
    const char *device_id,
    const char *authenticator,
    const char *auth_code) {
    int ret                                           = E2EES_RESULT_SUCC;

    E2ees__Account *account                           = NULL;
    E2ees__RegisterUserRequest *register_user_request = NULL;
    E2ees__RegisterUserResponse *response             = NULL;
    register_user_params_t params                     = { .e2ees_pack_id = e2ees_pack_id,
                                                          .user_name     = user_name,
                                                          .user_id       = user_id,
                                                          .device_id     = device_id,
                                                          .authenticator = authenticator,
                                                          .auth_code     = auth_code };

    if (!is_valid_register_user_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    // generate an account
    if (ret == E2EES_RESULT_SUCC) {
        ret = create_account(&account, e2ees_pack_id);
    }

    // register account to server
    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_register_request(&register_user_request, &params, account);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.register_user, register_user_request);

        if (is_valid_register_user_response(response)) {
            bool consumed = consume_register_response(account, response);
        } else {
            e2ees_notify_log(
                NULL,
                BAD_REGISTER_USER_RESPONSE,
                "register_user(): invalid register_user_response");
            ret = E2EES_RESULT_FAIL;
        }

        // output register response
        *response_out = response;
    }

    // release
    free_proto(account);
    free_proto(register_user_request);

    // done
    return ret;
}

E2ees__InviteResponse *reinvite(E2ees__Session *outbound_session) {
    int ret                         = E2EES_RESULT_SUCC;

    E2ees__InviteResponse *response = NULL;
    // only reinvite the outbound session that is not responded
    if (!outbound_session->responded) {
        // check the time we invited last time
        int64_t now = get_e2ees_plugin()->common_handler.gen_ts();
        if (now < outbound_session->invite_t + E2EES_INVITE_WAITING_TIME_MS) {
            e2ees_notify_log(
                outbound_session->our_address,
                DEBUG_LOG,
                "reinvite(): skipped for not exceed "
                "E2EES_INVITE_WAITING_TIME_MS(60s)");
            return NULL;
        }

        // update the invitation time and resend
        outbound_session->invite_t = get_e2ees_plugin()->common_handler.gen_ts();
        get_e2ees_plugin()->db_handler.store_session(outbound_session);
        ret = invite_internal(&response, outbound_session);

        if (response == NULL || response->code != E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
            // keep outbound session to enable retry
            e2ees_notify_log(
                outbound_session->our_address,
                DEBUG_LOG,
                "reinvite(): from [%s:%s] to[%s:%s] failed need another try",
                outbound_session->our_address->user->user_id,
                outbound_session->our_address->user->device_id,
                outbound_session->their_address->user->user_id,
                outbound_session->their_address->user->device_id);
        }
    }

    return response;
}

E2ees__InviteResponse *
invite(E2ees__E2eeAddress *from, const char *to_user_id, const char *to_domain) {
    int ret                                      = E2EES_RESULT_SUCC;

    char *auth                                   = NULL;
    E2ees__InviteResponse *invite_response       = NULL;
    E2ees__InviteResponse **invite_response_list = NULL;
    size_t invite_response_num                   = 0;

    if (is_valid_address(from)) {
        get_e2ees_plugin()->db_handler.load_auth(from, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(
                from,
                BAD_ACCOUNT,
                "invite() from [%s:%s] to [%s@%s]",
                from->user->user_id,
                from->user->device_id,
                to_user_id,
                to_domain);
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "invite(): no from");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(to_user_id)) {
        e2ees_notify_log(NULL, BAD_USER_ID, "invite(): no to_user_id");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(to_domain)) {
        e2ees_notify_log(NULL, BAD_DOMAIN, "invite(): no to_domain");
        ret = E2EES_RESULT_FAIL;
    }

    // we should always call get_pre_key_bundle_internal() since there may be
    // new devices for to_user_id@to_domain not just check outbound sessions in
    // db currently.

    if (ret == E2EES_RESULT_SUCC) {
        ret = get_pre_key_bundle_internal(
            &invite_response_list,
            &invite_response_num,
            from,
            auth,
            to_user_id,
            to_domain,
            NULL,
            true,
            NULL,
            0);
    }

    // done
    invite_response = (E2ees__InviteResponse *)malloc(sizeof(E2ees__InviteResponse));
    e2ees__invite_response__init(invite_response);
    if (ret == E2EES_RESULT_SUCC) {
        invite_response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_ACCEPTED;
    } else {
        invite_response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_BAD_REQUEST;
    }

    // release
    free_string(auth);
    free_invite_response_list(&invite_response_list, invite_response_num);

    // done
    return invite_response;
}

void send_sync_msg(
    E2ees__E2eeAddress *from, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    E2ees__Session **self_outbound_sessions = NULL;
    size_t self_outbound_sessions_num       = get_e2ees_plugin()->db_handler.load_outbound_sessions(
        from, from->user->user_id, from->domain, &self_outbound_sessions);

    if (self_outbound_sessions_num > 0) {
        e2ees_notify_log(
            from,
            DEBUG_LOG,
            "send_sync_msg(): self_outbound_sessions_num = %zu",
            self_outbound_sessions_num);
        // pack syncing plaintext before sending it
        uint8_t *common_plaintext_data = NULL;
        size_t common_plaintext_data_len;
        pack_common_plaintext(
            plaintext_data,
            plaintext_data_len,
            E2EES__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG,
            &common_plaintext_data,
            &common_plaintext_data_len);

        size_t i;
        for (i = 0; i < self_outbound_sessions_num; i++) {
            E2ees__Session *self_outbound_session = self_outbound_sessions[i];
            // if the device is different from the sender's
            if (strcmp(
                    self_outbound_session->their_address->user->device_id, from->user->device_id) !=
                0) {
                if (self_outbound_session->responded == true) {
                    // send syncing plaintext to server
                    E2ees__SendOne2oneMsgResponse *sync_response = send_one2one_msg_internal(
                        self_outbound_session,
                        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
                        common_plaintext_data,
                        common_plaintext_data_len);
                    // release
                    e2ees__send_one2one_msg_response__free_unpacked(sync_response, NULL);
                } else {
                    e2ees_notify_log(
                        from,
                        DEBUG_LOG,
                        "send_sync_msg(): outbound session[%s] "
                        "(user_id:deviceid = %s, %s) not responded, store "
                        "common_plaintext_data",
                        self_outbound_session->session_id,
                        self_outbound_session->their_address->user->user_id,
                        self_outbound_session->their_address->user->device_id);
                    // store pending common_plaintext_data
                    store_pending_common_plaintext_data_internal(
                        self_outbound_session->our_address,
                        self_outbound_session->their_address,
                        common_plaintext_data,
                        common_plaintext_data_len,
                        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL);
                }
            }
            // release
            e2ees__session__free_unpacked(self_outbound_session, NULL);
        }

        // release
        free_mem((void **)&common_plaintext_data, common_plaintext_data_len);
        free_mem(
            (void **)&self_outbound_sessions,
            sizeof(E2ees__Session *) * self_outbound_sessions_num);
    }
}

int send_one2one_msg(
    E2ees__SendOne2oneMsgResponse **response_out,
    E2ees__E2eeAddress *from,
    const char *to_user_id,
    const char *to_domain,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len) {
    int ret                                 = E2EES_RESULT_SUCC;

    E2ees__SendOne2oneMsgResponse *response = NULL;
    uint8_t *common_plaintext_data          = NULL;
    size_t common_plaintext_data_len        = 0;
    E2ees__Session **outbound_sessions      = NULL;
    size_t outbound_sessions_num            = 0;
    E2ees__E2eeAddress *to                  = NULL;
    bool succ                               = false;
    size_t i;

    // pack common plaintext before sending it
    pack_common_plaintext(
        plaintext_data,
        plaintext_data_len,
        E2EES__PLAINTEXT__PAYLOAD_COMMON_MSG,
        &common_plaintext_data,
        &common_plaintext_data_len);

    outbound_sessions_num = get_e2ees_plugin()->db_handler.load_outbound_sessions(
        from, to_user_id, to_domain, &outbound_sessions);
    if (outbound_sessions_num == 0 || outbound_sessions == NULL) {
        // save common_plaintext_data and will be resent after the first
        // outbound session established
        e2ees_notify_log(
            from,
            DEBUG_LOG,
            "send_one2one_msg(): outbound_sessions_num = %zu, store "
            "common_plaintext_data",
            outbound_sessions_num);
        to = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
        e2ees__e2ee_address__init(to);
        to->domain                 = strdup(to_domain);
        E2ees__PeerUser *peer_user = (E2ees__PeerUser *)malloc(sizeof(E2ees__PeerUser));
        e2ees__peer_user__init(peer_user);
        peer_user->user_id = strdup(to_user_id);
        // no specific deviceId currently
        to->peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
        to->user      = peer_user;
        store_pending_common_plaintext_data_internal(
            from, to, common_plaintext_data, common_plaintext_data_len, notif_level);

        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        for (i = 0; i < outbound_sessions_num; i++) {
            E2ees__Session *outbound_session = outbound_sessions[i];
            if (outbound_session->responded == false) {
                e2ees_notify_log(
                    from,
                    DEBUG_LOG,
                    "send_one2one_msg(): outbound session %zu of %zu [%s] not "
                    "responded, store common_plaintext_data",
                    i + 1,
                    outbound_sessions_num,
                    outbound_session->session_id);
                // store pending common_plaintext_data
                store_pending_common_plaintext_data_internal(
                    outbound_session->our_address,
                    outbound_session->their_address,
                    common_plaintext_data,
                    common_plaintext_data_len,
                    notif_level);
                continue;
            }

            // send message to server
            E2ees__SendOne2oneMsgResponse *send_one2one_msg_response = send_one2one_msg_internal(
                outbound_session, notif_level, common_plaintext_data, common_plaintext_data_len);
            e2ees_notify_log(
                from,
                DEBUG_LOG,
                "send_one2one_msg(): outbound session %zu of %zu [%s] response "
                "code: %d",
                i + 1,
                outbound_sessions_num,
                outbound_session->session_id,
                send_one2one_msg_response->code);
            if (send_one2one_msg_response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
                succ = true;
            }
            // release
            e2ees__send_one2one_msg_response__free_unpacked(send_one2one_msg_response, NULL);
            send_one2one_msg_response = NULL;
        }
    }

    // send the message to other self devices, whether ret is success or not
    send_sync_msg(from, plaintext_data, plaintext_data_len);

    // release
    free_mem((void **)&common_plaintext_data, common_plaintext_data_len);
    if (to != NULL) {
        e2ees__e2ee_address__free_unpacked(to, NULL);
        to = NULL;
    }
    if (outbound_sessions_num > 0 && outbound_sessions != NULL) {
        for (i = 0; i < outbound_sessions_num; i++) {
            e2ees__session__free_unpacked(outbound_sessions[i], NULL);
            outbound_sessions[i] = NULL;
        }
        free_mem((void **)&outbound_sessions, sizeof(E2ees__Session *) * outbound_sessions_num);
        outbound_sessions = NULL;
    }

    // done
    // return ok response if there is at least one session sent successfully
    response = (E2ees__SendOne2oneMsgResponse *)malloc(sizeof(E2ees__SendOne2oneMsgResponse));
    e2ees__send_one2one_msg_response__init(response);
    if (ret == E2EES_RESULT_SUCC) {
        // there are some outbound sessions, but none of them were processed
        // successfully
        response->code =
            (succ ? E2EES__RESPONSE_CODE__RESPONSE_CODE_OK
                  : E2EES__RESPONSE_CODE__RESPONSE_CODE_BAD_REQUEST);
    } else {
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_EXPECTATION_FAILED;
        response->msg  = strdup("no outbound sessions");
    }
    *response_out = response;

    return ret;
}

int create_group(
    E2ees__CreateGroupResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    const char *group_name,
    E2ees__GroupMember **group_members,
    size_t group_members_num) {
    int ret                                         = E2EES_RESULT_SUCC;

    E2ees__CreateGroupRequest *create_group_request = NULL;
    E2ees__CreateGroupResponse *response            = NULL;
    E2ees__Account *account                         = NULL;
    create_group_params_t params                    = { .sender_address    = sender_address,
                                                        .group_name        = group_name,
                                                        .group_members     = group_members,
                                                        .group_members_num = group_members_num };

    if (!is_valid_create_group_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_account_by_address(sender_address, &account);
        if (!account || !is_valid_e2ees_pack_id(account->e2ees_pack_id) ||
            !is_valid_string(account->auth)) {
            e2ees_notify_log(sender_address, BAD_ACCOUNT, "create_group(): invalid account");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_create_group_request(&create_group_request, &params, account->e2ees_pack_id);
    }

    if (ret == E2EES_RESULT_SUCC) {
        // send message to server
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.create_group,
            create_group_request,
            sender_address,
            account->auth);

        if (!is_valid_create_group_response(response)) {
            e2ees_notify_log(
                sender_address,
                BAD_CREATE_GROUP_RESPONSE,
                "create_group(): invalid create_group_response");
            ret = E2EES_RESULT_FAIL;
            // do not keep pending request for create_group():
            // pack reuest to request_data
            // size_t request_data_len =
            // e2ees__create_group_request__get_packed_size(create_group_request);
            // uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) *
            // request_data_len);
            // e2ees__create_group_request__pack(create_group_request,
            // request_data); store_pending_request_internal(sender_address,
            // E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_CREATE_GROUP,
            // request_data, request_data_len, NULL, 0); release free_mem((void
            // **)&request_data, request_data_len);
        }

        // output create_group response
        *response_out = response;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = consume_create_group_response(
            account->e2ees_pack_id,
            sender_address,
            group_name,
            group_members,
            group_members_num,
            response);
        if (ret != E2EES_RESULT_SUCC) {
            e2ees_notify_log(
                sender_address,
                BAD_CONSUME,
                "Server created group but local consume response failed");
        }
    }

    // release
    free_proto(account);
    free_proto(create_group_request);

    // done
    return ret;
}

int add_group_members(
    E2ees__AddGroupMembersResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupMember **adding_members,
    size_t adding_members_num) {
    int ret                                                  = E2EES_RESULT_SUCC;

    E2ees__AddGroupMembersRequest *add_group_members_request = NULL;
    E2ees__AddGroupMembersResponse *response                 = NULL;
    char *auth                                               = NULL;
    E2ees__GroupSession *outbound_group_session              = NULL;
    add_group_members_params_t params                        = { .sender_address     = sender_address,
                                                                 .group_address      = group_address,
                                                                 .adding_members     = adding_members,
                                                                 .adding_members_num = adding_members_num };

    if (!is_valid_add_group_members_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(sender_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "add_group_members: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(
            sender_address, sender_address, group_address, &outbound_group_session);
        if (!is_valid_group_session(outbound_group_session)) {
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_add_group_members_request(
            &add_group_members_request, &params, outbound_group_session);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.add_group_members,
            add_group_members_request,
            sender_address,
            auth);

        if (!is_valid_add_group_members_response(response)) {
            e2ees_notify_log(
                NULL,
                BAD_ADD_GROUP_MEMBERS_RESPONSE,
                "add_group_members(): invalid add_group_members_response");
            ret = E2EES_RESULT_FAIL;
            // do not keep pending request for add_group_members():
            // pack reuest to request_data
            // size_t request_data_len =
            // e2ees__add_group_members_request__get_packed_size(add_group_members_request);
            // uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) *
            // request_data_len);
            // e2ees__add_group_members_request__pack(add_group_members_request,
            // request_data); store_pending_request_internal(sender_address,
            // E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBERS,
            // request_data, request_data_len, NULL, 0); release free_mem((void
            // **)&request_data, request_data_len);
        }

        // output add_group_members response
        *response_out = response;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = consume_add_group_members_response(
            outbound_group_session,
            response,
            response->added_group_member_list,
            response->n_added_group_member_list);
        if (ret != E2EES_RESULT_SUCC) {
            e2ees_notify_log(
                sender_address,
                BAD_CONSUME,
                "Server added group members but local consume response failed");
        }
    }

    // release
    free_proto(add_group_members_request);
    free_string(auth);
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    // done
    return ret;
}

int remove_group_members(
    E2ees__RemoveGroupMembersResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupMember **removing_members,
    size_t removing_members_num) {
    int ret                                                        = E2EES_RESULT_SUCC;

    E2ees__RemoveGroupMembersRequest *remove_group_members_request = NULL;
    E2ees__RemoveGroupMembersResponse *response                    = NULL;
    char *auth                                                     = NULL;
    E2ees__GroupSession *outbound_group_session                    = NULL;
    remove_group_members_params_t params = { .sender_address       = sender_address,
                                             .group_address        = group_address,
                                             .removing_members     = removing_members,
                                             .removing_members_num = removing_members_num };

    if (!is_valid_remove_group_members_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(sender_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "remove_group_members: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(
            sender_address, sender_address, group_address, &outbound_group_session);
        if (!is_valid_group_session(outbound_group_session)) {
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_remove_group_members_request(
            &remove_group_members_request, &params, outbound_group_session);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.remove_group_members,
            remove_group_members_request,
            sender_address,
            auth);

        if (!is_valid_remove_group_members_response(response)) {
            e2ees_notify_log(
                NULL,
                BAD_REMOVE_GROUP_MEMBERS_RESPONSE,
                "remove_group_members(): invalid "
                "remove_group_members_response");
            ret = E2EES_RESULT_FAIL;
            // do not keep pending request for remove_group_members():
            // pack request to request_data
            // size_t request_data_len =
            // e2ees__remove_group_members_request__get_packed_size(remove_group_members_request);
            // uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) *
            // request_data_len);
            // e2ees__remove_group_members_request__pack(remove_group_members_request,
            // request_data); store_pending_request_internal(sender_address,
            // E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_REMOVE_GROUP_MEMBERS,
            // request_data, request_data_len, NULL, 0); release free_mem((void
            // **)&request_data, request_data_len);
        }

        // output remove_group_members response
        *response_out = response;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = consume_remove_group_members_response(
            outbound_group_session,
            response,
            response->removed_group_member_list,
            response->n_removed_group_member_list);
        if (ret != E2EES_RESULT_SUCC) {
            e2ees_notify_log(
                sender_address,
                BAD_CONSUME,
                "Server removed group members but local consume response "
                "failed");
        }
    }

    // release
    free_proto(remove_group_members_request);
    free_string(auth);
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    // done
    return ret;
}

int leave_group(
    E2ees__LeaveGroupResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address) {
    int ret                                       = E2EES_RESULT_SUCC;

    E2ees__LeaveGroupRequest *leave_group_request = NULL;
    E2ees__LeaveGroupResponse *response           = NULL;
    char *auth                                    = NULL;
    leave_group_params_t params                   = { .sender_address = sender_address,
                                                      .group_address  = group_address };

    if (!is_valid_leave_group_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(sender_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "leave_group: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_leave_group_request(&leave_group_request, &params);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.leave_group,
            leave_group_request,
            sender_address,
            auth);

        if (!is_valid_leave_group_response(response)) {
            e2ees_notify_log(
                NULL, BAD_LEAVE_GROUP_RESPONSE, "leave_group(): invalid leave_group_response");
            ret = E2EES_RESULT_FAIL;
            // do not keep pending request for leave_group():
            // pack request to request_data
            // size_t request_data_len =
            // e2ees__leave_group_request__get_packed_size(leave_group_request);
            // uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) *
            // request_data_len);
            // e2ees__leave_group_request__pack(leave_group_request,
            // request_data); store_pending_request_internal(sender_address,
            // E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_LEAVE_GROUP,
            // request_data, request_data_len, NULL, 0); release free_mem((void
            // **)&request_data, request_data_len);
        }

        // output leave_group response
        *response_out = response;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = consume_leave_group_response(sender_address, response);
    }

    // release
    free_proto(leave_group_request);
    free_string(auth);

    // done
    return ret;
}

int send_group_msg_with_filter(
    E2ees__SendGroupMsgResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len,
    E2ees__E2eeAddress **allow_list,
    size_t allow_list_len,
    E2ees__E2eeAddress **deny_list,
    size_t deny_list_len) {
    int ret                                            = E2EES_RESULT_SUCC;

    E2ees__SendGroupMsgRequest *send_group_msg_request = NULL;
    E2ees__SendGroupMsgResponse *response              = NULL;
    E2ees__Account *account                            = NULL;
    E2ees__GroupSession *outbound_group_session        = NULL;
    E2ees__GroupMsgPayload *group_msg_payload          = NULL;
    char *auth                                         = NULL;
    send_group_msg_params_t params                     = { .sender_address = sender_address,
                                                           .group_address  = group_address,
                                                           .allow_list     = allow_list,
                                                           .allow_list_len = allow_list_len,
                                                           .deny_list      = deny_list,
                                                           .deny_list_len  = deny_list_len };

    if (!is_valid_send_group_msg_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(sender_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "send_group_msg_with_filter: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_account_by_address(sender_address, &account);
        if (!account || !is_valid_identity_key(account->identity_key)) {
            e2ees_notify_log(
                NULL, BAD_KEY_PAIR, "send_group_msg_with_filter(): invalid identity_key");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(
            sender_address, sender_address, group_address, &outbound_group_session);
        if (!is_valid_group_session(outbound_group_session)) {
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = encrypt_group_msg(
            &group_msg_payload,
            outbound_group_session->e2ees_pack_id,
            plaintext_data,
            plaintext_data_len,
            &(outbound_group_session->chain_key),
            &(outbound_group_session->associated_data),
            outbound_group_session->sequence,
            account->identity_key);
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_send_group_msg_request(
            &send_group_msg_request,
            &params,
            notif_level,
            outbound_group_session,
            group_msg_payload);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.send_group_msg,
            send_group_msg_request,
            sender_address,
            auth);

        ret = consume_send_group_msg_response(outbound_group_session, response);
        if (ret != E2EES_RESULT_SUCC) {
            // do not keep failed reqiest
            // e2ees_notify_log(sender_address, BAD_SEND_GROUP_MSG_RESPONSE,
            // "send_group_msg()"); ret = E2EES_RESULT_FAIL;
            // // pack request to request_data
            // size_t request_data_len =
            // e2ees__send_group_msg_request__get_packed_size(send_group_msg_request);
            // uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) *
            // request_data_len);
            // e2ees__send_group_msg_request__pack(send_group_msg_request,
            // request_data);

            // store_pending_request_internal(sender_address,
            // E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_GROUP_MSG,
            // request_data, request_data_len, NULL, 0); release free_mem((void
            // **)&request_data, request_data_len);
        }

        // output send_group_msg response
        *response_out = response;
    } else {
        e2ees_notify_log(
            sender_address, BAD_SEND_GROUP_MSG_RESPONSE, "send_group_msg() response is null");
        *response_out = NULL;
    }

    // release
    free_proto(send_group_msg_request);
    free_proto(account);
    free_string(auth);
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    // done
    return ret;
}

int send_group_msg(
    E2ees__SendGroupMsgResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len) {
    return send_group_msg_with_filter(
        response_out,
        sender_address,
        group_address,
        notif_level,
        plaintext_data,
        plaintext_data_len,
        NULL,
        0,
        NULL,
        0);
}

E2ees__ConsumeProtoMsgResponse *
consume_proto_msg(E2ees__E2eeAddress *sender_address, const char *proto_msg_id) {
    char *auth = NULL;
    get_e2ees_plugin()->db_handler.load_auth(sender_address, &auth);

    if (!is_valid_string(auth)) {
        e2ees_notify_log(sender_address, BAD_ACCOUNT, "consume_proto_msg(): no auth");
        free_string(auth);
        return NULL;
    }

    E2ees__ConsumeProtoMsgRequest *request =
        (E2ees__ConsumeProtoMsgRequest *)malloc(sizeof(E2ees__ConsumeProtoMsgRequest));
    e2ees__consume_proto_msg_request__init(request);
    request->proto_msg_id = strdup(proto_msg_id);
    E2ees__ConsumeProtoMsgResponse *response =
        get_e2ees_plugin()->proto_handler.consume_proto_msg(sender_address, auth, request);

    // release
    free_string(auth);
    e2ees__consume_proto_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

E2ees__ConsumeProtoMsgResponse *
process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len) {
    int ret                                  = E2EES_RESULT_SUCC;
    int server_check                         = 0;
    bool consumed                            = false;

    ds_suite_t *digital_signature_suite      = NULL;
    E2ees__E2eeAddress *receiver_address     = NULL;
    ProtobufCBinaryData server_public_key    = { 0, NULL };
    E2ees__ConsumeProtoMsgResponse *response = NULL;
    E2ees__ProtoMsg *proto_msg = e2ees__proto_msg__unpack(NULL, proto_msg_data_len, proto_msg_data);
    size_t i;

    if (is_valid_proto_msg(proto_msg)) {
        receiver_address = proto_msg->to;
        load_server_public_key_from_cache(&server_public_key, receiver_address);
        for (i = 0; i < proto_msg->n_signature_list; i++) {
            digital_signature_suite = get_ds_suite(proto_msg->signature_list[i]->signing_alg);
            server_check            = digital_signature_suite->verify(
                proto_msg->signature_list[i]->signature.data,
                proto_msg->signature_list[i]->signature.len,
                proto_msg->signature_list[i]->msg_fingerprint.data,
                proto_msg->signature_list[i]->msg_fingerprint.len,
                server_public_key.data);
            if (server_check < 0) {
                e2ees_notify_log(
                    NULL, BAD_SERVER_SIGNATURE, "process_proto_msg(): invalid server signature");
                ret = E2EES_RESULT_FAIL;
            }
        }
    } else {
        e2ees_notify_log(NULL, BAD_PROTO_MSG, "process_proto_msg(): invalid proto_msg");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        log_proto(receiver_address, (const ProtobufCMessage *)proto_msg);
        switch (proto_msg->payload_case) {
        case E2EES__PROTO_MSG__PAYLOAD_SUPPLY_OPKS_MSG:
            consumed = consume_supply_opks_msg(receiver_address, proto_msg->supply_opks_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ADD_USER_DEVICE_MSG:
            consumed =
                consume_add_user_device_msg(receiver_address, proto_msg->add_user_device_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_REMOVE_USER_DEVICE_MSG:
            consumed =
                consume_remove_user_device_msg(receiver_address, proto_msg->remove_user_device_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_INVITE_MSG:
            consumed = consume_invite_msg(receiver_address, proto_msg->invite_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ACCEPT_MSG:
            consumed = consume_accept_msg(receiver_address, proto_msg->accept_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_E2EE_MSG:
            if (proto_msg->e2ee_msg->payload_case == E2EES__E2EE_MSG__PAYLOAD_ONE2ONE_MSG)
                consumed = consume_one2one_msg(receiver_address, proto_msg->e2ee_msg);
            else if (proto_msg->e2ee_msg->payload_case == E2EES__E2EE_MSG__PAYLOAD_GROUP_MSG)
                consumed = consume_group_msg(receiver_address, proto_msg->e2ee_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_CREATE_GROUP_MSG:
            consumed = consume_create_group_msg(receiver_address, proto_msg->create_group_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBERS_MSG:
            consumed =
                consume_add_group_members_msg(receiver_address, proto_msg->add_group_members_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBER_DEVICE_MSG:
            consumed = consume_add_group_member_device_msg(
                receiver_address, proto_msg->add_group_member_device_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG:
            consumed = consume_remove_group_members_msg(
                receiver_address, proto_msg->remove_group_members_msg);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_LEAVE_GROUP_MSG:
            consumed = consume_leave_group_msg(receiver_address, proto_msg->leave_group_msg);
            break;
        default:
            // consume the message that is arriving here
            consumed = true;
            break;
        };

        // notify server that the proto_msg has been consumed
        if (consumed) {
            if (proto_msg->tag != NULL) {
                response = consume_proto_msg(receiver_address, proto_msg->tag->proto_msg_id);
                bool save_pending_request = false;
                if (response != NULL) {
                    if (response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK ||
                        response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                        // server consumed
                    } else {
                        save_pending_request = true;
                    }
                } else {
                    save_pending_request = true;
                    response             = (E2ees__ConsumeProtoMsgResponse *)malloc(
                        sizeof(E2ees__ConsumeProtoMsgResponse));
                    e2ees__consume_proto_msg_response__init(response);
                    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_SERVICE_UNAVAILABLE;
                }
                if (save_pending_request) {
                    // pack and save as pending request
                    size_t request_data_len = e2ees__proto_msg__get_packed_size(proto_msg);
                    uint8_t *request_data   = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
                    e2ees__proto_msg__pack(proto_msg, request_data);

                    store_pending_request_internal(
                        proto_msg->to,
                        E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_PROTO_MSG,
                        request_data,
                        request_data_len,
                        NULL,
                        0);
                    // release
                    free_mem((void **)&request_data, request_data_len);
                }
            } else {
                response = (E2ees__ConsumeProtoMsgResponse *)malloc(
                    sizeof(E2ees__ConsumeProtoMsgResponse));
                e2ees__consume_proto_msg_response__init(response);
                response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
            }
        } else {
            e2ees_notify_log(
                receiver_address,
                DEBUG_LOG,
                "process_proto_msg() proto_msg is not consumed payload_case: "
                "%d, proto_msg_id: %s",
                proto_msg->payload_case,
                proto_msg->tag == NULL ? "" : proto_msg->tag->proto_msg_id);
        }
    }

    // release
    if (proto_msg != NULL) {
        free_proto(proto_msg);
    }
    if (server_public_key.data != NULL) {
        free_mem((void **)&(server_public_key.data), sizeof(uint8_t) * server_public_key.len);
    }

    // done
    return response;
}

void resume_connection() {
    // loop on all accounts
    E2ees__Account **accounts   = NULL;
    size_t account_num          = get_e2ees_plugin()->db_handler.load_accounts(&accounts);

    E2ees__Account *cur_account = NULL;
    size_t i;
    for (i = 0; i < account_num; i++) {
        cur_account = accounts[i];
        resume_connection_internal(cur_account);
        // release
        e2ees__account__free_unpacked(cur_account, NULL);
    }

    // release
    if (accounts != NULL)
        free(accounts);
}
