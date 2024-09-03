/**
 * @file
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * @brief Create a get_pre_key_bundle_request to be sent to messaging server.
 *
 * @param request_out
 * @param to_user_id
 * @param to_domain
 * @param to_device_id
 * @param active
 * @return 0 if success
 */
int produce_get_pre_key_bundle_request(
    Skissm__GetPreKeyBundleRequest **request_out,
    const char *to_user_id,
    const char *to_domain,
    const char *to_device_id,
    bool active
);

/**
 * @brief Process an incoming get_pre_key_bundle_response_payload.
 *
 * @param invite_response_list_out
 * @param invite_response_num
 * @param from
 * @param group_pre_key_plaintext_data
 * @param group_pre_key_plaintext_data_len
 * @param get_pre_key_bundle_response
 * @return 0 if success
 */
int consume_get_pre_key_bundle_response(
    Skissm__InviteResponse ***invite_response_list_out,
    size_t *invite_response_num,
    Skissm__E2eeAddress *from,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len,
    Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response
);

/**
 * @brief Create a send_one2one_msg_request to be sent to messaging server.
 *
 * @param request_out
 * @param outbound_session
 * @param notif_level
 * @param plaintext_data
 * @param plaintext_data_len
 * @return 0 if success
 */
int produce_send_one2one_msg_request(
    Skissm__SendOne2oneMsgRequest **request_out,
    Skissm__Session *outbound_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
);

/**
 * @brief Process an send_one2one_msg_response with corresponding inbound session.
 *
 * @param outbound_session
 * @param response
 * @return true
 * @return false
 */
bool consume_send_one2one_msg_response(
    Skissm__Session *outbound_session,
    Skissm__SendOne2oneMsgResponse *response
);

/**
 * @brief Process a received Skissm__E2eeMsg message from server.
 *
 * @param receiver_address
 * @param e2ee_msg
 * @return true
 * @return false
 */
bool consume_one2one_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__E2eeMsg *e2ee_msg
);

/**
 * @brief Process an incoming AddUserDeviceMsg message.
 *
 * @param receiver_address
 * @param msg
 * @return true
 * @return false
 */
bool consume_add_user_device_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__AddUserDeviceMsg *msg
);

/**
 * @brief Process an incoming Skissm__RemoveUserDeviceMsg message.
 *
 * @param receiver_address
 * @param msg
 * @return true
 * @return false
 */
bool consume_remove_user_device_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__RemoveUserDeviceMsg *msg
);

/**
 * @brief Create a Skissm__InviteRequest message to be sent to server.
 *
 * @param request_out
 * @param outbound_session
 * @return 0 if success
 */
int produce_invite_request(
    Skissm__InviteRequest **request_out,
    Skissm__Session *outbound_session
);

/**
 * @brief Process an incoming InviteResponse message.
 *
 * @param user_address
 * @param response
 * @return true
 * @return false
 */
int consume_invite_response(
    Skissm__E2eeAddress *user_address,
    Skissm__InviteResponse *response
);

/**
 * @brief Process an incoming Skissm__InviteMsg message.
 *
 * @param receiver_address
 * @param invite_msg
 * @return true
 * @return false
 */
bool consume_invite_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__InviteMsg *invite_msg
);

/**
 * @brief Create a Skissm__AcceptRequest message to be sent to server.
 *
 * @param request_out
 * @param e2ee_pack_id
 * @param from
 * @param to
 * @param ciphertext_1
 * @return 0 if success
 */
int produce_accept_request(
    Skissm__AcceptRequest **request_out,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key
);

/**
 * @brief Process an incoming AcceptResponse message.
 *
 * @param user_address
 * @param response
 * @return true
 * @return false
 */
int consume_accept_response(Skissm__E2eeAddress *user_address, Skissm__AcceptResponse *response);

/**
 * @brief Process an incoming AcceptMsg message.
 *
 * @param receiver_address
 * @param accept_msg
 * @return true
 * @return false
 */
bool consume_accept_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__AcceptMsg *accept_msg
);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_MANAGER_H_ */
