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
#ifndef E2EES_CLIENT_INTERNAL_H_
#define E2EES_CLIENT_INTERNAL_H_

#include "e2ees/e2ees.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the pre-key bundle internal object.
 * @param invite_response_list_out
 * @param invite_response_num_out
 * @param from
 * @param auth
 * @param to_user_id
 * @param to_domain
 * @param to_device_id
 * @param active
 * @param group_pre_key_plaintext_data
 * @param group_pre_key_plaintext_data_len
 * @return 0 if success
 */
int get_pre_key_bundle_internal(
    E2ees__InviteResponse ***invite_response_list_out,
    size_t *invite_response_num_out,
    E2ees__E2eeAddress *from,
    const char *auth,
    const char *to_user_id,
    const char *to_domain,
    const char *to_device_id,
    bool active,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len
);

/**
 * @brief Send invite request to server.
 * @param response_out
 * @param outbound_session
 * @return 0 if success
 */
int invite_internal(
    E2ees__InviteResponse **response_out,
    E2ees__Session *outbound_session
);

/**
 * @brief Send accept request to server.
 * @param response_out
 * @param e2ees_pack_id
 * @param from
 * @param to
 * @param ciphertext_1
 * @param our_ratchet_key
 * @return 0 if success
 */
int accept_internal(
    E2ees__AcceptResponse **response_out,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key
);

/**
 * @brief Send publish_spk request to server.
 * @param response_out
 * @param account The account to be processed
 * @return 0 if success
 */
int publish_spk_internal(
    E2ees__PublishSpkResponse **response_out,
    E2ees__Account *account
);

/**
 * @brief Send supply_opks request to server.
 * @param response_out
 * @param account
 * @param opks_num
 * @return 0 if success
 */
int supply_opks_internal(
    E2ees__SupplyOpksResponse **response_out,
    E2ees__Account *account,
    uint32_t opks_num
);

/**
 * @brief Send one2one_msg request to server.
 * @param outbound_session
 * @param notif_level
 * @param plaintext_data
 * @param plaintext_data_len
 * @return E2ees__SendOne2oneMsgResponse *
 */
E2ees__SendOne2oneMsgResponse *send_one2one_msg_internal(
    E2ees__Session *outbound_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
);

/**
 * @brief Send add_group_member_device request to server.
 * @param response_out
 * @param sender_address
 * @param group_address
 * @param new_device_address
 * @return 0 if success
 */
int add_group_member_device_internal(
    E2ees__AddGroupMemberDeviceResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    E2ees__E2eeAddress *new_device_address
);

/**
 * @brief Store pending plain text data to db.
 * @param from
 * @param to
 * @param common_plaintext_data
 * @param common_plaintext_data_len
 * @param notif_level
*/
void store_pending_common_plaintext_data_internal(
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    uint8_t *common_plaintext_data,
    size_t common_plaintext_data_len,
    E2ees__NotifLevel notif_level
);

/**
 * @brief Store pending request to db.
 * @param user_address
 * @param type
 * @param request_data
 * @param request_data_len
 * @param request_arg_list
 * @param request_arg_list_len
 */
void store_pending_request_internal(
    E2ees__E2eeAddress *user_address,
    E2ees__PendingRequestType type,
    uint8_t *request_data,
    size_t request_data_len,
    ProtobufCBinaryData *request_arg_list,
    size_t request_arg_list_len
);

/**
 * @brief Resume connection with a given account.
 * @param account
 */
void resume_connection_internal(E2ees__Account *account);

#ifdef __cplusplus
}
#endif

#endif // E2EES_CLIENT_INTERNAL_H_
