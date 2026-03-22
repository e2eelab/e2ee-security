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
#ifndef E2EES_CLIENT_H_
#define E2EES_CLIENT_H_

#include "e2ees/e2ees.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register a new account.
 * @param response_out The output
 * @param e2ees_pack_id The e2ee package id to be used.
 * @param user_name The user name that is creating the new account.
 * @param user_id The unique user id that will be binded to the new account.
 * @param device_id The device id that will be binded to the new account.
 * @param authenticator The authenticator (email and etc.) is used to receive an
 * register auth code.
 * @param auth_code The auth code that is received by the authenticator.
 * @return 0 if success
 */
int register_user(
    E2ees__RegisterUserResponse **response_out,
    uint32_t e2ees_pack_id,
    const char *user_name,
    const char *user_id,
    const char *device_id,
    const char *authenticator,
    const char *auth_code);

/**
 * @brief Send invite request again if the outbound session has not been
 * responded.
 * @param outbound_session The outbound session
 * @return  E2ees__InviteResponse *
 */
E2ees__InviteResponse *reinvite(E2ees__Session *outbound_session);

/**
 * @brief Send invite request and create a new outbound session
 * that needs to be responded before it can be used
 * to send encryption message.
 * @param from From address
 * @param to_user_id The receiver's user_id
 * @param to_domain The receiver's domain
 * @return  E2ees__InviteResponse *
 */
E2ees__InviteResponse *
invite(E2ees__E2eeAddress *from, const char *to_user_id, const char *to_domain);

/**
 * @brief Send invite request to create a new outbound session
 * and delete the old outbound session.
 * @param from From address
 * @param to_user_id The receiver's user_id
 * @param to_domain The receiver's domain
 * @return  E2ees__InviteResponse *
 */
E2ees__InviteResponse *
new_invite(E2ees__E2eeAddress *from, const char *to_user_id, const char *to_domain);

/**
 * @brief Send one2one msg.
 * @param response_out
 * @param from
 * @param to_user_id
 * @param to_domain
 * @param notif_level
 * @param plaintext_data
 * @param plaintext_data_len
 * @return 0 if success
 */
int send_one2one_msg(
    E2ees__SendOne2oneMsgResponse **response_out,
    E2ees__E2eeAddress *from,
    const char *to_user_id,
    const char *to_domain,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len);

/**
 * @brief Send sync msg to other devices.
 * @param from
 * @param plaintext_data
 * @param plaintext_data_len
 */
void send_sync_msg(
    E2ees__E2eeAddress *from, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Send sync invite msg to other devices.
 * @param from
 * @param to_user_id
 * @param to_domain
 * @param to_device_id_list
 * @param to_device_num
 */
void send_sync_invite_msg(
    E2ees__E2eeAddress *from,
    const char *to_user_id,
    const char *to_domain,
    char **to_device_id_list,
    size_t to_device_num);

/**
 * @brief Create a group.
 * @param response_out
 * @param sender_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @return 0 if success
 */
int create_group(
    E2ees__CreateGroupResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    const char *group_name,
    E2ees__GroupMember **group_members,
    size_t group_members_num);

/**
 * @brief Add group members.
 * @param response_out
 * @param sender_address
 * @param group_address
 * @param adding_members
 * @param adding_members_num
 * @return 0 if success
 */
int add_group_members(
    E2ees__AddGroupMembersResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupMember **adding_members,
    size_t adding_members_num);

/**
 * @brief Remove group members.
 * @param response_out
 * @param sender_address
 * @param group_address
 * @param removing_members
 * @param removing_members_num
 * @return 0 if success
 */
int remove_group_members(
    E2ees__RemoveGroupMembersResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupMember **removing_members,
    size_t removing_members_num);

/**
 * @brief Leave group.
 * @param response_out
 * @param sender_address
 * @param group_address
 * @return 0 if success
 */
int leave_group(
    E2ees__LeaveGroupResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address);

/**
 * @brief Send group msg.
 * @param response_out
 * @param sender_address
 * @param group_address
 * @param notif_level,
 * @param plaintext_data
 * @param plaintext_data_len
 * @return 0 if success
 */
int send_group_msg(
    E2ees__SendGroupMsgResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len);

/**
 * @brief Send group msg with filter.
 * @param response_out
 * @param sender_address
 * @param group_address
 * @param notif_level,
 * @param plaintext_data
 * @param plaintext_data_len
 * @param allow_list optional allow list with type E2ees__E2eeAddress **.
 * @param allow_list_len optional allow list len with type size_t.
 * @param deny_list optional deny list with type E2ees__E2eeAddress **.
 * @param deny_list_len optional deny list len with type size_t.
 * @return 0 if success
 */
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
    size_t deny_list_len);

/**
 * @brief Send consume_proto_msg request to server.
 * @param sender_address
 * @param proto_msg_id
 * @return E2ees__ConsumeProtoMsgResponse *
 */
E2ees__ConsumeProtoMsgResponse *
consume_proto_msg(E2ees__E2eeAddress *sender_address, const char *proto_msg_id);

/**
 * @brief Process incoming protocol messages.
 * @param proto_msg_data
 * @param proto_msg_data_len
 * @return E2ees__ConsumeProtoMsgResponse *
 */
E2ees__ConsumeProtoMsgResponse *
process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len);

void resume_connection();

#ifdef __cplusplus
}
#endif

#endif // E2EES_CLIENT_H_
