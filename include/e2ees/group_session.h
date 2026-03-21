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
#ifndef GROUP_SESSION_H_
#define GROUP_SESSION_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/**
 * @brief Advance the chain key of group session.
 *
 * @param cipher_suite
 * @param chain_key
 */
void advance_group_chain_key(
    const cipher_suite_t *cipher_suite,
    ProtobufCBinaryData *chain_key
);

/**
 * @brief Create group message key.
 *
 * @param cipher_suite
 * @param chain_key
 * @param message_key
 */
void create_group_message_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    E2ees__MsgKey *message_key
);

/**
 * @brief Encrypt a group message payload.
 *
 * @param group_msg_payload_out Output group message payload.
 * @param e2ees_pack_id The pack ID.
 * @param plaintext_data Plaintext data to encrypt.
 * @param plaintext_data_len Length of the plaintext data.
 * @param chain_key The current chain key.
 * @param assoicated_data Associated data for the AEAD.
 * @param sequence The sequence number of the message.
 * @param identity_key The sender's identity key.
 * @return 0 if success, < 0 for error.
 */
int encrypt_group_msg(
    E2ees__GroupMsgPayload **group_msg_payload_out,
    uint32_t e2ees_pack_id,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len,
    const ProtobufCBinaryData *chain_key,
    const ProtobufCBinaryData *assoicated_data,
    uint32_t sequence,
    E2ees__IdentityKey *identity_key
);

/**
 * @brief Pack the group pre-keys.
 *
 * @param outbound_group_session
 * @param group_pre_key_plaintext_data
 * @param old_session_id
 */
size_t pack_group_pre_key_plaintext(
    E2ees__GroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext_data,
    char *old_session_id
);

/**
 * @brief Create an outbound group session by a group creator.
 *
 * @param n_member_info_list
 * @param member_info_list
 * @param e2ees_pack_id
 * @param user_address
 * @param group_name
 * @param group_address
 * @param group_members
 * @param group_members_num
 * @param old_session_id
 */
int new_outbound_group_session_by_sender(
    size_t n_member_info_list,
    E2ees__GroupMemberInfo **member_info_list,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    const char *group_name,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupMember **group_members,
    size_t group_members_num,
    char *old_session_id
);

/**
 * @brief Create an outbound group session by a group receiver.
 *
 * @param group_seed
 * @param e2ees_pack_id
 * @param user_address
 * @param group_name
 * @param group_address
 * @param session_id
 * @param group_members
 * @param group_members_num
 */
int new_outbound_group_session_by_receiver(
    const ProtobufCBinaryData *group_seed,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    const char *group_name,
    E2ees__E2eeAddress *group_address,
    const char *session_id,
    E2ees__GroupMember **group_members,
    size_t group_members_num
);

/**
 * @brief Create an outbound group session when receiving other group member's invitation.
 *
 * @param group_update_key_bundle
 * @param user_address
 */
int new_outbound_group_session_invited(
    E2ees__GroupUpdateKeyBundle *group_update_key_bundle,
    E2ees__E2eeAddress *user_address
);

/**
 * @brief Create an inbound group session with group pre-key bundle.
 *
 * @param e2ees_pack_id
 * @param user_address
 * @param group_pre_key_bundle
 */
int new_inbound_group_session_by_pre_key_bundle(
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    E2ees__GroupPreKeyBundle *group_pre_key_bundle
);

/**
 * @brief Create an inbound group session with other member's id.
 *
 * @param e2ees_pack_id
 * @param user_address
 * @param group_member_id
 * @param group_info
 */
int new_inbound_group_session_by_member_id(
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    E2ees__GroupMemberInfo *group_member_id,
    E2ees__GroupInfo *group_info
);

/**
 * @brief Complete an inbound group session with group pre-key bundle.
 *
 * @param inbound_group_session
 * @param group_pre_key_bundle
 */
int complete_inbound_group_session_by_pre_key_bundle(
    E2ees__GroupSession *inbound_group_session,
    E2ees__GroupPreKeyBundle *group_pre_key_bundle
);

/**
 * @brief Complete an inbound group session with other member's id.
 *
 * @param inbound_group_session
 * @param group_member_id
 */
int complete_inbound_group_session_by_member_id(
    E2ees__GroupSession *inbound_group_session,
    E2ees__GroupMemberInfo *group_member_id
);

/**
 * @brief Create and complete an inbound group session.
 *
 * @param group_member_id
 * @param other_inbound_group_session
 */
int new_and_complete_inbound_group_session(
    E2ees__GroupMemberInfo *group_member_id,
    E2ees__GroupSession *other_inbound_group_session
);

/**
 * @brief Create and complete an inbound group session with other's chain key.
 *
 * @param group_member_id
 * @param other_group_session
 * @param their_chain_key
 */
int new_and_complete_inbound_group_session_with_chain_key(
    E2ees__GroupMemberInfo *group_member_id,
    E2ees__GroupSession *other_group_session,
    ProtobufCBinaryData *their_chain_key
);

/**
 * @brief Create and complete an inbound group session with other's ratchet state.
 *
 * @param group_update_key_bundle
 * @param user_address
 */
int new_and_complete_inbound_group_session_with_ratchet_state(
    E2ees__GroupUpdateKeyBundle *group_update_key_bundle,
    E2ees__E2eeAddress *user_address
);

/**
 * @brief Renew the outbound group session when someone joins the group.
 *
 * @param outbound_group_session
 * @param sender_chain_key
 * @param sender_address
 * @param n_adding_member_info_list
 * @param adding_member_info_list
 * @param adding_group_members_num
 * @param adding_group_members
 */
int renew_outbound_group_session_by_welcome_and_add(
    E2ees__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    E2ees__E2eeAddress *sender_address,
    size_t n_adding_member_info_list,
    E2ees__GroupMemberInfo **adding_member_info_list,
    size_t adding_group_members_num,
    E2ees__GroupMember **adding_group_members
);

/**
 * @brief Renew the inbound group session when someone joins the group.
 *
 * @param sender_chain_key
 * @param inbound_group_session
 * @param new_group_info
 */
int renew_inbound_group_session_by_welcome_and_add(
    ProtobufCBinaryData *sender_chain_key,
    E2ees__GroupSession *inbound_group_session,
    E2ees__GroupInfo *new_group_info
);

/**
 * @brief Renew group sessions when someone add a new device.
 *
 * @param outbound_group_session
 * @param sender_chain_key
 * @param sender_address
 * @param new_device_address
 * @param adding_member_device_info
 */
int renew_group_sessions_with_new_device(
    E2ees__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *new_device_address,
    E2ees__GroupMemberInfo *adding_member_device_info
);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_SESSION_H_ */
