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
#ifndef MEM_UTIL_H_
#define MEM_UTIL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

#define free_string(arg) \
    if (arg != NULL) { \
        free(arg); \
        arg = NULL; \
    }

#define free_proto(arg) \
    if (arg != NULL) { \
        e2ees__##arg##__free_unpacked(arg, NULL); \
        arg = NULL; \
    }

/** Check if two buffers are equal in constant time. */
bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t len);

/**
 * @brief Generate a UUID string.
 *
 * @return char*
 */
char *generate_uuid_str();

/**
 * @brief Generate hex string from given uint8 array.
 *
 * @param buffer
 * @param buffer_len
 * @param hex_str output hex str
 * @return the length of output hex str
 */
size_t to_hex_str(const uint8_t *buffer, size_t buffer_len, char **hex_str);

/**
 * @brief Compare two ProtobufCBinaryData objects.
 *
 * @param src_1
 * @param src_2
 * @return true
 * @return false
 */
bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2);

/**
 * @brief Compare two char string that can be NULL.
 *
 * @param str_1
 * @param str_2
 * @return true
 * @return false
 */
bool safe_strcmp(const char *str_1, const char *str_2);

/**
 * @brief Compare two user's ids.
 *
 * @param address
 * @param user_id
 * @param domain
 * @return true
 * @return false
 */
bool compare_user_id(E2ees__E2eeAddress *address, const char *user_id, const char *domain);

/**
 * @brief Compare two E2ees__E2eeAddress objects.
 *
 * @param address_1
 * @param address_2
 * @return true
 * @return false
 */
bool compare_address(E2ees__E2eeAddress *address_1, E2ees__E2eeAddress *address_2);

/**
 * @brief Compaare two E2ees__GroupMember arrays.
 *
 * @param group_members_1
 * @param group_member_num_1
 * @param group_members_2
 * @param group_member_num_2
 * @return true
 * @return false
 */
bool compare_group_member(
    E2ees__GroupMember **group_members_1,
    size_t group_member_num_1,
    E2ees__GroupMember **group_members_2,
    size_t group_member_num_2
);

/**
 * @brief Initialize the ProtobufCBinaryData.
 *
 * @param dest
 */
void init_protobuf(ProtobufCBinaryData *dest);

/**
 * @brief Malloc the ProtobufCBinaryData with given len.
 *
 * @param dest
 * @param len
 */
void malloc_protobuf(ProtobufCBinaryData *dest, size_t len);

uint8_t *get_identity_public_key_ds_uint8_from_account(E2ees__Account *src);

ProtobufCBinaryData *get_identity_public_key_ds_bytes_from_account(E2ees__Account *src);

/**
 * @brief Copy ProtobufCBinaryData from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src);

/**
 * @brief Copy ProtobufCBinaryData from bool.
 *
 * @param dest
 * @param src
 */
void copy_protobuf_from_bool(ProtobufCBinaryData *dest, bool src);

/**
 * @brief Copy data from byte array to ProtobufCBinaryData.
 *
 * @param dest
 * @param src
 * @param len
 */
void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len);

/**
 * @brief Overwrite data from byte array to ProtobufCBinaryData.
 *
 * @param dest
 * @param src
 */
void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src);

/**
 * @brief Copy ProtobufCBinaryData list from src to dest.
 *
 * @param dest
 * @param src
 * @param protobuf_num
 */
void copy_protobuf_list_from_protobuf_list(
    ProtobufCBinaryData *dest, const ProtobufCBinaryData *src, size_t protobuf_num
);

/**
 * @brief Copy E2ees__E2eeAddress from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_address_from_address(E2ees__E2eeAddress **dest, const E2ees__E2eeAddress *src);

/**
 * @brief Copy E2ees__KeyPair from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_key_pair_from_key_pair(E2ees__KeyPair **dest, E2ees__KeyPair *src);

/**
 * @brief Copy E2ees__IdentityKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_ik_from_ik(E2ees__IdentityKey **dest, E2ees__IdentityKey *src);

/**
 * @brief Copy E2ees__SignedPreKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_spk_from_spk(E2ees__SignedPreKey **dest, E2ees__SignedPreKey *src);

/**
 * @brief Copy E2ees__OneTimePreKey from src to dest.
 *
 * @param dest
 * @param src
 * @param opk_num
 */
void copy_opks_from_opks(E2ees__OneTimePreKey ***dest, E2ees__OneTimePreKey **src, size_t opk_num);

/**
 * @brief Copy E2ees__Subject from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_subject_from_subject(E2ees__Subject **dest, E2ees__Subject *src);

/**
 * @brief Copy E2ees__Cert from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_cert_from_cert(E2ees__Cert **dest, E2ees__Cert *src);

/**
 * @brief Copy E2ees__Certificate from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_certificate_from_certificate(E2ees__Certificate **dest, E2ees__Certificate *src);

/**
 * @brief Copy E2ees__Account from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_account_from_account(E2ees__Account **dest, E2ees__Account *src);

/**
 * @brief Copy E2ees__ChainKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_chain_key_from_chain_key(E2ees__ChainKey **dest, E2ees__ChainKey *src);

/**
 * @brief Copy E2ees__MsgKey from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_msg_key_from_msg_key(E2ees__MsgKey **dest, E2ees__MsgKey *src);

/**
 * @brief Copy E2ees__SenderChainNode from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_sender_chain_from_sender_chain(E2ees__SenderChainNode **dest, E2ees__SenderChainNode *src);

/**
 * @brief Copy E2ees__ReceiverChainNode from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_receiver_chain_from_receiver_chain(E2ees__ReceiverChainNode **dest, E2ees__ReceiverChainNode *src);

/**
 * @brief Copy E2ees__SkippedMsgKeyNode from src to dest.
 *
 * @param dest
 * @param src
 * @param skipped_msg_keys_num
 */
void copy_skipped_msg_keys_from_skipped_msg_keys(
    E2ees__SkippedMsgKeyNode ***dest,
    E2ees__SkippedMsgKeyNode **src,
    size_t skipped_msg_keys_num
);

/**
 * @brief Copy E2ees__Ratchet from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_ratchet_from_ratchet(E2ees__Ratchet **dest, E2ees__Ratchet *src);

/**
 * @brief Copy E2ees__Session from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_session_from_session(E2ees__Session **dest, E2ees__Session *src);

/**
 * @brief Copy E2ees__IdentityKeyPublic from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_ik_public_from_ik_public(E2ees__IdentityKeyPublic **dest, E2ees__IdentityKeyPublic *src);

/**
 * @brief Copy E2ees__SignedPreKeyPublic from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_spk_public_from_spk_public(E2ees__SignedPreKeyPublic **dest, E2ees__SignedPreKeyPublic *src);

/**
 * @brief Copy E2ees__OneTimePreKeyPublic from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_opk_public_from_opk_public(E2ees__OneTimePreKeyPublic **dest, E2ees__OneTimePreKeyPublic *src);

void copy_ik_to_public(E2ees__IdentityKeyPublic **dest, E2ees__IdentityKey *src);

void copy_spk_to_public(E2ees__SignedPreKeyPublic **dest, E2ees__SignedPreKey *src);

void copy_opk_to_public(E2ees__OneTimePreKeyPublic **dest, E2ees__OneTimePreKey *src);

void copy_opk_list_to_public(E2ees__OneTimePreKeyPublic ***dest, E2ees__OneTimePreKey **src, size_t opk_num);

/**
 * @brief Copy E2ees__GroupMemberInfo from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_group_member_id(E2ees__GroupMemberInfo **dest, E2ees__GroupMemberInfo *src);

/**
 * @brief Copy E2ees__GroupMemberInfo array from src to dest.
 *
 * @param dest
 * @param src
 * @param to_member_addresses_total_num
 */
void copy_group_member_ids(E2ees__GroupMemberInfo ***dest, E2ees__GroupMemberInfo **src, size_t to_member_addresses_total_num);

/**
 * @brief Copy E2ees__GroupMember from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_group_member(E2ees__GroupMember **dest, E2ees__GroupMember *src);

/**
 * @brief Copy E2ees__GroupMember array from src to dest.
 *
 * @param dest
 * @param src
 * @param group_members_num
 */
void copy_group_members(E2ees__GroupMember ***dest, E2ees__GroupMember **src, size_t group_members_num);

/**
 * @brief Copy E2ees__GroupInfo from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_group_info(E2ees__GroupInfo **dest, E2ees__GroupInfo *src);

/**
 * @brief Copy E2ees__CreateGroupMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_create_group_msg(E2ees__CreateGroupMsg **dest, E2ees__CreateGroupMsg *src);

/**
 * @brief Copy E2ees__AddGroupMembersMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_add_group_members_msg(E2ees__AddGroupMembersMsg **dest, E2ees__AddGroupMembersMsg *src);

/**
 * @brief Copy E2ees__AddGroupMemberDeviceMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_add_group_member_device_msg(E2ees__AddGroupMemberDeviceMsg **dest, E2ees__AddGroupMemberDeviceMsg *src);

/**
 * @brief Copy E2ees__RemoveGroupMembersMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_remove_group_members_msg(E2ees__RemoveGroupMembersMsg **dest, E2ees__RemoveGroupMembersMsg *src);

/**
 * @brief Copy E2ees__LeaveGroupMsg from src to dest.
 *
 * @param dest
 * @param src
 */
void copy_leave_group_msg(E2ees__LeaveGroupMsg **dest, E2ees__LeaveGroupMsg *src);

/**
 * @brief Add new E2ees__GroupMember array to dest.
 *
 * @param dest
 * @param old_group_info
 * @param adding_members
 * @param adding_members_num
 */
void add_group_members_to_group_info(
    E2ees__GroupInfo **dest,
    E2ees__GroupInfo *old_group_info,
    E2ees__GroupMember **adding_members,
    size_t adding_members_num
);

/**
 * @brief Remove some E2ees__GroupMember from old_group_info.
 *
 * @param dest
 * @param old_group_info
 * @param removing_members
 * @param removing_members_num
 */
void remove_group_members_from_group_info(
    E2ees__GroupInfo **dest,
    E2ees__GroupInfo *old_group_info,
    E2ees__GroupMember **removing_members,
    size_t removing_members_num
);

/**
 * @brief Copy member info to group member.
 * @param member_info
 * @return
 */
E2ees__GroupMember *member_info_to_group_member(E2ees__GroupMemberInfo *member_info);

/**
 *  * @brief Collect unique user ID from member_info_list then convert and collect it into member_list
 * @param dest
 * @param member_info_list
 * @param member_info_list_num
 * @param member_list
 * @param member_list_num
 * @return
 */
size_t member_info_to_group_members(
    E2ees__GroupMember ***dest,
    E2ees__GroupMemberInfo **member_info_list,
    size_t member_info_list_num,
    E2ees__GroupMember **member_list,
    size_t member_list_num
);

/**
 * @brief Release memory of E2ees__E2eeAddress array.
 *
 * @param dest
 * @param e2ee_addresses_num
 */
void free_e2ee_addresses(E2ees__E2eeAddress ***dest, size_t e2ee_addresses_num);

/**
 * @brief Release memory of E2ees__InviteResponse array.
 *
 * @param dest
 * @param invite_response_num
 */
void free_invite_response_list(E2ees__InviteResponse ***dest, size_t invite_response_num);

/**
 * @brief Release memory of E2ees__OneTimePreKey array.
 *
 */
void free_one_time_pre_key_list(E2ees__OneTimePreKey ***dest, uint32_t opks_num);

/**
 * @brief Release memory of E2ees__GroupMember array.
 *
 * @param dest
 * @param group_members_num
 */
void free_group_member_list(E2ees__GroupMember ***dest, size_t group_members_num);

/**
 * @brief Release memory of ProtobufCBinaryData.
 *
 * @param output
 */
void free_protobuf(ProtobufCBinaryData *output);

/**
 * @brief Release memory of ProtobufCBinaryData list.
 *
 * @param output
 * @param protobuf_num
 */
void free_protobuf_list(ProtobufCBinaryData **output, size_t protobuf_num);

/**
 * @brief Release a memory block.
 *
 * @param buffer
 * @param buffer_len
 */
void free_mem(void **buffer, size_t buffer_len);

/**
 * Clear the memory held in the buffer.
 * This is more resilient to being optimised away than memset or bzero.
 */
void unset(void volatile *buffer, size_t buffer_len);

void secure_unset(void *buffer, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MEM_UTIL_H_ */
