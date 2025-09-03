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
#ifndef TEST_UTIL_H_
#define TEST_UTIL_H_

#include "e2ees/e2ees.h"

#define E2EELAB_DOMAIN          "e2eelab.org"

#define gen_e2ees_pack_id_ecc() \
    gen_e2ees_pack_id_raw( \
        E2EES_PACK_ID_V_0, \
        E2EES_PACK_ALG_DS_CURVE25519, \
        E2EES_PACK_ALG_KEM_CURVE25519, \
        E2EES_PACK_ALG_SE_AES256GCM, \
        E2EES_PACK_ALG_HASH_SHA2_256 \
    )

#define gen_e2ees_pack_id_pqc() \
    gen_e2ees_pack_id_raw( \
        E2EES_PACK_ID_V_0, \
        E2EES_PACK_ALG_DS_MLDSA87, \
        E2EES_PACK_ALG_KEM_MLKEM1024, \
        E2EES_PACK_ALG_SE_AES256GCM, \
        E2EES_PACK_ALG_HASH_SHA2_256 \
    )

#define malloc_group_members(number) \
    group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * number ); \
    group_members[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember)); \
    e2ees__group_member__init(group_members[0]); \
    group_members[0]->user_id = strdup(user_id_list[0]); \
    group_members[0]->domain = strdup(domain_list[0]); \
    group_members[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER; \
    for (i = 1; i < number ; i++) { \
        group_members[i] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember)); \
        e2ees__group_member__init(group_members[i]); \
        group_members[i]->user_id = strdup(user_id_list[i]); \
        group_members[i]->domain = strdup(domain_list[i]); \
        group_members[i]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER; \
    }

#define malloc_new_group_members(number) \
    new_group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * number ); \
    for (i = 0; i < number ; i++) { \
        new_group_members[i] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember)); \
        e2ees__group_member__init(new_group_members[i]); \
        new_group_members[i]->user_id = strdup(new_user_id_list[i]); \
        new_group_members[i]->domain = strdup(new_domain_list[i]); \
        new_group_members[i]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER; \
    }

#define malloc_removing_group_members(number) \
    removing_group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * number ); \
    for (i = 0; i < number ; i++) { \
        removing_group_members[i] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember)); \
        e2ees__group_member__init(removing_group_members[i]); \
        removing_group_members[i]->user_id = strdup(removing_user_id_list[i]); \
        removing_group_members[i]->domain = strdup(removing_domain_list[i]); \
        removing_group_members[i]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER; \
    }

// debug msg to console
void print_hex(char *title, uint8_t *msg, size_t msg_len);
void print_msg(char *title, uint8_t *msg, size_t len);
void print_log(char *log_msg, int log_code);
void print_result(char *title, bool success);

bool is_null(void *pointer_1, void *pointer_2);
bool is_not_null(void *pointer_1, void *pointer_2);

// is_equal
bool is_equal_data(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2);
bool is_equal_str(char *str1, char *str2);
bool is_equal_keypair(E2ees__KeyPair *src_1, E2ees__KeyPair *src_2);
bool is_equal_ik(E2ees__IdentityKey *src_1, E2ees__IdentityKey *src_2);
bool is_equal_spk(E2ees__SignedPreKey *src_1, E2ees__SignedPreKey *src_2);
bool is_equal_opk(E2ees__OneTimePreKey *src_1, E2ees__OneTimePreKey *src_2);
bool is_equal_opk_list(E2ees__OneTimePreKey **src_1, E2ees__OneTimePreKey **src_2, size_t len);
bool is_equal_account(E2ees__Account *src_1, E2ees__Account *src_2);
bool is_equal_message_key(E2ees__MsgKey *msg_key_1, E2ees__MsgKey *msg_key_2);
bool is_equal_chain(E2ees__ChainKey *chain_key_1, E2ees__ChainKey *chain_key_2);
bool is_equal_sender_chain(E2ees__SenderChainNode *sender_chain_1, E2ees__SenderChainNode *sender_chain_2);
bool is_equal_receiver_chain(E2ees__ReceiverChainNode *receiver_chain_node_1, E2ees__ReceiverChainNode *receiver_chain_node_2);
bool is_equal_skipped_message_key(E2ees__SkippedMsgKeyNode *skipped_msg_key_node_1, E2ees__SkippedMsgKeyNode *skipped_msg_key_node_2);
bool is_equal_ratchet(E2ees__Ratchet *ratchet_1, E2ees__Ratchet *ratchet_2);
bool is_equal_session(E2ees__Session *session_1, E2ees__Session *session_2);
bool is_equal_sessions(E2ees__Session **sessions_1, E2ees__Session **sessions_2, size_t session_num);
bool is_equal_group_session(E2ees__GroupSession *group_session_1, E2ees__GroupSession *group_session_2);

// mock
void mock_data(ProtobufCBinaryData *to, const char *from);
void mock_string(char **to, const char *from);
char *mock_domain_str();
void mock_address(E2ees__E2eeAddress **address_pp, const char *user_id, const char *domain, const char *device_id);
void mock_random_group_address(E2ees__E2eeAddress **address);
void mock_random_user_address(E2ees__E2eeAddress **address);
void mock_keypair(E2ees__KeyPair **keypair);
void mock_identity_key(E2ees__IdentityKey **identity_keypair);
void mock_signed_pre_key(E2ees__SignedPreKey **signed_pre_keypair, uint32_t spk_id);
void mock_one_time_pre_key(E2ees__OneTimePreKey **one_time_pre_keypair, uint32_t opk_id);
void mock_one_time_pre_key_list(E2ees__OneTimePreKey ***one_time_pre_key_list);
void mock_account(E2ees__Account **account_out);

// hash
void pre_key_bundle_hash(
    uint8_t **out,
    size_t *out_len,
    E2ees__E2eeAddress *address,
    E2ees__IdentityKeyPublic *ik,
    E2ees__SignedPreKeyPublic *spk,
    E2ees__OneTimePreKeyPublic *opk
);

void proto_msg_hash(
    uint8_t **out,
    size_t *out_len,
    E2ees__ProtoMsgTag *tag,
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    E2ees__ProtoMsg__PayloadCase payload_case,
    void *payload
);

// free
void free_account(E2ees__Account *account);
void free_address(E2ees__E2eeAddress *address);

#endif /* TEST_UTIL_H_ */
