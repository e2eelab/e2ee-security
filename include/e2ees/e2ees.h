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
#ifndef E2EES_H_
#define E2EES_H_

#include <stdint.h>
#include <stdlib.h>

#include "e2ees/AcceptMsg.pb-c.h"
#include "e2ees/AcceptRequest.pb-c.h"
#include "e2ees/AcceptResponse.pb-c.h"
#include "e2ees/Account.pb-c.h"
#include "e2ees/AddGroupMemberDeviceMsg.pb-c.h"
#include "e2ees/AddGroupMemberDeviceRequest.pb-c.h"
#include "e2ees/AddGroupMemberDeviceResponse.pb-c.h"
#include "e2ees/AddGroupMembersMsg.pb-c.h"
#include "e2ees/AddGroupMembersRequest.pb-c.h"
#include "e2ees/AddGroupMembersResponse.pb-c.h"
#include "e2ees/AddUserDeviceMsg.pb-c.h"
#include "e2ees/ChainKey.pb-c.h"
#include "e2ees/ConsumeProtoMsgRequest.pb-c.h"
#include "e2ees/ConsumeProtoMsgResponse.pb-c.h"
#include "e2ees/CreateGroupMsg.pb-c.h"
#include "e2ees/CreateGroupRequest.pb-c.h"
#include "e2ees/CreateGroupResponse.pb-c.h"
#include "e2ees/E2eeAddress.pb-c.h"
#include "e2ees/E2eeMsg.pb-c.h"
#include "e2ees/GetGroupRequest.pb-c.h"
#include "e2ees/GetGroupResponse.pb-c.h"
#include "e2ees/GetPreKeyBundleRequest.pb-c.h"
#include "e2ees/GetPreKeyBundleResponse.pb-c.h"
#include "e2ees/GroupMember.pb-c.h"
#include "e2ees/GroupMemberInfo.pb-c.h"
#include "e2ees/GroupMsgPayload.pb-c.h"
#include "e2ees/GroupPreKeyBundle.pb-c.h"
#include "e2ees/GroupUpdateKeyBundle.pb-c.h"
#include "e2ees/GroupSession.pb-c.h"
#include "e2ees/IdentityKey.pb-c.h"
#include "e2ees/IdentityKeyPublic.pb-c.h"
#include "e2ees/InviteMsg.pb-c.h"
#include "e2ees/InviteRequest.pb-c.h"
#include "e2ees/InviteResponse.pb-c.h"
#include "e2ees/KeyPair.pb-c.h"
#include "e2ees/LeaveGroupMsg.pb-c.h"
#include "e2ees/LeaveGroupRequest.pb-c.h"
#include "e2ees/LeaveGroupResponse.pb-c.h"
#include "e2ees/MsgKey.pb-c.h"
#include "e2ees/NotifLevel.pb-c.h"
#include "e2ees/One2oneMsgPayload.pb-c.h"
#include "e2ees/OneTimePreKey.pb-c.h"
#include "e2ees/OneTimePreKeyPublic.pb-c.h"
#include "e2ees/PendingRequest.pb-c.h"
#include "e2ees/Plaintext.pb-c.h"
#include "e2ees/PreKeyBundle.pb-c.h"
#include "e2ees/ProtoMsg.pb-c.h"
#include "e2ees/ProtoMsgTag.pb-c.h"
#include "e2ees/PublishSpkRequest.pb-c.h"
#include "e2ees/PublishSpkResponse.pb-c.h"
#include "e2ees/Ratchet.pb-c.h"
#include "e2ees/ReceiverChainNode.pb-c.h"
#include "e2ees/RegisterUserRequest.pb-c.h"
#include "e2ees/RegisterUserResponse.pb-c.h"
#include "e2ees/RemoveGroupMembersMsg.pb-c.h"
#include "e2ees/RemoveGroupMembersRequest.pb-c.h"
#include "e2ees/RemoveGroupMembersResponse.pb-c.h"
#include "e2ees/RemoveUserDeviceMsg.pb-c.h"
#include "e2ees/ResponseCode.pb-c.h"
#include "e2ees/SendGroupMsgRequest.pb-c.h"
#include "e2ees/SendGroupMsgResponse.pb-c.h"
#include "e2ees/SendOne2oneMsgRequest.pb-c.h"
#include "e2ees/SendOne2oneMsgResponse.pb-c.h"
#include "e2ees/SenderChainNode.pb-c.h"
#include "e2ees/Session.pb-c.h"
#include "e2ees/SignedPreKey.pb-c.h"
#include "e2ees/SignedPreKeyPublic.pb-c.h"
#include "e2ees/SkippedMsgKeyNode.pb-c.h"
#include "e2ees/SupplyOpksMsg.pb-c.h"
#include "e2ees/SupplyOpksRequest.pb-c.h"
#include "e2ees/SupplyOpksResponse.pb-c.h"
#include "e2ees/UserDevicesBundle.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/cipher.h"
#include "e2ees/session.h"
#include "e2ees/log_code.h"

#define E2EES_PROTOCOL_VERSION                                "\001"
#define E2EES_PLAINTEXT_VERSION                               "\001"

#define E2EES_RESULT_SUCC                                     0
#define E2EES_RESULT_FAIL                                     -1

#define E2EES_UUID_LEN                                        16
#define E2EES_SIGNED_PRE_KEY_EXPIRATION_MS                    604800000 // 7 days
#define E2EES_ONE_TIME_PRE_KEY_INITIAL_NUM                    100
#define E2EES_INVITE_WAITING_TIME_MS                          60000     // 1 minute

#define E2EES_PACK_ALG_DS_CURVE25519                          0
#define E2EES_PACK_ALG_DS_MLDSA44                             1
#define E2EES_PACK_ALG_DS_MLDSA65                             9
#define E2EES_PACK_ALG_DS_MLDSA87                             17
#define E2EES_PACK_ALG_DS_FALCON512                           33
#define E2EES_PACK_ALG_DS_FALCON1024                          41
#define E2EES_PACK_ALG_DS_SPHINCS_SHA2_128F                   65
#define E2EES_PACK_ALG_DS_SPHINCS_SHA2_128S                   69
#define E2EES_PACK_ALG_DS_SPHINCS_SHA2_192F                   73
#define E2EES_PACK_ALG_DS_SPHINCS_SHA2_192S                   77
#define E2EES_PACK_ALG_DS_SPHINCS_SHA2_256F                   81
#define E2EES_PACK_ALG_DS_SPHINCS_SHA2_256S                   85
#define E2EES_PACK_ALG_DS_SPHINCS_SHAKE_128F                  89
#define E2EES_PACK_ALG_DS_SPHINCS_SHAKE_128S                  93
#define E2EES_PACK_ALG_DS_SPHINCS_SHAKE_192F                  97
#define E2EES_PACK_ALG_DS_SPHINCS_SHAKE_192S                  101
#define E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256F                  105
#define E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256S                  109

#define E2EES_PACK_ALG_KEM_CURVE25519                         0
#define E2EES_PACK_ALG_KEM_HQC128                             1
#define E2EES_PACK_ALG_KEM_HQC192                             9
#define E2EES_PACK_ALG_KEM_HQC256                             17
#define E2EES_PACK_ALG_KEM_MLKEM512                           33
#define E2EES_PACK_ALG_KEM_MLKEM768                           41
#define E2EES_PACK_ALG_KEM_MLKEM1024                          49
#define E2EES_PACK_ALG_KEM_MCELIECE348864                     65
#define E2EES_PACK_ALG_KEM_MCELIECE348864F                    69
#define E2EES_PACK_ALG_KEM_MCELIECE460896                     73
#define E2EES_PACK_ALG_KEM_MCELIECE460896F                    77
#define E2EES_PACK_ALG_KEM_MCELIECE6688128                    81
#define E2EES_PACK_ALG_KEM_MCELIECE6688128F                   85
#define E2EES_PACK_ALG_KEM_MCELIECE6960119                    89
#define E2EES_PACK_ALG_KEM_MCELIECE6960119F                   93
#define E2EES_PACK_ALG_KEM_MCELIECE8192128                    97
#define E2EES_PACK_ALG_KEM_MCELIECE8192128F                   101

#define E2EES_PACK_ALG_SE_AES256GCM                           0

#define E2EES_PACK_ALG_HASH_SHA2_224                          0
#define E2EES_PACK_ALG_HASH_SHA2_256                          1
#define E2EES_PACK_ALG_HASH_SHA2_384                          2
#define E2EES_PACK_ALG_HASH_SHA2_512                          3
#define E2EES_PACK_ALG_HASH_SHA3_224                          8
#define E2EES_PACK_ALG_HASH_SHA3_256                          9
#define E2EES_PACK_ALG_HASH_SHA3_384                          10
#define E2EES_PACK_ALG_HASH_SHA3_512                          11
#define E2EES_PACK_ALG_HASH_SHAKE_128                         12
#define E2EES_PACK_ALG_HASH_SHAKE_256                         13

#define E2EES_PACK_ID_UNSPECIFIED                             0
#define E2EES_PACK_ID_V_0_DEFAULT                             0x113101

#define E2EES_CIPHER_SUITE_PART_LEN_IN_BITS                   8
#define E2EES_CIPHER_SUITE_PART_HALF_LEN_IN_BITS              4

// forward declaration
typedef struct crypto_ds_param_t crypto_ds_param_t;
typedef struct crypto_kem_param_t crypto_kem_param_t;
typedef struct crypto_se_param_t crypto_se_param_t;
typedef struct crypto_hf_param_t crypto_hf_param_t;
typedef struct ds_suite_t ds_suite_t;
typedef struct kem_suite_t kem_suite_t;
typedef struct se_suite_t se_suite_t;
typedef struct hf_suite_t hf_suite_t;
typedef struct cipher_suite_t cipher_suite_t;

/**
 * @brief Type definition of E2EE Security pack id.
 */
typedef struct e2ees_pack_id_t {
    unsigned ver:E2EES_CIPHER_SUITE_PART_LEN_IN_BITS;          // version
    unsigned ds:E2EES_CIPHER_SUITE_PART_LEN_IN_BITS;           // digital signature algorithm
    unsigned kem:E2EES_CIPHER_SUITE_PART_LEN_IN_BITS;          // key encapsulation mechanism algorithm
    unsigned se:E2EES_CIPHER_SUITE_PART_HALF_LEN_IN_BITS;      // symmetric encryption algorithm
    unsigned hash:E2EES_CIPHER_SUITE_PART_HALF_LEN_IN_BITS;    // hash function algorithm
} e2ees_pack_id_t;

/**
 * @brief Type definition of E2EE Security pack.
 *        An e2ees_pack_t consists of cipher suite and session suite.
 */
typedef struct e2ees_pack_t {
    struct cipher_suite_t *cipher_suite;
    struct session_suite_t *session_suite;
} e2ees_pack_t;

/**
 * @brief Type definition of common handler.
 */
typedef struct e2ees_common_handler_t {
    /**
     * @brief generate time stamp
     * @return current timestamp in milliseconds since 1970
     */
    int64_t (*gen_ts)();

    /**
     * @brief generate random number
     * @param rand_data pre-allocated memory to be filled with random data
     * @param rand_data_len length of random data
     */
    void (*gen_rand)(uint8_t *rand_data, size_t rand_data_len);
    void (*gen_uuid)(uint8_t uuid[E2EES_UUID_LEN]);
} e2ees_common_handler_t;

/**
 * @brief Type definition of database handler.
 */
typedef struct e2ees_db_handler_t {
    // account related handlers
    /**
     * @brief store account to db
     * @param account
     */
    void (*store_account)(
        E2ees__Account *account
    );
    /**
     * @brief load account from db by giving user address
     * @param user_address
     * @param account
     */
    void (*load_account_by_address)(
        E2ees__E2eeAddress *user_address,
        E2ees__Account **account
    );
    /**
     * @brief load all accounts from db
     * @param accounts
     * @return number of loaded accounts
     */
    size_t (*load_accounts)(
        E2ees__Account ***accounts
    );
    /**
     * @brief update signed pre-key of account to db
     * @param user_address
     * @param signed_pre_key
     */
    bool (*update_signed_pre_key)(
        E2ees__E2eeAddress *user_address,
        E2ees__SignedPreKey *signed_pre_key
    );
    /**
     * @brief load old signed pre-key by spk_id
     * @param user_address
     * @param spk_id
     * @param signed_pre_key
     */
    void (*load_signed_pre_key)(
        E2ees__E2eeAddress *user_address,
        uint32_t spk_id,
        E2ees__SignedPreKey **signed_pre_key
    );
    /**
     * @brief remove expired signed pre-key (keep last two) of account from db
     * @param user_address
     */
    bool (*remove_expired_signed_pre_key)(
        E2ees__E2eeAddress *user_address
    );
    /**
     * @brief add an one time pre-key of account to db
     * @param user_address
     * @param one_time_pre_key
     */
    bool (*add_one_time_pre_key)(
        E2ees__E2eeAddress *user_address,
        E2ees__OneTimePreKey *one_time_pre_key
    );
    /**
     * @brief remove an one time pre-key of account to db
     * @param user_address
     * @param one_time_pre_key_id
     */
    bool (*remove_one_time_pre_key)(
        E2ees__E2eeAddress *user_address,
        uint32_t one_time_pre_key_id
    );
    /**
     * @brief update an one time pre-key of acount from db
     * @param user_address
     * @param one_time_pre_key_id
     */
    bool (*update_one_time_pre_key)(
        E2ees__E2eeAddress *user_address,
        uint32_t one_time_pre_key_id
    );
    /**
     * @brief load auth from the account given by the user address
     * @param user_address
     * @param auth
     */
    void (*load_auth)(
        E2ees__E2eeAddress *user_address,
        char **auth
    );
    // session related handlers
    /**
     * @brief find inbound session
     * @param session_id
     * @param our_address
     * @param inbound_session
     */
    void (*load_inbound_session)(
        char *session_id,
        E2ees__E2eeAddress *our_address,
        E2ees__Session **inbound_session
    );
    /**
     * @brief find the lastest outbound session
     * @param our_address
     * @param their_address
     * @param outbound_session
     */
    void (*load_outbound_session)(
        E2ees__E2eeAddress *our_address,
        E2ees__E2eeAddress *their_address,
        E2ees__Session **outbound_session
    );

    /**
     * @brief find the list of outbound sessions that are related to their_user_id and their_domain
     * @param our_address
     * @param their_user_id
     * @param their_domain
     * @param outbound_sessions
     */
    size_t (*load_outbound_sessions)(
        E2ees__E2eeAddress *our_address,
        const char *their_user_id,
        const char *their_domain,
        E2ees__Session ***outbound_sessions
    );

    /**
     * @brief store session
     * @param session
     */
    void (*store_session)(
        E2ees__Session *session
    );
    /**
     * @brief delete all sessions
     * @param our_address
     * @param their_address
     */
    void (*unload_session)(
        E2ees__E2eeAddress *our_address,
        E2ees__E2eeAddress *their_address
    );
    /**
     * @brief delete old sessions that are older than 1 day after invite_t 
     * @param our_address
     * @param their_address
     * @param invite_t
     */
    void (*unload_old_session)(
        E2ees__E2eeAddress *our_address,
        E2ees__E2eeAddress *their_address,
        int64_t invite_t
    );

    // group session related handlers
    /**
     * @brief find a group session by address
     * @param sender_address
     * @param session_owner_address
     * @param group_address
     * @param group_session
     */
    void (*load_group_session_by_address)(
        E2ees__E2eeAddress *sender_address,
        E2ees__E2eeAddress *session_owner_address,
        E2ees__E2eeAddress *group_address,
        E2ees__GroupSession **group_session
    );
    /**
     * @brief find a group session by id
     * @param sender_address
     * @param session_owner_address
     * @param group_session_id
     * @param group_session
     */
    void (*load_group_session_by_id)(
        E2ees__E2eeAddress *sender_address,
        E2ees__E2eeAddress *session_owner_address,
        char *group_session_id,
        E2ees__GroupSession **group_session
    );
    /**
     * @brief load group sessions
     * @param session_owner_address
     * @param group_address
     * @param group_sessions
     */
    size_t (*load_group_sessions)(
        E2ees__E2eeAddress *session_owner_address,
        E2ees__E2eeAddress *group_address,
        E2ees__GroupSession ***group_sessions
    );
    /**
     * @brief load group addresses
     * @param sender_address
     * @param session_owner_address
     * @param group_addresses
     */
    size_t (*load_group_addresses)(
        E2ees__E2eeAddress *sender_address,
        E2ees__E2eeAddress *session_owner_address,
        E2ees__E2eeAddress ***group_addresses
    );
    /**
     * @brief store group session
     * @param group_session
     */
    void (*store_group_session)(
        E2ees__GroupSession *group_session
    );
    /**
     * @brief delete group sessions by address
     * @param session_owner_address
     * @param group_address
     */
    void (*unload_group_session_by_address)(
        E2ees__E2eeAddress *session_owner_address,
        E2ees__E2eeAddress *group_address
    );
    /**
     * @brief delete group sessions by session id
     * @param session_owner_address
     * @param group_session_id
     */
    void (*unload_group_session_by_id)(
        E2ees__E2eeAddress *session_owner_address,
        char *group_session_id
    );

    // pending plaintext related handlers
    /**
     * @brief store pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id
     * @param plaintext_data
     * @param plaintext_data_len
     * @param notif_level
     */
    void (*store_pending_plaintext_data)(
        E2ees__E2eeAddress *from_address,
        E2ees__E2eeAddress *to_address,
        char *plaintext_id,
        uint8_t *plaintext_data,
        size_t plaintext_data_len,
        E2ees__NotifLevel notif_level
    );
    /**
     * @brief load pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id_list
     * @param plaintext_data_list
     * @param plaintext_data_len_list
     * @param notif_level_list
     * @return number of loaded plaintext_data list
     */
    size_t (*load_pending_plaintext_data)(
        E2ees__E2eeAddress *from_address,
        E2ees__E2eeAddress *to_address,
        char ***plaintext_id_list,
        uint8_t ***plaintext_data_list,
        size_t **plaintext_data_len_list,
        E2ees__NotifLevel **notif_level_list
    );
    /**
     * @brief delete pending plaintext data
     * @param from_address
     * @param to_address
     * @param plaintext_id
     */
    void (*unload_pending_plaintext_data)(
        E2ees__E2eeAddress *from_address,
        E2ees__E2eeAddress *to_address,
        char *plaintext_id
    );
    /**
     * @brief store pending request data
     * @param user_address
     * @param request_id
     * @param request_type
     * @param request_data
     * @param request_data_len
     */
    void (*store_pending_request_data)(
        E2ees__E2eeAddress *user_address,
        char *request_id,
        uint8_t request_type,
        uint8_t *request_data,
        size_t request_data_len
    );
    /**
     * @brief load pending request data
     * @param user_address
     * @param request_id_list
     * @param request_type_list
     * @param request_data_list
     * @param request_data_len_list
     * @return number of loaded request_data list
     */
    size_t (*load_pending_request_data)(
        E2ees__E2eeAddress * user_address,
        char ***request_id_list,
        uint8_t **request_type_list,
        uint8_t ***request_data_list,
        size_t **request_data_len_list
    );
    /**
     * @brief delete pending request data
     * @param user_address
     * @param request_id
     */
    void (*unload_pending_request_data)(
        E2ees__E2eeAddress *user_address,
        char *request_id
    );
} e2ees_db_handler_t;

/**
 * @brief Type definition of protocol handler.
 */
typedef struct e2ees_proto_handler_t {
    /**
     * @brief Register user
     * @param request
     * @return response
     */
    E2ees__RegisterUserResponse *(*register_user)(
        E2ees__RegisterUserRequest *request
    );
    /**
     * @brief Get pre-key bundle
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__GetPreKeyBundleResponse *(*get_pre_key_bundle)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__GetPreKeyBundleRequest *request
    );
    /**
     * @brief Invite
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__InviteResponse *(*invite)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__InviteRequest *request
    );
    /**
     * @brief Accept
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__AcceptResponse *(*accept)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__AcceptRequest *request
    );
    /**
     * @brief Publish signed pre-key
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__PublishSpkResponse *(*publish_spk)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__PublishSpkRequest *request
    );
    /**
     * @brief Supply onetime pre-key
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__SupplyOpksResponse *(*supply_opks)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__SupplyOpksRequest *request
    );
    /**
     * @brief Send one2one message
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__SendOne2oneMsgResponse *(*send_one2one_msg)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__SendOne2oneMsgRequest *request
    );
    /**
     * @brief Create group
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__CreateGroupResponse *(*create_group)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__CreateGroupRequest *request
    );
    /**
     * @brief Add group members
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__AddGroupMembersResponse *(*add_group_members)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__AddGroupMembersRequest *request
    );
    /**
     * @brief Add group member device
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__AddGroupMemberDeviceResponse *(*add_group_member_device)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__AddGroupMemberDeviceRequest *request
    );
    /**
     * @brief Remove group members
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__RemoveGroupMembersResponse *(*remove_group_members)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__RemoveGroupMembersRequest *request
    );
    /**
     * @brief Leave group
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__LeaveGroupResponse *(*leave_group)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__LeaveGroupRequest *request
    );
    /**
     * @brief Send group message
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__SendGroupMsgResponse *(*send_group_msg)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__SendGroupMsgRequest *request
    );
    /**
     * @brief Consume a ProtoMsg
     * @param from
     * @param auth
     * @param request
     * @return response
     */
    E2ees__ConsumeProtoMsgResponse *(*consume_proto_msg)(
        E2ees__E2eeAddress *from,
        const char *auth,
        E2ees__ConsumeProtoMsgRequest *request
    );
} e2ees_proto_handler_t;

typedef struct e2ees_event_handler_t {
    /**
     * @brief notify log msg
     * @param user_address
     * @param log_code
     * @param log_msg
     */
    void (*on_log)(
        E2ees__E2eeAddress *user_address,
        LogCode log_code,
        const char *log_msg
    );
    /**
     * @brief notify user registered event
     * @param account
     */
    void (*on_user_registered)(
        E2ees__Account *account
    );
    /**
     * @brief notify inbound session invited
     * @param user_address
     * @param from
     */
    void (*on_inbound_session_invited)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *from
    );
    /**
     * @brief notify inbound session ready
     * @param user_address
     * @param inbound_session
     */
    void (*on_inbound_session_ready)(
        E2ees__E2eeAddress *user_address,
        E2ees__Session *inbound_session
    );
    /**
     * @brief notify outbound session ready
     * @param user_address
     * @param outbound_session
     */
    void (*on_outbound_session_ready)(
        E2ees__E2eeAddress *user_address,
        E2ees__Session *outbound_session
    );
    /**
     * @brief notify one2one msg received event
     * @param user_address
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_one2one_msg_received)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *from_address,
        E2ees__E2eeAddress *to_address,
        uint8_t *plaintext,
        size_t plaintext_len
    );

    /**
     * @brief notify messages from other devices received event
     * @param user_address
     * @param from_address
     * @param to_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_other_device_msg_received)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *from_address,
        E2ees__E2eeAddress *to_address,
        uint8_t *plaintext,
        size_t plaintext_len
    );

    /**
     * @brief notify group msg received event
     * @param user_address
     * @param from_address
     * @param group_address
     * @param plaintext
     * @param plaintext_len
     */
    void (*on_group_msg_received)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *from_address,
        E2ees__E2eeAddress *group_address,
        uint8_t *plaintext,
        size_t plaintext_len
    );

    /**
     * @brief notify group created event
     * @param user_address
     * @param group_address
     * @param group_name
     * @param group_members
     * @param group_members_num
     */
    void (*on_group_created)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *group_address,
        const char *group_name,
        E2ees__GroupMember **group_members,
        size_t group_members_num
    );

    /**
     * @brief notify group members added
     * @param user_address
     * @param group_address
     * @param group_name
     * @param group_members
     * @param group_members_num
     * @param added_group_members
     * @param added_group_members_num
     */
    void (*on_group_members_added)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *group_address,
        const char *group_name,
        E2ees__GroupMember **group_members,
        size_t group_members_num,
        E2ees__GroupMember **added_group_members,
        size_t added_group_members_num
    );

    /**
     * @brief notify group members removed
     * @param user_address
     * @param group_address
     * @param group_name
     * @param group_members
     * @param group_members_num
     * @param removed_group_members
     * @param removed_group_members_num
     */
    void (*on_group_members_removed)(
        E2ees__E2eeAddress *user_address,
        E2ees__E2eeAddress *group_address,
        const char *group_name,
        E2ees__GroupMember **group_members,
        size_t group_members_num,
        E2ees__GroupMember **removed_group_members,
        size_t removed_group_members_num
    );
} e2ees_event_handler_t;

/**
 * @brief Type definition of E2EE Security plugin.
 */
typedef struct e2ees_plugin_t {
    e2ees_common_handler_t common_handler;
    e2ees_db_handler_t db_handler;
    e2ees_proto_handler_t proto_handler;
    e2ees_event_handler_t event_handler;
} e2ees_plugin_t;

/**
 * @brief Get digital signature suite by ID.
 *
 * @param digital_signature_id
 * @return
 */
ds_suite_t *get_ds_suite(unsigned digital_signature_id);

/**
 * @brief Get kem suite by ID.
 *
 * @param kem_id
 * @return
 */
kem_suite_t *get_kem_suite(unsigned kem_id);

/**
 * @brief Get symmetric encryption suite by ID.
 *
 * @param symmetric_encryption_id
 * @return
 */
se_suite_t *get_se_suite(unsigned symmetric_encryption_id);

/**
 * @brief Get hash function suite by ID.
 * @param hf_id
 * @return
 */
hf_suite_t *get_hf_suite(unsigned hf_id);

/**
 * @brief Generate the E2EE Security pack ID raw number.
 * @param ver Version
 * @param ds Digital signature algorithm
 * @param kem key encapsulation mechanism algorithm
 * @param se Symmetric encryption algorithm
 * @param hash hash function algorithm
 */
uint32_t gen_e2ees_pack_id_raw(
    unsigned ver, unsigned ds, unsigned kem, unsigned se, unsigned hash);

/**
 * @brief Get the E2EE Security pack by given e2ees_pack_id raw number.
 * @param e2ees_pack_id_raw
 */
e2ees_pack_t *get_e2ees_pack(uint32_t e2ees_pack_id_raw);

/**
 * @brief The begining function for starting E2EE Security.
 * @param plugin
 */
void e2ees_begin(e2ees_plugin_t *plugin);

/**
 * @brief The ending function for terminating E2EE Security.
 */
void e2ees_end();

/**
 * @brief Get the current plugin of E2EE Security.
 */
e2ees_plugin_t *get_e2ees_plugin();

/**
 * @brief Convert e2ees_pack_id_t to raw number.
 */
uint32_t e2ees_pack_id_to_raw(e2ees_pack_id_t e2ees_pack_id);

/**
 * @brief Convert raw number to e2ees_pack_id_t.
 */
e2ees_pack_id_t raw_to_e2ees_pack_id(uint32_t e2ees_pack_id_raw);

/**
 * @brief A delegate function to generate random bytes
 * 
 * @param rand_data 
 * @param rand_data_len 
 */
void e2ees_randombytes(uint8_t *rand_data, size_t rand_data_len);

/**
 * @brief Log function with additional arguments.
 * @param user_address
 * @param log_code
 * @param log_msg
 */
void e2ees_notify_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *log_msg, ...);

/**
 * @brief Event for notifying that user is registered.
 * @param account
 */
void e2ees_notify_user_registered(E2ees__Account *account);

/**
 * @brief Event for notifying that an inbound session is invited.
 * @param user_address
 * @param from
 */
void e2ees_notify_inbound_session_invited(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from);

/**
 * @brief Event for notifying that an inbound session is ready.
 * @param user_address
 * @param inbound_session
 */
void e2ees_notify_inbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *inbound_session);

/**
 * @brief Event for notifying that an outbound session is ready.
 * @param user_address
 * @param outbound_session
 */
void e2ees_notify_outbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *outbound_session);

/**
 * @brief Event for notifying that an one2one msg is received.
 * @param user_address
 * @param from_address
 * @param to_address
 * @param plaintext
 * @param plaintext_len
 */
void e2ees_notify_one2one_msg(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Event for notifying that a msg from user of other device is received.
 * @param user_address
 * @param from_address
 * @param to_address
 * @param plaintext
 * @param plaintext_len
 */
void e2ees_notify_other_device_msg(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Event for notifying that a group is received.
 * @param user_address
 * @param from_address
 * @param group_address
 * @param plaintext
 * @param plaintext_len
 */
void e2ees_notify_group_msg(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *group_address,
    uint8_t *plaintext, size_t plaintext_len
);

/**
 * @brief Event for notifying that a group is created.
 * @param user_address
 * @param group_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 */
void e2ees_notify_group_created(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num
);

/**
 * @brief Event for notifying that some group members are added.
 * @param user_address
 * @param group_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @param added_group_members
 * @param added_group_members_num
 */
void e2ees_notify_group_members_added(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **added_group_members, size_t added_group_members_num
);

/**
 * @brief Event for notifying that some group members are removed.
 * @param user_address
 * @param group_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @param removed_group_members
 * @param removed_group_members_num
 */
void e2ees_notify_group_members_removed(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **removed_group_members, size_t removed_group_members_num
);

#ifdef __cplusplus
}
#endif

#endif /* E2EES_H_ */
