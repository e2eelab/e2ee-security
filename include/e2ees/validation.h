#ifndef VALIDATION_H_
#define VALIDATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/**
 * @brief Check if the key pair is accurate based on expected lengths.
 * @param key_pair The key pair to check.
 * @param pub_key_len Expected public key length.
 * @param priv_key_len Expected private key length.
 * @return true if valid, false otherwise.
 */
bool accurate_key_pair(E2ees__KeyPair *key_pair, uint32_t pub_key_len, uint32_t priv_key_len);

/**
 * @brief Check if a cipher suite is valid.
 * @param cipher_suite The cipher suite to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_cipher_suite(const cipher_suite_t *cipher_suite);

/**
 * @brief Check if an E2EE pack ID is valid.
 * @param e2ees_pack_id The E2EE pack ID to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_e2ees_pack_id(uint32_t e2ees_pack_id);

/**
 * @brief Check if a ProtobufCBinaryData is valid.
 * @param src The binary data to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_protobuf(const ProtobufCBinaryData *src);

/**
 * @brief Check if a list of ProtobufCBinaryData is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_protobuf_list(ProtobufCBinaryData *src, size_t len);

/**
 * @brief Check if a string is valid (not NULL and not empty).
 * @param src The string to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_string(const char *src);

/**
 * @brief Check if a string is invalid (NULL or empty).
 * @param src The string to check.
 * @return true if invalid, false otherwise.
 */
bool is_invalid_string(const char *src);

/**
 * @brief Check if a list of strings is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_string_list(char **src, size_t len);

/**
 * @brief Check if an E2EE address is valid.
 * @param src The address to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_address(E2ees__E2eeAddress *src);

/**
 * @brief Check if an E2EE address is valid (ignores device ID).
 * @param src The address to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_no_device_id_user_address(E2ees__E2eeAddress *src);

/**
 * @brief Check if an E2EE address is invalid.
 * @param src The address to check.
 * @return true if invalid, false otherwise.
 */
bool is_invalid_address(E2ees__E2eeAddress *src);

/**
 * @brief Check if a list of E2EE addresses is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_address_list(E2ees__E2eeAddress **src, size_t len);

/**
 * @brief Check if a list of E2EE addresses is valid (ignores device ID).
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_no_device_id_user_address_list(E2ees__E2eeAddress **src, size_t len);

/**
 * @brief Check if a key pair is valid.
 * @param src The key pair to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_key_pair(const E2ees__KeyPair *src);

/**
 * @brief Check if an identity key is valid.
 * @param src The identity key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_identity_key(E2ees__IdentityKey *src);

/**
 * @brief Check if a signed pre-key is valid.
 * @param src The signed pre-key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_signed_pre_key(E2ees__SignedPreKey *src);

/**
 * @brief Check if a one-time pre-key is valid.
 * @param src The one-time pre-key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_one_time_pre_key(E2ees__OneTimePreKey *src);

/**
 * @brief Check if a list of one-time pre-keys is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_one_time_pre_key_list(E2ees__OneTimePreKey **src, size_t len);

/**
 * @brief Check if an unregistered account is valid.
 * @param src The account to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_unregistered_account(E2ees__Account *src);

/**
 * @brief Check if a registered account is valid.
 * @param src The account to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_registered_account(E2ees__Account *src);

/**
 * @brief Check if a message key is valid.
 * @param msg_key The message key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_msg_key(const E2ees__MsgKey *msg_key);

/**
 * @brief Check if a chain key is valid.
 * @param chain_key The chain key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_chain_key(const E2ees__ChainKey *chain_key);

/**
 * @brief Check if a sender chain node is valid.
 * @param sender_chain The node to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_sender_chain(E2ees__SenderChainNode *sender_chain);

/**
 * @brief Check if a receiver chain node is valid.
 * @param receiver_chain The node to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_receiver_chain(E2ees__ReceiverChainNode *receiver_chain);

/**
 * @brief Check if a skipped message key node is valid.
 * @param skipped_msg_key_node The node to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_skipped_msg_key_node(E2ees__SkippedMsgKeyNode *skipped_msg_key_node);

/**
 * @brief Check if a list of skipped message key nodes is valid.
 * @param skipped_msg_key_list The list to check.
 * @param skipped_msg_key_list_len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_skipped_msg_key_list(
    E2ees__SkippedMsgKeyNode **skipped_msg_key_list,
    size_t skipped_msg_key_list_len
);

/**
 * @brief Check if a ratchet is valid.
 * @param ratchet The ratchet to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_ratchet(const E2ees__Ratchet *ratchet);

/**
 * @brief Check if an uncompleted session is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_uncompleted_session(E2ees__Session *src);

/**
 * @brief Check if a completed session is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_completed_session(E2ees__Session *src);

/**
 * @brief Check if an inbound session is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_inbound_session(E2ees__Session *src);

/**
 * @brief Check if an identity key public is valid.
 * @param src The public key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_identity_key_public(E2ees__IdentityKeyPublic *src);

/**
 * @brief Check if a signed pre-key public is valid.
 * @param src The public key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_signed_pre_key_public(E2ees__SignedPreKeyPublic *src);

/**
 * @brief Check if a one-time pre-key public is valid.
 * @param src The public key to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_one_time_pre_key_public(E2ees__OneTimePreKeyPublic *src);

/**
 * @brief Check if a list of one-time pre-key publics is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_one_time_pre_key_public_list(E2ees__OneTimePreKeyPublic **src, size_t len);

/**
 * @brief Check if a pre-key bundle is valid.
 * @param src The bundle to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_pre_key_bundle(E2ees__PreKeyBundle *src);

/**
 * @brief Check if a list of pre-key bundles is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_pre_key_bundle_list(E2ees__PreKeyBundle **src, size_t len);

/**
 * @brief Check if a one-to-one message payload is valid.
 * @param payload The payload to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_one2one_msg_payload(const E2ees__One2oneMsgPayload *payload);

/**
 * @brief Check if a group member is valid.
 * @param src The member to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_member(E2ees__GroupMember *src);

/**
 * @brief Check if a list of group members is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_member_list(E2ees__GroupMember **src, size_t len);

/**
 * @brief Check if group info is valid.
 * @param src The info to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_info(const E2ees__GroupInfo *src);

/**
 * @brief Check if a list of group info is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_info_list(const E2ees__GroupInfo **src, size_t len);

/**
 * @brief Check if a group member info is valid.
 * @param src The info to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_member_info(const E2ees__GroupMemberInfo *src);

/**
 * @brief Check if a list of group member info is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_member_info_list(const E2ees__GroupMemberInfo **src, size_t len);

/**
 * @brief Check if a group session by member ID is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_session_by_member_id(E2ees__GroupSession *src);

/**
 * @brief Check if a group session by pre-key bundle is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_session_by_pre_key_bundle(E2ees__GroupSession *src);

/**
 * @brief Check if a group session is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_session(E2ees__GroupSession *src);

/**
 * @brief Check if a group session (without chain key) is valid.
 * @param src The session to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_session_no_chain_key(E2ees__GroupSession *src);

/**
 * @brief Check if a group update key bundle is valid.
 * @param src The bundle to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_update_key_bundle(E2ees__GroupUpdateKeyBundle *src);

/**
 * @brief Check if a group pre-key bundle is valid.
 * @param src The bundle to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_pre_key_bundle(E2ees__GroupPreKeyBundle *src);

/**
 * @brief Check if a group message payload is valid.
 * @param payload The payload to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_group_msg_payload(const E2ees__GroupMsgPayload *payload);

/**
 * @brief Check if a register user response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_register_user_response(E2ees__RegisterUserResponse *src);

/**
 * @brief Check if a publish spk response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_publish_spk_response(E2ees__PublishSpkResponse *src);

/**
 * @brief Check if a supply opks response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_supply_opks_response(E2ees__SupplyOpksResponse *src);

/**
 * @brief Check if a get pre-key bundle response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_get_pre_key_bundle_response(E2ees__GetPreKeyBundleResponse *src);

/**
 * @brief Check if an invite response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_invite_response(E2ees__InviteResponse *src);

/**
 * @brief Check if an accept response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_accept_response(E2ees__AcceptResponse *src);

/**
 * @brief Check if a create group response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_create_group_response(E2ees__CreateGroupResponse *src);

/**
 * @brief Check if an add group members response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_group_members_response(E2ees__AddGroupMembersResponse *src);

/**
 * @brief Check if an add group member device response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_group_member_device_response(E2ees__AddGroupMemberDeviceResponse *src);

/**
 * @brief Check if a remove group members response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_remove_group_members_response(E2ees__RemoveGroupMembersResponse *src);

/**
 * @brief Check if a leave group response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_leave_group_response(E2ees__LeaveGroupResponse *src);

/**
 * @brief Check if a send group message response is valid.
 * @param src The response to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_send_group_msg_response(E2ees__SendGroupMsgResponse *src);

/**
 * @brief Check if a supply opks message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_supply_opks_msg(E2ees__SupplyOpksMsg *src);

/**
 * @brief Check if an add user device message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_user_device_msg(E2ees__AddUserDeviceMsg *src);

/**
 * @brief Check if a remove user device message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_remove_user_device_msg(E2ees__RemoveUserDeviceMsg *src);

/**
 * @brief Check if an invite message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_invite_msg(E2ees__InviteMsg *src);

/**
 * @brief Check if an accept message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_accept_msg(E2ees__AcceptMsg *src);

/**
 * @brief Check if an E2EE message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_e2ee_msg(E2ees__E2eeMsg *src);

/**
 * @brief Check if a create group message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_create_group_msg(E2ees__CreateGroupMsg *src);

/**
 * @brief Check if an add group members message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_group_members_msg(E2ees__AddGroupMembersMsg *src);

/**
 * @brief Check if an add group member device message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_group_member_device_msg(E2ees__AddGroupMemberDeviceMsg *src);

/**
 * @brief Check if a remove group members message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_remove_group_members_msg(E2ees__RemoveGroupMembersMsg *src);

/**
 * @brief Check if a leave group message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_leave_group_msg(E2ees__LeaveGroupMsg *src);

/**
 * @brief Check if a generic proto message is valid.
 * @param src The message to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_proto_msg(E2ees__ProtoMsg *src);

/**
 * @brief Check if a subject is valid.
 * @param src The subject to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_subject(E2ees__Subject *src);

/**
 * @brief Check if a certificate structure is valid.
 * @param src The cert to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_cert(E2ees__Cert *src);

/**
 * @brief Check if a full certificate is valid.
 * @param src The certificate to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_certificate(E2ees__Certificate *src);

/**
 * @brief Check if a server signed signature is valid.
 * @param src The signature to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_server_signed_signature(E2ees__ServerSignedSignature *src);

/**
 * @brief Check if a list of server signed signatures is valid.
 * @param src The list to check.
 * @param len The length of the list.
 * @return true if valid, false otherwise.
 */
bool is_valid_server_signed_signature_list(E2ees__ServerSignedSignature **src, size_t len);

/**
 * @brief Validate register user parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_register_user_inputs(const register_user_params *params);

/**
 * @brief Validate publish spk parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_publish_spk_inputs(const publish_spk_params *params);

/**
 * @brief Validate supply opks parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_supply_opks_inputs(const supply_opks_params *params);

/**
 * @brief Validate get pre-key bundle parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_get_pre_key_bundle_inputs(const get_pre_key_bundle_params *params);

/**
 * @brief Validate accept parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_accept_inputs(const accept_params *params);

/**
 * @brief Validate create group parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_create_group_inputs(const create_group_params *params);

/**
 * @brief Validate add group members parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_group_members_inputs(const add_group_members_params *params);

/**
 * @brief Validate remove group members parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_remove_group_members_inputs(const remove_group_members_params *params);

/**
 * @brief Validate add group member device parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_add_group_member_device_inputs(const add_group_member_device_params *params);

/**
 * @brief Validate leave group parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_leave_group_inputs(const leave_group_params *params);

/**
 * @brief Validate send group message parameters.
 * @param params The parameters to check.
 * @return true if valid, false otherwise.
 */
bool is_valid_send_group_msg_inputs(const send_group_msg_params *params);

#ifdef __cplusplus
}
#endif

#endif /* VALIDATION_H_ */
