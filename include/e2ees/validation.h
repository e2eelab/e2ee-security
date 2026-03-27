#ifndef VALIDATION_H_
#define VALIDATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"
#include "e2ees/e2ees_client_internal.h"

bool accurate_key_pair(E2ees__KeyPair *key_pair, uint32_t pub_key_len, uint32_t priv_key_len);

bool is_valid_cipher_suite(const cipher_suite_t *cipher_suite);

bool is_valid_e2ees_pack_id(uint32_t e2ees_pack_id);

bool is_valid_protobuf(const ProtobufCBinaryData *src);

bool is_valid_protobuf_list(ProtobufCBinaryData *src, size_t len);

bool is_valid_string(const char *src);

bool is_valid_optional_string(const char *src);

bool is_invalid_string(const char *src);

bool is_valid_string_list(char **src, size_t len);

bool is_valid_address(E2ees__E2eeAddress *src);

bool is_valid_no_device_id_user_address(E2ees__E2eeAddress *src);

bool is_invalid_address(E2ees__E2eeAddress *src);

bool is_valid_address_list(E2ees__E2eeAddress **src, size_t len);

bool is_valid_no_device_id_user_address_list(E2ees__E2eeAddress **src, size_t len);

bool is_valid_key_pair(const E2ees__KeyPair *src);

bool is_valid_identity_key(E2ees__IdentityKey *src);

bool is_valid_signed_pre_key(E2ees__SignedPreKey *src);

bool is_valid_one_time_pre_key(E2ees__OneTimePreKey *src);

bool is_valid_one_time_pre_key_list(E2ees__OneTimePreKey **src, size_t len);

bool is_valid_unregistered_account(E2ees__Account *src);

bool is_valid_registered_account(E2ees__Account *src);

bool is_valid_msg_key(const E2ees__MsgKey *msg_key);

bool is_valid_chain_key(const E2ees__ChainKey *chain_key);

bool is_valid_sender_chain(E2ees__SenderChainNode *sender_chain);

bool is_valid_receiver_chain(E2ees__ReceiverChainNode *receiver_chain);

bool is_valid_skipped_msg_key_node(E2ees__SkippedMsgKeyNode *skipped_msg_key_node);

bool is_valid_skipped_msg_key_list(
    E2ees__SkippedMsgKeyNode **skipped_msg_key_list, size_t skipped_msg_key_list_len);

bool is_valid_ratchet(const E2ees__Ratchet *ratchet);

bool is_valid_uncompleted_session(E2ees__Session *src);

bool is_valid_completed_session(E2ees__Session *src);

bool is_valid_inbound_session(E2ees__Session *src);

bool is_valid_identity_key_public(E2ees__IdentityKeyPublic *src);

bool is_valid_signed_pre_key_public(E2ees__SignedPreKeyPublic *src);

bool is_valid_one_time_pre_key_public(E2ees__OneTimePreKeyPublic *src);

bool is_valid_one_time_pre_key_public_list(E2ees__OneTimePreKeyPublic **src, size_t len);

bool is_valid_pre_key_bundle(E2ees__PreKeyBundle *src);

bool is_valid_pre_key_bundle_list(E2ees__PreKeyBundle **src, size_t len);

bool is_valid_one2one_msg_payload(const E2ees__One2oneMsgPayload *payload);

bool is_valid_group_member(E2ees__GroupMember *src);

bool is_valid_group_member_list(E2ees__GroupMember **src, size_t len);

bool is_valid_group_info(const E2ees__GroupInfo *src);

bool is_valid_group_info_list(const E2ees__GroupInfo **src, size_t len);

bool is_valid_group_member_info(const E2ees__GroupMemberInfo *src);

bool is_valid_group_member_info_list(const E2ees__GroupMemberInfo **src, size_t len);

bool is_valid_group_session_by_member_id(E2ees__GroupSession *src);

bool is_valid_group_session_by_pre_key_bundle(E2ees__GroupSession *src);

bool is_valid_group_session(E2ees__GroupSession *src);

bool is_valid_group_session_no_chain_key(E2ees__GroupSession *src);

bool is_valid_group_update_key_bundle(E2ees__GroupUpdateKeyBundle *src);

bool is_valid_group_pre_key_bundle(E2ees__GroupPreKeyBundle *src);

bool is_valid_group_msg_payload(const E2ees__GroupMsgPayload *payload);

bool is_valid_register_user_response(E2ees__RegisterUserResponse *src);

bool is_valid_publish_spk_response(E2ees__PublishSpkResponse *src);

bool is_valid_supply_opks_response(E2ees__SupplyOpksResponse *src);

bool is_valid_get_pre_key_bundle_response(E2ees__GetPreKeyBundleResponse *src);

bool is_valid_invite_response(E2ees__InviteResponse *src);

bool is_valid_accept_response(E2ees__AcceptResponse *src);

bool is_valid_create_group_response(E2ees__CreateGroupResponse *src);

bool is_valid_add_group_members_response(E2ees__AddGroupMembersResponse *src);

bool is_valid_add_group_member_device_response(E2ees__AddGroupMemberDeviceResponse *src);

bool is_valid_remove_group_members_response(E2ees__RemoveGroupMembersResponse *src);

bool is_valid_leave_group_response(E2ees__LeaveGroupResponse *src);

bool is_valid_send_group_msg_response(E2ees__SendGroupMsgResponse *src);

bool is_valid_supply_opks_msg(E2ees__SupplyOpksMsg *src);

bool is_valid_add_user_device_msg(E2ees__AddUserDeviceMsg *src);

bool is_valid_remove_user_device_msg(E2ees__RemoveUserDeviceMsg *src);

bool is_valid_invite_msg(E2ees__InviteMsg *src);

bool is_valid_accept_msg(E2ees__AcceptMsg *src);

bool is_valid_e2ee_msg(E2ees__E2eeMsg *src);

bool is_valid_create_group_msg(E2ees__CreateGroupMsg *src);

bool is_valid_add_group_members_msg(E2ees__AddGroupMembersMsg *src);

bool is_valid_add_group_member_device_msg(E2ees__AddGroupMemberDeviceMsg *src);

bool is_valid_remove_group_members_msg(E2ees__RemoveGroupMembersMsg *src);

bool is_valid_leave_group_msg(E2ees__LeaveGroupMsg *src);

bool is_valid_proto_msg(E2ees__ProtoMsg *src);

bool is_valid_subject(E2ees__Subject *src);

bool is_valid_cert(E2ees__Cert *src);

bool is_valid_certificate(E2ees__Certificate *src);

bool is_valid_server_signed_signature(E2ees__ServerSignedSignature *src);

bool is_valid_server_signed_signature_list(E2ees__ServerSignedSignature **src, size_t len);

bool is_valid_register_user_inputs(const register_user_params_t *params);

bool is_valid_publish_spk_inputs(const publish_spk_params_t *params);

bool is_valid_supply_opks_inputs(const supply_opks_params_t *params);

bool is_valid_get_pre_key_bundle_inputs(const get_pre_key_bundle_params_t *params);

bool is_valid_accept_inputs(const accept_params_t *params);

bool is_valid_create_group_inputs(const create_group_params_t *params);

bool is_valid_add_group_members_inputs(const add_group_members_params_t *params);

bool is_valid_remove_group_members_inputs(const remove_group_members_params_t *params);

bool is_valid_add_group_member_device_inputs(const add_group_member_device_params_t *params);

bool is_valid_leave_group_inputs(const leave_group_params_t *params);

bool is_valid_send_group_msg_inputs(const send_group_msg_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* VALIDATION_H_ */
