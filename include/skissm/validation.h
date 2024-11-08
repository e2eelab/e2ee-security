#ifndef VALIDATION_H_
#define VALIDATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

bool accurate_key_pair(Skissm__KeyPair *key_pair, uint32_t pub_key_len, uint32_t priv_key_len);

bool is_valid_cipher_suite(const cipher_suite_t *cipher_suite);

bool is_valid_e2ee_pack_id(uint32_t e2ee_pack_id);

bool is_valid_protobuf(const ProtobufCBinaryData *src);

bool is_valid_protobuf_list(ProtobufCBinaryData *src, size_t len);

bool is_valid_string(const char *src);

bool is_valid_string_list(char **src, size_t len);

bool is_valid_address(Skissm__E2eeAddress *src);

bool is_valid_address_list(Skissm__E2eeAddress **src, size_t len);

bool is_valid_key_pair(const Skissm__KeyPair *src);

bool is_valid_identity_key(Skissm__IdentityKey *src);

bool is_valid_signed_pre_key(Skissm__SignedPreKey *src);

bool is_valid_one_time_pre_key(Skissm__OneTimePreKey *src);

bool is_valid_one_time_pre_key_list(Skissm__OneTimePreKey **src, size_t len);

bool is_valid_unregistered_account(Skissm__Account *src);

bool is_valid_registered_account(Skissm__Account *src);

bool is_valid_msg_key(const Skissm__MsgKey *msg_key);

bool is_valid_chain_key(const Skissm__ChainKey *chain_key);

bool is_valid_sender_chain(Skissm__SenderChainNode *sender_chain);

bool is_valid_receiver_chain(Skissm__ReceiverChainNode *receiver_chain);

bool is_valid_skipped_msg_key_node(Skissm__SkippedMsgKeyNode *skipped_msg_key_node);

bool is_valid_skipped_msg_key_list(
    Skissm__SkippedMsgKeyNode **skipped_msg_key_list,
    size_t skipped_msg_key_list_len
);

bool is_valid_ratchet(const Skissm__Ratchet *ratchet);

bool is_valid_uncompleted_session(Skissm__Session *src);

bool is_valid_completed_session(Skissm__Session *src);

bool is_valid_identity_key_public(Skissm__IdentityKeyPublic *src);

bool is_valid_signed_pre_key_public(Skissm__SignedPreKeyPublic *src);

bool is_valid_one_time_pre_key_public(Skissm__OneTimePreKeyPublic *src);

bool is_valid_pre_key_bundle(Skissm__PreKeyBundle *src);

bool is_valid_pre_key_bundle_list(Skissm__PreKeyBundle **src, size_t len);

bool is_valid_one2one_msg_payload(const Skissm__One2oneMsgPayload *payload);

bool is_valid_group_member(Skissm__GroupMember *src);

bool is_valid_group_member_list(Skissm__GroupMember **src, size_t len);

bool is_valid_group_info(const Skissm__GroupInfo *src);

bool is_valid_group_info_list(const Skissm__GroupInfo **src, size_t len);

bool is_valid_group_member_info(const Skissm__GroupMemberInfo *src);

bool is_valid_group_member_info_list(const Skissm__GroupMemberInfo **src, size_t len);

bool is_valid_group_session_by_member_id(Skissm__GroupSession *src);

bool is_valid_group_session_by_pre_key_bundle(Skissm__GroupSession *src);

bool is_valid_group_session(Skissm__GroupSession *src);

bool is_valid_group_session_no_chain_key(Skissm__GroupSession *src);

bool is_valid_group_update_key_bundle(Skissm__GroupUpdateKeyBundle *src);

bool is_valid_group_pre_key_bundle(Skissm__GroupPreKeyBundle *src);

bool is_valid_group_msg_payload(const Skissm__GroupMsgPayload *payload);

bool is_valid_register_user_response(Skissm__RegisterUserResponse *src);

bool is_valid_publish_spk_response(Skissm__PublishSpkResponse *src);

bool is_valid_supply_opks_response(Skissm__SupplyOpksResponse *src);

bool is_valid_get_pre_key_bundle_response(Skissm__GetPreKeyBundleResponse *src);

bool is_valid_invite_response(Skissm__InviteResponse *src);

bool is_valid_accept_response(Skissm__AcceptResponse *src);

bool is_valid_create_group_response(Skissm__CreateGroupResponse *src);

bool is_valid_add_group_members_response(Skissm__AddGroupMembersResponse *src);

bool is_valid_add_group_member_device_response(Skissm__AddGroupMemberDeviceResponse *src);

bool is_valid_remove_group_members_response(Skissm__RemoveGroupMembersResponse *src);

bool is_valid_leave_group_response(Skissm__LeaveGroupResponse *src);

bool is_valid_send_group_msg_response(Skissm__SendGroupMsgResponse *src);

bool is_valid_supply_opks_msg(Skissm__SupplyOpksMsg *src);

bool is_valid_add_user_device_msg(Skissm__AddUserDeviceMsg *src);

bool is_valid_remove_user_device_msg(Skissm__RemoveUserDeviceMsg *src);

bool is_valid_invite_msg(Skissm__InviteMsg *src);

bool is_valid_accept_msg(Skissm__AcceptMsg *src);

bool is_valid_e2ee_msg(Skissm__E2eeMsg *src);

bool is_valid_create_group_msg(Skissm__CreateGroupMsg *src);

bool is_valid_add_group_members_msg(Skissm__AddGroupMembersMsg *src);

bool is_valid_add_group_member_device_msg(Skissm__AddGroupMemberDeviceMsg *src);

bool is_valid_remove_group_members_msg(Skissm__RemoveGroupMembersMsg *src);

bool is_valid_leave_group_msg(Skissm__LeaveGroupMsg *src);

bool is_valid_proto_msg(Skissm__ProtoMsg *src);

bool is_valid_subject(Skissm__Subject *src);

bool is_valid_cert(Skissm__Cert *src);

bool is_valid_certificate(Skissm__Certificate *src);

bool is_valid_server_signed_signature(Skissm__ServerSignedSignature *src);

bool is_valid_server_signed_signature_list(Skissm__ServerSignedSignature **src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VALIDATION_H_ */
