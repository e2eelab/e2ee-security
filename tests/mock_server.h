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
#ifndef MOCK_SERVER_H_
#define MOCK_SERVER_H_

#include "e2ees/e2ees.h"

void mock_server_begin();

/**
 * @brief Close the mock server
 * 
 */
void mock_server_end();

/**
 * @brief 
 * 
 * @param request 
 * @return E2ees__RegisterUserResponse* 
 */
E2ees__RegisterUserResponse *mock_register_user(E2ees__RegisterUserRequest *request);

/**
 * @brief Get the pre-key bundle object
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__GetPreKeyBundleResponse* 
 */
E2ees__GetPreKeyBundleResponse *mock_get_pre_key_bundle(E2ees__E2eeAddress *from, const char *auth, E2ees__GetPreKeyBundleRequest *request);

/**
 * @brief 
 * 
 * @param request 
 * @return E2ees__InviteResponse* 
 */
E2ees__InviteResponse *mock_invite(E2ees__E2eeAddress *from, const char *auth, E2ees__InviteRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__AcceptResponse* 
 */
E2ees__AcceptResponse *mock_accept(E2ees__E2eeAddress *from, const char *auth, E2ees__AcceptRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__PublishSpkResponse* 
 */
E2ees__PublishSpkResponse *mock_publish_spk(E2ees__E2eeAddress *from, const char *auth, E2ees__PublishSpkRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__SupplyOpksResponse* 
 */
E2ees__SupplyOpksResponse *mock_supply_opks(E2ees__E2eeAddress *from, const char *auth, E2ees__SupplyOpksRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__SendOne2oneMsgResponse* 
 */
E2ees__SendOne2oneMsgResponse *mock_send_one2one_msg(E2ees__E2eeAddress *from, const char *auth, E2ees__SendOne2oneMsgRequest *request);

/**
 * @brief Create a group object
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__CreateGroupResponse* 
 */
E2ees__CreateGroupResponse *mock_create_group(E2ees__E2eeAddress *from, const char *auth, E2ees__CreateGroupRequest *request);

/**
 * @brief Renew a group
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__RenewGroupResponse* 
 */
E2ees__RenewGroupResponse *mock_renew_group(E2ees__E2eeAddress *from, const char *auth, E2ees__RenewGroupRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__AddGroupMembersResponse* 
 */
E2ees__AddGroupMembersResponse *mock_add_group_members(E2ees__E2eeAddress *from, const char *auth, E2ees__AddGroupMembersRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__AddGroupMemberDeviceResponse* 
 */
E2ees__AddGroupMemberDeviceResponse *mock_add_group_member_device(
    E2ees__E2eeAddress *from, const char *auth, E2ees__AddGroupMemberDeviceRequest *request
);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__RemoveGroupMembersResponse* 
 */
E2ees__RemoveGroupMembersResponse *mock_remove_group_members(E2ees__E2eeAddress *from, const char *auth, E2ees__RemoveGroupMembersRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__LeaveGroupResponse* 
 */
E2ees__LeaveGroupResponse *mock_leave_group(E2ees__E2eeAddress *from, const char *auth, E2ees__LeaveGroupRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__SendGroupMsgResponse* 
 */
E2ees__SendGroupMsgResponse *mock_send_group_msg(E2ees__E2eeAddress *from, const char *auth, E2ees__SendGroupMsgRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return E2ees__ConsumeProtoMsgResponse* 
 */
E2ees__ConsumeProtoMsgResponse *mock_consume_proto_msg(E2ees__E2eeAddress *from, const char *auth, E2ees__ConsumeProtoMsgRequest *request);

#endif /* MOCK_SERVER_H_ */
