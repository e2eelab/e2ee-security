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
#include "e2ees/group_session_manager.h"

#include <string.h>

#include "e2ees/account_cache.h"
#include "e2ees/cipher.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/validation.h"
#include "e2ees/session.h"

int produce_create_group_request(
    E2ees__CreateGroupRequest **request_out,
    create_group_params *params,
    uint32_t e2ees_pack_id
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__CreateGroupRequest *request = NULL;
    E2ees__CreateGroupMsg *msg = NULL;

    request = (E2ees__CreateGroupRequest *)malloc(sizeof(E2ees__CreateGroupRequest));
    e2ees__create_group_request__init(request);

    msg = (E2ees__CreateGroupMsg *)malloc(sizeof(E2ees__CreateGroupMsg));
    e2ees__create_group_msg__init(msg);

    copy_address_from_address(&(msg->sender_address), params->sender_address);

    msg->e2ees_pack_id = e2ees_pack_id;

    msg->group_info = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = msg->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup(params->group_name);
    group_info->n_group_member_list = params->group_members_num;
    copy_group_members(&(group_info->group_member_list), params->group_members, params->group_members_num);

    request->msg = msg;

    if (ret == E2EES_RESULT_SUCC) {
        *request_out = request;
    }

    return ret;
}

int consume_create_group_response(
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *sender_address,
    const char *group_name,
    E2ees__GroupMember **group_member_list,
    size_t group_members_num,
    E2ees__CreateGroupResponse *response
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__E2eeAddress *group_address = NULL;

    if (!is_valid_e2ees_pack_id(e2ees_pack_id)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_address(sender_address)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_string(group_name)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_list(group_member_list, group_members_num)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_create_group_response(response)) {
        group_address = response->group_address;
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = new_outbound_group_session_by_sender(
            response->n_member_info_list, response->member_info_list,
            e2ees_pack_id, sender_address, group_name, group_address, group_member_list, group_members_num, NULL
        );
    }

    if (ret == E2EES_RESULT_SUCC) {
        // notify
        e2ees_notify_group_created(sender_address, group_address, group_name, group_member_list, group_members_num);
    } else {
        e2ees_notify_log(sender_address, DEBUG_LOG, "group creation failed");
    }

    // done
    return ret;
}

bool consume_create_group_msg(E2ees__E2eeAddress *receiver_address, E2ees__CreateGroupMsg *msg) {
    int ret = E2EES_RESULT_SUCC;

    uint32_t e2ees_pack_id;
    E2ees__GroupInfo *group_info = NULL;
    char *group_name = NULL;
    E2ees__E2eeAddress *sender_address = NULL;
    E2ees__E2eeAddress *group_address = NULL;
    size_t group_members_num = 0;
    E2ees__GroupMember **group_member_list = NULL;
    size_t i;
    E2ees__GroupSession *inbound_group_session = NULL;
    bool inbound_group_session_exist = true;
    E2ees__GroupMemberInfo *cur_group_member_info = NULL;

    if (is_valid_address(receiver_address)) {
        if (is_valid_create_group_msg(msg)) {
            e2ees_pack_id = msg->e2ees_pack_id;
            group_info = msg->group_info;
            group_name = group_info->group_name;
            sender_address = msg->sender_address;
            group_address = group_info->group_address;
            group_members_num = group_info->n_group_member_list;
            group_member_list = group_info->group_member_list;
        } else {
            e2ees_notify_log(NULL, BAD_CREATE_GROUP_MSG, "consume_create_group_msg() invalid create_group_msg");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_create_group_msg() invalid receiver_address");
        ret = E2EES_RESULT_FAIL;
    }

    // try to load inbound group session
    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(sender_address, receiver_address, group_address, &inbound_group_session);
        if (inbound_group_session != NULL) {
            inbound_group_session_exist = true;
            if (!is_valid_group_session_by_pre_key_bundle(inbound_group_session)) {
                e2ees_notify_log(NULL, BAD_GROUP_SESSION, "consume_create_group_msg() invalid inbound_group_session");
                ret = E2EES_RESULT_FAIL;
            }
        } else {
            inbound_group_session_exist = false;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        if (inbound_group_session_exist == false) {
            // there is no inbound group session, so create a new one
            for (i = 0; i < msg->n_member_info_list; i++) {
                cur_group_member_info = (msg->member_info_list)[i];
                if (!compare_address(cur_group_member_info->member_address, receiver_address)) {
                    ret = new_inbound_group_session_by_member_id(e2ees_pack_id, receiver_address, cur_group_member_info, group_info);
                    if (ret == E2EES_RESULT_FAIL) {
                        e2ees_notify_log(
                            receiver_address,
                            BAD_GROUP_SESSION,
                            "consume_create_group_msg() new_inbound_group_session_by_member_id failed with member_address: [%s:%s]",
                            cur_group_member_info->member_address->user->user_id,
                            cur_group_member_info->member_address->user->device_id
                        );
                    }
                }
            }
        } else {
            for (i = 0; i < msg->n_member_info_list; i++) {
                cur_group_member_info = (msg->member_info_list)[i];
                if (!compare_address(cur_group_member_info->member_address, sender_address)) {
                    if (!compare_address(cur_group_member_info->member_address, receiver_address)) {
                        // the senders in the inbound group sessions are the members in the group, except for the one who creates the group
                        ret = new_and_complete_inbound_group_session(cur_group_member_info, inbound_group_session);
                        if (ret == E2EES_RESULT_FAIL) {
                            e2ees_notify_log(
                                receiver_address,
                                DEBUG_LOG,
                                "consume_create_group_msg() new_and_complete_inbound_group_session failed with member_address: [%s:%s]",
                                cur_group_member_info->member_address->user->user_id,
                                cur_group_member_info->member_address->user->device_id
                            );
                        }
                    }
                } else {
                    // the sender in this inbound group session is the one who creates the group
                    ret = complete_inbound_group_session_by_member_id(inbound_group_session, cur_group_member_info);
                    if (ret == E2EES_RESULT_FAIL) {
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "consume_create_group_msg() complete_inbound_group_session_by_member_id failed with member_address: [%s:%s]",
                            cur_group_member_info->member_address->user->user_id,
                            cur_group_member_info->member_address->user->device_id
                        );
                    }
                }
            }

            // create a new outbound group session
            ret = new_outbound_group_session_by_receiver(
                &(inbound_group_session->group_seed),
                e2ees_pack_id,
                receiver_address,
                group_name,
                group_address,
                inbound_group_session->session_id,
                group_member_list,
                group_members_num
            );
            if (ret == E2EES_RESULT_FAIL) {
                e2ees_notify_log(
                    receiver_address,
                    DEBUG_LOG,
                    "consume_create_group_msg() new_outbound_group_session_by_receiver failed with session_owner and sender_address: [%s:%s]",
                    receiver_address->user->user_id,
                    receiver_address->user->device_id
                );
            }
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        // notify
        e2ees_notify_group_created(receiver_address, group_address, group_name, group_member_list, group_members_num);
    } else {
        e2ees_notify_log(NULL, DEBUG_LOG, "failed to consume create group msg");
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    // done
    return true;
}

bool consume_get_group_response(E2ees__GetGroupResponse *response) {
    if (response != NULL && response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
        char *group_name = response->group_name;
        size_t n_group_member_list = response->n_group_member_list;
        E2ees__GroupMember **group_member_list = response->group_member_list;

        // @TODO update group info, and notify
        return true;
    } else {
        return false;
    }
}

int produce_add_group_members_request(
    E2ees__AddGroupMembersRequest **request_out,
    add_group_members_params *params,
    E2ees__GroupSession *outbound_group_session
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__AddGroupMembersRequest *request = NULL;
    E2ees__AddGroupMembersMsg *msg = NULL;

    request = (E2ees__AddGroupMembersRequest *)malloc(sizeof(E2ees__AddGroupMembersRequest));
    e2ees__add_group_members_request__init(request);

    msg = (E2ees__AddGroupMembersMsg *)malloc(sizeof(E2ees__AddGroupMembersMsg));
    e2ees__add_group_members_msg__init(msg);

    msg->e2ees_pack_id = outbound_group_session->e2ees_pack_id;

    copy_address_from_address(&(msg->sender_address), params->sender_address);

    msg->sequence = outbound_group_session->sequence;

    msg->n_adding_member_list = params->adding_members_num;
    copy_group_members(&(msg->adding_member_list), params->adding_members, params->adding_members_num);
    add_group_members_to_group_info(&(msg->group_info), outbound_group_session->group_info, params->adding_members, params->adding_members_num);

    request->msg = msg;

    if (ret == E2EES_RESULT_SUCC) {
        *request_out = request;
    }

    return ret;
}

int consume_add_group_members_response(
    E2ees__GroupSession *outbound_group_session,
    E2ees__AddGroupMembersResponse *response,
    E2ees__GroupMember **added_members,
    size_t added_members_num
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupMember **new_group_members = NULL;
    size_t new_group_members_num = 0;
    E2ees__E2eeAddress *session_owner = NULL;
    char *group_name = NULL;
    E2ees__E2eeAddress *group_address = NULL;

    if (is_valid_group_session(outbound_group_session)) {
        session_owner = outbound_group_session->session_owner;
    } else {
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_add_group_members_response(response)) {
        new_group_members = response->group_member_list;
        new_group_members_num = response->n_group_member_list;
    } else {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_group_member_list(added_members, added_members_num)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // renew the outbound group session
        ret = renew_outbound_group_session_by_welcome_and_add(
            outbound_group_session, NULL, session_owner,
            response->n_adding_member_info_list, response->adding_member_info_list,
            added_members_num, added_members
        );
    }

    if (ret == E2EES_RESULT_SUCC) {
        // use renewed group_info
        group_name = outbound_group_session->group_info->group_name;
        group_address = outbound_group_session->group_info->group_address;

        // notify
        e2ees_notify_group_members_added(
            session_owner,
            group_address,
            group_name,
            new_group_members,
            new_group_members_num,
            added_members,
            added_members_num
        );
    } else {
        e2ees_notify_log(session_owner, DEBUG_LOG, "group members adding failed");
    }

    return ret;
}

bool consume_add_group_members_msg(E2ees__E2eeAddress *receiver_address, E2ees__AddGroupMembersMsg *msg) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__E2eeAddress *group_address = NULL;
    char *group_name = NULL;
    E2ees__GroupMember **new_group_members = NULL;
    size_t new_group_members_num = 0;
    uint32_t e2ees_pack_id;
    E2ees__GroupSession *outbound_group_session = NULL;
    E2ees__GroupSession *inbound_group_session = NULL;
    uint32_t their_sequence = 0;

    if (is_valid_address(receiver_address)) {
        if (is_valid_add_group_members_msg(msg)) {
            group_address = msg->group_info->group_address;
            group_name = msg->group_info->group_name;
            new_group_members = msg->group_info->group_member_list;
            new_group_members_num = msg->group_info->n_group_member_list;
            e2ees_pack_id = msg->e2ees_pack_id;
        } else {
            e2ees_notify_log(NULL, BAD_ADD_GROUP_MEMBERS_MSG, "consume_add_group_members_msg() invalid add_group_members_msg");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_add_group_members_msg() invalid receiver_address");
        ret = E2EES_RESULT_FAIL;
    }

    /** The old group members have their own outbound group sessions, so they need to renew them.
     *  On the other hand, the new group members need to create the outbound group session.
     */
    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(
            receiver_address, receiver_address, group_address, &outbound_group_session
        );
        if (is_valid_group_session(outbound_group_session)) {
            get_e2ees_plugin()->db_handler.load_group_session_by_id(
                msg->sender_address, receiver_address, outbound_group_session->session_id, &inbound_group_session
            );
            if (!is_valid_group_session(inbound_group_session)) {
                e2ees_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_add_group_members_msg() invalid inbound_group_session");
                ret = E2EES_RESULT_FAIL;
            }
        } else {
            e2ees_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_add_group_members_msg() invalid outbound_group_session");
            ret = E2EES_RESULT_FAIL;
        }
    }

    // renew the outbound group session if it exists
    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_group_session->e2ees_pack_id)->cipher_suite;
        their_sequence = msg->sequence;
        while (inbound_group_session->sequence < their_sequence) {
            advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
            inbound_group_session->sequence += 1;
        }

        // renew the outbound group session
        ret = renew_outbound_group_session_by_welcome_and_add(
            outbound_group_session, &(inbound_group_session->chain_key), msg->sender_address,
            msg->n_adding_member_info_list, msg->adding_member_info_list,
            msg->n_adding_member_list, msg->adding_member_list
        );
    }

    if (ret == E2EES_RESULT_SUCC) {
        // notify
        e2ees_notify_group_members_added(
            receiver_address,
            group_address,
            group_name,
            new_group_members,
            new_group_members_num,
            msg->adding_member_list,
            msg->n_adding_member_list
        );
    } else {
        e2ees_notify_log(NULL, DEBUG_LOG, "failed to consume add group members msg");
    }

    // release
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    // done
    return true;
}

int produce_add_group_member_device_request(
    E2ees__AddGroupMemberDeviceRequest **request_out,
    add_group_member_device_params *params,
    E2ees__GroupSession *outbound_group_session
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__AddGroupMemberDeviceRequest *request = NULL;
    E2ees__AddGroupMemberDeviceMsg *msg = NULL;

    request = (E2ees__AddGroupMemberDeviceRequest *)malloc(sizeof(E2ees__AddGroupMemberDeviceRequest));
    e2ees__add_group_member_device_request__init(request);

    msg = (E2ees__AddGroupMemberDeviceMsg *)malloc(sizeof(E2ees__AddGroupMemberDeviceMsg));
    e2ees__add_group_member_device_msg__init(msg);

    msg->e2ees_pack_id = outbound_group_session->e2ees_pack_id;

    copy_address_from_address(&(msg->sender_address), params->sender_address);

    msg->sequence = outbound_group_session->sequence;

    copy_group_info(&(msg->group_info), outbound_group_session->group_info);

    msg->adding_member_device = (E2ees__GroupMemberInfo *)malloc(sizeof(E2ees__GroupMemberInfo));
    e2ees__group_member_info__init(msg->adding_member_device);
    copy_address_from_address(&(msg->adding_member_device->member_address), params->new_device_address);

    request->msg = msg;

    if (ret == E2EES_RESULT_SUCC) {
        *request_out = request;
    }

    return ret;
}

int consume_add_group_member_device_response(
    E2ees__GroupSession *outbound_group_session,
    E2ees__AddGroupMemberDeviceResponse *response
) {
    int ret = E2EES_RESULT_SUCC;

    char *group_name = NULL;
    E2ees__E2eeAddress *session_owner = NULL;
    E2ees__E2eeAddress *group_address = NULL;
    E2ees__GroupMemberInfo *adding_member_device_info = NULL;
    E2ees__E2eeAddress *new_device_address = NULL;

    if (is_valid_group_session(outbound_group_session)) {
        group_name = outbound_group_session->group_info->group_name;
        session_owner = outbound_group_session->session_owner;
        group_address = outbound_group_session->group_info->group_address;
    } else {
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_add_group_member_device_response(response)) {
        adding_member_device_info = response->adding_member_device_info;
        new_device_address = adding_member_device_info->member_address;
    } else {
        if (response != NULL && response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
            // Can not collect group member info, or member device already added
            return true;
        }
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // renew the outbound group session
        ret = renew_group_sessions_with_new_device(
            outbound_group_session, NULL, session_owner, new_device_address, adding_member_device_info
        );
    }

    if (ret == E2EES_RESULT_SUCC) {
        e2ees_notify_log(
            outbound_group_session->session_owner,
            DEBUG_LOG,
            "consume_add_group_member_device_response() success, new_device_address: [%s:%s], group_address:[%s@%s]",
            new_device_address->user->user_id,
            new_device_address->user->device_id,
            group_address->group->group_id,
            group_address->domain
        );
    } else {
        e2ees_notify_log(session_owner, DEBUG_LOG, "consume_add_group_member_device_response() failed");
    }

    return ret;
}

bool consume_add_group_member_device_msg(
    E2ees__E2eeAddress *receiver_address,
    E2ees__AddGroupMemberDeviceMsg *msg
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__E2eeAddress *group_address = NULL;
    char *group_name = NULL;
    E2ees__GroupMember **group_member_list = NULL;
    size_t group_members_num = 0;
    uint32_t e2ees_pack_id;
    E2ees__GroupSession *outbound_group_session = NULL;
    E2ees__GroupSession *inbound_group_session = NULL;
    uint32_t their_sequence = 0;

    if (is_valid_address(receiver_address)) {
        if (is_valid_add_group_member_device_msg(msg)) {
            group_address = msg->group_info->group_address;
            group_name = msg->group_info->group_name;
            group_member_list = msg->group_info->group_member_list;
            group_members_num = msg->group_info->n_group_member_list;
            e2ees_pack_id = msg->e2ees_pack_id;
        } else {
            e2ees_notify_log(NULL, BAD_ADD_GROUP_MEMBER_DEVICE_MSG, "consume_add_group_member_device_msg() invalid add_group_member_device_msg");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_add_group_member_device_msg() invalid receiver_address");
        ret = E2EES_RESULT_FAIL;
    }

    /** The old group members have their own outbound group sessions, so they need to renew them.
     *  On the other hand, the new group members need to create the outbound group session.
     */
    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(
            receiver_address, receiver_address, group_address, &outbound_group_session
        );
        if (is_valid_group_session(outbound_group_session)) {
            // load the inbound group session to get the chain key
            get_e2ees_plugin()->db_handler.load_group_session_by_id(
                msg->sender_address, receiver_address, outbound_group_session->session_id, &inbound_group_session
            );
            if (!is_valid_group_session(inbound_group_session)) {
                e2ees_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_add_group_member_device_msg()");
                ret = E2EES_RESULT_FAIL;
            }
        } else {
            e2ees_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_add_group_member_device_msg() invalid outbound_group_session");
            ret = E2EES_RESULT_FAIL;
        }
    }

    // renew the outbound group session if it exists
    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_group_session->e2ees_pack_id)->cipher_suite;
        their_sequence = msg->sequence;
        while (inbound_group_session->sequence < their_sequence) {
            advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
            inbound_group_session->sequence += 1;
        }

        // renew the outbound group session
        ret = renew_group_sessions_with_new_device(
            outbound_group_session, &(inbound_group_session->chain_key),
            msg->sender_address, msg->adding_member_device->member_address, msg->adding_member_device
        );
    }

    // release
    if (outbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    // done
    return true;
}

int produce_remove_group_members_request(
    E2ees__RemoveGroupMembersRequest **request_out,
    remove_group_members_params *params,
    E2ees__GroupSession *outbound_group_session
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__RemoveGroupMembersRequest *request = NULL;
    E2ees__RemoveGroupMembersMsg *msg = NULL;

    request = (E2ees__RemoveGroupMembersRequest *)malloc(sizeof(E2ees__RemoveGroupMembersRequest));
    e2ees__remove_group_members_request__init(request);

    msg = (E2ees__RemoveGroupMembersMsg *)malloc(sizeof(E2ees__RemoveGroupMembersMsg));
    e2ees__remove_group_members_msg__init(msg);

    msg->e2ees_pack_id = outbound_group_session->e2ees_pack_id;

    copy_address_from_address(&(msg->sender_address), params->sender_address);

    remove_group_members_from_group_info(
        &(msg->group_info), outbound_group_session->group_info, params->removing_members, params->removing_members_num
    );

    msg->n_removing_member_list = params->removing_members_num;
    copy_group_members(&(msg->removing_member_list), params->removing_members, params->removing_members_num);

    request->msg = msg;

    if (ret == E2EES_RESULT_SUCC) {
        *request_out = request;
    }

    return ret;
}

static bool user_in_group(E2ees__E2eeAddress *user_address, E2ees__GroupMember **group_member_list, size_t group_members_num) {
    size_t i;
    for (i = 0; i < group_members_num; i++) {
        if (safe_strcmp(group_member_list[i]->user_id, user_address->user->user_id)
            && safe_strcmp(group_member_list[i]->domain, user_address->domain)
        ) {
            return true;
        }
    }
    return false;
}

int consume_remove_group_members_response(
    E2ees__GroupSession *outbound_group_session,
    E2ees__RemoveGroupMembersResponse *response,
    E2ees__GroupMember **removed_members,
    size_t removed_members_num
) {
    int ret = E2EES_RESULT_SUCC;

    uint32_t e2ees_pack_id;
    E2ees__E2eeAddress *sender_address = NULL;
    E2ees__E2eeAddress *group_address = NULL;
    E2ees__GroupMember **group_member_list = NULL;
    size_t group_members_num = 0;
    char *old_session_id = NULL;
    char *group_name = NULL;

    if (is_valid_group_session(outbound_group_session)) {
        e2ees_pack_id = outbound_group_session->e2ees_pack_id;
        sender_address = outbound_group_session->session_owner;
        group_address = outbound_group_session->group_info->group_address;
        old_session_id = outbound_group_session->session_id;
        group_name = outbound_group_session->group_info->group_name;
    } else {
        ret = E2EES_RESULT_FAIL;
    }
    if (is_valid_remove_group_members_response(response)) {
        group_member_list = response->group_member_list;
        group_members_num = response->n_group_member_list;
    } else {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // delete the old outbound group session
        get_e2ees_plugin()->db_handler.unload_group_session_by_id(sender_address, old_session_id);

        if (group_members_num > 0 && user_in_group(sender_address, group_member_list, group_members_num)) {
            // generate a new outbound group session
            ret = new_outbound_group_session_by_sender(
                response->n_member_info_list, response->member_info_list,
                e2ees_pack_id, sender_address, group_name, group_address, group_member_list, group_members_num, old_session_id
            );
        } else {
            // user is removed from group
            e2ees_notify_log(sender_address, DEBUG_LOG, "consume_remove_group_members_response() skip renew outbound group session since user is not in group");
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        // notify
        e2ees_notify_group_members_removed(
            sender_address,
            group_address,
            group_name,
            group_member_list,
            group_members_num,
            removed_members,
            removed_members_num
        );
    } else {
        e2ees_notify_log(sender_address, DEBUG_LOG, "group members removing failed");
    }

    return ret;
}

bool consume_remove_group_members_msg(E2ees__E2eeAddress *receiver_address, E2ees__RemoveGroupMembersMsg *msg) {
    int ret = E2EES_RESULT_SUCC;

    uint32_t e2ees_pack_id;
    E2ees__GroupInfo *group_info = NULL;
    char *group_name = NULL;
    E2ees__E2eeAddress *sender_address = NULL;
    E2ees__E2eeAddress *group_address = NULL;
    size_t new_group_members_num = 0;
    E2ees__GroupMember **new_group_members = NULL;
    E2ees__GroupSession *inbound_group_session = NULL;
    bool new_group_session = true;
    bool removed_member = false;
    size_t i;

    if (is_valid_address(receiver_address)) {
        if (is_valid_remove_group_members_msg(msg)) {
            e2ees_pack_id = msg->e2ees_pack_id;
            group_info = msg->group_info;
            group_name = group_info->group_name;
            sender_address = msg->sender_address;
            group_address = group_info->group_address;
            new_group_members_num = group_info->n_group_member_list;
            new_group_members = group_info->group_member_list;
        } else {
            e2ees_notify_log(NULL, BAD_REMOVE_GROUP_MEMBERS_MSG, "consume_remove_group_members_msg() invalid remove_group_members_msg");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_remove_group_members_msg() invalid receiver_address");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // if the receiver is the one who is going to be removed, the receiver should unload his or her own group session
        for (i = 0; i < msg->n_removing_member_list; i++) {
            if (safe_strcmp(receiver_address->user->user_id, msg->removing_member_list[i]->user_id)
                && safe_strcmp(receiver_address->domain, msg->removing_member_list[i]->domain)
            ) {
                // unload all outbound and inbound group sessions
                get_e2ees_plugin()->db_handler.unload_group_session_by_address(receiver_address, group_address);

                // notify
                e2ees_notify_group_members_removed(
                    receiver_address,
                    group_address,
                    group_name,
                    new_group_members,
                    new_group_members_num,
                    msg->removing_member_list,
                    msg->n_removing_member_list
                );

                // done
                // no need to renew outbound group session
                e2ees_notify_log(receiver_address, DEBUG_LOG, "consume_remove_group_members_msg() skip renew outbound group session because local user is removed");
                removed_member = true;
            }
        }
    }

    if ((ret == E2EES_RESULT_SUCC) && (removed_member == false)) {
        // unload the old group sessions if necessary
        get_e2ees_plugin()->db_handler.load_group_session_by_address(sender_address, receiver_address, group_address, &inbound_group_session);

        if (is_valid_group_session(inbound_group_session)) {
            if (!compare_group_member(
                inbound_group_session->group_info->group_member_list, inbound_group_session->group_info->n_group_member_list,
                new_group_members, new_group_members_num)
            ) {
                new_group_session = false;
                // unload the old group sessions
                get_e2ees_plugin()->db_handler.unload_group_session_by_id(receiver_address, inbound_group_session->session_id);
            }
        } else {
            // there is no inbound group session
            // the inbound group session may be invalid
            new_group_session = false;
        }

        if (new_group_session == false) {
            for (i = 0; i < msg->n_member_info_list; i++) {
                E2ees__GroupMemberInfo *cur_group_member_id = (msg->member_info_list)[i];
                if (!compare_address(cur_group_member_id->member_address, receiver_address)) {
                    ret = new_inbound_group_session_by_member_id(e2ees_pack_id, receiver_address, cur_group_member_id, group_info);
                    if (ret == E2EES_RESULT_FAIL) {
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "consume_remove_group_members_msg() new_inbound_group_session_by_member_id failed with member_address: [%s:%s]",
                            cur_group_member_id->member_address->user->user_id,
                            cur_group_member_id->member_address->user->device_id
                        );
                    }
                }
            }
        } else {
            for (i = 0; i < msg->n_member_info_list; i++) {
                E2ees__GroupMemberInfo *cur_group_member_id = (msg->member_info_list)[i];
                if (!compare_address(cur_group_member_id->member_address, sender_address)) {
                    if (!compare_address(cur_group_member_id->member_address, receiver_address)) {
                        ret = new_and_complete_inbound_group_session(cur_group_member_id, inbound_group_session);
                        if (ret == E2EES_RESULT_FAIL) {
                            e2ees_notify_log(
                                receiver_address,
                                DEBUG_LOG,
                                "consume_remove_group_members_msg() new_and_complete_inbound_group_session failed with member_address: [%s:%s]",
                                cur_group_member_id->member_address->user->user_id,
                                cur_group_member_id->member_address->user->device_id
                            );
                        }
                    }
                } else {
                    ret = complete_inbound_group_session_by_member_id(inbound_group_session, cur_group_member_id);
                    if (ret == E2EES_RESULT_FAIL) {
                        e2ees_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "consume_remove_group_members_msg() complete_inbound_group_session_by_member_id failed with member_address: [%s:%s]",
                            cur_group_member_id->member_address->user->user_id,
                            cur_group_member_id->member_address->user->device_id
                        );
                    }
                }
            }

            // create a new outbound group session
            ret = new_outbound_group_session_by_receiver(
                &(inbound_group_session->group_seed),
                e2ees_pack_id,
                receiver_address,
                group_name,
                group_address,
                inbound_group_session->session_id,
                new_group_members,
                new_group_members_num
            );
            if (ret == E2EES_RESULT_FAIL) {
                e2ees_notify_log(
                    receiver_address,
                    DEBUG_LOG,
                    "consume_remove_group_members_msg() new_outbound_group_session_by_receiver failed"
                );
            }
        }

        if (ret == E2EES_RESULT_SUCC) {
            // notify
            e2ees_notify_group_members_removed(
                receiver_address,
                group_address,
                group_name,
                new_group_members,
                new_group_members_num,
                msg->removing_member_list,
                msg->n_removing_member_list
            );
        }
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }

    return true;
}

int produce_leave_group_request(
    E2ees__LeaveGroupRequest **request_out,
    leave_group_params *params
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__LeaveGroupRequest *request = NULL;
    E2ees__LeaveGroupMsg *msg = NULL;

    request = (E2ees__LeaveGroupRequest *)malloc(sizeof(E2ees__LeaveGroupRequest));
    e2ees__leave_group_request__init(request);

    msg = (E2ees__LeaveGroupMsg *)malloc(sizeof(E2ees__LeaveGroupMsg));
    e2ees__leave_group_msg__init(msg);

    copy_address_from_address(&(msg->user_address), params->sender_address);
    copy_address_from_address(&(msg->group_address), params->group_address);

    request->msg = msg;

    if (ret == E2EES_RESULT_SUCC) {
        *request_out = request;
    }

    // done
    return ret;
}

int consume_leave_group_response(
    E2ees__E2eeAddress *user_address,
    E2ees__LeaveGroupResponse *response
) {
    int ret = E2EES_RESULT_SUCC;

    if (!is_valid_address(user_address)) {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_leave_group_response(response)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        e2ees_notify_log(user_address, DEBUG_LOG, "consume_leave_group_response() success, unload group session");
        // unload
        get_e2ees_plugin()->db_handler.unload_group_session_by_address(user_address, response->group_address);
    } else {
        e2ees_notify_log(user_address, DEBUG_LOG, "consume_leave_group_response() failed, redo later");
    }

    return ret;
}

bool consume_leave_group_msg(E2ees__E2eeAddress *receiver_address, E2ees__LeaveGroupMsg *msg) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__E2eeAddress *user_address = NULL;
    E2ees__E2eeAddress *group_address = NULL;
    E2ees__GroupMember **removing_group_members = NULL;
    E2ees__RemoveGroupMembersResponse *remove_group_members_response = NULL;

    if (is_valid_address(receiver_address)) {
        if (is_valid_leave_group_msg(msg)) {
            user_address = msg->user_address;
            group_address = msg->group_address;
        } else {
            e2ees_notify_log(NULL, BAD_LEAVE_GROUP_MSG, "consume_leave_group_msg() invalid leave_group_msg");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_leave_group_msg() invalid receiver_address");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // prepare the removing group member
        removing_group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *));
        removing_group_members[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
        e2ees__group_member__init(removing_group_members[0]);
        removing_group_members[0]->user_id = strdup(user_address->user->user_id);
        removing_group_members[0]->domain = strdup(user_address->domain);
        removing_group_members[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
        size_t removing_group_member_num = 1;

        ret = remove_group_members(
            &remove_group_members_response, receiver_address, group_address, removing_group_members, removing_group_member_num
        );
    }

    if (is_valid_remove_group_members_response(remove_group_members_response)) {
        e2ees_notify_log(receiver_address, DEBUG_LOG, "consume_leave_group_msg() success");
    }

    // release
    if (removing_group_members != NULL) {
        e2ees__group_member__free_unpacked(removing_group_members[0], NULL);
        removing_group_members[0] = NULL;
        free_mem((void **)&removing_group_members, sizeof(E2ees__GroupMember *));
    }
    free_proto(remove_group_members_response);

    // done
    return true;
}

int produce_send_group_msg_request(
    E2ees__SendGroupMsgRequest **request_out,
    send_group_msg_params *params,
    uint32_t notif_level,
    E2ees__GroupSession *outbound_group_session,
    E2ees__GroupMsgPayload *group_msg_payload
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__SendGroupMsgRequest *request = NULL;
    E2ees__E2eeMsg *e2ee_msg = NULL;

    request = (E2ees__SendGroupMsgRequest *)malloc(sizeof(E2ees__SendGroupMsgRequest));
    e2ees__send_group_msg_request__init(request);

    // prepare an e2ee message
    e2ee_msg = (E2ees__E2eeMsg *)malloc(sizeof(E2ees__E2eeMsg));
    e2ees__e2ee_msg__init(e2ee_msg);
    e2ee_msg->version = strdup(outbound_group_session->version);
    e2ee_msg->session_id = strdup(outbound_group_session->session_id);
    copy_address_from_address(&(e2ee_msg->from), params->sender_address);
    copy_address_from_address(&(e2ee_msg->to), params->group_address);
    e2ee_msg->msg_id = generate_uuid_str();
    e2ee_msg->notif_level = notif_level;
    e2ee_msg->payload_case = E2EES__E2EE_MSG__PAYLOAD_GROUP_MSG;

    // optional allow_list and denny_list
    size_t i;
    if (params->allow_list_len > 0 && params->allow_list) {
        e2ees_notify_log(params->sender_address, DEBUG_LOG, "produce_send_group_msg_request() with allow_list_len: %d", params->allow_list_len);
        request->n_allow_list = params->allow_list_len;
        request->allow_list = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * params->allow_list_len);
        for (i = 0; i < params->allow_list_len; i++) {
            copy_address_from_address(&((request->allow_list)[i]), params->allow_list[i]);
        }
    }
    if (params->deny_list_len > 0 && params->deny_list) {
        e2ees_notify_log(params->sender_address, DEBUG_LOG, "produce_send_group_msg_request() with deny_list_len: %d", params->deny_list_len);
        request->n_deny_list = params->deny_list_len;
        request->deny_list = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * params->deny_list_len);
        for (i = 0; i < params->deny_list_len; i++) {
            copy_address_from_address(&((request->deny_list)[i]), params->deny_list[i]);
        }
    }

    e2ee_msg->group_msg = group_msg_payload;
    request->msg = e2ee_msg;

    if (ret == E2EES_RESULT_SUCC) {
        *request_out = request;
    }

    return ret;
}

int consume_send_group_msg_response(E2ees__GroupSession *outbound_group_session, E2ees__SendGroupMsgResponse *response) {
    int ret = E2EES_RESULT_SUCC;

    cipher_suite_t *cipher_suite = NULL;

    if (is_valid_group_session(outbound_group_session)) {
        cipher_suite = get_e2ees_pack(outbound_group_session->e2ees_pack_id)->cipher_suite;
    } else {
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_send_group_msg_response(response)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // prepare a new chain key for next encryption
        advance_group_chain_key(cipher_suite, &(outbound_group_session->chain_key));
        outbound_group_session->sequence += 1;
        // store sesson state
        get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);
    }

    return ret;
}

bool consume_group_msg(E2ees__E2eeAddress *receiver_address, E2ees__E2eeMsg *e2ee_msg) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__GroupSession *inbound_group_session = NULL;
    uint32_t sign_key_len = 0;
    E2ees__GroupMsgPayload *group_msg_payload = NULL;
    uint8_t *identity_public_key = NULL;
    E2ees__MsgKey *msg_key = NULL;
    uint8_t *plaintext_data = NULL;
    size_t plaintext_data_len = 0;

    if (is_valid_address(receiver_address)) {
        if (is_valid_e2ee_msg(e2ee_msg)) {
            group_msg_payload = e2ee_msg->group_msg;
        } else {
            e2ees_notify_log(NULL, BAD_LEAVE_GROUP_MSG, "consume_group_msg() invalid e2ee_msg");
            ret = E2EES_RESULT_FAIL;
        }
    } else {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_group_msg() invalid receiver_address");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // load the inbound group session
        get_e2ees_plugin()->db_handler.load_group_session_by_id(e2ee_msg->from, receiver_address, e2ee_msg->session_id, &inbound_group_session);

        if (!is_valid_group_session(inbound_group_session)) {
            e2ees_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_group_msg() invalid inbound group session");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ees_pack(inbound_group_session->e2ees_pack_id)->cipher_suite;
        sign_key_len = cipher_suite->ds_suite->get_param().sign_pub_key_len;

        // unpack the e2ee message
        identity_public_key = (uint8_t *)malloc(sizeof(uint8_t) * sign_key_len);
        memcpy(identity_public_key, inbound_group_session->associated_data.data, sign_key_len);

        // verify the signature
        ret = cipher_suite->ds_suite->verify(
            group_msg_payload->signature.data, group_msg_payload->signature.len,
            group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len,
            identity_public_key
        );
        if (ret == E2EES_RESULT_SUCC) {
            // advance the chain key
            while (inbound_group_session->sequence < group_msg_payload->sequence){
                advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
                inbound_group_session->sequence += 1;
            }

            // create the message key
            msg_key = (E2ees__MsgKey *)malloc(sizeof(E2ees__MsgKey));
            e2ees__msg_key__init(msg_key);
            create_group_message_key(cipher_suite, &(inbound_group_session->chain_key), msg_key);

            // decryption
            ret = cipher_suite->se_suite->decrypt(
                &plaintext_data,
                &plaintext_data_len,
                &(inbound_group_session->associated_data),
                msg_key->derived_key.data,
                group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len
            );

            if (ret == E2EES_RESULT_SUCC) {
                e2ees_notify_group_msg(inbound_group_session->session_owner, e2ee_msg->from, inbound_group_session->group_info->group_address, plaintext_data, plaintext_data_len);

                // advance the chain key
                advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
                inbound_group_session->sequence += 1;
                get_e2ees_plugin()->db_handler.store_group_session(inbound_group_session);
            } else {
                e2ees_notify_log(inbound_group_session->session_owner, BAD_MESSAGE_DECRYPTION, "consume_group_msg(): decryption failed");
            }
        } else {
            e2ees_notify_log(inbound_group_session->session_owner, BAD_SIGNATURE, "consume_group_msg(): verification failed");
        }
    }

    // release
    if (inbound_group_session != NULL) {
        e2ees__group_session__free_unpacked(inbound_group_session, NULL);
        inbound_group_session = NULL;
    }
    free_mem((void **)&identity_public_key, sizeof(uint8_t) * sign_key_len);
    if (msg_key != NULL) {
        e2ees__msg_key__free_unpacked(msg_key, NULL);
        msg_key = NULL;
    }
    free_mem((void **)&plaintext_data, plaintext_data_len);

    return true;
}
