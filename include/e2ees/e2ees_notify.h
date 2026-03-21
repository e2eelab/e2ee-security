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
#ifndef E2EES_NOTIFY_H_
#define E2EES_NOTIFY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

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

#endif /* E2EES_NOTIFY_H_ */