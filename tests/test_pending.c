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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ees/mem_util.h"

#include "mock_db.h"
#include "test_util.h"
#include "test_plugin.h"

void test_pending_plaintext_data() {
    tear_up();

    E2ees__E2eeAddress from_addr;
    e2ees__e2ee_address__init(&from_addr);
    E2ees__PeerUser from_user;
    e2ees__peer_user__init(&from_user);
    from_user.user_id = "alice";
    from_addr.domain = "test.com";
    from_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    from_addr.user = &from_user;

    E2ees__E2eeAddress to_addr;
    e2ees__e2ee_address__init(&to_addr);
    E2ees__PeerUser to_user;
    e2ees__peer_user__init(&to_user);
    to_user.user_id = "bob";
    to_addr.domain = "test.com";
    to_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    to_addr.user = &to_user;

    char *mock_id = "pending_pt_123";
    uint8_t mock_data[] = { 0xAA, 0xBB, 0xCC };
    size_t mock_len = sizeof(mock_data);
    E2ees__NotifLevel mock_notif = 1;

    store_pending_plaintext_data(&from_addr, &to_addr, mock_id, mock_data, mock_len, mock_notif);

    char **id_list = NULL;
    uint8_t **data_list = NULL;
    size_t *len_list = NULL;
    E2ees__NotifLevel *notif_list = NULL;

    size_t count = load_pending_plaintext_data(&from_addr, &to_addr, &id_list, &data_list, &len_list, &notif_list);

    bool is_success = false;
    if (count > 0 && id_list != NULL && data_list != NULL && len_list != NULL) {
        if (strcmp(id_list[0], mock_id) == 0 && 
            len_list[0] == mock_len && 
            memcmp(data_list[0], mock_data, mock_len) == 0) {
            is_success = true;
        }
    } else {
        printf("test_pending_plaintext_data: failed to load data\n");
    }
    print_result("test_pending_plaintext_data (Load)", is_success);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            if (id_list[i]) free(id_list[i]);
            if (data_list[i]) free(data_list[i]);
        }
        if (id_list) free(id_list);
        if (data_list) free(data_list);
        if (len_list) free(len_list);
        if (notif_list) free(notif_list);
    }
    id_list = NULL; data_list = NULL; len_list = NULL; notif_list = NULL;

    unload_pending_plaintext_data(&from_addr, &to_addr, mock_id);

    size_t new_count = load_pending_plaintext_data(&from_addr, &to_addr, &id_list, &data_list, &len_list, &notif_list);
    print_result("test_pending_plaintext_data (Unload)", new_count == 0);

    if (new_count > 0) {
        for (size_t i = 0; i < new_count; i++) {
            if (id_list && id_list[i]) free(id_list[i]);
            if (data_list && data_list[i]) free(data_list[i]);
        }
        if (id_list) free(id_list);
        if (data_list) free(data_list);
        if (len_list) free(len_list);
        if (notif_list) free(notif_list);
    }

    tear_down();
}

void test_pending_request_data() {
    tear_up();

    E2ees__E2eeAddress user_addr;
    e2ees__e2ee_address__init(&user_addr);
    E2ees__PeerUser user_peer;
    e2ees__peer_user__init(&user_peer);
    user_peer.user_id = "alice";
    user_addr.domain = "test.com";
    user_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    user_addr.user = &user_peer;

    char *mock_id = "pending_req_456";
    uint8_t mock_type = 99;
    uint8_t mock_data[] = { 0x11, 0x22, 0x33, 0x44 };
    size_t mock_len = sizeof(mock_data);

    store_pending_request_data(&user_addr, mock_id, mock_type, mock_data, mock_len);

    char **id_list = NULL;
    uint8_t *type_list = NULL;
    uint8_t **data_list = NULL;
    size_t *len_list = NULL;

    size_t count = load_pending_request_data(&user_addr, &id_list, &type_list, &data_list, &len_list);

    bool is_success = false;
    if (count > 0 && id_list != NULL && type_list != NULL && data_list != NULL && len_list != NULL) {
        if (strcmp(id_list[0], mock_id) == 0 && 
            type_list[0] == mock_type && 
            len_list[0] == mock_len && 
            memcmp(data_list[0], mock_data, mock_len) == 0) {
            is_success = true;
        }
    } else {
        printf("test_pending_request_data: failed to load data\n");
    }
    print_result("test_pending_request_data (Load)", is_success);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            if (id_list[i]) free(id_list[i]);
            if (data_list[i]) free(data_list[i]);
        }
        if (id_list) free(id_list);
        if (type_list) free(type_list);
        if (data_list) free(data_list);
        if (len_list) free(len_list);
    }
    id_list = NULL; type_list = NULL; data_list = NULL; len_list = NULL;

    unload_pending_request_data(&user_addr, mock_id);

    size_t new_count = load_pending_request_data(&user_addr, &id_list, &type_list, &data_list, &len_list);
    print_result("test_pending_request_data (Unload)", new_count == 0);

    if (new_count > 0) {
        for (size_t i = 0; i < new_count; i++) {
            if (id_list && id_list[i]) free(id_list[i]);
            if (data_list && data_list[i]) free(data_list[i]);
        }
        if (id_list) free(id_list);
        if (type_list) free(type_list);
        if (data_list) free(data_list);
        if (len_list) free(len_list);
    }

    tear_down();
}

int main(){
    test_pending_plaintext_data();
    test_pending_request_data();

    return 0;
}
