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
#include "test_plugin.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sqlite3.h>
#include <string.h>

#include "e2ees/cipher.h"
#include "e2ees/crypto.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/mem_util.h"

#include "mock_server.h"
#include "mock_server_sending.h"
#include "mock_db.h"
#include "test_util.h"

static int64_t invite_time = 0;

// ===============================================================
static int64_t gen_ts() {
    // time_t now = time(0);
    // return now;
    invite_time++;
    return invite_time;
}

static void gen_rand(uint8_t *rand_out, size_t rand_out_len) {
    size_t i;
    for (i = 0; i < rand_out_len; i++) {
        rand_out[i] = random() % UCHAR_MAX;
    }
}

static void gen_uuid(uint8_t uuid[E2EES_UUID_LEN]) {
    gen_rand(uuid, E2EES_UUID_LEN);
}

// ===============================================================
// e2ees_event_handler_t
// callback handlers
static void on_log(
    E2ees__E2eeAddress *user_address,
    LogCode log_code,
    const char *log_msg
) {
    print_log((char *)log_msg, log_code);
}

static void on_one2one_msg_received(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_other_device_msg_received(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_group_msg_received(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *group_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    print_msg("on_group_msg_received: plaintext", plaintext, plaintext_len);
}

struct e2ees_plugin_t mock_plugin = {
    // common
    {
        gen_ts,
        gen_rand,
        gen_uuid
    },
    {
        // account
        store_account,
        load_account_by_address,
        load_accounts,
        update_signed_pre_key,
        load_signed_pre_key,
        remove_expired_signed_pre_key,
        add_one_time_pre_key,
        remove_one_time_pre_key,
        update_one_time_pre_key,
        load_auth,
        // session
        load_session,
        load_outbound_session,
        load_outbound_sessions,
        store_session,
        unload_session,
        unload_old_session,
        load_group_session_by_address,
        load_group_session_by_id,
        load_group_sessions,
        load_group_addresses,
        store_group_session,
        unload_group_session_by_address,
        unload_group_session_by_id,
        // pending data
        store_pending_plaintext_data,
        load_pending_plaintext_data,
        unload_pending_plaintext_data,
        store_pending_request_data,
        load_pending_request_data,
        unload_pending_request_data
    },
    {
        mock_register_user,
        mock_get_pre_key_bundle,
        mock_invite,
        mock_accept,
        mock_publish_spk,
        mock_supply_opks,
        mock_send_one2one_msg,
        mock_create_group,
        mock_renew_group,
        mock_add_group_members,
        mock_add_group_member_device,
        mock_remove_group_members,
        mock_leave_group,
        mock_send_group_msg,
        mock_consume_proto_msg
    },
    {
        on_log,
        NULL,
        NULL,
        NULL,
        NULL,
        on_one2one_msg_received,
        on_other_device_msg_received,
        on_group_msg_received,
        NULL,
        NULL,
        NULL
    }
};

// test case interface

void tear_up() {
    srand((unsigned int)time(NULL));
    mock_db_begin();
    mock_server_begin();
    e2ees_begin(&mock_plugin);
}

void tear_down() {
    invite_time = 0;
    mock_db_end();
    mock_server_end();
    stop_mock_server_sending();
    e2ees_end();
}
