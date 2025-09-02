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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "e2ees/account.h"
#include "e2ees/crypto.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/ratchet.h"
#include "e2ees/session.h"
#include "e2ees/e2ees.h"

#include "test_plugin.h"
#include "mock_db.h"
#include "test_plugin.h"
#include "test_util.h"

static const cipher_suite_t *test_cipher_suite;

void test_load_outbound_session(uint32_t e2ees_pack_id)
{
    tear_up();

    // create session and two addresses
    E2ees__Session *session = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    E2ees__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, e2ees_pack_id, from, to);
    copy_address_from_address(&(session->our_address), from);

    // create mock public keys
    session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session->pre_shared_input_list[0].len = 32;
    session->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // insert to the db
    store_session(session);

    // load_outbound_session
    E2ees__Session *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_load_outbound_session", is_equal_session(session, session_copy));

    // free
    e2ees__e2ee_address__free_unpacked(from, NULL);
    e2ees__e2ee_address__free_unpacked(to, NULL);
    e2ees__session__free_unpacked(session, NULL);
    e2ees__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_load_outbound_sessions(uint32_t e2ees_pack_id)
{
    tear_up();

    // create sessions
    E2ees__Session *session_1, *session_2, *session_3;
    session_1 = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    session_2 = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    session_3 = (E2ees__Session *)malloc(sizeof(E2ees__Session));

    // create addresses
    E2ees__E2eeAddress *from, *to_1, *to_2, *to_3;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to_1, "bob", "bob's domain", "bob's device 1");
    mock_address(&to_2, "bob", "bob's domain", "bob's device 2");
    mock_address(&to_3, "bob", "bob's domain", "bob's device 3");

    // initialise sessions
    initialise_session(session_1, e2ees_pack_id, from, to_1);
    copy_address_from_address(&(session_1->our_address), from);
    initialise_session(session_2, e2ees_pack_id, from, to_2);
    copy_address_from_address(&(session_2->our_address), from);
    initialise_session(session_3, e2ees_pack_id, from, to_3);
    copy_address_from_address(&(session_3->our_address), from);

    // create mock public keys for session_1
    session_1->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session_1->pre_shared_input_list[0].len = 32;
    session_1->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session_1->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session_1->associated_data.len = 64;
    session_1->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session_1->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session_1->session_id = generate_uuid_str();

    // insert to the db
    store_session(session_1);

    // create mock public keys for session_2
    session_2->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session_2->pre_shared_input_list[0].len = 32;
    session_2->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session_2->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session_2->associated_data.len = 64;
    session_2->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session_2->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session_2->session_id = generate_uuid_str();

    // insert to the db
    store_session(session_2);

    // create mock public keys for session_3
    session_3->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session_3->pre_shared_input_list[0].len = 32;
    session_3->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session_3->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session_3->associated_data.len = 64;
    session_3->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session_3->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session_3->session_id = generate_uuid_str();

    // insert to the db
    store_session(session_3);

    E2ees__Session **sessions = (E2ees__Session **)malloc(sizeof(E2ees__Session *) * 3);
    sessions[0] = session_1;
    sessions[1] = session_2;
    sessions[2] = session_3;

    // load_outbound_session
    E2ees__Session **sessions_copy;
    load_outbound_sessions(from, to_1->user->user_id, to_1->domain, &sessions_copy);

    // assert session equals to session_copy
    print_result("test_load_outbound_sessions", is_equal_sessions(sessions, sessions_copy, 3));

    // free
    e2ees__e2ee_address__free_unpacked(from, NULL);
    e2ees__e2ee_address__free_unpacked(to_1, NULL);
    e2ees__e2ee_address__free_unpacked(to_2, NULL);
    e2ees__e2ee_address__free_unpacked(to_3, NULL);
    e2ees__session__free_unpacked(session_1, NULL);
    e2ees__session__free_unpacked(session_2, NULL);
    e2ees__session__free_unpacked(session_3, NULL);

    tear_down();
}

void test_load_session(uint32_t e2ees_pack_id)
{
    tear_up();

    // create session and two addresses
    E2ees__Session *session = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    e2ees__session__init(session);

    E2ees__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, e2ees_pack_id, from, to);
    copy_address_from_address(&(session->our_address), to);

    // create mock public keys
    session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session->pre_shared_input_list[0].len = 32;
    session->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // insert to the db
    store_session(session);

    // load_session
    E2ees__Session *session_copy;
    load_session(session->session_id, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_load_session", is_equal_session(session, session_copy));

    // free
    e2ees__e2ee_address__free_unpacked(from, NULL);
    e2ees__e2ee_address__free_unpacked(to, NULL);
    e2ees__session__free_unpacked(session, NULL);
    e2ees__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_load_group_session_by_address(uint32_t e2ees_pack_id)
{
    tear_up();

    // create two addresses
    E2ees__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", "alice's domain", "alice's device");
    mock_address(&Bob, "bob", "bob's domain", "bob's device");

    // create group_member_list
    E2ees__GroupMember **group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 2);
    group_member_list[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[0]);
    group_member_list[0]->user_id = strdup("alice");
    group_member_list[0]->domain = strdup("alice's domain");
    group_member_list[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_member_list[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[1]);
    group_member_list[1]->user_id = strdup("bob");
    group_member_list[1]->domain = strdup("bob's domain");
    group_member_list[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    E2ees__E2eeAddress *group_address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(group_address);
    group_address->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init(group_address->group);
    group_address->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create outbound group session
    E2ees__GroupSession *group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
    e2ees__group_session__init(group_session);

    group_session->version = strdup(E2EES_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->sender), Alice);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = group_session->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = 2;
    copy_group_members(&(group_info->group_member_list), group_member_list, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    group_session->group_seed.len = 32;
    group_session->group_seed.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->group_seed.data, "01234567890123456789012345678901", 32);

    group_session->associated_data.len = 64;
    group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, 32);
    memcpy((group_session->associated_data.data) + 32, group_session->group_seed.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_outbound_group_session
    E2ees__GroupSession *group_session_copy;
    load_group_session_by_address(Alice, Alice, group_address, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_group_session_by_address", is_equal_group_session(group_session, group_session_copy));

    // free
    e2ees__e2ee_address__free_unpacked(Alice, NULL);
    e2ees__e2ee_address__free_unpacked(Bob, NULL);
    e2ees__e2ee_address__free_unpacked(group_address, NULL);
    e2ees__group_session__free_unpacked(group_session, NULL);
    e2ees__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

void test_load_group_session_by_id(uint32_t e2ees_pack_id)
{
    tear_up();

    // create two addresses
    E2ees__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // create group_member_list
    E2ees__GroupMember **group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 2);
    group_member_list[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[0]);
    group_member_list[0]->user_id = strdup("alice");
    group_member_list[0]->domain = strdup("alice's domain");
    group_member_list[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_member_list[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[1]);
    group_member_list[1]->user_id = strdup("bob");
    group_member_list[1]->domain = strdup("bob's domain");
    group_member_list[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    E2ees__E2eeAddress *group_address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(group_address);
    group_address->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init(group_address->group);
    group_address->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create inbound group session
    E2ees__GroupSession *group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
    e2ees__group_session__init(group_session);

    group_session->version = strdup(E2EES_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->sender), Bob);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = group_session->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = 2;
    copy_group_members(&(group_info->group_member_list), group_member_list, 2);

    group_session->sequence = 0;

    group_session->chain_key.len = 32;
    group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(group_session->chain_key.data, "01234567890123456789012345678901", 32);

    group_session->associated_data.len = 64;
    group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(group_session->associated_data.data, group_session->chain_key.data, CURVE25519_KEY_LENGTH);
    memcpy((group_session->associated_data.data) + CURVE25519_KEY_LENGTH, group_session->chain_key.data, CURVE25519_KEY_LENGTH);

    // insert to the db
    store_group_session(group_session);

    // load_inbound_group_session for owner: Alice
    E2ees__GroupSession *group_session_copy = NULL;
    load_group_session_by_id(Bob, Alice, group_session->session_id, &group_session_copy);

    // assert session equals to session_copy
    print_result("test_load_group_session_by_id", is_equal_group_session(group_session, group_session_copy));

    // free
    e2ees__e2ee_address__free_unpacked(Alice, NULL);
    e2ees__e2ee_address__free_unpacked(Bob, NULL);
    e2ees__e2ee_address__free_unpacked(group_address, NULL);
    e2ees__group_session__free_unpacked(group_session, NULL);
    e2ees__group_session__free_unpacked(group_session_copy, NULL);

    tear_down();
}

void test_load_group_addresses(uint32_t e2ees_pack_id) {
    tear_up();

    // create two addresses
    E2ees__E2eeAddress *Alice, *Bob;
    mock_address(&Alice, "alice", E2EELAB_DOMAIN, "alice's device");
    mock_address(&Bob, "bob", E2EELAB_DOMAIN, "bob's device");

    // create group_member_list
    E2ees__GroupMember **group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 2);
    group_member_list[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[0]);
    group_member_list[0]->user_id = strdup("alice");
    group_member_list[0]->domain = strdup("alice's domain");
    group_member_list[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_member_list[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member_list[1]);
    group_member_list[1]->user_id = strdup("bob");
    group_member_list[1]->domain = strdup("bob's domain");
    group_member_list[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock two group addresses
    E2ees__E2eeAddress *group_address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(group_address);
    group_address->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init(group_address->group);
    group_address->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    E2ees__E2eeAddress *group_address_2 = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(group_address_2);
    group_address_2->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init(group_address_2->group);
    group_address_2->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_address_2->domain = mock_domain_str();
    group_address_2->group->group_id = generate_uuid_str();

    // create an outbound group session
    E2ees__GroupSession *group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
    e2ees__group_session__init(group_session);

    group_session->version = strdup(E2EES_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session->sender), Alice);
    copy_address_from_address(&(group_session->session_owner), Alice);
    group_session->session_id = generate_uuid_str();

    group_session->group_info =
    (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = group_session->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = 2;
    copy_group_members(&(group_info->group_member_list), group_member_list, 2);

    // insert to the db
    store_group_session(group_session);

    // create a second outbound group session
    E2ees__GroupSession *group_session_2 = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
    e2ees__group_session__init(group_session_2);

    group_session_2->version = strdup(E2EES_PROTOCOL_VERSION);

    copy_address_from_address(&(group_session_2->sender), Alice);
    copy_address_from_address(&(group_session_2->session_owner), Alice);
    group_session_2->session_id = generate_uuid_str();

    group_session_2->group_info =
    (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    group_info = group_session_2->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address_2);
    group_info->n_group_member_list = 2;
    copy_group_members(&(group_info->group_member_list), group_member_list, 2);

    // insert to the db
    store_group_session(group_session_2);

    // load the group address
    E2ees__E2eeAddress **group_addresses;
    size_t n_group_addresses = load_group_addresses(Alice, Alice, &group_addresses);

    // assert the group addresses
    bool success = false;
    if (compare_address(group_addresses[0], group_address)) {
        if (compare_address(group_addresses[1], group_address_2)) {
            success = true;
        }
    }
    print_result("test_load_group_addresses", success);

    // free
    e2ees__e2ee_address__free_unpacked(Alice, NULL);
    e2ees__e2ee_address__free_unpacked(Bob, NULL);
    e2ees__e2ee_address__free_unpacked(group_address, NULL);
    e2ees__e2ee_address__free_unpacked(group_address_2, NULL);
    e2ees__group_session__free_unpacked(group_session, NULL);
    e2ees__group_session__free_unpacked(group_session_2, NULL);
    size_t i;
    for (i = 0; i < n_group_addresses; i++) {
        e2ees__e2ee_address__free_unpacked(group_addresses[i], NULL);
    }
    free(group_addresses);

    tear_down();
}

void test_store_session(uint32_t e2ees_pack_id)
{
    tear_up();

    // create session and two addresses
    E2ees__Session *session = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    E2ees__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, e2ees_pack_id, from, to);
    copy_address_from_address(&(session->our_address), from);

    // create mock public keys
    session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session->pre_shared_input_list[0].len = 32;
    session->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    ProtobufCBinaryData their_ratchet_key;
    their_ratchet_key.len = 32;
    their_ratchet_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(their_ratchet_key.data, "11111111111111111111111111111111", 32);
    E2ees__KeyPair *our_ratchet_key = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    ProtobufCBinaryData their_encaps_ciphertext;
    their_encaps_ciphertext.len = 32;
    their_encaps_ciphertext.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(their_encaps_ciphertext.data, "11111111111111111111111111111111", 32);

    initialise_as_alice(&(session->ratchet), test_cipher_suite, secret, 128, our_ratchet_key, &their_ratchet_key, &their_encaps_ciphertext);

    // insert to the db
    store_session(session);

    session->ratchet->sender_chain->chain_key->index += 1;
    store_session(session);

    // load_outbound_session
    E2ees__Session *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    bool is_equal_index;
    is_equal_index = (session->ratchet->sender_chain->chain_key->index == session_copy->ratchet->sender_chain->chain_key->index);
    print_result("test_store_session", is_equal_index);

    // free
    e2ees__e2ee_address__free_unpacked(from, NULL);
    e2ees__e2ee_address__free_unpacked(to, NULL);
    e2ees__session__free_unpacked(session, NULL);
    e2ees__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_equal_ratchet_outbound(uint32_t e2ees_pack_id)
{
    tear_up();

    // create session and two addresses
    E2ees__Session *session = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    E2ees__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, e2ees_pack_id, from, to);
    copy_address_from_address(&(session->our_address), from);

    // create mock public keys
    session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session->pre_shared_input_list[0].len = 32;
    session->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    ProtobufCBinaryData their_ratchet_key;
    their_ratchet_key.len = 32;
    their_ratchet_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(their_ratchet_key.data, "11111111111111111111111111111111", 32);
    E2ees__KeyPair *our_ratchet_key = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    ProtobufCBinaryData their_encaps_ciphertext;
    their_encaps_ciphertext.len = 32;
    their_encaps_ciphertext.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(their_encaps_ciphertext.data, "11111111111111111111111111111111", 32);

    initialise_as_alice(&(session->ratchet), test_cipher_suite, secret, 128, our_ratchet_key, &their_ratchet_key, &their_encaps_ciphertext);

    // insert to the db
    store_session(session);

    // load_outbound_session
    E2ees__Session *session_copy;
    load_outbound_session(from, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_equal_ratchet_outbound", is_equal_ratchet(session->ratchet, session_copy->ratchet));

    // free
    e2ees__e2ee_address__free_unpacked(from, NULL);
    e2ees__e2ee_address__free_unpacked(to, NULL);
    e2ees__session__free_unpacked(session, NULL);
    e2ees__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_equal_ratchet_inbound(uint32_t e2ees_pack_id)
{
    tear_up();

    // create session and two addresses
    E2ees__Session *session = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    E2ees__E2eeAddress *from, *to;
    mock_address(&from, "alice", "alice's domain", "alice's device");
    mock_address(&to, "bob", "bob's domain", "bob's device");
    initialise_session(session, e2ees_pack_id, from, to);
    copy_address_from_address(&(session->our_address), to);

    // create mock public keys
    session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    session->pre_shared_input_list[0].len = 32;
    session->pre_shared_input_list[0].data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(session->pre_shared_input_list[0].data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    session->associated_data.len = 64;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);

    session->session_id = generate_uuid_str();

    // mock ratchet key pairs
    ProtobufCBinaryData their_ratchet_key;
    their_ratchet_key.len = 32;
    their_ratchet_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(their_ratchet_key.data, "11111111111111111111111111111111", 32);
    uint8_t secret[128] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
    E2ees__KeyPair *our_ratchet_key = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(our_ratchet_key);
    our_ratchet_key->private_key.len = 32;
    our_ratchet_key->private_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->private_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    our_ratchet_key->public_key.len = 32;
    our_ratchet_key->public_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);

    initialise_as_bob(&session->ratchet, test_cipher_suite, secret, 128, our_ratchet_key, &their_ratchet_key);

    // insert to the db
    store_session(session);

    // create mock receiver chain
    E2ees__ReceiverChainNode *chain = (E2ees__ReceiverChainNode *)malloc(sizeof(E2ees__ReceiverChainNode));
    e2ees__receiver_chain_node__init(chain);
    chain->chain_key = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
    e2ees__chain_key__init(chain->chain_key);
    chain->chain_key->index = 0;
    chain->chain_key->shared_key.len = 32;
    chain->chain_key->shared_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(chain->chain_key->shared_key.data, "abcdefghijklmnopqrstuvwxyz012345", 32);
    chain->their_ratchet_public_key.len = 32;
    chain->their_ratchet_public_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(chain->their_ratchet_public_key.data, "012345abcdefghijklmnopqrstuvwxyz", 32);
    chain->our_ratchet_private_key.len = 32;
    chain->our_ratchet_private_key.data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(chain->our_ratchet_private_key.data, "abcdefghijkl012345mnopqrstuvwxyz", 32);
    session->ratchet->receiver_chain = chain;

    // store session again
    store_session(session);

    // load_session
    E2ees__Session *session_copy;
    load_session(session->session_id, to, &session_copy);

    // assert session equals to session_copy
    print_result("test_equal_ratchet_inbound", is_equal_ratchet(session->ratchet, session_copy->ratchet));

    // free
    e2ees__e2ee_address__free_unpacked(from, NULL);
    e2ees__e2ee_address__free_unpacked(to, NULL);
    e2ees__session__free_unpacked(session, NULL);
    e2ees__session__free_unpacked(session_copy, NULL);

    tear_down();
}

void test_session_timestamp(uint32_t e2ees_pack_id) {
    tear_up();

    // create sessions
    E2ees__E2eeAddress *from_1, *to_1, *from_2, *to_2;
    mock_address(&from_1, "alice", "alice's domain", "alice's device");
    mock_address(&to_1, "bob", "bob's domain", "bob's device");
    mock_address(&from_2, "claire", "claire's domain", "claire's device");
    mock_address(&to_2, "david", "david's domain", "david's device");

    E2ees__Session *session_1 = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    initialise_session(session_1, e2ees_pack_id, from_1, to_1);
    session_1->session_id = generate_uuid_str();
    session_1->associated_data.len = 64;
    session_1->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session_1->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);
    store_session(session_1);

    E2ees__Session *session_2 = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    initialise_session(session_2, e2ees_pack_id, from_2, to_2);
    session_2->session_id = generate_uuid_str();
    session_2->associated_data.len = 64;
    session_2->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session_2->associated_data.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);
    store_session(session_2);

    sleep(3);

    // modify session_1
    session_1->fingerprint.len = 64;
    session_1->fingerprint.data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memcpy(session_1->fingerprint.data, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl", 64);
    store_session(session_1);

    // unload
    unload_old_session(from_1, to_1, session_1->invite_t);
    unload_old_session(from_2, to_2, session_2->invite_t);

    // free
    e2ees__e2ee_address__free_unpacked(from_1, NULL);
    e2ees__e2ee_address__free_unpacked(to_1, NULL);
    e2ees__session__free_unpacked(session_1, NULL);

    e2ees__e2ee_address__free_unpacked(from_2, NULL);
    e2ees__e2ee_address__free_unpacked(to_2, NULL);
    e2ees__session__free_unpacked(session_2, NULL);

    tear_down();
}

int main(){
    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    test_cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;

    test_load_outbound_session(e2ees_pack_id);
    test_load_outbound_sessions(e2ees_pack_id);
    test_load_session(e2ees_pack_id);
    test_load_group_session_by_address(e2ees_pack_id);
    test_load_group_session_by_id(e2ees_pack_id);
    test_load_group_addresses(e2ees_pack_id);
    test_store_session(e2ees_pack_id);
    test_equal_ratchet_outbound(e2ees_pack_id);
    test_equal_ratchet_inbound(e2ees_pack_id);
    // test_session_timestamp(e2ees_pack_id);

    return 0;
}
