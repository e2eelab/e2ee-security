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

void test_store_and_load_outbound_session() {
    tear_up();

    // initialize
    E2ees__Session dummy_session;
    e2ees__session__init(&dummy_session);

    // mock address(alice)
    E2ees__E2eeAddress our_address;
    e2ees__e2ee_address__init(&our_address);
    E2ees__PeerUser our_user;
    e2ees__peer_user__init(&our_user);
    
    our_user.user_id = "alice";
    our_user.device_id = "device_A";
    our_address.domain = "test.com";
    our_address.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    our_address.user = &our_user;

    // mock address(bob)
    E2ees__E2eeAddress their_address;
    e2ees__e2ee_address__init(&their_address);
    E2ees__PeerUser their_user;
    e2ees__peer_user__init(&their_user);
    
    their_user.user_id = "bob";
    their_user.device_id = "device_B";
    their_address.domain = "test.com";
    their_address.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    their_address.user = &their_user;

    // initialize ratchet
    E2ees__Ratchet dummy_ratchet;
    e2ees__ratchet__init(&dummy_ratchet);
    uint8_t fake_root_key[32] = { 0xDE, 0xAD, 0xBE, 0xEF };
    dummy_ratchet.root_key.data = fake_root_key;
    dummy_ratchet.root_key.len = sizeof(fake_root_key);

    // input date into session
    dummy_session.version = "1.0.0";
    dummy_session.e2ees_pack_id = 999;
    dummy_session.session_id = "session_mock_777";
    dummy_session.our_address = &our_address;
    dummy_session.their_address = &their_address;
    dummy_session.ratchet = &dummy_ratchet;

    // store into db
    store_session(&dummy_session);

    // load
    E2ees__Session *loaded_session = NULL;
    load_outbound_session(&our_address, &their_address, &loaded_session);

    // assert
    bool is_success = false;
    if (loaded_session != NULL) {
        is_success = is_equal_session(&dummy_session, loaded_session);
    } else {
        printf("test_store_and_load_outbound_session: failed (loaded_session is NULL)\n");
    }

    print_result("test_store_and_load_outbound_session", is_success);

    // release
    if (loaded_session != NULL) {
        e2ees__session__free_unpacked(loaded_session, NULL);
        loaded_session = NULL;
    }

    tear_down();
}

void test_store_and_load_session() {
    tear_up();

    E2ees__Session dummy_session;
    e2ees__session__init(&dummy_session);

    E2ees__E2eeAddress our_address;
    e2ees__e2ee_address__init(&our_address);
    E2ees__PeerUser our_user;
    e2ees__peer_user__init(&our_user);
    
    our_user.user_id = "alice";
    our_user.device_id = "device_A";
    our_address.domain = "test.com";
    our_address.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    our_address.user = &our_user;

    E2ees__E2eeAddress their_address;
    e2ees__e2ee_address__init(&their_address);
    E2ees__PeerUser their_user;
    e2ees__peer_user__init(&their_user);
    
    their_user.user_id = "bob";
    their_user.device_id = "device_B";
    their_address.domain = "test.com";
    their_address.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    their_address.user = &their_user;

    E2ees__Ratchet dummy_ratchet;
    e2ees__ratchet__init(&dummy_ratchet);
    uint8_t fake_root_key[32] = { 0xDE, 0xAD, 0xBE, 0xEF };
    dummy_ratchet.root_key.data = fake_root_key;
    dummy_ratchet.root_key.len = sizeof(fake_root_key);

    dummy_session.version = "1.0.0";
    dummy_session.e2ees_pack_id = 999;
    dummy_session.session_id = "session_mock_777";
    dummy_session.our_address = &our_address;
    dummy_session.their_address = &their_address;
    dummy_session.ratchet = &dummy_ratchet;

    store_session(&dummy_session);

    E2ees__Session *loaded_session = NULL;
    load_session("session_mock_777", &our_address, &loaded_session);

    bool is_success = false;
    if (loaded_session != NULL) {
        is_success = is_equal_session(&dummy_session, loaded_session);
    } else {
        printf("test_store_and_load_session: failed (loaded_session is NULL)\n");
    }
    
    print_result("test_store_and_load_session", is_success);

    if (loaded_session != NULL) {
        e2ees__session__free_unpacked(loaded_session, NULL);
        loaded_session = NULL;
    }

    tear_down();
}

void test_store_and_load_outbound_sessions() {
    tear_up();

    E2ees__Session dummy_session;
    e2ees__session__init(&dummy_session);

    E2ees__E2eeAddress our_address;
    e2ees__e2ee_address__init(&our_address);
    E2ees__PeerUser our_user;
    e2ees__peer_user__init(&our_user);
    
    our_user.user_id = "alice";
    our_user.device_id = "device_A";
    our_address.domain = "test.com";
    our_address.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    our_address.user = &our_user;

    E2ees__E2eeAddress their_address;
    e2ees__e2ee_address__init(&their_address);
    E2ees__PeerUser their_user;
    e2ees__peer_user__init(&their_user);
    
    their_user.user_id = "bob"; 
    their_user.device_id = "device_B";
    their_address.domain = "test.com";
    their_address.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    their_address.user = &their_user;

    E2ees__Ratchet dummy_ratchet;
    e2ees__ratchet__init(&dummy_ratchet);
    uint8_t fake_root_key[32] = { 0xDE, 0xAD, 0xBE, 0xEF };
    dummy_ratchet.root_key.data = fake_root_key;
    dummy_ratchet.root_key.len = sizeof(fake_root_key);

    dummy_session.version = "1.0.0";
    dummy_session.e2ees_pack_id = 999;
    dummy_session.session_id = "session_mock_777";
    dummy_session.our_address = &our_address;
    dummy_session.their_address = &their_address;
    dummy_session.ratchet = &dummy_ratchet;

    store_session(&dummy_session);

    E2ees__Session **loaded_sessions = NULL;

    size_t count = load_outbound_sessions(&our_address, "bob", "test.com", &loaded_sessions);

    bool is_success = false;

    if (count > 0 && loaded_sessions != NULL && loaded_sessions[0] != NULL) {
        is_success = is_equal_session(&dummy_session, loaded_sessions[0]);
    } else {
        printf("test_store_and_load_outbound_sessions: failed (count is 0 or array is NULL)\n");
    }
    
    print_result("test_store_and_load_outbound_sessions", is_success);

    if (loaded_sessions != NULL) {
        for (size_t i = 0; i < count; i++) {
            if (loaded_sessions[i] != NULL) {
                e2ees__session__free_unpacked(loaded_sessions[i], NULL); 
            }
        }
        free_mem((void **)&loaded_sessions, sizeof(E2ees__Session *) * count); 
    }

    tear_down();
}

void test_load_group_session_by_address() {
    tear_up();

    // sender (Alice)
    E2ees__E2eeAddress sender_addr;
    e2ees__e2ee_address__init(&sender_addr);
    E2ees__PeerUser sender_user;
    e2ees__peer_user__init(&sender_user);
    sender_user.user_id = "alice";
    sender_addr.domain = "test.com";
    sender_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    sender_addr.user = &sender_user;

    // owner (Bob)
    E2ees__E2eeAddress owner_addr;
    e2ees__e2ee_address__init(&owner_addr);
    E2ees__PeerUser owner_user;
    e2ees__peer_user__init(&owner_user);
    owner_user.user_id = "bob";
    owner_addr.domain = "test.com";
    owner_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    owner_addr.user = &owner_user;

    // group address (Group 1)
    E2ees__E2eeAddress group_addr;
    e2ees__e2ee_address__init(&group_addr);
    E2ees__PeerGroup group_peer; 
    e2ees__peer_group__init(&group_peer);
    group_peer.group_name = "Top Secret Avengers";
    group_peer.group_id = "group_123";
    group_addr.domain = "test.com";
    group_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_addr.group = &group_peer;

    // group members
    E2ees__GroupMember member1;
    e2ees__group_member__init(&member1);
    member1.user_id = "alice";
    member1.domain = "test.com";
    member1.role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    
    E2ees__GroupMember *members_array[1] = { &member1 };

    // group info
    E2ees__GroupInfo group_info;
    e2ees__group_info__init(&group_info);
    group_info.group_name = "Top Secret Avengers";
    group_info.group_address = &group_addr;
    group_info.n_group_member_list = 1;
    group_info.group_member_list = members_array;

    // group session
    E2ees__GroupSession dummy_group_session;
    e2ees__group_session__init(&dummy_group_session);
    dummy_group_session.version = "1.0.0";
    dummy_group_session.e2ees_pack_id = 999;
    dummy_group_session.session_id = "group_session_mock_777";
    dummy_group_session.sender = &sender_addr;
    dummy_group_session.session_owner = &owner_addr;
    dummy_group_session.group_info = &group_info;

    uint8_t fake_key[32] = { 0xAA, 0xBB, 0xCC };
    dummy_group_session.chain_key.data = fake_key;
    dummy_group_session.chain_key.len = sizeof(fake_key);
    dummy_group_session.group_seed.data = fake_key;
    dummy_group_session.group_seed.len = sizeof(fake_key);

    store_group_session(&dummy_group_session);

    E2ees__GroupSession *loaded_session = NULL;
    load_group_session_by_address(&sender_addr, &owner_addr, &group_addr, &loaded_session);

    bool is_success = false;
    if (loaded_session != NULL) {
        is_success = is_equal_group_session(&dummy_group_session, loaded_session);
    } else {
        printf("test_load_group_session_by_address: failed (loaded_session is NULL)\n");
    }

    print_result("test_load_group_session_by_address", is_success);

    if (loaded_session != NULL) {
        e2ees__group_session__free_unpacked(loaded_session, NULL);
        loaded_session = NULL;
    }

    tear_down();
}

void test_load_group_session_by_id() {
    tear_up();

    // sender (Alice)
    E2ees__E2eeAddress sender_addr;
    e2ees__e2ee_address__init(&sender_addr);
    E2ees__PeerUser sender_user;
    e2ees__peer_user__init(&sender_user);
    sender_user.user_id = "alice";
    sender_addr.domain = "test.com";
    sender_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    sender_addr.user = &sender_user;

    // owner (Bob)
    E2ees__E2eeAddress owner_addr;
    e2ees__e2ee_address__init(&owner_addr);
    E2ees__PeerUser owner_user;
    e2ees__peer_user__init(&owner_user);
    owner_user.user_id = "bob";
    owner_addr.domain = "test.com";
    owner_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    owner_addr.user = &owner_user;

    // group address (Group 1)
    E2ees__E2eeAddress group_addr;
    e2ees__e2ee_address__init(&group_addr);
    E2ees__PeerGroup group_peer; 
    e2ees__peer_group__init(&group_peer);
    group_peer.group_name = "Top Secret Avengers";
    group_peer.group_id = "group_123";
    group_addr.domain = "test.com";
    group_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_addr.group = &group_peer;

    // group members
    E2ees__GroupMember member1;
    e2ees__group_member__init(&member1);
    member1.user_id = "alice";
    member1.domain = "test.com";
    member1.role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    
    E2ees__GroupMember *members_array[1] = { &member1 };

    // group info
    E2ees__GroupInfo group_info;
    e2ees__group_info__init(&group_info);
    group_info.group_name = "Top Secret Avengers";
    group_info.group_address = &group_addr;
    group_info.n_group_member_list = 1;
    group_info.group_member_list = members_array;

    // group session
    E2ees__GroupSession dummy_group_session;
    e2ees__group_session__init(&dummy_group_session);
    dummy_group_session.version = "1.0.0";
    dummy_group_session.e2ees_pack_id = 999;
    dummy_group_session.session_id = "group_session_mock_777";
    dummy_group_session.sender = &sender_addr;
    dummy_group_session.session_owner = &owner_addr;
    dummy_group_session.group_info = &group_info;

    uint8_t fake_key[32] = { 0xAA, 0xBB, 0xCC };
    dummy_group_session.chain_key.data = fake_key;
    dummy_group_session.chain_key.len = sizeof(fake_key);
    dummy_group_session.group_seed.data = fake_key;
    dummy_group_session.group_seed.len = sizeof(fake_key);

    store_group_session(&dummy_group_session);

    E2ees__GroupSession *loaded_session = NULL;
    load_group_session_by_id(&sender_addr, &owner_addr, "group_session_mock_777", &loaded_session);

    bool is_success = false;
    if (loaded_session != NULL) {
        is_success = is_equal_group_session(&dummy_group_session, loaded_session);
    } else {
        printf("test_load_group_session_by_id: failed (loaded_session is NULL)\n");
    }
    
    print_result("test_load_group_session_by_id", is_success);

    if (loaded_session != NULL) {
        e2ees__group_session__free_unpacked(loaded_session, NULL);
        loaded_session = NULL;
    }

    tear_down();
}

void test_load_group_addresses() {
    tear_up();

    // sender (Alice)
    E2ees__E2eeAddress sender_addr;
    e2ees__e2ee_address__init(&sender_addr);
    E2ees__PeerUser sender_user;
    e2ees__peer_user__init(&sender_user);
    sender_user.user_id = "alice";
    sender_addr.domain = "test.com";
    sender_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    sender_addr.user = &sender_user;

    // owner (Bob)
    E2ees__E2eeAddress owner_addr;
    e2ees__e2ee_address__init(&owner_addr);
    E2ees__PeerUser owner_user;
    e2ees__peer_user__init(&owner_user);
    owner_user.user_id = "bob";
    owner_addr.domain = "test.com";
    owner_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    owner_addr.user = &owner_user;

    // group address (Group 1)
    E2ees__E2eeAddress group_addr;
    e2ees__e2ee_address__init(&group_addr);
    E2ees__PeerGroup group_peer; 
    e2ees__peer_group__init(&group_peer);
    group_peer.group_name = "Top Secret Avengers";
    group_peer.group_id = "group_123";
    group_addr.domain = "test.com";
    group_addr.peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_addr.group = &group_peer;

    // group members
    E2ees__GroupMember member1;
    e2ees__group_member__init(&member1);
    member1.user_id = "alice";
    member1.domain = "test.com";
    member1.role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    
    E2ees__GroupMember *members_array[1] = { &member1 };

    // group info
    E2ees__GroupInfo group_info;
    e2ees__group_info__init(&group_info);
    group_info.group_name = "Top Secret Avengers";
    group_info.group_address = &group_addr;
    group_info.n_group_member_list = 1;
    group_info.group_member_list = members_array;

    // group session
    E2ees__GroupSession dummy_group_session;
    e2ees__group_session__init(&dummy_group_session);
    dummy_group_session.version = "1.0.0";
    dummy_group_session.e2ees_pack_id = 999;
    dummy_group_session.session_id = "group_session_mock_777";
    dummy_group_session.sender = &sender_addr;
    dummy_group_session.session_owner = &owner_addr;
    dummy_group_session.group_info = &group_info;

    uint8_t fake_key[32] = { 0xAA, 0xBB, 0xCC };
    dummy_group_session.chain_key.data = fake_key;
    dummy_group_session.chain_key.len = sizeof(fake_key);
    dummy_group_session.group_seed.data = fake_key;
    dummy_group_session.group_seed.len = sizeof(fake_key);

    store_group_session(&dummy_group_session);

    E2ees__E2eeAddress **loaded_addresses = NULL;
    
    size_t count = load_group_addresses(&sender_addr, &owner_addr, &loaded_addresses);

    bool is_success = false;
    if (count > 0 && loaded_addresses != NULL && loaded_addresses[0] != NULL) {
        is_success = compare_address(&group_addr, loaded_addresses[0]);
    } else {
        printf("test_load_group_addresses: failed (count is 0 or array is NULL)\n");
    }
    
    print_result("test_load_group_addresses", is_success);

    if (loaded_addresses != NULL) {
        for (size_t i = 0; i < count; i++) {
            if (loaded_addresses[i] != NULL) {
                e2ees__e2ee_address__free_unpacked(loaded_addresses[i], NULL); 
            }
        }
        free_mem((void **)&loaded_addresses, sizeof(E2ees__E2eeAddress *) * count); 
    }

    tear_down();
}

int main(){
    test_store_and_load_outbound_session();
    test_store_and_load_session();
    test_store_and_load_outbound_sessions();
    test_load_group_session_by_address();
    test_load_group_session_by_id();
    test_load_group_addresses();

    return 0;
}
