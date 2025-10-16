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
 * 
 * @defgroup new_device_int new device test
 * @ingroup Integration
 * This includes integration tests about session.
 * 
 * @defgroup new_device_test_two_members_session two members test
 * @ingroup new_device_int
 * @{
 * @section sec51001 Test Case ID
 * v1.0ind01
 * @section sec51002 Test Case Title
 * test_two_members_session
 * @section sec51003 Test Description
 * Alice and Bob establish their session. Alice adds a new device.
 * @section sec51004 Test Objectives
 * To assure that the session still works after one member adds a new device.
 * @section sec51005 Preconditions
 * @section sec51006 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice adds a new device.\n
 * Step 3: Alice sends a message to Bob.\n
 * Step 4: Bob decrypts the message.
 * @section sec51007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup new_device_test_two_members_four_devices two members and four devices test
 * @ingroup new_device_int
 * @{
 * @section sec51101 Test Case ID
 * v1.0ind02
 * @section sec51102 Test Case Title
 * test_two_members_four_devices
 * @section sec51103 Test Description
 * Alice and Bob establish their session. Alice and Bob add a new device respectively.
 * @section sec51104 Test Objectives
 * To assure that the session still works after the two members both add a new device.
 * @section sec51105 Preconditions
 * @section sec51106 Test Steps
 * Step 1: Alice invites Bob to create a session.\n
 * Step 2: Alice adds a new device.\n
 * Step 3: Alice and Bob send a message to each other.\n
 * Step 4: Bob adds a new device.\n
 * Step 5: Alice and Bob send a message to each other.
 * @section sec51107 Expected Results
 * No output.
 * @}
 * 
 * @defgroup new_device_test_multiple_devices multiple devices test
 * @ingroup new_device_int
 * @{
 * @section sec51201 Test Case ID
 * v1.0ind03
 * @section sec51202 Test Case Title
 * test_multiple_devices
 * @section sec51203 Test Description
 * Alice has two devices while Bob has one device. Alice adds a new device.
 * @section sec51204 Test Objectives
 * To assure that the session still works after one member adds a new device.
 * @section sec51205 Preconditions
 * @section sec51206 Test Steps
 * Step 1: Alice registers two devices and Bob register one device.\n
 * Step 2: Alice invites Bob to create a session.\n
 * Step 3: Alice adds a new device.\n
 * Step 4: Bob sends a message to Alice.
 * @section sec51207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup new_device_test_several_members_and_groups several members and groups test
 * @ingroup new_device_int
 * @{
 * @section sec51401 Test Case ID
 * v1.0ind04
 * @section sec51402 Test Case Title
 * test_several_members_and_groups
 * @section sec51403 Test Description
 * There are some members and groups in this test.
 * @section sec51404 Test Objectives
 * To assure that several sessions and group sessions can work.
 * @section sec51405 Preconditions
 * @section sec51406 Test Steps
 * 
 * @section sec51407 Expected Results
 * No output.
 * @}
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "e2ees/e2ees_client.h"
#include "e2ees/mem_util.h"

#include "mock_server_sending.h"
#include "test_util.h"
#include "test_plugin.h"

#define account_data_max 20
#define group_max 10

static E2ees__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

static uint8_t test_plaintext[] = "New devices test!!!";
static size_t test_plaintext_len;

static void on_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    // print_log((char *)log_msg, log_code);
}

static void on_user_registered(E2ees__Account *account){
    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from) {
    // printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *inbound_session){
    // if (inbound_session->f2f == true) {
    //     printf("the face-to-face inbound session is ready\n");
    // } else {
    //     printf("on_inbound_session_ready\n");
    // }
}

static void on_outbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *outbound_session){
    // if (outbound_session->f2f == true) {
    //     printf("the face-to-face outbound session is ready\n");
    // } else {
    //     printf("on_outbound_session_ready\n");
    // }
}

static void on_one2one_msg_received(
    E2ees__E2eeAddress *user_address, 
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    // printf("%s received the message!\n", to_address->user->user_name);
}

static void on_other_device_msg_received(
    E2ees__E2eeAddress *user_address, 
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    // printf("%s received the message from other devices!\n", to_address->user->user_name);
}

static void on_group_msg_received(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *group_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
    // printf("%s received the message from a group member!\n", user_address->user->user_name);
}

static void on_group_created(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num
) {
    // print_msg("on_group_created: group_name", (uint8_t *)group_name, strlen(group_name));
}

static void on_group_members_added(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **added_group_members, size_t added_group_members_num
) {
    // print_msg("on_group_members_added: group_name", (uint8_t *)group_name, strlen(group_name));
    // size_t i;
    // for (i = 0; i < added_group_members_num; i++) {
    //     print_msg("    member_id", (uint8_t *)(added_group_members[i]->user_id), strlen(added_group_members[i]->user_id));
    // }
}

static void on_group_members_removed(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **removed_group_members, size_t removed_group_members_num
) {
    // print_msg("on_group_members_removed: group_name", (uint8_t *)group_name, strlen(group_name));
    // size_t i;
    // for (i = 0; i < removed_group_members_num; i++) {
    //     print_msg("    member_id", (uint8_t *)(removed_group_members[i]->user_id), strlen(removed_group_members[i]->user_id));
    // }
}

static e2ees_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    on_other_device_msg_received,
    on_group_msg_received,
    on_group_created,
    on_group_members_added,
    on_group_members_removed
};

static void test_begin(){
    test_plaintext_len = sizeof(test_plaintext) - 1;

    int i;
    for (i = 0; i < account_data_max; i++) {
        account_data[i] = NULL;
    }
    account_data_insert_pos = 0;

    get_e2ees_plugin()->event_handler = test_event_handler;

    start_mock_server_sending();
}

static void test_end(){
    stop_mock_server_sending();

    int i;
    for (i = 0; i < account_data_max; i++) {
        if (account_data[i] != NULL) {
            e2ees__account__free_unpacked(account_data[i], NULL);
            account_data[i] = NULL;
        }
    }
    account_data_insert_pos = 0;
}

static void mock_user_pqc_account(const char *user_name, const char *authenticator, const char *auth_code) {
    int ret = 0;
    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    char *device_id = generate_uuid_str();
    E2ees__RegisterUserResponse *response = NULL;
    ret = register_user(
        &response,
        e2ees_pack_id,
        user_name,
        user_name,
        device_id,
        authenticator,
        auth_code
    );
    assert(ret == 0);

    // release
    free(device_id);
    e2ees__register_user_response__free_unpacked(response, NULL);
}

static void test_encryption(
    E2ees__E2eeAddress *from_address, const char *to_user_id, const char *to_domain,
    uint8_t *plaintext, size_t plaintext_len
) {
    // send encrypted msg
    E2ees__SendOne2oneMsgResponse *response = NULL;
    int ret = send_one2one_msg(
        &response,
        from_address, to_user_id, to_domain,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext, plaintext_len);

    // release
    e2ees__send_one2one_msg_response__free_unpacked(response, NULL);
}

static void test_group_encryption(
    E2ees__E2eeAddress *sender_address, E2ees__E2eeAddress *group_address,
    uint8_t *plaintext_data, size_t plaintext_data_len
) {
    E2ees__SendGroupMsgResponse *response = NULL;
    int ret = send_group_msg(
        &response,
        sender_address, group_address,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext_data, plaintext_data_len
    );

    // release
    e2ees__send_group_msg_response__free_unpacked(response, NULL);
}

static void test_two_members_session() {
    // print test case
    print_test_case("v1.0ind01", "test_two_members_session");

    tear_up();
    test_begin();

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");

    E2ees__E2eeAddress *alice_address = account_data[0]->address;
    char *alice_user_id = alice_address->user->user_id;
    char *alice_domain = alice_address->domain;
    E2ees__E2eeAddress *bob_address = account_data[1]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    // Alice invites Bob to create a session
    E2ees__InviteResponse *invite_response = invite(alice_address, bob_user_id, bob_domain);

    sleep(1);

    // Alice add a new device
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    E2ees__E2eeAddress *device_2 = account_data[2]->address;

    sleep(1);
    // Alice sends an encrypted message to Bob
    test_encryption(device_2, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // release
    free_proto(invite_response);

    // test stop
    test_end();
    tear_down();
    print_test_case_final();
}

static void test_two_members_four_devices() {
    // print test case
    print_test_case("v1.0ind02", "test_two_members_four_devices");

    tear_up();
    test_begin();

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");

    E2ees__E2eeAddress *alice_device_1 = account_data[0]->address;
    char *alice_user_id = alice_device_1->user->user_id;
    char *alice_domain = alice_device_1->domain;
    E2ees__E2eeAddress *bob_device_1 = account_data[1]->address;
    char *bob_user_id = bob_device_1->user->user_id;
    char *bob_domain = bob_device_1->domain;

    // Alice invites Bob to create a session
    E2ees__InviteResponse *invite_response = invite(alice_device_1, bob_user_id, bob_domain);

    sleep(3);

    // Alice sends a message to Bob
    test_encryption(alice_device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // Bob sends a message to Alice
    test_encryption(bob_device_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    sleep(2);

    // Alice adds a new device
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    E2ees__E2eeAddress *alice_device_2 = account_data[2]->address;

    sleep(1);

    // Alice uses the first device to send a message
    test_encryption(alice_device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    // Alice uses the second device to send a message
    test_encryption(alice_device_2, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    // Bob sends a message
    test_encryption(bob_device_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    sleep(2);

    // Bob adds a new device
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");

    E2ees__E2eeAddress *bob_device_2 = account_data[3]->address;

    sleep(1);

    // Bob uses the first device to send a message
    test_encryption(bob_device_1, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);
    // Bob uses the second device to send a message
    test_encryption(bob_device_2, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);
    // Alice uses the first device to send a message
    test_encryption(alice_device_1, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);
    // Alice uses the second device to send a message
    test_encryption(alice_device_2, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

    // release
    free_proto(invite_response);

    // test stop
    test_end();
    tear_down();
    print_test_case_final();
}

static void test_multiple_devices() {
    // print test case
    print_test_case("v1.0ind03", "test_multiple_devices");

    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");

    E2ees__E2eeAddress *alice_address_1 = account_data[0]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    E2ees__E2eeAddress *alice_address_2 = account_data[1]->address;

    E2ees__E2eeAddress *bob_address = account_data[2]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    E2ees__InviteResponse *invite_response = invite(alice_address_1, bob_user_id, bob_domain);

    sleep(3);

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    sleep(3);

    test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // release
    free_proto(invite_response);

    // test stop
    test_end();
    tear_down();
    print_test_case_final();
}

static void test_several_members_and_groups() {
    // print test case
    print_test_case("v1.0ind04", "test_several_members_and_groups");

    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");
    mock_user_pqc_account("Frank", "frank@domain.com.tw", "678901");

    sleep(5);

    E2ees__E2eeAddress *alice_address_1 = account_data[0]->address;
    char *alice_user_id = alice_address_1->user->user_id;
    char *alice_domain = alice_address_1->domain;
    E2ees__E2eeAddress *alice_address_2 = account_data[1]->address;

    E2ees__E2eeAddress *bob_address = account_data[2]->address;
    char *bob_user_id = bob_address->user->user_id;
    char *bob_domain = bob_address->domain;

    E2ees__E2eeAddress *claire_address_1 = account_data[3]->address;
    char *claire_user_id = claire_address_1->user->user_id;
    char *claire_domain = claire_address_1->domain;
    E2ees__E2eeAddress *claire_address_2 = account_data[4]->address;

    E2ees__E2eeAddress *david_address = account_data[5]->address;
    char *david_user_id = david_address->user->user_id;
    char *david_domain = david_address->domain;

    E2ees__E2eeAddress *emily_address_1 = account_data[6]->address;
    char *emily_user_id = emily_address_1->user->user_id;
    char *emily_domain = emily_address_1->domain;
    E2ees__E2eeAddress *emily_address_2 = account_data[7]->address;

    E2ees__E2eeAddress *frank_address = account_data[8]->address;
    char *frank_user_id = frank_address->user->user_id;
    char *frank_domain = frank_address->domain;

    // some invitation
    E2ees__InviteResponse *response_1 = invite(alice_address_1, bob_user_id, bob_domain);
    E2ees__InviteResponse *response_2 = invite(alice_address_2, claire_user_id, claire_domain);

    E2ees__InviteResponse *response_3 = invite(david_address, emily_user_id, emily_domain);

    E2ees__InviteResponse *response_4 = invite(frank_address, alice_user_id, alice_domain);
    E2ees__InviteResponse *response_5 = invite(emily_address_2, frank_user_id, frank_domain);

    sleep(3);

    // Alice, Bob and Claire create a group
    E2ees__GroupMember **group_members_1 = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 3);
    group_members_1[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members_1[0]);
    group_members_1[0]->user_id = strdup(alice_user_id);
    group_members_1[0]->domain = strdup(alice_domain);
    group_members_1[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members_1[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members_1[1]);
    group_members_1[1]->user_id = strdup(bob_user_id);
    group_members_1[1]->domain = strdup(bob_domain);
    group_members_1[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    group_members_1[2] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members_1[2]);
    group_members_1[2]->user_id = strdup(claire_user_id);
    group_members_1[2]->domain = strdup(claire_domain);
    group_members_1[2]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    E2ees__CreateGroupResponse *create_group_response_1 = NULL;
    create_group(&create_group_response_1, alice_address_1, "The first group", group_members_1, 3);

    sleep(2);

    // Alice, Emily and Frank create a group
    E2ees__GroupMember **group_members_2 = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 3);
    group_members_2[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members_2[0]);
    group_members_2[0]->user_id = strdup(frank_user_id);
    group_members_2[0]->domain = strdup(frank_domain);
    group_members_2[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    group_members_2[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members_2[1]);
    group_members_2[1]->user_id = strdup(emily_user_id);
    group_members_2[1]->domain = strdup(emily_domain);
    group_members_2[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    group_members_2[2] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members_2[2]);
    group_members_2[2]->user_id = strdup(alice_user_id);
    group_members_2[2]->domain = strdup(alice_domain);
    group_members_2[2]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    // create the group
    E2ees__CreateGroupResponse *create_group_response_2 = NULL;
    create_group(&create_group_response_2, frank_address, "The second group", group_members_2, 3);

    sleep(2);

    // Alice adds a new device
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    // Emily adds a new device
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");

    sleep(3);

    // Bob sends a message to Alice
    test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

    // Alice sends a message to the first group
    test_group_encryption(alice_address_1, create_group_response_1->group_address, test_plaintext, test_plaintext_len);

    // Frank sends a message to the second group
    test_group_encryption(frank_address, create_group_response_2->group_address, test_plaintext, test_plaintext_len);

    // Emily sends a message to David
    test_encryption(emily_address_2, david_user_id, david_domain, test_plaintext, test_plaintext_len);

    // release
    if (response_1 != NULL) {
        e2ees__invite_response__free_unpacked(response_1, NULL);
        response_1 = NULL;
    }
    if (response_2 != NULL) {
        e2ees__invite_response__free_unpacked(response_2, NULL);
        response_2 = NULL;
    }
    if (response_3 != NULL) {
        e2ees__invite_response__free_unpacked(response_3, NULL);
        response_3 = NULL;
    }
    if (response_4 != NULL) {
        e2ees__invite_response__free_unpacked(response_4, NULL);
        response_4 = NULL;
    }
    if (response_5 != NULL) {
        e2ees__invite_response__free_unpacked(response_5, NULL);
        response_5 = NULL;
    }
    e2ees__group_member__free_unpacked(group_members_1[0], NULL);
    e2ees__group_member__free_unpacked(group_members_1[1], NULL);
    e2ees__group_member__free_unpacked(group_members_1[2], NULL);
    free(group_members_1);
    e2ees__group_member__free_unpacked(group_members_2[0], NULL);
    e2ees__group_member__free_unpacked(group_members_2[1], NULL);
    e2ees__group_member__free_unpacked(group_members_2[2], NULL);
    free(group_members_2);
    e2ees__create_group_response__free_unpacked(create_group_response_1, NULL);
    e2ees__create_group_response__free_unpacked(create_group_response_2, NULL);

    // test stop
    test_end();
    tear_down();
    print_test_case_final();
}

int main() {
    test_two_members_session();
    test_two_members_four_devices();
    test_multiple_devices();
    test_several_members_and_groups();
    return 0;
}
