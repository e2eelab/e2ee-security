/**
 * @file
 * @copyright © 2020-2021 by Academia Sinica
 * @brief account test
 *
 * @page test_account account documentation
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
 * @section test_create_accounts
 * Test if we can create accounts.
 * 
 * @section test_register_user
 * This can check if a client can register or not.
 * 
 * @section test_publish_spk
 * If the signed pre-key is expired, the client should generate a new signed pre-key and publish it to the server.
 * 
 * @section test_supply_opks
 * The client will be notified to generate a number of one-time pre-keys if the server finds that the one-time pre-keys are used up.
 * 
 * 
 * 
 * @defgroup Unit Unit test
 * This includes unit tests.
 * 
 * @defgroup Integration Integration test
 * This includes integration tests.
 * 
 * 
 * @defgroup account_unit account unit test
 * @ingroup Unit
 * This includes unit tests about account.
 * 
 * @defgroup generate_identity_key generate identity key test
 * @ingroup account_unit
 * @{
 * @section sec10201 Test Case ID
 * v1.0ua01
 * @section sec10202 Test Case Title
 * generate_identity_key
 * @section sec10203 Test Description
 * Given an e2ee pack ID, generate an identity key pair.
 * @section sec10204 Test Objectives
 * To verify the functionality of the function generate_identity_key.
 * @section sec10205 Preconditions
 * @section sec10206 Test Steps
 * Step 1: Determine an e2ee pack ID.\n
 * Step 2: Generate an identity key pair.
 * @section sec10207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup generate_signed_pre_key generate signed pre-key test
 * @ingroup account_unit
 * @{
 * @section sec10301 Test Case ID
 * v1.0ua02
 * @section sec10302 Test Case Title
 * generate_signed_pre_key
 * @section sec10303 Test Description
 * Given an e2ee pack ID, generate a signed pre-key pair and a signature.
 * @section sec10304 Test Objectives
 * To verify the functionality of the function generate_signed_pre_key.
 * @section sec10305 Preconditions
 * @section sec10306 Test Steps
 * Step 1: Determine an e2ee pack ID.\n
 * Step 2: Generate an identity key pair.\n
 * Step 3: Generate a signed pre-key pair and a signature.
 * @section sec10307 Expected Results
 * No output.
 * @}
 * 
 * @defgroup generate_opks generate one-time pre-key test
 * @ingroup account_unit
 * @{
 * @section sec10401 Test Case ID
 * v1.0ua03
 * @section sec10402 Test Case Title
 * generate_opks
 * @section sec10403 Test Description
 * Given an e2ee pack ID, generate a certain number of one-time pre-key pairs.
 * @section sec10404 Test Objectives
 * To verify the functionality of the function generate_opks.
 * @section sec10405 Preconditions
 * @section sec10406 Test Steps
 * Step 1: Determine an e2ee pack ID and the number of keys to be generated.\n
 * Step 2: Generate a certain number of one-time pre-key pairs.
 * @section sec10407 Expected Results
 * No output.
 * @}
 * 
 * @defgroup create_account create account test
 * @ingroup account_unit
 * @{
 * @section sec10501 Test Case ID
 * v1.0ua04
 * @section sec10502 Test Case Title
 * create_account
 * @section sec10503 Test Description
 * Given an e2ee pack ID, create an account.
 * @section sec10504 Test Objectives
 * To verify the functionality of the function create_account.
 * @section sec10505 Preconditions
 * @section sec10506 Test Steps
 * Step 1: Determine an e2ee pack ID.\n
 * Step 2: Generate an account.
 * @section sec10507 Expected Results
 * No output.
 * @}
 * 
 * 
 * @defgroup account_int account integration test
 * @ingroup Integration
 * This includes integration tests about account.
 * 
 * @defgroup account_test_create_accounts create account test
 * @ingroup account_int
 * @{
 * @section sec11001 Test Case ID
 * v1.0ia01
 * @section sec11002 Test Case Title
 * test_create_accounts
 * @section sec11003 Test Description
 * This test case generates a certain number, given by the input, of accounts.
 * @section sec11004 Test Objectives
 * To assure that this device can create several accounts.
 * @section sec11005 Preconditions
 * The input parameter num should be inserted.
 * @section sec11006 Test Steps
 * Step 1: Input the parameter num, the number of accounts to be created.\n
 * Step 2: Create the accounts.
 * @section sec11007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup account_test_register_user register user test
 * @ingroup account_int
 * @{
 * @section sec11101 Test Case ID
 * v1.0ia02
 * @section sec11102 Test Case Title
 * test_register_user
 * @section sec11103 Test Description
 * To call the function register_user with given inputs.
 * @section sec11104 Test Objectives
 * To verify the functionality of the function register_user.
 * @section sec11105 Preconditions
 * @section sec11106 Test Steps
 * Step 1: Generate the address, including the user name, user id, device id, etc.\n
 * Step 2: Register.
 * @section sec11107 Expected Results
 * No output.
 * @}
 * 
 * @defgroup account_test_publish_spk publish spk test
 * @ingroup account_int
 * @{
 * @section sec11201 Test Case ID
 * v1.0ia03
 * @section sec11202 Test Case Title
 * test_publish_spk
 * @section sec11203 Test Description
 * A registered account will generate a new pair of signed pre-key pair and publish the public part of the key pair and the signature to the server.
 * @section sec11204 Test Objectives
 * To verify the functionality of the function publish_spk_internal.
 * @section sec11205 Preconditions
 * @section sec11206 Test Steps
 * Step 1: Register.\n
 * Step 2: Generate a new pair of signed pre-key.\n
 * Step 3: Pulish the public part of signed pre-key pair to the server.
 * @section sec11207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup account_test_supply_opks supply opks test
 * @ingroup account_int
 * @{
 * @section sec11301 Test Case ID
 * v1.0ia04
 * @section sec11302 Test Case Title
 * test_supply_opks
 * @section sec11303 Test Description
 * The server notifies the client to generate a number of one-time pre-keys.
 * @section sec11304 Test Objectives
 * To assure that the procedure of supplying one-time pre-keys is correct.
 * @section sec11305 Preconditions
 * @section sec11306 Test Steps
 * Step 1: Register.\n
 * Step 2: Server notifies this device to generate some one-time pre-key pairs.\n
 * Step 3: Generate the one-time pre-key pairs and publish them to the server.
 * @section sec11307 Expected Results
 * No output.
 * @}
 * 
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include "e2ees/account.h"
#include "e2ees/cipher.h"
#include "e2ees/crypto.h"
#include "e2ees/mem_util.h"
#include "e2ees/e2ees.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/e2ees_client_internal.h"

#include "test_plugin.h"
#include "test_util.h"

static void on_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static void on_user_registered(E2ees__Account *account){
    print_msg("on_user_registered: user_id", (uint8_t *)account->address->user->user_id, strlen(account->address->user->user_id));
}

static e2ees_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

///-----------------unit test-----------------///

static void test_generate_identity_key() {
    // test start
    printf("====== test_generate_identity_key ======\n");

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    int ret = 0;

    E2ees__IdentityKey *identity_key = NULL;
    ret = generate_identity_key(&identity_key, e2ees_pack_id);
    assert(ret == 0);

    // release
    free_proto(identity_key);

    // test stop
    printf("====================================\n");
}

static void test_generate_signed_pre_key() {
    // test start
    printf("====== test_generate_signed_pre_key ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    int ret = 0;

    E2ees__IdentityKey *identity_key = NULL;
    E2ees__SignedPreKey *signed_pre_key = NULL;
    generate_identity_key(&identity_key, e2ees_pack_id);
    ret = generate_signed_pre_key(&signed_pre_key, e2ees_pack_id, 0, identity_key->sign_key_pair->private_key.data);
    assert(ret == 0);

    // release
    free_proto(identity_key);
    free_proto(signed_pre_key);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_generate_opks() {
    // test start
    printf("====== test_generate_opks ======\n");
    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    int ret = 0;
    size_t number_of_keys = E2EES_ONE_TIME_PRE_KEY_INITIAL_NUM, i;

    E2ees__OneTimePreKey **one_time_pre_key_list = NULL;
    ret = generate_opks(&one_time_pre_key_list, number_of_keys, e2ees_pack_id, 0);
    assert(ret == 0);

    // release
    for (i = 0; i < number_of_keys; i++) {
        e2ees__one_time_pre_key__free_unpacked(one_time_pre_key_list[i], NULL);
        one_time_pre_key_list[i] = NULL;
    }
    free_mem((void **)&one_time_pre_key_list, sizeof(E2ees__OneTimePreKey *) * number_of_keys);

    // test stop
    printf("====================================\n");
}

static void test_create_account() {
    // test start
    printf("====== test_create_account ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;
    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();

    int ret = 0;

    E2ees__Account *account = NULL;
    ret = create_account(&account, e2ees_pack_id);
    assert(ret == 0);

    // release
    free_proto(account);

    // test stop
    tear_down();
    printf("====================================\n");
}

///-----------------integration test-----------------///

static void test_create_accounts(uint64_t num) {
    // test start
    printf("====== test_create_accounts ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint64_t i;
    for (i = 1; i <= num; i++) {
        test_create_account();
    }

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_register_user() {
    // test start
    printf("====== test_register_user ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    E2ees__RegisterUserResponse *response = NULL;
    ret = register_user(
        &response, e2ees_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );
    assert(ret == 0);
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    e2ees__register_user_response__free_unpacked(response, NULL);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_publish_spk() {
    // test start
    printf("====== test_publish_spk ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    E2ees__RegisterUserResponse *register_user_response = NULL;
    ret = register_user(
        &register_user_response, e2ees_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );

    // load account
    E2ees__Account *account = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(register_user_response->address, &account);
    uint32_t old_spk_id = account->signed_pre_key->spk_id;

    // update the signed pre-key
    E2ees__SignedPreKey *signed_pre_key = NULL;
    generate_signed_pre_key(&signed_pre_key, e2ees_pack_id, 1, account->signed_pre_key->key_pair->private_key.data);

    e2ees__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
    account->signed_pre_key = signed_pre_key;

    uint32_t new_spk_id = account->signed_pre_key->spk_id;
    E2ees__PublishSpkResponse *publish_spk_response = NULL;
    publish_spk_internal(&publish_spk_response, account);

    assert(new_spk_id == old_spk_id + 1);

    // release
    free_proto(register_user_response);
    free_proto(account);
    free_proto(publish_spk_response);

    // test stop
    tear_down();
    printf("====================================\n");
}

E2ees__ProtoMsg *mock_supply_opks_msg(E2ees__E2eeAddress *user_address, uint32_t supply_opks_num) {
    E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
    e2ees__proto_msg__init(proto_msg);

    copy_address_from_address(&(proto_msg->to), user_address);
    proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_SUPPLY_OPKS_MSG;
    proto_msg->supply_opks_msg = (E2ees__SupplyOpksMsg *)malloc(sizeof(E2ees__SupplyOpksMsg));
    e2ees__supply_opks_msg__init(proto_msg->supply_opks_msg);
    proto_msg->supply_opks_msg->opks_num = supply_opks_num;
    copy_address_from_address(&(proto_msg->supply_opks_msg->user_address), user_address);

    return proto_msg;
}

static void test_supply_opks() {
    // test start
    printf("====== test_supply_opks ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    E2ees__RegisterUserResponse *register_user_response = NULL;
    ret = register_user(
        &register_user_response, e2ees_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );

    // load account
    E2ees__Account *account = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(register_user_response->address, &account);

    // use some opk
    size_t i;
    for (i = 0; i < (account->n_one_time_pre_key_list)/2; i++) {
        get_e2ees_plugin()->db_handler.remove_one_time_pre_key(account->address, account->one_time_pre_key_list[i]->opk_id);
    }
    
    // the server asks the client to supply some one-time pre-keys
    uint32_t supply_opks_num = 100;
    E2ees__E2eeAddress *user_address = account->address;
    E2ees__ProtoMsg *proto_msg = mock_supply_opks_msg(user_address, supply_opks_num);
    size_t proto_msg_data_len = e2ees__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    e2ees__proto_msg__pack(proto_msg, proto_msg_data);
    E2ees__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

    // assert
    E2ees__Account *account_new = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(register_user_response->address, &account_new);
    assert(account_new->n_one_time_pre_key_list == (E2EES_ONE_TIME_PRE_KEY_INITIAL_NUM + supply_opks_num));

    // release
    free_proto(register_user_response);
    free_proto(account);
    if (account_new != NULL) {
        e2ees__account__free_unpacked(account_new, NULL);
        account_new = NULL;
    }
    free_proto(proto_msg);

    // test stop
    tear_down();
    printf("====================================\n");
}

static void test_free_opks() {
    // test start
    printf("====== test_free_opks ======\n");
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    const char *user_name = "alice";
    const char *user_id = "alice";
    const char *device_id = generate_uuid_str();
    const char *authenticator = "email";
    const char *auth_code = "123456";
    int ret = 0;
    E2ees__RegisterUserResponse *register_user_response = NULL;
    ret = register_user(
        &register_user_response, e2ees_pack_id, user_name, user_id, device_id, authenticator, auth_code
    );

    // load account
    E2ees__Account *account = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(register_user_response->address, &account);

    size_t used_opks = 80;
    size_t i;
    for (i = 0; i < used_opks; i++) {
        account->one_time_pre_key_list[i]->used = true;
    }
    free_one_time_pre_key(account);
    // store
    get_e2ees_plugin()->db_handler.store_account(account);

    // load account
    E2ees__Account *account_new = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(register_user_response->address, &account_new);
    size_t unused_opks = E2EES_ONE_TIME_PRE_KEY_INITIAL_NUM - used_opks;
    assert(account_new->n_one_time_pre_key_list == unused_opks);
    for (i = 0; i < unused_opks; i++) {
        assert(account_new->one_time_pre_key_list[i]->used == false);
    }

    // release
    free_proto(register_user_response);
    free_proto(account);
    if (account_new != NULL) {
        e2ees__account__free_unpacked(account_new, NULL);
        account_new = NULL;
    }

    // test stop
    tear_down();
    printf("====================================\n");
}

int main() {
    // unit test
    test_generate_identity_key();
    test_generate_signed_pre_key();
    test_generate_opks();
    test_create_account();

    // integration test
    test_create_accounts(8);
    test_register_user();
    test_publish_spk();
    test_supply_opks();
    test_free_opks();

    return 0;
}
