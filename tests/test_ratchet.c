/**
 * @file
 * @copyright © 2020-2021 by Academia Sinica
 * @brief ratchet test
 *
 * @page test_ratchet ratchet documentation
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
 * @section test_alice_to_bob
 * Alice and Bob establish their ratchet. Alice encrypts a message. Bob should decrypt the message successfully.
 * 
 * @section test_bob_to_alice
 * Alice and Bob establish their ratchet. Bob encrypts a message. Alice should decrypt the message successfully.
 * 
 * @section test_interaction_alice_first
 * Alice and Bob establish their ratchet. Alice encrypts a message and Bob decrypts the message. Next, Bob encrypts a message and Alice decrypts the message.
 * 
 * @section test_interaction_bob_first
 * Alice and Bob establish their ratchet. Bob encrypts a message and Alice decrypts the message. Next, Alice encrypts a message and Bob decrypts the message.
 * 
 * @section test_out_of_order
 * Alice and Bob establish their ratchet. Alice encrypts two messages. Bob decrypts the second message first and then decrypts the first message.
 * 
 * @section test_continual_message
 * Alice and Bob establish their ratchet. Alice encrypts 1000 messages. Bob decrypts these messages.
 * 
 * @section test_interaction_v2
 * Alice and Bob establish their ratchet. Alice encrypts two messages and Bob decrypts the messages. Next, Bob encrypts two messages and Alice decrypts the messages.
 * 
 * @section test_out_of_order_v2
 * 
 * 
 * 
 * 
 * @defgroup ratchet_unit ratchet unit test
 * @ingroup Unit
 * This includes unit tests about ratchet.
 * 
 * @defgroup initialise_as_alice initialise ratchet test: Alice
 * @ingroup ratchet_unit
 * @{
 * @section sec20001 Test Case ID
 * v1.0urt01
 * @section sec20002 Test Case Title
 * initialise_as_alice
 * @section sec20003 Test Description
 * Given an e2ee pack ID and some keys, the inviter initialises his or her ratchet.
 * @section sec20004 Test Objectives
 * To verify the functionality of the function initialise_as_alice.
 * @section sec20005 Preconditions
 * @section sec20006 Test Steps
 * Step 1: Determine an e2ee pack ID.\n
 * Step 2: Generate some keys and shared secret.\n
 * Step 3: Initialise the ratchet.
 * @section sec20007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup initialise_as_bob initialise ratchet test: Bob
 * @ingroup ratchet_unit
 * @{
 * @section sec20101 Test Case ID
 * v1.0urt02
 * @section sec20102 Test Case Title
 * initialise_as_bob
 * @section sec20103 Test Description
 * Given an e2ee pack ID and some keys, the invitee initialises his or her ratchet.
 * @section sec20104 Test Objectives
 * To verify the functionality of the function initialise_as_bob.
 * @section sec20105 Preconditions
 * @section sec20106 Test Steps
 * Step 1: Determine an e2ee pack ID.\n
 * Step 2: Generate some keys and shared secret.\n
 * Step 3: Initialise the ratchet.
 * @section sec20107 Expected Results
 * No output.
 * @}
 * 
 * 
 * @defgroup ratchet_int ratchet integration test
 * @ingroup Integration
 * This includes integration tests about ratchet.
 * 
 * @defgroup ratchet_test_alice_to_bob basic ratchet test: Alice to Bob
 * @ingroup ratchet_int
 * @{
 * @section sec21001 Test Case ID
 * v1.0irt01
 * @section sec21002 Test Case Title
 * test_alice_to_bob
 * @section sec21003 Test Description
 * Alice and Bob establish their ratchet. Alice encrypts a message. Bob should decrypt the message successfully.
 * @section sec21004 Test Objectives
 * To assure that the invitee can decrypt the inviter's message once the ratchet is completed.
 * @section sec21005 Preconditions
 * @section sec21006 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Alice encrypts a message.\n
 * Step 3: Bob decrypts the message.
 * @section sec21007 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_bob_to_alice basic ratchet test: Bob to Alice
 * @ingroup ratchet_int
 * @{
 * @section sec21101 Test Case ID
 * v1.0irt02
 * @section sec21102 Test Case Title
 * test_bob_to_alice
 * @section sec21103 Test Description
 * Alice and Bob establish their ratchet. Bob encrypts a message. Alice should decrypt the message successfully.
 * @section sec21104 Test Objectives
 * To assure that the inviter can decrypt the invitee's message once the ratchet is completed.
 * @section sec21105 Preconditions
 * @section sec21106 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Bob encrypts a message.\n
 * Step 3: Alice decrypts the message.
 * @section sec21107 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_interaction_alice_first interaction test: Alice first
 * @ingroup ratchet_int
 * @{
 * @section sec21201 Test Case ID
 * v1.0irt03
 * @section sec21202 Test Case Title
 * test_interaction_alice_first
 * @section sec21203 Test Description
 * Alice and Bob establish their ratchet. Alice encrypts a message and Bob decrypts the message.
 * Next, Bob encrypts a message and Alice decrypts the message.
 * @section sec21204 Test Objectives
 * To assure that both of the inviter and the invitee can decrypt the other's message.
 * @section sec21205 Preconditions
 * @section sec21206 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Alice encrypts a message.\n
 * Step 3: Bob decrypts the message.\n
 * Step 4: Bob encrypts a message.\n
 * Step 5: Alice decrypts the message.
 * @section sec21207 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_interaction_bob_first interaction test: Bob first
 * @ingroup ratchet_int
 * @{
 *  @section sec21301 Test Case ID
 * v1.0irt04
 * @section sec21302 Test Case Title
 * test_interaction_bob_first
 * @section sec21303 Test Description
 * Alice and Bob establish their ratchet. Bob encrypts a message and Alice decrypts the message.
 * Next, Alice encrypts a message and Bob decrypts the message.
 * @section sec21304 Test Objectives
 * To assure that both of the inviter and the invitee can decrypt the other's message.
 * @section sec21305 Preconditions
 * @section sec21306 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Bob encrypts a message.\n
 * Step 3: Alice decrypts the message.\n
 * Step 4: Alice encrypts a message.\n
 * Step 5: Bob decrypts the message.
 * @section sec21307 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_out_of_order out of order test: simple case
 * @ingroup ratchet_int
 * @{
 * @section sec21401 Test Case ID
 * v1.0irt05
 * @section sec21402 Test Case Title
 * test_out_of_order
 * @section sec21403 Test Description
 * Alice and Bob establish their ratchet. Alice encrypts two messages.
 * Bob decrypts the second message first and then decrypts the first message.
 * @section sec21404 Test Objectives
 * To verify the out-of-order mechanism.
 * @section sec21405 Preconditions
 * @section sec21406 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Alice encrypts two messages.\n
 * Step 3: Bob decrypts the second message.\n
 * Step 4: Bob decrypts the first message.
 * @section sec21407 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_continual_message continual messages test
 * @ingroup ratchet_int
 * @{
 * @section sec21501 Test Case ID
 * v1.0irt06
 * @section sec21502 Test Case Title
 * test_continual_message
 * @section sec21503 Test Description
 * Alice and Bob establish their ratchet. Alice encrypts 1000 messages. Bob decrypts these messages.
 * @section sec21504 Test Objectives
 * To assure that a large number of messages can be decrypted.
 * @section sec21505 Preconditions
 * @section sec21506 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Alice encrypts 1000 messages.\n
 * Step 3: Bob decrypts all of the messages.
 * @section sec21507 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_interaction_v2 interaction test
 * @ingroup ratchet_int
 * @{
 * @section sec21601 Test Case ID
 * v1.0irt07
 * @section sec21602 Test Case Title
 * test_interaction_v2
 * @section sec21603 Test Description
 * Alice and Bob establish their ratchet. Alice encrypts two messages and Bob decrypts the messages.
 * Next, Bob encrypts two messages and Alice decrypts the messages.
 * @section sec21604 Test Objectives
 * To assure that both of the inviter and the invitee can decrypt the other's message.
 * @section sec21605 Preconditions
 * @section sec21606 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Alice encrypts a message and the Bob decrypts the message.\n
 * Step 3: Alice encrypts a message and the Bob decrypts the message.\n
 * Step 4: Bob encrypts a message and the Alice decrypts the message.\n
 * Step 5: Bob encrypts a message and the Alice decrypts the message.\n
 * Step 6: Process Step 2 - Step 5 for ten times.
 * @section sec21607 Expected Results
 * No output.
 * @}
 * 
 * @defgroup ratchet_test_out_of_order_v2 out of order test
 * @ingroup ratchet_int
 * @{
 * @section sec21701 Test Case ID
 * v1.0irt08
 * @section sec21702 Test Case Title
 * test_out_of_order_v2
 * @section sec21703 Test Description
 * Alice and Bob encrypt some messages, but they do not decrypt the others' messages in order.
 * @section sec21704 Test Objectives
 * To verify the out-of-order mechanism.
 * @section sec21705 Preconditions
 * @section sec21706 Test Steps
 * Step 1: Initialise Alice's and Bob's ratchet.\n
 * Step 2: Alice encrypts a message and the Bob decrypts the message.\n
 * Step 3: Alice encrypts a message.\n
 * Step 4: Bob encrypts three messages.\n
 * Step 5: Alice decrypts two of Bob's messages.\n
 * Step 6: Alice encrypts three messages.\n
 * Step 7: Bob decrypts two of Alice's messages.\n
 * Step 8: Bob encrypts two messages.\n
 * Step 9: Alice and Bob decrypts the others' rest messages.
 * @section sec21707 Expected Results
 * No output.
 * @}
 * 
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "e2ees/cipher.h"
#include "e2ees/mem_util.h"
#include "e2ees/ratchet.h"

#include "test_util.h"
#include "test_plugin.h"

static const cipher_suite_t *test_cipher_suite;

static void on_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static e2ees_event_handler_t test_event_handler = {
    on_log,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void initialization(
    E2ees__Ratchet **alice_ratchet,
    E2ees__Ratchet **bob_ratchet,
    ProtobufCBinaryData *ad
) {
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    test_cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;

    E2ees__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&(alice_ratchet_key.public_key), &(alice_ratchet_key.private_key));

    E2ees__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&(bob_spk.public_key), &(bob_spk.private_key));

    int ad_len = 2 * test_cipher_suite->kem_suite->get_param().asym_pub_key_len;
    uint8_t associated_data[ad_len];
    memset(associated_data, 0, ad_len);
    ad->len = ad_len;
    ad->data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    int i;
    for (i = 0; i < ad_len; i++) {
        ad->data[i] = associated_data[i];
    }

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    initialise_as_bob(
        bob_ratchet,
        test_cipher_suite,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    initialise_as_alice(
        alice_ratchet,
        test_cipher_suite,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &((*bob_ratchet)->sender_chain->our_ratchet_public_key)
    );

    // release
    free_protobuf(&(alice_ratchet_key.public_key));
    free_protobuf(&(alice_ratchet_key.private_key));
    free_protobuf(&(bob_spk.public_key));
    free_protobuf(&(bob_spk.private_key));
}

///-----------------unit test-----------------///

static void test_initialise_as_alice() {
    // print test case
    print_test_case("v1.0urt01", "test_initialise_as_alice");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL;

    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    test_cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;

    E2ees__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&(alice_ratchet_key.public_key), &(alice_ratchet_key.private_key));

    E2ees__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&(bob_spk.public_key), &(bob_spk.private_key));

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    ProtobufCBinaryData ciphertext = {0, NULL};
    int temp_shared_key_len = test_cipher_suite->kem_suite->get_param().shared_secret_len;
    uint8_t temp_secret[temp_shared_key_len];
    test_cipher_suite->kem_suite->encaps(temp_secret, &ciphertext, &(alice_ratchet_key.public_key));

    int ret = initialise_as_alice(
        &alice_ratchet,
        test_cipher_suite,
        shared_secret,
        strlen((const char *)shared_secret),
        &alice_ratchet_key,
        &(bob_spk.public_key),
        &ciphertext
    );
    assert(ret == E2EES_RESULT_SUCC);

    // release
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    free_protobuf(&(alice_ratchet_key.public_key));
    free_protobuf(&(alice_ratchet_key.private_key));
    free_protobuf(&(bob_spk.public_key));
    free_protobuf(&(bob_spk.private_key));
    if (ciphertext.data != NULL) {
        free_mem((void **)&(ciphertext.data), sizeof(uint8_t) * ciphertext.len);
    }
    unset(temp_secret, sizeof(temp_secret));

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_initialise_as_bob() {
    // print test case
    print_test_case("v1.0urt02", "test_initialise_as_bob");

    // test start
    tear_up();

    E2ees__Ratchet *bob_ratchet = NULL;

    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    test_cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;

    E2ees__KeyPair alice_ratchet_key;
    test_cipher_suite->kem_suite->asym_key_gen(&(alice_ratchet_key.public_key), &(alice_ratchet_key.private_key));

    E2ees__KeyPair bob_spk;
    test_cipher_suite->kem_suite->asym_key_gen(&(bob_spk.public_key), &(bob_spk.private_key));

    uint8_t shared_secret[] = "shared_secret:nwjeldUbnjwcwkdt5q";

    int ret = initialise_as_bob(
        &bob_ratchet,
        test_cipher_suite,
        shared_secret,
        strlen((const char *)shared_secret),
        &bob_spk,
        &(alice_ratchet_key.public_key)
    );
    assert(ret == E2EES_RESULT_SUCC);

    // release
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);
    free_protobuf(&(alice_ratchet_key.public_key));
    free_protobuf(&(alice_ratchet_key.private_key));
    free_protobuf(&(bob_spk.public_key));
    free_protobuf(&(bob_spk.private_key));

    // test stop
    tear_down();
    print_test_case_final();
}

///-----------------integration test-----------------///

static void test_alice_to_bob() {
    // print test case
    print_test_case("v1.0irt01", "test_alice_to_bob");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    // Alice sends Bob a message
    E2ees__One2oneMsgPayload *message = NULL;

    encrypt_ratchet(&message, test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_length);

    uint8_t *output = NULL;
    decrypt_ratchet(&output, &decrypt_length, test_cipher_suite, bob_ratchet, ad, message);
    assert(decrypt_length == plaintext_length);
    bool result = is_equal(plaintext, output, plaintext_length);
    assert(result);

    free_protobuf(&ad);
    e2ees__one2one_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_bob_to_alice() {
    // print test case
    print_test_case("v1.0irt02", "test_bob_to_alice");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1;

    size_t decrypt_length;

    /* Bob sends Alice a message */
    E2ees__One2oneMsgPayload *message = NULL;

    encrypt_ratchet(&message, test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_length);

    uint8_t *output = NULL;
    decrypt_ratchet(&output, &decrypt_length, test_cipher_suite, alice_ratchet, ad, message);
    assert(decrypt_length == plaintext_length);
    bool result = is_equal(plaintext, output, plaintext_length);
    assert(result);

    free_protobuf(&ad);
    e2ees__one2one_msg_payload__free_unpacked(message, NULL);
    free_mem((void **)&output, decrypt_length);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_interaction_alice_first() {
    // print test case
    print_test_case("v1.0irt03", "test_interaction_alice_first");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    bool result;

    /* Alice sends Bob a message */
    uint8_t plaintext_1[] = "Alice's Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    E2ees__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(&message_1, test_cipher_suite, alice_ratchet, ad, plaintext_1, plaintext_1_length);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1;
    decrypt_ratchet(&output_1, &decrypt_length_1, test_cipher_suite, bob_ratchet, ad, message_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    /* Bob sends Alice a message */
    uint8_t plaintext_2[] = "Bob's Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    E2ees__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(&message_2, test_cipher_suite, bob_ratchet, ad, plaintext_2, plaintext_2_length);

    uint8_t *output_2 = NULL;
    size_t decrypt_length_2;
    decrypt_ratchet(&output_2, &decrypt_length_2, test_cipher_suite, alice_ratchet, ad, message_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    free_protobuf(&ad);
    e2ees__one2one_msg_payload__free_unpacked(message_1, NULL);
    e2ees__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_interaction_bob_first() {
    // print test case
    print_test_case("v1.0irt04", "test_interaction_bob_first");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    bool result;

    /* Bob sends Alice a message */
    uint8_t plaintext_1[] = "Bob's Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    E2ees__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(&message_1, test_cipher_suite, bob_ratchet, ad, plaintext_1, plaintext_1_length);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1;
    decrypt_ratchet(&output_1, &decrypt_length_1, test_cipher_suite, alice_ratchet, ad, message_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    /* Alice sends Bob a message */
    uint8_t plaintext_2[] = "Alice's Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    E2ees__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(&message_2, test_cipher_suite, alice_ratchet, ad, plaintext_2, plaintext_2_length);

    uint8_t *output_2 = NULL;
    size_t decrypt_length_2;
    decrypt_ratchet(&output_2, &decrypt_length_2, test_cipher_suite, bob_ratchet, ad, message_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    free_protobuf(&ad);
    e2ees__one2one_msg_payload__free_unpacked(message_1, NULL);
    e2ees__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_out_of_order() {
    // print test case
    print_test_case("v1.0irt05", "test_out_of_order");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    bool result;

    /* Alice sends Bob two messages */
    uint8_t plaintext_1[] = "Alice's first Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1;

    E2ees__One2oneMsgPayload *message_1 = NULL;

    encrypt_ratchet(&message_1, test_cipher_suite, alice_ratchet, ad, plaintext_1, plaintext_1_length);

    uint8_t plaintext_2[] = "Alice's second Message";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1;

    E2ees__One2oneMsgPayload *message_2 = NULL;

    encrypt_ratchet(&message_2, test_cipher_suite, alice_ratchet, ad, plaintext_2, plaintext_2_length);

    // decrypt the second message first
    uint8_t *output_2 = NULL;
    size_t decrypt_length_2;
    decrypt_ratchet(&output_2, &decrypt_length_2, test_cipher_suite, bob_ratchet, ad, message_2);
    assert(decrypt_length_2 == plaintext_2_length);
    result = is_equal(plaintext_2, output_2, plaintext_2_length);
    assert(result);

    uint8_t *output_1 = NULL;
    size_t decrypt_length_1;
    decrypt_ratchet(&output_1, &decrypt_length_1, test_cipher_suite, bob_ratchet, ad, message_1);
    assert(decrypt_length_1 == plaintext_1_length);
    result = is_equal(plaintext_1, output_1, plaintext_1_length);
    assert(result);

    free_protobuf(&ad);
    e2ees__one2one_msg_payload__free_unpacked(message_1, NULL);
    e2ees__one2one_msg_payload__free_unpacked(message_2, NULL);
    free_mem((void **)&output_1, decrypt_length_1);
    free_mem((void **)&output_2, decrypt_length_2);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_continual_message() {
    // print test case
    print_test_case("v1.0irt06", "test_continual_message");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    // Alice sends Bob messages many times
    int message_num = 1000;
    int i;

    uint8_t **plaintext = (uint8_t **)malloc(sizeof(uint8_t *) * message_num);
    size_t *plaintext_len = (size_t *)malloc(sizeof(size_t) * message_num);
    E2ees__One2oneMsgPayload **message = (E2ees__One2oneMsgPayload **)malloc(sizeof(E2ees__One2oneMsgPayload *) * message_num);

    for (i = 0; i < message_num; i++) {
        plaintext[i] = (uint8_t *)malloc(sizeof(uint8_t) * 64);
        plaintext_len[i] = snprintf((char *)plaintext[i], 64, "[%4d]This message will be sent a lot of times.", i);
        encrypt_ratchet(&message[i], test_cipher_suite, alice_ratchet, ad, plaintext[i], plaintext_len[i]);
    }

    uint8_t **output = (uint8_t **)malloc(sizeof(uint8_t *) * message_num);
    size_t *output_len = (size_t *)malloc(sizeof(size_t) * message_num);

    bool result;
    for (i = 0; i < message_num; i++) {
        decrypt_ratchet(&output[i], &output_len[i], test_cipher_suite, bob_ratchet, ad, message[i]);

        assert(output_len[i] == plaintext_len[i]);
        result = is_equal(plaintext[i], output[i], plaintext_len[i]);
        assert(result);
    }

    free_protobuf(&ad);
    for (i = 0; i < message_num; i++) {
        free_mem((void **)&plaintext[i], sizeof(uint8_t) * 64);
        free_mem((void **)&output[i], output_len[i]);
        e2ees__one2one_msg_payload__free_unpacked(message[i], NULL);
    }
    free_mem((void **)&message, sizeof(E2ees__One2oneMsgPayload *) * message_num);
    free_mem((void **)&plaintext, sizeof(uint8_t *) * message_num);
    free_mem((void **)&plaintext_len, sizeof(size_t) * message_num);
    free_mem((void **)&output, sizeof(uint8_t *) * message_num);
    free_mem((void **)&output_len, sizeof(size_t) * message_num);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_interaction_v2() {
    // print test case
    print_test_case("v1.0irt07", "test_interaction_v2");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    int round = 10;
    int i;

    uint8_t *plaintext = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    size_t plaintext_len;
    E2ees__One2oneMsgPayload *message = NULL;
    uint8_t *output = NULL;
    size_t output_len;
    bool result;

    for (i = 0; i < round; i++) {
        // the first time, from Alice to Bob
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Alice to Bob.", i * 4);
        encrypt_ratchet(&message, test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_len);

        decrypt_ratchet(&output, &output_len, test_cipher_suite, bob_ratchet, ad, message);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        e2ees__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);

        // the second time, from Alice to Bob
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Alice to Bob.", i * 4 + 1);
        encrypt_ratchet(&message, test_cipher_suite, alice_ratchet, ad, plaintext, plaintext_len);

        decrypt_ratchet(&output, &output_len, test_cipher_suite, bob_ratchet, ad, message);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        e2ees__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);

        // the third time, from Bob to Alice
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Bob to Alice.", i * 4 + 2);
        encrypt_ratchet(&message, test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_len);

        decrypt_ratchet(&output, &output_len, test_cipher_suite, alice_ratchet, ad, message);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        e2ees__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);

        // the fourth time, from Bob to Alice
        plaintext_len = snprintf((char *)plaintext, 64, "[%4d]This message is from Bob to Alice.", i * 4 + 3);
        encrypt_ratchet(&message, test_cipher_suite, bob_ratchet, ad, plaintext, plaintext_len);

        decrypt_ratchet(&output, &output_len, test_cipher_suite, alice_ratchet, ad, message);
        assert(output_len == plaintext_len);
        result = is_equal(plaintext, output, plaintext_len);
        assert(result);

        e2ees__one2one_msg_payload__free_unpacked(message, NULL);
        message = NULL;
        free_mem((void **)&output, sizeof(uint8_t) * output_len);
    }

    free_protobuf(&ad);
    free_mem((void **)&plaintext, sizeof(uint8_t) * 64);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

static void test_out_of_order_v2() {
    // print test case
    print_test_case("v1.0irt08", "test_out_of_order_v2");

    // test start
    tear_up();

    E2ees__Ratchet *alice_ratchet = NULL, *bob_ratchet = NULL;
    ProtobufCBinaryData ad;

    initialization(&alice_ratchet, &bob_ratchet, &ad);

    int msg_num = 10;
    int i;
    uint8_t **plaintext = (uint8_t **)malloc(sizeof(uint8_t *) * msg_num);
    size_t *plaintext_len = (size_t *)malloc(sizeof(size_t) * msg_num);
    E2ees__One2oneMsgPayload **message = (E2ees__One2oneMsgPayload **)malloc(sizeof(E2ees__One2oneMsgPayload *) * msg_num);
    uint8_t **output = (uint8_t **)malloc(sizeof(uint8_t *) * msg_num);
    size_t *output_len = (size_t *)malloc(sizeof(size_t) * msg_num);
    bool result;

    for (i = 0; i < msg_num; i++) {
        plaintext[i] = (uint8_t *)malloc(sizeof(uint8_t) * 64);
        plaintext_len[i] = snprintf((char *)plaintext[i], 64, "[%4d]This message may be from Alice or Bob.", i);
    }

    encrypt_ratchet(&message[0], test_cipher_suite, alice_ratchet, ad, plaintext[0], plaintext_len[0]);
    decrypt_ratchet(&output[0], &output_len[0], test_cipher_suite, bob_ratchet, ad, message[0]);
    assert(output_len[0] == plaintext_len[0]);
    result = is_equal(plaintext[0], output[0], plaintext_len[0]);
    assert(result);

    encrypt_ratchet(&message[1], test_cipher_suite, alice_ratchet, ad, plaintext[1], plaintext_len[1]);
    encrypt_ratchet(&message[2], test_cipher_suite, bob_ratchet, ad, plaintext[2], plaintext_len[2]);
    encrypt_ratchet(&message[3], test_cipher_suite, bob_ratchet, ad, plaintext[3], plaintext_len[3]);
    encrypt_ratchet(&message[4], test_cipher_suite, bob_ratchet, ad, plaintext[4], plaintext_len[4]);

    decrypt_ratchet(&output[4], &output_len[4], test_cipher_suite, alice_ratchet, ad, message[4]);
    assert(output_len[4] == plaintext_len[4]);
    result = is_equal(plaintext[4], output[4], plaintext_len[4]);
    assert(result);
    decrypt_ratchet(&output[2], &output_len[2], test_cipher_suite, alice_ratchet, ad, message[2]);
    assert(output_len[2] == plaintext_len[2]);
    result = is_equal(plaintext[2], output[2], plaintext_len[2]);
    assert(result);

    encrypt_ratchet(&message[5], test_cipher_suite, alice_ratchet, ad, plaintext[5], plaintext_len[5]);
    encrypt_ratchet(&message[6], test_cipher_suite, alice_ratchet, ad, plaintext[6], plaintext_len[6]);
    encrypt_ratchet(&message[7], test_cipher_suite, alice_ratchet, ad, plaintext[7], plaintext_len[7]);

    decrypt_ratchet(&output[6], &output_len[6], test_cipher_suite, bob_ratchet, ad, message[6]);
    assert(output_len[6] == plaintext_len[6]);
    result = is_equal(plaintext[6], output[6], plaintext_len[6]);
    assert(result);
    decrypt_ratchet(&output[1], &output_len[1], test_cipher_suite, bob_ratchet, ad, message[1]);
    assert(output_len[1] == plaintext_len[1]);
    result = is_equal(plaintext[1], output[1], plaintext_len[1]);
    assert(result);

    encrypt_ratchet(&message[8], test_cipher_suite, bob_ratchet, ad, plaintext[8], plaintext_len[8]);
    encrypt_ratchet(&message[9], test_cipher_suite, bob_ratchet, ad, plaintext[9], plaintext_len[9]);
    decrypt_ratchet(&output[9], &output_len[9], test_cipher_suite, alice_ratchet, ad, message[9]);
    assert(output_len[9] == plaintext_len[9]);
    result = is_equal(plaintext[9], output[9], plaintext_len[9]);
    assert(result);
    decrypt_ratchet(&output[3], &output_len[3], test_cipher_suite, alice_ratchet, ad, message[3]);
    assert(output_len[3] == plaintext_len[3]);
    result = is_equal(plaintext[3], output[3], plaintext_len[3]);
    assert(result);

    decrypt_ratchet(&output[5], &output_len[5], test_cipher_suite, bob_ratchet, ad, message[5]);
    assert(output_len[5] == plaintext_len[5]);
    result = is_equal(plaintext[5], output[5], plaintext_len[5]);
    assert(result);
    decrypt_ratchet(&output[7], &output_len[7], test_cipher_suite, bob_ratchet, ad, message[7]);
    assert(output_len[7] == plaintext_len[7]);
    result = is_equal(plaintext[7], output[7], plaintext_len[7]);
    assert(result);

    decrypt_ratchet(&output[8], &output_len[8], test_cipher_suite, alice_ratchet, ad, message[8]);
    assert(output_len[8] == plaintext_len[8]);
    result = is_equal(plaintext[8], output[8], plaintext_len[8]);
    assert(result);

    free_protobuf(&ad);
    for (i = 0; i < msg_num; i++) {
        free_mem((void **)&plaintext[i], sizeof(uint8_t) * 64);
        free_mem((void **)&output[i], output_len[i]);
        e2ees__one2one_msg_payload__free_unpacked(message[i], NULL);
    }
    free_mem((void **)&message, sizeof(E2ees__One2oneMsgPayload *) * msg_num);
    free_mem((void **)&plaintext, sizeof(uint8_t *) * msg_num);
    free_mem((void **)&plaintext_len, sizeof(size_t) * msg_num);
    free_mem((void **)&output, sizeof(uint8_t *) * msg_num);
    free_mem((void **)&output_len, sizeof(size_t) * msg_num);
    e2ees__ratchet__free_unpacked(alice_ratchet, NULL);
    e2ees__ratchet__free_unpacked(bob_ratchet, NULL);

    // test stop
    tear_down();
    print_test_case_final();
}

int main() {
    // unit test
    test_initialise_as_alice();
    test_initialise_as_bob();

    // integration test
    test_alice_to_bob();
    test_bob_to_alice();
    test_interaction_alice_first();
    test_interaction_bob_first();
    test_out_of_order();
    test_continual_message();
    test_interaction_v2();
    test_out_of_order_v2();

    return 0;
}
