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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "e2ees/account.h"
#include "e2ees/account_manager.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/mem_util.h"
#include "e2ees/session_manager.h"

#include "mock_server_sending.h"
#include "test_plugin.h"
#include "test_util.h"

static uint8_t test_plaintext[] = "Crypto test!!!";

static unsigned digital_signature_data_selected[] = {
    E2EES_PACK_ALG_DS_MLDSA87,
    E2EES_PACK_ALG_DS_FALCON1024,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_256S,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256F
};

static unsigned kem_data_selected[] = {
    E2EES_PACK_ALG_KEM_HQC256,
    E2EES_PACK_ALG_KEM_MLKEM1024
};

static unsigned digital_signature_data_all[] = {
    E2EES_PACK_ALG_DS_MLDSA44,
    E2EES_PACK_ALG_DS_MLDSA65,
    E2EES_PACK_ALG_DS_MLDSA87,
    E2EES_PACK_ALG_DS_FALCON512,
    E2EES_PACK_ALG_DS_FALCON1024,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_128F,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_128S,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_192F,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_192S,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_256F,
    E2EES_PACK_ALG_DS_SPHINCS_SHA2_256S,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_128F,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_128S,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_192F,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_192S,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256F,
    E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256S
};

static unsigned kem_data_all[] = {
    E2EES_PACK_ALG_KEM_HQC128,
    E2EES_PACK_ALG_KEM_HQC192,
    E2EES_PACK_ALG_KEM_HQC256,
    E2EES_PACK_ALG_KEM_MLKEM512,
    E2EES_PACK_ALG_KEM_MLKEM768,
    E2EES_PACK_ALG_KEM_MLKEM1024,
    // Too Slow:
    //   E2EES_PACK_ALG_KEM_MCELIECE348864,
    //   E2EES_PACK_ALG_KEM_MCELIECE348864F,
    //   E2EES_PACK_ALG_KEM_MCELIECE460896,
    //   E2EES_PACK_ALG_KEM_MCELIECE460896F,
    //   E2EES_PACK_ALG_KEM_MCELIECE6688128,
    //   E2EES_PACK_ALG_KEM_MCELIECE6688128F,
    //   E2EES_PACK_ALG_KEM_MCELIECE6960119,
    //   E2EES_PACK_ALG_KEM_MCELIECE6960119F,
    //   E2EES_PACK_ALG_KEM_MCELIECE8192128,
    //   E2EES_PACK_ALG_KEM_MCELIECE8192128F
};

#define account_data_max 10

static E2ees__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

static void on_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static void on_user_registered(E2ees__Account *account) {
    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from) {
    // printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *inbound_session){
    // printf("on_inbound_session_ready\n");
}

static void on_outbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *outbound_session){
    // printf("on_outbound_session_ready\n");
}

static void on_one2one_msg_received(
    E2ees__E2eeAddress *user_address, 
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    assert(memcmp(plaintext, test_plaintext, plaintext_len) == 0);
}

static void on_other_device_msg_received(
    E2ees__E2eeAddress *user_address, 
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    // print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static e2ees_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    on_other_device_msg_received,
    NULL,
    NULL,
    NULL,
    NULL
};

static void test_begin(){
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

static uint32_t mock_e2ees_pack_id(unsigned digital_signature_choice, unsigned kem_choice) {
    return gen_e2ees_pack_id_raw(
        E2EES_PACK_ID_V_0,
        digital_signature_choice,
        kem_choice,
        E2EES_PACK_ALG_SE_AES256GCM,
        E2EES_PACK_ALG_HASH_SHA2_256
    );
}

static void mock_alice_account(const char *user_name, uint32_t e2ees_pack_id) {
    char *device_id = generate_uuid_str();
    const char *authenticator = "alice@domain.com.tw";
    const char *auth_code = "123456";
    E2ees__RegisterUserResponse *response = NULL;
    int ret = register_user(
        &response, e2ees_pack_id, user_name, user_name, device_id, authenticator, auth_code
    );

    if (ret == 0) {
        printf("%s registered completely!\n", user_name);
    } else {
        printf("%s registered failed!\n", user_name);
    }

    // release
    free(device_id);
    e2ees__register_user_response__free_unpacked(response, NULL);
}

static void mock_bob_account(const char *user_name, uint32_t e2ees_pack_id) {
    char *device_id = generate_uuid_str();
    const char *authenticator = "bob@domain.com.tw";
    const char *auth_code = "654321";
    E2ees__RegisterUserResponse *response = NULL;
    int ret = register_user(
        &response, e2ees_pack_id, user_name, user_name, device_id, authenticator, auth_code
    );

    if (ret == 0) {
        printf("%s registered completely!\n", user_name);
    } else {
        printf("%s registered failed!\n", user_name);
    }

    // release
    free(device_id);
    e2ees__register_user_response__free_unpacked(response, NULL);
}

static void test_encryption(
    E2ees__E2eeAddress *from_address, const char *to_user_id, const char *to_domain,
    uint8_t *plaintext, size_t plaintext_len
) {
    // send encrypted msg
    E2ees__SendOne2oneMsgResponse *send_one2one_msg_response = NULL;
    send_one2one_msg_response = send_one2one_msg(
        from_address, to_user_id, to_domain, 
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext, plaintext_len
    );

    // release
    free_proto(send_one2one_msg_response);
}

static void test_e2ees_pack_id() {
    // test start
    printf("test_e2ees_pack_id begin!!!\n");
    uint32_t default_e2ee_pack_id_raw = E2EES_PACK_ID_DEFAULT;
    uint32_t e2ees_pack_id_raw = gen_e2ees_pack_id_pqc();

    assert(e2ees_pack_id_raw == default_e2ee_pack_id_raw);
    printf("default_e2ee_pack_id_raw test ok: 0x%x\n", default_e2ee_pack_id_raw);

    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(default_e2ee_pack_id_raw);
    assert(e2ees_pack_id.ds == E2EES_PACK_ALG_DS_MLDSA87);
    assert(e2ees_pack_id.kem == E2EES_PACK_ALG_KEM_MLKEM1024);
    assert(e2ees_pack_id.se == E2EES_PACK_ALG_SE_AES256GCM);
    assert(e2ees_pack_id.hash == E2EES_PACK_ALG_HASH_SHA2_256);
    printf("default_e2ee_pack_id_raw to e2ees_pack_id test ok\n");

    printf("====================================\n");
}

static void test_one_to_one_session_selected() {
    // test start
    printf("test_one_to_one_session_selected begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    size_t digital_signature_data_selected_len = sizeof(digital_signature_data_selected)/sizeof(digital_signature_data_selected[0]);
    size_t kem_data_selected_len = sizeof(kem_data_selected)/sizeof(kem_data_selected[0]);

    size_t i,j;
    for (i = 0; i < digital_signature_data_selected_len; i++) {
        for (j = 0; j < kem_data_selected_len; j++) {
            printf("Digital signature suite: %u\n", digital_signature_data_selected[i]);
            printf("Kem suite: %u\n", kem_data_selected[j]);

            tear_up();
            test_begin();

            uint32_t e2ees_pack_id = mock_e2ees_pack_id(digital_signature_data_selected[i], kem_data_selected[j]);

            mock_alice_account("Alice", e2ees_pack_id);
            mock_bob_account("Bob", e2ees_pack_id);

            E2ees__E2eeAddress *alice_address = account_data[0]->address;
            char *alice_user_id = alice_address->user->user_id;
            char *alice_domain = alice_address->domain;
            E2ees__E2eeAddress *bob_address = account_data[1]->address;
            char *bob_user_id = bob_address->user->user_id;
            char *bob_domain = bob_address->domain;

            // Alice invites Bob to create a session
            E2ees__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);

            // sleep(1);

            // Alice sends an encrypted message to Bob, and Bob decrypts the message
            test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

            // Bob sends an encrypted message to Alice, and Alice decrypts the message
            test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

            // test stop
            if (response != NULL) {
                e2ees__invite_response__free_unpacked(response, NULL);
                response = NULL;
            }
            test_end();
            tear_down();

            printf("\n");
        }
    }

    printf("====================================\n");
}

static void test_one_to_one_session_all() {
    // test start
    printf("test_one_to_one_session_all begin!!!\n");

    size_t test_plaintext_len = sizeof(test_plaintext) - 1;

    size_t digital_signature_data_all_len = sizeof(digital_signature_data_all)/sizeof(digital_signature_data_all[0]);
    size_t kem_data_all_len = sizeof(kem_data_all)/sizeof(kem_data_all[0]);

    size_t i,j;
    for (i = 0; i < digital_signature_data_all_len; i++) {
        for (j = 0; j < kem_data_all_len; j++) {
            printf("Digital signature suite: %u\n", digital_signature_data_all[i]);
            printf("Kem suite: %u\n", kem_data_all[j]);

            tear_up();
            test_begin();

            uint32_t e2ees_pack_id = mock_e2ees_pack_id(digital_signature_data_all[i], kem_data_all[j]);

            mock_alice_account("Alice", e2ees_pack_id);
            mock_bob_account("Bob", e2ees_pack_id);

            E2ees__E2eeAddress *alice_address = account_data[0]->address;
            char *alice_user_id = alice_address->user->user_id;
            char *alice_domain = alice_address->domain;
            E2ees__E2eeAddress *bob_address = account_data[1]->address;
            char *bob_user_id = bob_address->user->user_id;
            char *bob_domain = bob_address->domain;

            // Alice invites Bob to create a session
            E2ees__InviteResponse *response = invite(alice_address, bob_user_id, bob_domain);

            sleep(1);

            // Alice sends an encrypted message to Bob, and Bob decrypts the message
            test_encryption(alice_address, bob_user_id, bob_domain, test_plaintext, test_plaintext_len);

            // Bob sends an encrypted message to Alice, and Alice decrypts the message
            test_encryption(bob_address, alice_user_id, alice_domain, test_plaintext, test_plaintext_len);

            // test stop
            e2ees__invite_response__free_unpacked(response, NULL);
            test_end();
            tear_down();

            printf("\n");
        }
    }

    printf("====================================\n");
}

int main() {
    test_e2ees_pack_id();
    test_one_to_one_session_selected();
    // test_one_to_one_session_all();

    return 0;
}
