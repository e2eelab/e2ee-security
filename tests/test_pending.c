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

#include "e2ees/cipher.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/session_manager.h"
#include "e2ees/validation.h"

#include "test_util.h"
#include "test_plugin.h"

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

static const cipher_suite_t *test_cipher_suite;

static void test_one_group_pre_key() {
    // test start
    tear_up();
    get_e2ees_plugin()->event_handler = test_event_handler;

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    test_cipher_suite = get_e2ees_pack(e2ees_pack_id)->cipher_suite;

    // mock address
    E2ees__E2eeAddress *user_address, *member_address;
    mock_address(&user_address, "alice", "alice's domain", "alice's device");
    mock_address(&member_address, "bob", "bob's domain", "bob's device");

    int key_len = test_cipher_suite->ds_suite->get_param().sign_pub_key_len;

    size_t group_members_num = 2;
    // the first group member is Alice
    E2ees__GroupMember **group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * group_members_num);
    group_members[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(user_address->user->user_id);
    group_members[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    // the second group member is Bob
    group_members[1] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members[1]);
    group_members[1]->user_id = strdup(member_address->user->user_id);
    group_members[1]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;

    // mock group address
    E2ees__E2eeAddress *group_address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(group_address);
    group_address->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init(group_address->group);
    group_address->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    group_address->domain = mock_domain_str();
    group_address->group->group_id = generate_uuid_str();

    // create an outbound group session
    E2ees__GroupSession *outbound_group_session = (E2ees__GroupSession *)malloc(sizeof(E2ees__GroupSession));
    e2ees__group_session__init(outbound_group_session);

    outbound_group_session->version = strdup(E2EES_PROTOCOL_VERSION);
    outbound_group_session->e2ees_pack_id = e2ees_pack_id;
    copy_address_from_address(&(outbound_group_session->sender), user_address);
    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    outbound_group_session->session_id = generate_uuid_str();

    outbound_group_session->group_info =
    (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    E2ees__GroupInfo *group_info = outbound_group_session->group_info;
    e2ees__group_info__init(group_info);
    group_info->group_name = strdup("test_group");
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = group_members_num;
    copy_group_members(&(group_info->group_member_list), group_members, group_members_num);

    outbound_group_session->sequence = 0;

    outbound_group_session->chain_key.len = test_cipher_suite->hf_suite->get_param().hf_len;
    outbound_group_session->chain_key.data = (uint8_t *)malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    get_e2ees_plugin()->common_handler.gen_rand(outbound_group_session->chain_key.data, outbound_group_session->chain_key.len);

    outbound_group_session->group_seed.len = test_cipher_suite->hf_suite->get_param().hf_len;
    outbound_group_session->group_seed.data = (uint8_t *)malloc(sizeof(uint8_t) * outbound_group_session->group_seed.len);
    get_e2ees_plugin()->common_handler.gen_rand(outbound_group_session->group_seed.data, outbound_group_session->group_seed.len);

    int ad_len = 2 * key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, outbound_group_session->chain_key.data, key_len);
    memcpy((outbound_group_session->associated_data.data) + key_len, outbound_group_session->chain_key.data, key_len);

    get_e2ees_plugin()->db_handler.store_group_session(outbound_group_session);

    uint8_t *group_pre_key_plaintext = NULL;
    size_t group_pre_key_plaintext_len = pack_group_pre_key_plaintext(outbound_group_session, &group_pre_key_plaintext, NULL);

    // store group pre-key
    char *pending_plaintext_id = generate_uuid_str();
    get_e2ees_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_id,
        group_pre_key_plaintext,
        group_pre_key_plaintext_len,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );

    // load group pre-key
    uint32_t n_group_pre_keys;
    char **pending_plaintext_id_list;
    uint8_t **group_pre_key_plaintext_data_list;
    size_t *group_pre_key_plaintext_data_len_list;
    E2ees__NotifLevel *notif_level;
    n_group_pre_keys = get_e2ees_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_list,
        &group_pre_key_plaintext_data_list,
        &group_pre_key_plaintext_data_len_list,
        &notif_level
    );
    assert(group_pre_key_plaintext_len == group_pre_key_plaintext_data_len_list[0]);
    assert(memcmp(group_pre_key_plaintext, group_pre_key_plaintext_data_list[0], group_pre_key_plaintext_data_len_list[0]) == 0);

    // unload group pre-key
    get_e2ees_plugin()->db_handler.unload_pending_plaintext_data(user_address, member_address, pending_plaintext_id_list[0]);
    char **pending_plaintext_id_list_null;
    uint8_t **group_pre_key_plaintext_data_list_null;
    size_t *group_pre_key_plaintext_data_len_list_null;
    E2ees__NotifLevel *notif_level_null;
    get_e2ees_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_list_null,
        &group_pre_key_plaintext_data_list_null,
        &group_pre_key_plaintext_data_len_list_null,
        &notif_level_null
    );
    assert(pending_plaintext_id_list_null == NULL);
    assert(group_pre_key_plaintext_data_list_null == NULL);
    assert(group_pre_key_plaintext_data_len_list_null == NULL);

    // release
    e2ees__e2ee_address__free_unpacked(user_address, NULL);
    e2ees__e2ee_address__free_unpacked(member_address, NULL);
    e2ees__e2ee_address__free_unpacked(group_address, NULL);
    e2ees__group_session__free_unpacked(outbound_group_session, NULL);
    free(pending_plaintext_id);
    free_mem((void **)&(group_pre_key_plaintext_data_list[0]), group_pre_key_plaintext_data_len_list[0]);
    free(pending_plaintext_id_list[0]);
    free_mem((void **)&pending_plaintext_id_list, sizeof(char *) * n_group_pre_keys);
    free_mem((void **)&group_pre_key_plaintext_data_list, sizeof(uint8_t *) * n_group_pre_keys);
    free_mem((void **)&group_pre_key_plaintext_data_len_list, sizeof(size_t) * n_group_pre_keys);
    free_mem((void **)&notif_level, sizeof(E2ees__NotifLevel) * n_group_pre_keys);

    // test stop
    tear_down();
}

static void test_multiple_group_pre_keys() {
    // test start
    tear_up();

    // mock address
    E2ees__E2eeAddress *user_address, *member_address;
    mock_address(&user_address, "alice", "alice's domain", "alice's device");
    mock_address(&member_address, "bob", "bob's domain", "bob's device");

    // mock plaintext
    uint8_t plaintext_1[] = "abcdefghijklmnopqrstuvwxyz";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    uint8_t plaintext_2[] = "12345678901234567890";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    uint8_t plaintext_3[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;

    // store group pre-key
    char *pending_plaintext_1_id = generate_uuid_str();
    char *pending_plaintext_2_id = generate_uuid_str();
    char *pending_plaintext_3_id = generate_uuid_str();
    get_e2ees_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_1_id,
        plaintext_1,
        plaintext_1_len,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );
    get_e2ees_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_2_id,
        plaintext_2,
        plaintext_2_len,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );
    get_e2ees_plugin()->db_handler.store_pending_plaintext_data(
        user_address,
        member_address,
        pending_plaintext_3_id,
        plaintext_3,
        plaintext_3_len,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
    );

    // load pending plaintext
    uint32_t n_pending_plaintext;
    char **pending_plaintext_id_list;
    uint8_t **pending_plaintext_data_list;
    size_t *pending_plaintext_data_len_list;
    E2ees__NotifLevel *notif_level;
    n_pending_plaintext = get_e2ees_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_list,
        &pending_plaintext_data_list,
        &pending_plaintext_data_len_list,
        &notif_level
    );
    assert(n_pending_plaintext == 3);

    // unload group pre-key
    get_e2ees_plugin()->db_handler.unload_pending_plaintext_data(user_address, member_address, pending_plaintext_2_id);

    // load pending plaintext again
    uint32_t n_pending_plaintext_left;
    char **pending_plaintext_id_left_list;
    uint8_t **pending_plaintext_data_left_list;
    size_t *pending_plaintext_data_len_left_list;
    E2ees__NotifLevel *notif_level_left;
    n_pending_plaintext_left = get_e2ees_plugin()->db_handler.load_pending_plaintext_data(
        user_address,
        member_address,
        &pending_plaintext_id_left_list,
        &pending_plaintext_data_left_list,
        &pending_plaintext_data_len_left_list,
        &notif_level_left
    );
    assert(n_pending_plaintext_left == 2);

    // release
    e2ees__e2ee_address__free_unpacked(user_address, NULL);
    e2ees__e2ee_address__free_unpacked(member_address, NULL);
    free(pending_plaintext_1_id);
    free(pending_plaintext_2_id);
    free(pending_plaintext_3_id);
    free_mem((void **)&pending_plaintext_id_list, sizeof(char *) * n_pending_plaintext);
    free_mem((void **)&pending_plaintext_data_list, sizeof(uint8_t *) * n_pending_plaintext);
    free_mem((void **)&pending_plaintext_data_len_list, sizeof(size_t) * n_pending_plaintext);
    free_mem((void **)&notif_level, sizeof(E2ees__NotifLevel) * n_pending_plaintext);
    free_mem((void **)&pending_plaintext_id_left_list, sizeof(char *) * n_pending_plaintext_left);
    free_mem((void **)&pending_plaintext_data_left_list, sizeof(uint8_t *) * n_pending_plaintext_left);
    free_mem((void **)&pending_plaintext_data_len_left_list, sizeof(size_t) * n_pending_plaintext_left);
    free_mem((void **)&notif_level_left, sizeof(E2ees__NotifLevel) * n_pending_plaintext_left);

    // test stop
    tear_down();
}

static void test_pending_request_data() {
    // test start
    tear_up();

    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();

    // mock address
    E2ees__E2eeAddress *alice_address, *bob_address;
    mock_address(&alice_address, "alice", "alice's domain", "alice's device");
    mock_address(&bob_address, "bob", "bob's domain", "bob's device");

    char *session_id = "session_id";

    ProtobufCBinaryData *our_ratchet_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    our_ratchet_key->len = 32;
    our_ratchet_key->data = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    memcpy(our_ratchet_key->data, "abcdefghijklmnopqrstuvwxyz012345", 32);

    E2ees__AcceptRequest *accept_request = NULL;
    session_ctx ctx = {0};
    validate_and_prepare_accept(&ctx, e2ees_pack_id, alice_address, bob_address, session_id, NULL, our_ratchet_key);
    produce_accept_request(&accept_request, &ctx);

    // pack request to request_data
    size_t request_data_len = e2ees__accept_request__get_packed_size(accept_request);
    uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
    e2ees__accept_request__pack(accept_request, request_data);

    store_pending_request_internal(alice_address, E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT, request_data, request_data_len, NULL, 0);

    // load
    char **pending_request_id_list;
    uint8_t *request_type_list;
    uint8_t **request_data_list;
    size_t *request_data_len_list;
    size_t pending_request_data_num =
        get_e2ees_plugin()->db_handler.load_pending_request_data(
            alice_address, &pending_request_id_list, &request_type_list, &request_data_list, &request_data_len_list
        );

    E2ees__PendingRequest *pending_request = e2ees__pending_request__unpack(NULL, request_data_len_list[0], request_data_list[0]);

    // assert
    assert(pending_request_data_num == 1);
    assert(request_type_list[0] == E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT);
    assert(pending_request->request_data.len == request_data_len);
    assert(memcmp((void *)(pending_request->request_data.data), (void *)(request_data), request_data_len) == 0);

    // release
    e2ees__e2ee_address__free_unpacked(alice_address, NULL);
    e2ees__e2ee_address__free_unpacked(bob_address, NULL);
    free_protobuf(our_ratchet_key);
    free_mem((void **)&our_ratchet_key, sizeof(ProtobufCBinaryData));
    e2ees__accept_request__free_unpacked(accept_request, NULL);
    e2ees__pending_request__free_unpacked(pending_request, NULL);
    free_mem((void **)&request_data, request_data_len);
    free_mem((void **)&pending_request_id_list, sizeof(char *) * pending_request_data_num);
    free_mem((void **)&request_type_list, sizeof(uint8_t) * pending_request_data_num);
    free_mem((void **)&(request_data_list[0]), request_data_len_list[0]);
    free_mem((void **)&request_data_list, sizeof(uint8_t *) * pending_request_data_num);
    free_mem((void **)&request_data_len_list, sizeof(size_t) * pending_request_data_num);

    // test stop
    tear_down();
}

static void test_sending_before_accept() {
    // test start
    tear_up();

    // register
    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    char *alice_device_id = generate_uuid_str();
    const char *alice_authenticator = "alice@domain.com.tw";
    const char *alice_auth_code = "123456";
    E2ees__RegisterUserResponse *alice_response = NULL;
    register_user(
        &alice_response, e2ees_pack_id, "Alice", "alice", alice_device_id, alice_authenticator, alice_auth_code
    );
    char *bob_device_id = generate_uuid_str();
    const char *bob_authenticator = "bob@domain.com.tw";
    const char *bob_auth_code = "654321";
    E2ees__RegisterUserResponse *bob_response = NULL;
    register_user(
        &bob_response, e2ees_pack_id, "Bob", "bob", bob_device_id, bob_authenticator, bob_auth_code
    );

    E2ees__E2eeAddress *alice_address = alice_response->address, *bob_address = bob_response->address;

    // send the message first
    uint8_t plaintext[] = "This message will be sent to Bob before he accepts Alice's invitation.";
    size_t plaintext_len = sizeof(plaintext) - 1;

    int i;
    E2ees__SendOne2oneMsgResponse *send_one2one_msg_response = NULL;
    for (i = 0; i < 20; i++) {
        send_one2one_msg(
            &send_one2one_msg_response,
            alice_address,
            bob_address->user->user_id, bob_address->domain,
            E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
            plaintext, plaintext_len);

        if (send_one2one_msg_response != NULL) {
            e2ees__send_one2one_msg_response__free_unpacked(send_one2one_msg_response, NULL);
            send_one2one_msg_response = NULL;
        }
    }

    // invite
    E2ees__InviteResponse *response = invite(alice_address, bob_address->user->user_id, bob_address->domain);

    // release
    free(alice_device_id);
    free(bob_device_id);
    e2ees__register_user_response__free_unpacked(alice_response, NULL);
    e2ees__register_user_response__free_unpacked(bob_response, NULL);
    e2ees__invite_response__free_unpacked(response, NULL);

    // test stop
    tear_down();
}

int main(){
    test_one_group_pre_key();
    test_multiple_group_pre_keys();
    // test_pending_request_data();

    return 0;
}
