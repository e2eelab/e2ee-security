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
#include "test_util.h"

#include <stdio.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/crypto.h"
#include "e2ees/mem_util.h"

void print_hex(char *title, uint8_t *msg, size_t msg_len) {
    printf("%s", title);
    size_t i;
    for (i = 0; i < msg_len; i++) {
        if (i % 16 == 0)
            printf("\n| ");
        printf("0x%02x ", msg[i]);

        if (i % 8 == 7)
            printf("| ");
    }

    printf("\n");
}

void print_msg(char *title, uint8_t *msg, size_t len) {
    printf("😊 %s [msg len=%zu]: %.*s\n", title, len, (int)len, msg);
}

void print_log(char *log_msg, int log_code) {
    if (log_code == DEBUG_LOG || log_code == VERBOSE_LOG)
        printf("🔭 [%d] : %s\n", log_code, log_msg);
    else
        printf("💀 [ErrorCode=%d]: %s\n", log_code, log_msg);
}

void print_result(char *title, bool success) {
    if (success)
        printf("%s: success\n", title);
    else
        printf("%s: failed\n", title);
}

void print_test_case_final() {
    printf("Result:\n");
    printf("\tSuccess!");
    printf("\n\n");
    printf("====================\n");
}

bool is_null(void *pointer_1, void *pointer_2) {
    if ((pointer_1 == NULL) && (pointer_2 == NULL)) {
        return true;
    }
    return false;
}

bool is_not_null(void *pointer_1, void *pointer_2) {
    if ((pointer_1 != NULL) && (pointer_2 != NULL)) {
        return true;
    }
    return false;
}

bool is_equal_data(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2) {
    if (src_1->len != src_2->len) {
        return false;
    }
    bool both_null = false;
    bool both_not_null = false;
    both_null = is_null(src_1->data, src_2->data);
    both_not_null = is_not_null(src_1->data, src_2->data);
    if ((both_null || both_not_null) == false) {
        return false;
    }

    if (both_not_null) {
        size_t i;
        for (i = 0; i < src_1->len; i++) {
            if (src_1->data[i] != src_2->data[i]) {
                return false;
            }
        }
    }

    return true;
}

bool is_equal_str(char *str1, char *str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    if (len1 != len2) {
        return false;
    }

    size_t i;
    for (i = 0; i < len1; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
    }

    return true;
}

bool is_equal_keypair(E2ees__KeyPair *src_1, E2ees__KeyPair *src_2) {
    if (is_not_null(src_1, src_2)) {
        if (!is_equal_data(&(src_1->public_key), &(src_2->public_key))) {
            return false;
        }
        if (!is_equal_data(&(src_1->private_key), &(src_2->private_key))) {
            return false;
        }
    } else {
        if (!is_null(src_1, src_2)) {
            return false;
        }
    }

    return true;
}

bool is_equal_ik(E2ees__IdentityKey *src_1, E2ees__IdentityKey *src_2) {
    if (is_not_null(src_1, src_2)) {
        if (!is_equal_keypair(src_1->asym_key_pair, src_2->asym_key_pair)) {
            return false;
        }
        if (!is_equal_keypair(src_1->sign_key_pair, src_2->sign_key_pair)) {
            return false;
        }
    } else {
        if (!is_null(src_1, src_2)) {
            return false;
        }
    }

    return true;
}

bool is_equal_spk(E2ees__SignedPreKey *src_1, E2ees__SignedPreKey *src_2) {
    if (is_not_null(src_1, src_2)) {
        if (src_1->spk_id != src_2->spk_id) {
            return false;
        }
        if (!is_equal_keypair(src_1->key_pair, src_2->key_pair)) {
            return false;
        }
        if (!is_equal_data(&(src_1->signature), &(src_2->signature))) {
            return false;
        }
        if (src_1->ttl != src_2->ttl) {
            return false;
        }
    } else {
        if (!is_null(src_1, src_2)) {
            return false;
        }
    }

    return true;
}

bool is_equal_opk(E2ees__OneTimePreKey *src_1, E2ees__OneTimePreKey *src_2) {
    if (is_not_null(src_1, src_2)) {
        if (src_1->opk_id != src_2->opk_id) {
            return false;
        }
        if (!is_equal_keypair(src_1->key_pair, src_2->key_pair)) {
            return false;
        }
    } else {
        if (!is_null(src_1, src_2)) {
            return false;
        }
    }

    return true;
}

bool is_equal_opk_list(E2ees__OneTimePreKey **src_1, E2ees__OneTimePreKey **src_2, size_t len) {
    if (is_not_null(src_1, src_2)) {
        size_t i;
        for (i = 0; i < len; i++) {
            if (!is_equal_opk(src_1[i], src_2[i])) {
                return false;
            }
        }
    } else {
        if (!is_null(src_1, src_2)) {
            return false;
        }
    }

    return true;
}

bool is_equal_account(E2ees__Account *src_1, E2ees__Account *src_2) {
    if (is_not_null(src_1, src_2)) {
        if (!safe_strcmp(src_1->version, src_2->version)) {
            printf("version not match");
            return false;
        }
        if (src_1->e2ees_pack_id != src_2->e2ees_pack_id) {
            printf("e2ees_pack_id not match");
            return false;
        }
        if (src_1->saved != src_2->saved) {
            printf("saved not match");
            return false;
        }
        if (!compare_address(src_1->address, src_2->address)) {
            printf("address not match");
            return false;
        }
        if (!is_equal_ik(src_1->identity_key, src_2->identity_key)) {
            printf("keypair not match");
            return false;
        }
        if (!is_equal_spk(src_1->signed_pre_key, src_2->signed_pre_key)) {
            printf("spk not match");
            return false;
        }
        if (src_1->n_one_time_pre_key_list != src_2->n_one_time_pre_key_list) {
            printf("1: %zu\n", src_1->n_one_time_pre_key_list);
            printf("2: %zu\n", src_1->n_one_time_pre_key_list);
            printf("n_one_time_pre_key_list not match");
            return false;
        }
        size_t len = src_1->n_one_time_pre_key_list;
        if (!is_equal_opk_list(src_1->one_time_pre_key_list, src_2->one_time_pre_key_list, len)) {
            printf("opk not match");
            return false;
        }
        if (src_1->next_one_time_pre_key_id != src_2->next_one_time_pre_key_id) {
            printf("next_one_time_pre_key_id not match");
            return false;
        }
    } else {
        if (!is_null(src_1, src_2)) {
            return false;
        }
    }

    return true;
}

bool is_equal_message_key(E2ees__MsgKey *message_key_1, E2ees__MsgKey *message_key_2) {
    if (message_key_1->index != message_key_2->index) {
        printf("index of message_key not match");
        return false;
    }
    if (!is_equal_data(&(message_key_1->derived_key), &(message_key_2->derived_key))) {
        printf("derived_key not match");
        return false;
    }

    return true;
}

bool is_equal_chain(E2ees__ChainKey *chain_key_1, E2ees__ChainKey *chain_key_2) {
    if (chain_key_1->index != chain_key_2->index) {
        printf("index of chain_key not match");
        return false;
    }
    if (!is_equal_data(&(chain_key_1->shared_key), &(chain_key_2->shared_key))) {
        printf("shared_key not match");
        return false;
    }

    return true;
}

bool is_equal_sender_chain(E2ees__SenderChainNode *sender_chain_1, E2ees__SenderChainNode *sender_chain_2) {
    if (!is_equal_data(&(sender_chain_1->our_ratchet_public_key), &(sender_chain_2->our_ratchet_public_key))) {
        printf("our_ratchet_public_key not match");
        return false;
    }
    if (!is_equal_data(&(sender_chain_1->their_ratchet_public_key), &(sender_chain_2->their_ratchet_public_key))) {
        printf("their_ratchet_public_key not match");
        return false;
    }
    if (is_not_null(sender_chain_1->chain_key, sender_chain_2->chain_key)) {
        if (!is_equal_chain(sender_chain_1->chain_key, sender_chain_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    } else {
        if (!is_null(sender_chain_1->chain_key, sender_chain_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    }

    return true;
}

bool is_equal_receiver_chain(E2ees__ReceiverChainNode *receiver_chain_node_1, E2ees__ReceiverChainNode *receiver_chain_node_2) {
    if (!is_equal_data(&(receiver_chain_node_1->their_ratchet_public_key), &(receiver_chain_node_2->their_ratchet_public_key))) {
        printf("their_ratchet_public_key not match");
        return false;
    }
    if (!is_equal_data(&(receiver_chain_node_1->our_ratchet_private_key), &(receiver_chain_node_2->our_ratchet_private_key))) {
        printf("our_ratchet_private_key not match");
        return false;
    }
    if (is_not_null(receiver_chain_node_1->chain_key, receiver_chain_node_2->chain_key)) {
        if (!is_equal_chain(receiver_chain_node_1->chain_key, receiver_chain_node_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    } else {
        if (!is_null(receiver_chain_node_1->chain_key, receiver_chain_node_2->chain_key)) {
            printf("chain_key not match");
            return false;
        }
    }

    return true;
}

bool is_equal_skipped_message_key(E2ees__SkippedMsgKeyNode *skipped_msg_key_node_1, E2ees__SkippedMsgKeyNode *skipped_msg_key_node_2) {
    if (!is_equal_data(&(skipped_msg_key_node_1->ratchet_key_public), &(skipped_msg_key_node_2->ratchet_key_public))) {
        printf("ratchet_key_public not match");
        return false;
    }
    if (is_not_null(skipped_msg_key_node_1->msg_key, skipped_msg_key_node_2->msg_key)) {
        if (!is_equal_message_key(skipped_msg_key_node_1->msg_key, skipped_msg_key_node_2->msg_key)) {
            printf("message_key not match");
            return false;
        }
    } else {
        if (!is_null(skipped_msg_key_node_1->msg_key, skipped_msg_key_node_2->msg_key)) {
            printf("message_key not match");
            return false;
        }
    }

    return true;
}

bool is_equal_ratchet(E2ees__Ratchet *ratchet_1, E2ees__Ratchet *ratchet_2) {
    if (!is_equal_data(&(ratchet_1->root_key), &(ratchet_2->root_key))) {
        printf("root_key not match");
        return false;
    }
    if (ratchet_1->root_sequence != ratchet_2->root_sequence) {
        printf("root_sequence not match");
        return false;
    }
    if (is_not_null(ratchet_1->sender_chain, ratchet_2->sender_chain)) {
        if (!is_equal_sender_chain(ratchet_1->sender_chain, ratchet_2->sender_chain)) {
            printf("sender_chain not match");
            return false;
        }
    } else {
        if (!is_null(ratchet_1->sender_chain, ratchet_2->sender_chain)) {
            printf("sender_chain not match");
            return false;
        }
    }
    if (!is_equal_receiver_chain(ratchet_1->receiver_chain, ratchet_2->receiver_chain)) {
        printf("receiver_chain not match");
        return false;
    }
    if (ratchet_1->n_skipped_msg_key_list != ratchet_2->n_skipped_msg_key_list) {
        printf("n_skipped_msg_key_list not match");
        return false;
    }
    size_t i;
    for (i = 0; i < ratchet_1->n_skipped_msg_key_list; i++) {
        if (!is_equal_skipped_message_key(ratchet_1->skipped_msg_key_list[i], ratchet_2->skipped_msg_key_list[i])) {
            printf("skipped_msg_key_list not match");
            return false;
        }
    }

    return true;
}

bool is_equal_session(E2ees__Session *session_1, E2ees__Session *session_2) {
    if (!safe_strcmp(session_1->version, session_2->version)) {
        printf("version not match");
        return false;
    }
    if (!safe_strcmp(session_1->session_id, session_2->session_id)) {
        printf("session_id not match");
        return false;
    }
    if (is_not_null(session_1->our_address, session_2->our_address)) {
        if (!compare_address(session_1->our_address, session_2->our_address)) {
            printf("our_address not match");
            return false;
        }
    } else {
        if (!is_null(session_1->our_address, session_2->our_address)) {
            printf("our_address not match");
            return false;
        }
    }
    if (is_not_null(session_1->their_address, session_2->their_address)) {
        if (!compare_address(session_1->their_address, session_2->their_address)) {
            printf("their_address not match");
            return false;
        }
    } else {
        if (!is_null(session_1->their_address, session_2->their_address)) {
            printf("their_address not match");
            return false;
        }
    }
    if (session_1->n_pre_shared_input_list != session_2->n_pre_shared_input_list) {
        printf("n_pre_shared_input_list not match");
        return false;
    }
    size_t i;
    for (i = 0; i < session_1->n_pre_shared_input_list; i++) {
        if (!is_equal_data(&(session_1->pre_shared_input_list[i]), &(session_2->pre_shared_input_list[i]))) {
            printf("pre_shared_input_list not match");
            return false;
        }
    }
    if (!is_equal_data(&(session_1->associated_data), &(session_2->associated_data))) {
        printf("associated_data not match");
        return false;
    }

    return true;
}

bool is_equal_sessions(E2ees__Session **sessions_1, E2ees__Session **sessions_2, size_t session_num) {
    size_t i;
    for (i = 0; i < session_num; i++) {
        if (is_equal_session(sessions_1[i], sessions_2[i]) == false) {
            return false;
        }
    }

    return true;
}

bool is_equal_group_session(E2ees__GroupSession *group_session_1, E2ees__GroupSession *group_session_2) {
    if (!safe_strcmp(group_session_1->version, group_session_2->version)) {
        printf("version not match");
        return false;
    }
    if (!safe_strcmp(group_session_1->session_id, group_session_2->session_id)) {
        printf("session_id not match");
        return false;
    }
    if (is_not_null(group_session_1->session_owner, group_session_2->session_owner)) {
        if (!compare_address(group_session_1->session_owner, group_session_2->session_owner)) {
            printf("session_owner not match");
            return false;
        }
    } else {
        if (!is_null(group_session_1->session_owner, group_session_2->session_owner)) {
            printf("session_owner not match");
            return false;
        }
    }
    if (is_not_null(group_session_1->group_info, group_session_2->group_info) && is_not_null(group_session_1->group_info->group_address, group_session_2->group_info->group_address)) {
        if (!compare_address(group_session_1->group_info->group_address, group_session_2->group_info->group_address)) {
            printf("group_address not match");
            return false;
        }
    } else {
        if (!is_null(group_session_1->group_info, group_session_2->group_info)) {
            printf("group_address not match");
            return false;
        }
    }
    if (!is_equal_data(&(group_session_1->chain_key), &(group_session_2->chain_key))) {
        printf("chain_key not match");
        return false;
    }
    if (!is_equal_data(&(group_session_1->group_seed), &(group_session_2->group_seed))) {
        printf("group_seed not match");
        return false;
    }
    if (!is_equal_data(&(group_session_1->associated_data), &(group_session_2->associated_data))) {
        printf("associated_data not match");
        return false;
    }

    return true;
}

void mock_data(ProtobufCBinaryData *to, const char *from) {
    size_t from_len = strlen(from);
    to->data = (uint8_t *)malloc(from_len);
    memcpy(to->data, from, from_len);
    to->len = from_len;
}

void mock_string(char **to, const char *from) {
    size_t from_len = sizeof(from);
    *to = (char *)malloc(from_len);
    memcpy(*to, from, from_len);
}

void mock_address(E2ees__E2eeAddress **address, const char *user_id, const char *domain, const char *device_id) {
    *address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(*address);
    (*address)->user = (E2ees__PeerUser *)malloc(sizeof(E2ees__PeerUser));
    e2ees__peer_user__init((*address)->user);
    (*address)->peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    (*address)->domain = strdup(domain);
    (*address)->user->user_name = strdup(user_id);
    (*address)->user->user_id = strdup(user_id);
    (*address)->user->device_id = strdup(device_id);
}

char *mock_domain_str() {
    char *domain_str = strdup(E2EELAB_DOMAIN);
    return domain_str;
}

void mock_random_user_address(E2ees__E2eeAddress **address) {
    *address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(*address);
    (*address)->user = (E2ees__PeerUser *)malloc(sizeof(E2ees__PeerUser));
    e2ees__peer_user__init((*address)->user);
    (*address)->peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    (*address)->domain = mock_domain_str();
    (*address)->user->user_id = generate_uuid_str();
    (*address)->user->device_id = generate_uuid_str();
}

void mock_random_group_address(E2ees__E2eeAddress **address) {
    *address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(*address);
    (*address)->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
    e2ees__peer_group__init((*address)->group);
    (*address)->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
    (*address)->domain = mock_domain_str();
    (*address)->group->group_id = generate_uuid_str();
}

void mock_keypair(E2ees__KeyPair **keypair) {
    *keypair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(*keypair);

    mock_data(&((*keypair)->public_key), "public_key");
    mock_data(&((*keypair)->private_key), "private_key");
}

void mock_identity_key(E2ees__IdentityKey **identity_keypair) {
    *identity_keypair = (E2ees__IdentityKey *)malloc(sizeof(E2ees__IdentityKey));
    e2ees__identity_key__init(*identity_keypair);
    mock_keypair(&((*identity_keypair)->asym_key_pair));
    mock_keypair(&((*identity_keypair)->sign_key_pair));
}

void mock_signed_pre_key(E2ees__SignedPreKey **signed_pre_keypair, uint32_t spk_id) {
    *signed_pre_keypair = (E2ees__SignedPreKey *)malloc(sizeof(E2ees__SignedPreKey));
    e2ees__signed_pre_key__init(*signed_pre_keypair);
    mock_data(&((*signed_pre_keypair)->signature), "signature");
    mock_keypair(&((*signed_pre_keypair)->key_pair));
    (*signed_pre_keypair)->spk_id = spk_id;
}

void mock_one_time_pre_key(E2ees__OneTimePreKey **one_time_pre_keypair, uint32_t opk_id) {
    *one_time_pre_keypair = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
    e2ees__one_time_pre_key__init(*one_time_pre_keypair);
    mock_keypair(&((*one_time_pre_keypair)->key_pair));
    (*one_time_pre_keypair)->opk_id = opk_id;
    (*one_time_pre_keypair)->used = false;
}

void mock_one_time_pre_key_list(E2ees__OneTimePreKey ***one_time_pre_key_list) {
    *one_time_pre_key_list = (E2ees__OneTimePreKey **)malloc(sizeof(E2ees__OneTimePreKey *) * 100);
    int i;
    for (i = 0; i < 100; i++) {
        mock_one_time_pre_key(&((*one_time_pre_key_list)[i]), i);
    }
}

void mock_account(E2ees__Account **account_out) {
    *account_out = (E2ees__Account *)malloc(sizeof(E2ees__Account));
    e2ees__account__init(*account_out);
    (*account_out)->version = strdup("version");
    (*account_out)->e2ees_pack_id = gen_e2ees_pack_id_pqc();
    mock_random_user_address(&((*account_out)->address));
    mock_identity_key(&((*account_out)->identity_key));
    mock_signed_pre_key(&((*account_out)->signed_pre_key), 0);
    mock_one_time_pre_key_list(&((*account_out)->one_time_pre_key_list));
    (*account_out)->n_one_time_pre_key_list = 100;
    (*account_out)->next_one_time_pre_key_id = 100;
    (*account_out)->password = strdup("password");
    (*account_out)->auth = strdup("auth");
}

void pre_key_bundle_hash(
    uint8_t **out,
    size_t *out_len,
    E2ees__E2eeAddress *address,
    E2ees__IdentityKeyPublic *ik,
    E2ees__SignedPreKeyPublic *spk,
    E2ees__OneTimePreKeyPublic *opk
) {
    uint8_t *address_data = NULL;
    uint8_t *ik_data = NULL;
    uint8_t *spk_data = NULL;
    uint8_t *opk_data = NULL;
    uint8_t *input = NULL;
    size_t address_data_len, ik_data_len, spk_data_len, opk_data_len, input_len;

    uint32_t e2ees_pack_id_raw = gen_e2ees_pack_id_raw(
        E2EES_PACK_ID_V_0,
        E2EES_PACK_ALG_DS_MLDSA87,
        E2EES_PACK_ALG_KEM_MLKEM1024,
        E2EES_PACK_ALG_SE_AES256GCM,
        E2EES_PACK_ALG_HASH_SHA2_256
    );

    address_data_len = e2ees__e2ee_address__get_packed_size(address);
    address_data = (uint8_t *)malloc(sizeof(uint8_t) * address_data_len);
    e2ees__e2ee_address__pack(address, address_data);

    ik_data_len = e2ees__identity_key_public__get_packed_size(ik);
    ik_data = (uint8_t *)malloc(sizeof(uint8_t) * ik_data_len);
    e2ees__identity_key_public__pack(ik, ik_data);

    spk_data_len = e2ees__signed_pre_key_public__get_packed_size(spk);
    spk_data = (uint8_t *)malloc(sizeof(uint8_t) * spk_data_len);
    e2ees__signed_pre_key_public__pack(spk, spk_data);

    if (opk != NULL) {
        opk_data_len = e2ees__one_time_pre_key_public__get_packed_size(opk);
        opk_data = (uint8_t *)malloc(sizeof(uint8_t) * opk_data_len);
        e2ees__one_time_pre_key_public__pack(opk, opk_data);
    } else {
        opk_data_len = 0;
    }

    input_len = address_data_len + ik_data_len + spk_data_len + opk_data_len;

    input = (uint8_t *)malloc(sizeof(uint8_t) * input_len);
    memcpy(input, address_data, address_data_len);
    memcpy(input + address_data_len, ik_data, ik_data_len);
    memcpy(input + address_data_len + ik_data_len, spk_data, spk_data_len);
    if (opk != NULL) {
        memcpy(input + address_data_len + ik_data_len + spk_data_len, opk_data, opk_data_len);
    }

    crypto_hash_by_e2ees_pack_id(e2ees_pack_id_raw, input, input_len, out, out_len);

    // release
    free_mem((void **)&address_data, address_data_len);
    free_mem((void **)&ik_data, ik_data_len);
    free_mem((void **)&spk_data, spk_data_len);
    if (opk != NULL) {
        free_mem((void **)&opk_data, opk_data_len);
    }
    free_mem((void **)&input, input_len);
}

void proto_msg_hash(
    uint8_t **out,
    size_t *out_len,
    E2ees__ProtoMsgTag *tag,
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    E2ees__ProtoMsg__PayloadCase payload_case,
    void *payload
) {
    uint8_t *tag_data = NULL;
    uint8_t *from_data = NULL;
    uint8_t *to_data = NULL;
    uint8_t *payload_data = NULL;
    uint8_t *input = NULL;
    size_t tag_data_len, from_data_len, to_data_len, payload_data_len, input_len;

    uint32_t e2ees_pack_id_raw = gen_e2ees_pack_id_raw(
        E2EES_PACK_ID_V_0,
        E2EES_PACK_ALG_DS_MLDSA87,
        E2EES_PACK_ALG_KEM_MLKEM1024,
        E2EES_PACK_ALG_SE_AES256GCM,
        E2EES_PACK_ALG_HASH_SHA2_256
    );

    if (tag != NULL) {
        tag_data_len = e2ees__proto_msg_tag__get_packed_size(tag);
        tag_data = (uint8_t *)malloc(sizeof(uint8_t) * tag_data_len);
        e2ees__proto_msg_tag__pack(tag, tag_data);
    } else {
        tag_data_len = 0;
    }

    from_data_len = e2ees__e2ee_address__get_packed_size(from);
    from_data = (uint8_t *)malloc(sizeof(uint8_t) * from_data_len);
    e2ees__e2ee_address__pack(from, from_data);

    to_data_len = e2ees__e2ee_address__get_packed_size(to);
    to_data = (uint8_t *)malloc(sizeof(uint8_t) * to_data_len);
    e2ees__e2ee_address__pack(to, to_data);

    switch(payload_case) {
        case E2EES__PROTO_MSG__PAYLOAD_ACQUIRE_SYNC_MSG:
            payload_data_len = e2ees__acquire_sync_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__acquire_sync_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_SUPPLY_OPKS_MSG:
            payload_data_len = e2ees__supply_opks_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__supply_opks_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_INVITE_MSG:
            payload_data_len = e2ees__invite_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__invite_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ACCEPT_MSG:
            payload_data_len = e2ees__accept_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__accept_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ADD_USER_DEVICE_MSG:
            payload_data_len = e2ees__add_user_device_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__add_user_device_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_REMOVE_USER_DEVICE_MSG:
            payload_data_len = e2ees__remove_user_device_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__remove_user_device_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_CREATE_GROUP_MSG:
            payload_data_len = e2ees__create_group_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__create_group_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBERS_MSG:
            payload_data_len = e2ees__add_group_members_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__add_group_members_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBER_DEVICE_MSG:
            payload_data_len = e2ees__add_group_member_device_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__add_group_member_device_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG:
            payload_data_len = e2ees__remove_group_members_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__remove_group_members_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_LEAVE_GROUP_MSG:
            payload_data_len = e2ees__leave_group_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__leave_group_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_E2EE_MSG:
            payload_data_len = e2ees__e2ee_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__e2ee_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_UPDATE_USER_MSG:
            payload_data_len = e2ees__update_user_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__update_user_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_FRIEND_MANAGER_MSG:
            payload_data_len = e2ees__friend_manager_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__friend_manager_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_GROUP_MANAGER_MSG:
            payload_data_len = e2ees__group_manager_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__group_manager_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_SYSTEM_MANAGER_MSG:
            payload_data_len = e2ees__system_manager_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__system_manager_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_CLIENT_HEARTBEAT_MSG:
            payload_data_len = e2ees__client_heartbeat_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__client_heartbeat_msg__pack(payload, payload_data);
            break;
        case E2EES__PROTO_MSG__PAYLOAD_SERVER_HEARTBEAT_MSG:
            payload_data_len = e2ees__server_heartbeat_msg__get_packed_size(payload);
            payload_data = (uint8_t *)malloc(sizeof(uint8_t) * payload_data_len);
            e2ees__server_heartbeat_msg__pack(payload, payload_data);
            break;
        default:
            break;
    };

    input_len = tag_data_len + from_data_len + to_data_len + payload_data_len;

    input = (uint8_t *)malloc(sizeof(uint8_t) * input_len);
    if (tag_data_len != 0) {
        memcpy(input, tag_data, tag_data_len);
    }
    memcpy(input + tag_data_len, from_data, from_data_len);
    memcpy(input + tag_data_len + from_data_len, to_data, to_data_len);
    memcpy(input + tag_data_len + from_data_len + to_data_len, payload_data, payload_data_len);

    crypto_hash_by_e2ees_pack_id(e2ees_pack_id_raw, input, input_len, out, out_len);

    // release
    if (tag_data != NULL) {
        free_mem((void **)&tag_data, tag_data_len);
    }
    free_mem((void **)&from_data, from_data_len);
    free_mem((void **)&to_data, to_data_len);
    free_mem((void **)&payload_data, payload_data_len);
    free_mem((void **)&input, input_len);
}

void free_account(E2ees__Account *account) {
    e2ees__account__free_unpacked(account, NULL);
    account = NULL;
}

void free_address(E2ees__E2eeAddress *address) {
    e2ees__e2ee_address__free_unpacked(address, NULL);
    address = NULL;
}
