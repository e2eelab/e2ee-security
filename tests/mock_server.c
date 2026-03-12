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
#include "mock_server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mock_server_sending.h"
#include "e2ees/crypto.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/mem_util.h"
#include "e2ees/validation.h"
#include "test_util.h"

#define user_data_max 205
#define group_data_max 8

static E2ees__Certificate *central_certificate = NULL;

static E2ees__Certificate *server_certificate = NULL;

static E2ees__KeyPair *central_key_pair = NULL;

static E2ees__KeyPair *server_key_pair = NULL;

typedef struct user_data {
    char *authenticator;
    E2ees__E2eeAddress *address;
    uint32_t e2ees_pack_id;
    E2ees__IdentityKeyPublic *identity_key_public;
    E2ees__SignedPreKeyPublic *signed_pre_key_public;
    E2ees__OneTimePreKeyPublic **one_time_pre_key_list;
    size_t n_one_time_pre_key_list;
} user_data;

typedef struct group_data {
    E2ees__E2eeAddress *group_address;
    char *group_name;
    size_t group_members_num;
    E2ees__GroupMember **group_member_list;
} group_data;

/* TODO : LINKED LIST */
typedef struct index_node {
    size_t index;
    E2ees__E2eeAddress *device_address;
    struct index_node *next;
} index_node;

static user_data user_data_set[user_data_max] = {
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0},
    {NULL, NULL, 0, NULL, NULL, NULL, 0}};

static group_data group_data_set[group_data_max] = {
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL}};

static bool session_record[user_data_max][user_data_max];

static bool group_record[user_data_max][group_data_max];

static bool device_invited_record[user_data_max][group_data_max];

static uint8_t user_data_set_insert_pos = 0;

static uint8_t group_data_set_insert_pos = 0;

static char file_path_buf[128] = "";
static char *get_path(char *file_sub_path) {
    memset(file_path_buf, 0, strlen(file_path_buf));
    if (ENV_USING_XCODE) {
        snprintf(file_path_buf, 128, "..%s", file_sub_path);
    } else {
        snprintf(file_path_buf, 128, ".%s", file_sub_path);
    }
    return file_path_buf;
}


static user_data *find_user(char *authenticator, uint8_t *position) {
    uint8_t i;
    for (i = 0; i < user_data_max; i++) {
        if (user_data_set[i].authenticator != NULL) {
            if (strcmp(user_data_set[i].authenticator, authenticator) == 0) {
                *position = i;
                return &(user_data_set[i]);
            }
        }
    }
    return NULL;
}

static uint8_t find_address(E2ees__E2eeAddress *user_address) {
    uint8_t i;
    for (i = 0; i < user_data_max; i++) {
        if (user_data_set[i].address != NULL) {
            if (compare_address(user_data_set[i].address, user_address)) {
                return i;
            }
        }
    }
    return user_data_max;
}

static void insert_index_node(index_node **head, index_node **tail, size_t index, E2ees__E2eeAddress *device_address) {
    index_node *new_node = (index_node *)malloc(sizeof(index_node));
    new_node->index = index;
    copy_address_from_address(&(new_node->device_address), device_address);
    new_node->next = NULL;

    if (*head == NULL) {
        *head = new_node;
        *tail = *head;
        return;
    }

    (*tail)->next = new_node;
    (*tail) = (*tail)->next;
    return;
}

// NOTE: used when user delete a device, not yet used
static size_t new_delete_node(index_node **head, size_t target_data) {
    index_node *cur_node = *head;
    index_node *prev_node = NULL;
    while (cur_node != NULL) {
        if (cur_node->index == target_data) {
            if (prev_node == NULL) { // head
                *head = cur_node->next;
            } else {
                prev_node->next = cur_node->next;
            }
            free(cur_node);
            return 1;
        }
        prev_node = cur_node;
        cur_node = cur_node->next;
    }
    return 0;
}

static size_t find_device_index_and_addresses(const char *user_id, index_node **user_devices_addresses) {
    size_t user_addresses_num = 0;
    index_node *tail = NULL;
    uint8_t i;

    for (i = 0; i < user_data_max; i++) {
        if (user_data_set[i].address != NULL) {
            // return non-zero if not equal
            if (safe_strcmp(user_data_set[i].address->user->user_id, user_id)) {
                user_addresses_num++;
                // input one user's device address, tail node and index , address
                insert_index_node(user_devices_addresses, &(tail), i, user_data_set[i].address);
            }
        }
    }

    return user_addresses_num;
}

static size_t find_device_addresses(const char *user_id, E2ees__E2eeAddress ***user_addresses) {
    size_t user_addresses_num = 0;
    uint8_t i, j;
    for (i = 0; i < user_data_max; i++) {
        if (user_data_set[i].address != NULL) {
            // return non-zero if not equal
            if (safe_strcmp(user_data_set[i].address->user->user_id, user_id))
                user_addresses_num++;
        }
    }
    if (user_addresses_num > 0) {
        *user_addresses = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * user_addresses_num);
        j = 0;
        for (i = 0; i < user_data_max; i++) {
            if (user_data_set[i].address != NULL) {
                if (safe_strcmp(user_data_set[i].address->user->user_id, user_id))
                    copy_address_from_address(&((*user_addresses)[j++]), user_data_set[i].address);
            }
        }
    }
    return user_addresses_num;
}
/*------------------------------------*/

static size_t find_friend_addresses(uint8_t user_index, E2ees__E2eeAddress ***friend_addresses) {
    size_t friends_num = 0;
    uint8_t i, j;
    for (i = 0; i < user_data_max; i++) {
        if (session_record[user_index][i] == true) {
            if (!safe_strcmp(user_data_set[user_index].address->user->user_id, user_data_set[i].address->user->user_id))
                friends_num++;
        }
    }
    if (friends_num > 0) {
        *friend_addresses = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * friends_num);
        j = 0;
        for (i = 0; i < user_data_max; i++) {
            if (session_record[user_index][i] == true) {
                if (!safe_strcmp(user_data_set[user_index].address->user->user_id, user_data_set[i].address->user->user_id))
                    copy_address_from_address(&((*friend_addresses)[j++]), user_data_set[i].address);
            }
        }
    }
    return friends_num;
}

static size_t find_group_data(uint8_t user_index, E2ees__GroupInfo ***group_info_list) {
    size_t group_num = 0;
    uint8_t i, j;
    for (i = 0; i < group_data_max; i++) {
        if (group_record[user_index][i] == true) {
            group_num++;
        }
    }
    if (group_num > 0) {
        *group_info_list = (E2ees__GroupInfo **)malloc(sizeof(E2ees__GroupInfo *) * group_num);
        j = 0;
        for (i = 0; i < group_data_max; i++) {
            if (group_record[user_index][i] == true) {
                (*group_info_list)[j] = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
                e2ees__group_info__init((*group_info_list)[j]);
                // copy group data
                group_data *cur_group_data = &(group_data_set[i]);
                (*group_info_list)[j]->group_name = strdup(cur_group_data->group_name);
                copy_address_from_address(&((*group_info_list)[j]->group_address), cur_group_data->group_address);
                (*group_info_list)[j]->n_group_member_list = cur_group_data->group_members_num;
                copy_group_members(&((*group_info_list)[j]->group_member_list), cur_group_data->group_member_list, cur_group_data->group_members_num);
                // done
                j++;
            }
        }
    }
    return group_num;
}

void mock_certificate() {
    FILE *fptr;
    size_t data_len;
    uint8_t *data = NULL;
    uint8_t *decoded_data = NULL;
    size_t decoded_data_len = 0;

    // central private key
    char *file_path = get_path("/cert/central_private.txt");
    if ((fptr = fopen(file_path, "r")) == NULL){
        printf("Error! Opening file in the data folder failed!\n");
        printf("errorno: %d\n", errno);
        // program exits if the file pointer returns NULL.
        exit(1);
    } else {
        fseek(fptr, 0, SEEK_END);
        data_len = ftell(fptr);
        fseek(fptr, 0, SEEK_SET);
        data = (uint8_t *)malloc(sizeof(uint8_t) * (data_len + 1));
        fread(data, 1, data_len, fptr);
        fclose(fptr);

        data[data_len] = '\0';
        decoded_data_len = crypto_base64_decode(&decoded_data, data);
        // the decoded_data is the private key
        if (decoded_data_len > 0) {
            central_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
            e2ees__key_pair__init(central_key_pair);
            copy_protobuf_from_array(&(central_key_pair->private_key), decoded_data, decoded_data_len);
        }

        // release
        free_mem((void **)&data, data_len + 1);
        free_mem((void **)&decoded_data, decoded_data_len);
    }

    // central certificate
    file_path = get_path("/cert/central_certificate.txt");
    if ((fptr = fopen(file_path, "r")) == NULL){
        printf("Error! Opening file in the data folder failed!\n");
        // program exits if the file pointer returns NULL.
        exit(1);
    } else {
        fseek(fptr, 0, SEEK_END);
        data_len = ftell(fptr);
        fseek(fptr, 0, SEEK_SET);
        data = (uint8_t *)malloc(sizeof(uint8_t) * (data_len + 1));
        fread(data, 1, data_len, fptr);
        fclose(fptr);

        data[data_len] = '\0';
        decoded_data_len = crypto_base64_decode(&decoded_data, data);
        central_certificate = e2ees__certificate__unpack(NULL, decoded_data_len, decoded_data);
        if (central_certificate != NULL) {
            copy_protobuf_from_protobuf(&(central_key_pair->public_key), &(central_certificate->cert->public_key));
        }

        // release
        free_mem((void **)&data, data_len + 1);
        free_mem((void **)&decoded_data, decoded_data_len);
    }

    // server private key
    file_path = get_path("/cert/test_private.txt");
    if ((fptr = fopen(file_path, "r")) == NULL){
        printf("Error! Opening file in the data folder failed!\n");
        // program exits if the file pointer returns NULL.
        exit(1);
    } else {
        fseek(fptr, 0, SEEK_END);
        data_len = ftell(fptr);
        fseek(fptr, 0, SEEK_SET);
        data = (uint8_t *)malloc(sizeof(uint8_t) * (data_len + 1));
        fread(data, 1, data_len, fptr);
        fclose(fptr);

        data[data_len] = '\0';
        decoded_data_len = crypto_base64_decode(&decoded_data, data);
        // the decoded_data is the private key
        if (decoded_data_len > 0) {
            server_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
            e2ees__key_pair__init(server_key_pair);
            copy_protobuf_from_array(&(server_key_pair->private_key), decoded_data, decoded_data_len);
        }

        // release
        free_mem((void **)&data, data_len + 1);
        free_mem((void **)&decoded_data, decoded_data_len);
    }

    // server certificate
    file_path = get_path("/cert/test_certificate.txt");
    if ((fptr = fopen(file_path, "r")) == NULL){
        printf("Error! Opening file in the data folder failed!\n");
        // program exits if the file pointer returns NULL.
        exit(1);
    } else {
        fseek(fptr, 0, SEEK_END);
        data_len = ftell(fptr);
        fseek(fptr, 0, SEEK_SET);
        data = (uint8_t *)malloc(sizeof(uint8_t) * (data_len + 1));
        fread(data, 1, data_len, fptr);
        fclose(fptr);

        data[data_len] = '\0';
        decoded_data_len = crypto_base64_decode(&decoded_data, data);
        server_certificate = e2ees__certificate__unpack(NULL, decoded_data_len, decoded_data);
        if (server_certificate != NULL) {
            copy_protobuf_from_protobuf(&(server_key_pair->public_key), &(server_certificate->cert->public_key));
        }

        // release
        free_mem((void **)&data, data_len + 1);
        free_mem((void **)&decoded_data, decoded_data_len);
    }
}

void mock_server_signed_signature(
    E2ees__ServerSignedSignature **out, uint8_t *msg, size_t msg_len
) {
    uint32_t e2ees_pack_id_raw = gen_e2ees_pack_id_pqc();
    const cipher_suite_t *cipher_suite = get_e2ees_pack(e2ees_pack_id_raw)->cipher_suite;
    int sig_len = cipher_suite->ds_suite->get_param().sig_len;

    *out = (E2ees__ServerSignedSignature *)malloc(sizeof(E2ees__ServerSignedSignature));
    e2ees__server_signed_signature__init(*out);

    (*out)->version = server_certificate->version;
    (*out)->hash_alg = server_certificate->hash_alg;
    (*out)->signing_alg = server_certificate->signing_alg;
    copy_subject_from_subject(&((*out)->signer), server_certificate->cert->issuee);
    copy_protobuf_from_protobuf(&((*out)->signing_public_key_fingerprint), &(server_certificate->signing_public_key_fingerprint));
    copy_protobuf_from_array(&((*out)->msg_fingerprint), msg, msg_len);
    // sign
    size_t signature_out_len;
    malloc_protobuf(&((*out)->signature), sig_len);
    cipher_suite->ds_suite->sign(
        (*out)->signature.data, &signature_out_len,
        msg, msg_len,
        server_key_pair->private_key.data
    );
}

void mock_server_begin() {
    uint8_t i, j;
    for (i = 0; i < user_data_max; i++) {
        for (j = 0; j < user_data_max; j++) {
            session_record[i][j] = 0;
        }
        for (j = 0; j < group_data_max; j++) {
            group_record[i][j] = 0;
            device_invited_record[i][j] = 0;
        }
    }
    mock_certificate();
}

void mock_server_end() {
    uint8_t i;
    size_t j;
    for (i = 0; i < user_data_set_insert_pos; i++) {
        if (user_data_set[i].authenticator != NULL) {
            free(user_data_set[i].authenticator);
            user_data_set[i].authenticator = NULL;
        }

        if (user_data_set[i].address != NULL) {
            e2ees__e2ee_address__free_unpacked(user_data_set[i].address, NULL);
            user_data_set[i].address = NULL;
        }

        user_data_set[i].e2ees_pack_id = 0;

        e2ees__identity_key_public__free_unpacked(user_data_set[i].identity_key_public, NULL);
        e2ees__signed_pre_key_public__free_unpacked(user_data_set[i].signed_pre_key_public, NULL);
        for (j = 0; j < user_data_set[i].n_one_time_pre_key_list; j++) {
            E2ees__OneTimePreKeyPublic *cur_opk = user_data_set[i].one_time_pre_key_list[j];
            if (cur_opk != NULL) {
                e2ees__one_time_pre_key_public__free_unpacked(cur_opk, NULL);
                cur_opk = NULL;
            }
        }
        free_mem((void **)&(user_data_set[i].one_time_pre_key_list), sizeof(E2ees__OneTimePreKeyPublic *) * user_data_set[i].n_one_time_pre_key_list);
        user_data_set[i].identity_key_public = NULL;
        user_data_set[i].signed_pre_key_public = NULL;
        user_data_set[i].one_time_pre_key_list = NULL;
        user_data_set[i].n_one_time_pre_key_list = 0;
    }
    user_data_set_insert_pos = 0;
    for (i = 0; i < group_data_set_insert_pos; i++) {
        e2ees__e2ee_address__free_unpacked(group_data_set[i].group_address, NULL);
        group_data_set[i].group_address = NULL;
        free(group_data_set[i].group_name);
        group_data_set[i].group_name = NULL;
        for (j = 0; j < group_data_set[i].group_members_num; j++) {
            E2ees__GroupMember *cur_group_member = group_data_set[i].group_member_list[j];
            if (cur_group_member != NULL) {
                e2ees__group_member__free_unpacked(cur_group_member, NULL);
                cur_group_member = NULL;
            }
        }
        free_mem((void **)&(group_data_set[i].group_member_list), sizeof(E2ees__GroupMember *) * group_data_set[i].group_members_num);
        group_data_set[i].group_members_num = 0;
    }
    group_data_set_insert_pos = 0;
    if (central_certificate != NULL) {
        e2ees__certificate__free_unpacked(central_certificate, NULL);
        central_certificate = NULL;
    }
    if (server_certificate != NULL) {
        e2ees__certificate__free_unpacked(server_certificate, NULL);
        server_certificate = NULL;
    }
    if (central_key_pair != NULL) {
        e2ees__key_pair__free_unpacked(central_key_pair, NULL);
        central_key_pair = NULL;
    }
    if (server_key_pair != NULL) {
        e2ees__key_pair__free_unpacked(server_key_pair, NULL);
        server_key_pair = NULL;
    }
}

E2ees__RegisterUserResponse *mock_register_user(E2ees__RegisterUserRequest *request) {
    if ((request == NULL) || (request->authenticator == NULL)) {
        e2ees_notify_log(NULL, BAD_REGISTER_USER_REQUEST, "mock_register_user()");
        return NULL;
    }

    // check if there is the user's data stored in the server's database
    uint8_t user_data_find;
    user_data *client_data = find_user(request->authenticator, &user_data_find);
    E2ees__E2eeAddress **other_device_address_list = NULL;
    E2ees__E2eeAddress **friend_addresses = NULL;
    E2ees__E2eeAddress **receiver_addresses = NULL;
    E2ees__GroupInfo **group_info_list = NULL;
    size_t other_device_num = 0, friends_num = 0, receiver_num = 0, group_num = 0;
    if (client_data != NULL) {
        other_device_num = find_device_addresses(client_data->address->user->user_id, &other_device_address_list);
        friends_num = find_friend_addresses(user_data_find, &friend_addresses);

        receiver_num = other_device_num + friends_num;

        group_num = find_group_data(user_data_find, &group_info_list);
    }

    // prepare to store
    user_data *cur_data = &(user_data_set[user_data_set_insert_pos]);
    cur_data->authenticator = strdup(request->authenticator);
    cur_data->e2ees_pack_id = request->e2ees_pack_id;

    copy_ik_public_from_ik_public(&(cur_data->identity_key_public), request->identity_key_public);
    copy_spk_public_from_spk_public(&(cur_data->signed_pre_key_public), request->signed_pre_key_public);
    cur_data->n_one_time_pre_key_list = request->n_one_time_pre_key_list;
    cur_data->one_time_pre_key_list = (E2ees__OneTimePreKeyPublic **)malloc(sizeof(E2ees__OneTimePreKeyPublic *) * cur_data->n_one_time_pre_key_list);
    size_t i, j;
    for (i = 0; i < cur_data->n_one_time_pre_key_list; i++) {
        copy_opk_public_from_opk_public(&(cur_data->one_time_pre_key_list[i]), request->one_time_pre_key_list[i]);
    }

    // copy address
    cur_data->address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    E2ees__E2eeAddress *cur_address = cur_data->address;
    e2ees__e2ee_address__init(cur_address);
    cur_address->domain = mock_domain_str();
    cur_address->user = (E2ees__PeerUser *)malloc(sizeof(E2ees__PeerUser));
    e2ees__peer_user__init(cur_address->user);
    cur_address->peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
    cur_address->user->user_name = strdup(request->user_name);
    cur_address->user->user_id = strdup(request->user_id);
    cur_address->user->device_id = strdup(request->device_id);

    user_data_set_insert_pos++;

    // prepare response
    E2ees__RegisterUserResponse *response = (E2ees__RegisterUserResponse *)malloc(sizeof(E2ees__RegisterUserResponse));
    e2ees__register_user_response__init(response);
    copy_address_from_address(&(response->address), cur_data->address);
    response->username = strdup(request->user_name);
    response->auth = strdup(request->auth_code);
    response->authenticator = strdup(request->authenticator);
    response->password = strdup("password");
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
    if (client_data != NULL) {
        receiver_addresses = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * receiver_num);
        if (other_device_num > 0) {
            // other devices
            response->n_other_device_address_list = other_device_num;
            response->other_device_address_list = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * other_device_num);
            for (i = 0; i < other_device_num; i++) {
                copy_address_from_address(&((response->other_device_address_list)[i]), other_device_address_list[i]);
                copy_address_from_address(&(receiver_addresses[i]), other_device_address_list[i]);
            }
        }
        if (friends_num > 0) {
            // other users
            response->n_other_user_address_list = friends_num;
            response->other_user_address_list = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * friends_num);
            for (i = 0; i < friends_num; i++) {
                copy_address_from_address(&((response->other_user_address_list)[i]), friend_addresses[i]);
                // remove device_id for more general cases
                free((response->other_user_address_list)[i]->user->device_id);
                (response->other_user_address_list)[i]->user->device_id = strdup("");
                
                copy_address_from_address(&(receiver_addresses[other_device_num + i]), friend_addresses[i]);
            }
        }
        if (group_num > 0) {
            // group
            response->n_group_info_list = group_num;
            response->group_info_list = (E2ees__GroupInfo **)malloc(sizeof(E2ees__GroupInfo *) * group_num);
            for (i = 0; i < group_num; i++) {
                (response->group_info_list)[i] = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
                E2ees__GroupInfo *cur_group = (response->group_info_list)[i];
                e2ees__group_info__init(cur_group);
                cur_group->group_name = strdup(group_info_list[i]->group_name);
                copy_address_from_address(&(cur_group->group_address), group_info_list[i]->group_address);
                cur_group->n_group_member_list = group_info_list[i]->n_group_member_list;
                copy_group_members(&(cur_group->group_member_list), group_info_list[i]->group_member_list, group_info_list[i]->n_group_member_list);
            }
        }
    }
    if (is_valid_certificate(server_certificate)) {
        copy_certificate_from_certificate(&(response->server_cert), server_certificate);
    }

    // send the new device message to other devices and users
    uint8_t *msg = NULL;
    size_t msg_len;
    for (j = 0; j < receiver_num; j++) {
        E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
        e2ees__proto_msg__init(proto_msg);
        copy_address_from_address(&(proto_msg->from), cur_data->address);
        copy_address_from_address(&(proto_msg->to), receiver_addresses[j]);
        proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_ADD_USER_DEVICE_MSG;
        proto_msg->add_user_device_msg = (E2ees__AddUserDeviceMsg *)malloc(sizeof(E2ees__AddUserDeviceMsg));
        e2ees__add_user_device_msg__init(proto_msg->add_user_device_msg);
        copy_address_from_address(&(proto_msg->add_user_device_msg->user_address), cur_data->address);
        if (other_device_num > 0) {
            proto_msg->add_user_device_msg->n_old_address_list = other_device_num;
            proto_msg->add_user_device_msg->old_address_list = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * other_device_num);
        }
        for (i = 0; i < other_device_num; i++) {
            copy_address_from_address(&((proto_msg->add_user_device_msg->old_address_list)[i]), other_device_address_list[i]);
        }

        proto_msg_hash(
            &msg, &msg_len,
            NULL,
            proto_msg->from,
            proto_msg->to,
            proto_msg->payload_case,
            proto_msg->add_user_device_msg
        );
        proto_msg->n_signature_list = 1;
        proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
        mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

        send_proto_msg(proto_msg);

        // release
        e2ees__proto_msg__free_unpacked(proto_msg, NULL);
        free_mem((void **)&msg, msg_len);
    }

    // release
    if (client_data != NULL) {
        for (i = 0; i < other_device_num; i++) {
            e2ees__e2ee_address__free_unpacked(other_device_address_list[i], NULL);
        }
        free_mem((void **)&other_device_address_list, sizeof(E2ees__E2eeAddress *) * other_device_num);
        for (i = 0; i < friends_num; i++) {
            e2ees__e2ee_address__free_unpacked(friend_addresses[i], NULL);
        }
        free_mem((void **)&friend_addresses, sizeof(E2ees__E2eeAddress *) * friends_num);
        for (i = 0; i < receiver_num; i++) {
            e2ees__e2ee_address__free_unpacked(receiver_addresses[i], NULL);
        }
        free_mem((void **)&receiver_addresses, sizeof(E2ees__E2eeAddress *) * receiver_num);
        for (i = 0; i < group_num; i++) {
            e2ees__group_info__free_unpacked(group_info_list[i], NULL);
        }
        free_mem((void **)&group_info_list, sizeof(E2ees__GroupInfo *) * group_num);
    }

    return response;
}

E2ees__GetPreKeyBundleResponse *mock_get_pre_key_bundle(E2ees__E2eeAddress *from, const char *auth, E2ees__GetPreKeyBundleRequest *request) {
    if ((request->user_id == NULL) || (request->domain == NULL)) {
        e2ees_notify_log(from, BAD_GET_PRE_KEY_BUNDLE_REQUEST, "mock_get_pre_key_bundle()");
        return NULL;
    }

    size_t user_device_num = 0;
    uint8_t user_data_find[user_data_max] = {0};
    uint8_t i;
    E2ees__E2eeAddress *cur_address;
    if ((request->device_id)[0] == '\0') {
        for (i = 0; i < user_data_set_insert_pos; i++) {
            cur_address = user_data_set[i].address;
            if ((cur_address != NULL) && compare_user_id(cur_address, request->user_id, request->domain)) {
                user_data_find[user_device_num] = i;
                user_device_num++;
            }
        }
    } else {
        for (i = 0; i < user_data_set_insert_pos; i++) {
            cur_address = user_data_set[i].address;
            if ((cur_address != NULL) && safe_strcmp(cur_address->domain, request->domain) && safe_strcmp(cur_address->user->user_id, request->user_id) &&
                safe_strcmp(cur_address->user->device_id, request->device_id)) {
                user_data_find[user_device_num] = i;
                user_device_num++;
            }
        }
    }

    if (user_device_num == 0) {
        // not found
        return NULL;
    }

    E2ees__GetPreKeyBundleResponse *response = NULL;
    response = (E2ees__GetPreKeyBundleResponse *)malloc(sizeof(E2ees__GetPreKeyBundleResponse));
    e2ees__get_pre_key_bundle_response__init(response);
    response->user_id = strdup(request->user_id);
    response->pre_key_bundles = (E2ees__PreKeyBundle **)malloc(sizeof(E2ees__PreKeyBundle *) * user_device_num);

    size_t j;
    uint8_t *msg = NULL;
    size_t msg_len;
    for (j = 0; j < user_device_num; j++) {
        i = user_data_find[j];
        user_data *cur_data = &(user_data_set[i]);

        response->n_pre_key_bundles += 1;
        response->pre_key_bundles[j] = (E2ees__PreKeyBundle *)malloc(sizeof(E2ees__PreKeyBundle));
        e2ees__pre_key_bundle__init(response->pre_key_bundles[j]);

        response->pre_key_bundles[j]->e2ees_pack_id = cur_data->e2ees_pack_id;
        copy_address_from_address(&(response->pre_key_bundles[j]->user_address), cur_data->address);
        copy_ik_public_from_ik_public(&(response->pre_key_bundles[j]->identity_key_public), cur_data->identity_key_public);
        copy_spk_public_from_spk_public(&(response->pre_key_bundles[j]->signed_pre_key_public), cur_data->signed_pre_key_public);

        size_t k;
        for (k = 0; k < cur_data->n_one_time_pre_key_list; k++) {
            if (cur_data->one_time_pre_key_list[k]) {
                copy_opk_public_from_opk_public(&(response->pre_key_bundles[j]->one_time_pre_key_public), cur_data->one_time_pre_key_list[k]);

                // release the one-time pre-key
                e2ees__one_time_pre_key_public__free_unpacked(cur_data->one_time_pre_key_list[k], NULL);
                cur_data->one_time_pre_key_list[k] = NULL;

                break;
            }
        }

        // generate server signed signature
        pre_key_bundle_hash(
            &msg, &msg_len,
            response->pre_key_bundles[j]->user_address,
            response->pre_key_bundles[j]->identity_key_public,
            response->pre_key_bundles[j]->signed_pre_key_public,
            response->pre_key_bundles[j]->one_time_pre_key_public
        );
        mock_server_signed_signature(&(response->pre_key_bundles[j]->signature), msg, msg_len);

        free_mem((void **)&msg, msg_len);
    }

    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

E2ees__InviteResponse *mock_invite(E2ees__E2eeAddress *from, const char *auth, E2ees__InviteRequest *request) {
    uint8_t *msg = NULL;
    size_t msg_len;

    // prepare response
    E2ees__InviteResponse *response = (E2ees__InviteResponse *)malloc(sizeof(E2ees__InviteResponse));
    e2ees__invite_response__init(response);

    E2ees__InviteMsg *invite_msg = request->msg;
    uint8_t inviter = find_address(invite_msg->from);
    if (inviter != user_data_max) {
        copy_protobuf_from_protobuf(&(invite_msg->alice_identity_key), &(user_data_set[inviter].identity_key_public->asym_public_key));

        size_t invite_msg_data_len = e2ees__invite_msg__get_packed_size(invite_msg);
        uint8_t invite_msg_data[invite_msg_data_len];
        e2ees__invite_msg__pack(invite_msg, invite_msg_data);

        // forward a copy of InviteMsg
        E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
        e2ees__proto_msg__init(proto_msg);
        copy_address_from_address(&(proto_msg->from), invite_msg->from);
        copy_address_from_address(&(proto_msg->to), invite_msg->to);
        proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_INVITE_MSG;
        proto_msg->invite_msg = e2ees__invite_msg__unpack(NULL, invite_msg_data_len, invite_msg_data);

        proto_msg_hash(
            &msg, &msg_len,
            NULL,
            proto_msg->from,
            proto_msg->to,
            proto_msg->payload_case,
            proto_msg->invite_msg
        );
        proto_msg->n_signature_list = 1;
        proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
        mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

        send_proto_msg(proto_msg);

        // release
        e2ees__proto_msg__free_unpacked(proto_msg, NULL);
        free_mem((void **)&msg, msg_len);

        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
    } else {
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND;
    }

    // done
    return response;
}

E2ees__AcceptResponse *mock_accept(E2ees__E2eeAddress *from, const char *auth, E2ees__AcceptRequest *request) {
    E2ees__AcceptMsg *accept_msg = request->msg;
    size_t accept_msg_data_len = e2ees__accept_msg__get_packed_size(accept_msg);
    uint8_t accept_msg_data[accept_msg_data_len];
    e2ees__accept_msg__pack(accept_msg, accept_msg_data);

    uint8_t *msg = NULL;
    size_t msg_len;
    // forward a copy of AcceptMsg
    E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
    e2ees__proto_msg__init(proto_msg);
    copy_address_from_address(&(proto_msg->from), accept_msg->from);
    copy_address_from_address(&(proto_msg->to), accept_msg->to);
    proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_ACCEPT_MSG;
    proto_msg->accept_msg = e2ees__accept_msg__unpack(NULL, accept_msg_data_len, accept_msg_data);

    proto_msg_hash(
        &msg, &msg_len,
        NULL,
        proto_msg->from,
        proto_msg->to,
        proto_msg->payload_case,
        proto_msg->accept_msg
    );
    proto_msg->n_signature_list = 1;
    proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
    mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

    send_proto_msg(proto_msg);

    // set the session record
    uint8_t inviter = find_address(accept_msg->to);
    uint8_t invitee = find_address(accept_msg->from);
    session_record[inviter][invitee] = true;
    session_record[invitee][inviter] = true;

    // prepare response
    E2ees__AcceptResponse *response = (E2ees__AcceptResponse *)malloc(sizeof(E2ees__AcceptResponse));
    e2ees__accept_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    // release
    e2ees__proto_msg__free_unpacked(proto_msg, NULL);
    free_mem((void **)&msg, msg_len);

    // done
    return response;
}

E2ees__PublishSpkResponse *mock_publish_spk(E2ees__E2eeAddress *from, const char *auth, E2ees__PublishSpkRequest *request) {
    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos) {
        if ((user_data_set[user_data_find].address) && (request->user_address) && compare_address(user_data_set[user_data_find].address, request->user_address)) {
            break;
        }
        user_data_find++;
    }

    // data not found
    if (user_data_find == user_data_set_insert_pos) {
        E2ees__PublishSpkResponse *response = (E2ees__PublishSpkResponse *)malloc(sizeof(E2ees__PublishSpkResponse));
        e2ees__publish_spk_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    user_data *cur_data = &(user_data_set[user_data_find]);
    // release old memory
    e2ees__signed_pre_key_public__free_unpacked(cur_data->signed_pre_key_public, NULL);
    // copy new data
    copy_spk_public_from_spk_public(&(cur_data->signed_pre_key_public), request->signed_pre_key_public);

    E2ees__PublishSpkResponse *response = (E2ees__PublishSpkResponse *)malloc(sizeof(E2ees__PublishSpkResponse));
    e2ees__publish_spk_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

E2ees__SupplyOpksResponse *mock_supply_opks(E2ees__E2eeAddress *from, const char *auth, E2ees__SupplyOpksRequest *request) {
    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos) {
        if ((user_data_set[user_data_find].address) && (request->user_address) && compare_address(user_data_set[user_data_find].address, request->user_address)) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos) {
        // not found
        return NULL;
    }

    user_data *cur_data = &(user_data_set[user_data_find]);

    size_t old_num = cur_data->n_one_time_pre_key_list;

    cur_data->n_one_time_pre_key_list += request->n_one_time_pre_key_public_list;
    E2ees__OneTimePreKeyPublic **temp;
    temp = (E2ees__OneTimePreKeyPublic **)malloc(sizeof(E2ees__OneTimePreKeyPublic *) * cur_data->n_one_time_pre_key_list);
    size_t i;
    for (i = 0; i < old_num; i++) {
        copy_opk_public_from_opk_public(&(temp[i]), cur_data->one_time_pre_key_list[i]);
        e2ees__one_time_pre_key_public__free_unpacked(cur_data->one_time_pre_key_list[i], NULL);
        cur_data->one_time_pre_key_list[i] = NULL;
    }
    free(cur_data->one_time_pre_key_list);
    cur_data->one_time_pre_key_list = temp;

    // copy new one-time pre-keys
    for (i = old_num; i < cur_data->n_one_time_pre_key_list; i++) {
        copy_opk_public_from_opk_public(&(cur_data->one_time_pre_key_list[i]), request->one_time_pre_key_public_list[i - old_num]);
    }

    // prepare response
    E2ees__SupplyOpksResponse *response = (E2ees__SupplyOpksResponse *)malloc(sizeof(E2ees__SupplyOpksResponse));
    e2ees__supply_opks_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

E2ees__SendOne2oneMsgResponse *mock_send_one2one_msg(E2ees__E2eeAddress *from, const char *auth, E2ees__SendOne2oneMsgRequest *request) {
    E2ees__E2eeMsg *e2ee_msg = request->msg;
    size_t e2ee_msg_data_len = e2ees__e2ee_msg__get_packed_size(e2ee_msg);
    uint8_t e2ee_msg_data[e2ee_msg_data_len];
    e2ees__e2ee_msg__pack(e2ee_msg, e2ee_msg_data);

    uint8_t *msg = NULL;
    size_t msg_len;
    E2ees__ProtoMsg *proto_msg = NULL;
    // E2ees__ConsumeProtoMsgResponse *consume_proto_msg_response = NULL;
    // check if the receiver's device id exists
    if ((e2ee_msg->to->user->device_id)[0] != '\0') {
        // forward a copy of E2eeMsg
        proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
        e2ees__proto_msg__init(proto_msg);
        copy_address_from_address(&(proto_msg->from), e2ee_msg->from);
        copy_address_from_address(&(proto_msg->to), e2ee_msg->to);
        proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_E2EE_MSG;
        proto_msg->e2ee_msg = e2ees__e2ee_msg__unpack(NULL, e2ee_msg_data_len, e2ee_msg_data);

        proto_msg_hash(
            &msg, &msg_len,
            NULL,
            proto_msg->from,
            proto_msg->to,
            proto_msg->payload_case,
            proto_msg->e2ee_msg
        );
        proto_msg->n_signature_list = 1;
        proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
        mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

        send_proto_msg(proto_msg);

        // release
        e2ees__proto_msg__free_unpacked(proto_msg, NULL);
        free_mem((void **)&msg, msg_len);
    } else {
        E2ees__E2eeAddress **to_addresses = NULL;
        size_t to_address_num = find_device_addresses(e2ee_msg->to->user->user_id, &to_addresses);
        size_t i;
        for (i = 0; i < to_address_num; i++) {
            // forward a copy of E2eeMsg
            proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), e2ee_msg->from);
            copy_address_from_address(&(proto_msg->to), to_addresses[i]);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_E2EE_MSG;
            proto_msg->e2ee_msg = e2ees__e2ee_msg__unpack(NULL, e2ee_msg_data_len, e2ee_msg_data);

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->e2ee_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
    }

    // prepare response
    E2ees__SendOne2oneMsgResponse *response = (E2ees__SendOne2oneMsgResponse *)malloc(sizeof(E2ees__SendOne2oneMsgResponse));
    e2ees__send_one2one_msg_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    // done
    return response;
}

E2ees__CreateGroupResponse *mock_create_group(E2ees__E2eeAddress *from, const char *auth, E2ees__CreateGroupRequest *request) {
    if (request == NULL) {
        return NULL;
    }
    if (request->msg == NULL) {
        return NULL;
    }

    // create a new group
    group_data *cur_group_data = &(group_data_set[group_data_set_insert_pos]);

    // generate a random address
    mock_random_group_address(&(cur_group_data->group_address));

    // prepare to store
    E2ees__GroupInfo *group_info = request->msg->group_info;
    cur_group_data->group_name = strdup(group_info->group_name);
    cur_group_data->group_members_num = group_info->n_group_member_list;
    copy_group_members(&(cur_group_data->group_member_list), group_info->group_member_list, group_info->n_group_member_list);

    E2ees__E2eeAddress *group_address = cur_group_data->group_address;
    group_address->group->group_name = strdup(group_info->group_name);
    size_t group_members_num = cur_group_data->group_members_num;

    // create create_group_msg
    E2ees__CreateGroupMsg *create_group_msg = NULL;
    copy_create_group_msg(&(create_group_msg), request->msg);

    copy_address_from_address(&(create_group_msg->group_info->group_address), group_address);

    /*-------------------insert each group member's identity key into create_group_msg-------------------*/
    // total #(address) to be sent, including users' every device
    size_t to_member_addresses_total_num = 0;
    size_t i, j;

    // store the number of addresses of each group member
    size_t *to_member_addresses_num_list = (size_t *)malloc(sizeof(size_t) * group_members_num);

    index_node **index_address_list = (index_node **)malloc(sizeof(index_node *) * group_members_num);

    for (i = 0; i < group_members_num; i++) {
        index_address_list[i] = NULL;

        to_member_addresses_num_list[i] = find_device_index_and_addresses(cur_group_data->group_member_list[i]->user_id, &(index_address_list[i]));

        to_member_addresses_total_num += to_member_addresses_num_list[i];
    }

    create_group_msg->n_member_info_list = to_member_addresses_total_num;

    E2ees__GroupMemberInfo **common_member_ids = (E2ees__GroupMemberInfo **)malloc(sizeof(E2ees__GroupMemberInfo *) * to_member_addresses_total_num);

    size_t member_id_insert_pos = 0;

    index_node *ptr;
    E2ees__E2eeAddress *to_member_address;
    uint8_t member_pos;

    // copy addresses and public key into common_member_ids
    for (i = 0; i < group_members_num; i++) {
        ptr = index_address_list[i];

        for (j = 0; j < to_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            // insert the group member data
            common_member_ids[member_id_insert_pos] = (E2ees__GroupMemberInfo *)malloc(sizeof(E2ees__GroupMemberInfo));
            E2ees__GroupMemberInfo *cur_common_member_id = common_member_ids[member_id_insert_pos];
            e2ees__group_member_info__init(cur_common_member_id);
            copy_address_from_address(&(cur_common_member_id->member_address), to_member_address);
            copy_protobuf_from_protobuf(&(cur_common_member_id->sign_public_key), &(user_data_set[member_pos].identity_key_public->sign_public_key));
            member_id_insert_pos++;

            ptr = ptr->next;
        }
    }
    // copy common_member_ids into createMsg
    copy_group_member_ids(&(create_group_msg->member_info_list), common_member_ids, to_member_addresses_total_num);

    // pack CreateGroupMsg
    size_t create_group_msg_data_len = e2ees__create_group_msg__get_packed_size(create_group_msg);
    uint8_t create_group_msg_data[create_group_msg_data_len];

    e2ees__create_group_msg__pack(create_group_msg, create_group_msg_data);

    // send msg to each group member
    E2ees__E2eeAddress *sender_address = create_group_msg->sender_address;
    const char *sender_user_id = sender_address->user->user_id;

    uint8_t *msg = NULL;
    size_t msg_len;
    for (i = 0; i < group_members_num; i++) {
        ptr = index_address_list[i];

        for (j = 0; j < to_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            group_record[member_pos][group_data_set_insert_pos] = true;

            if (safe_strcmp(sender_user_id, to_member_address->user->user_id)) {
                if (compare_address(sender_address, to_member_address)) {
                    ptr = ptr->next;
                    continue;
                }
            }

            E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), sender_address);
            copy_address_from_address(&(proto_msg->to), to_member_address);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_CREATE_GROUP_MSG;
            proto_msg->create_group_msg = e2ees__create_group_msg__unpack(NULL, create_group_msg_data_len, create_group_msg_data);

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->create_group_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            ptr = ptr->next;

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
    }

    /*-------------------------------------*/

    // prepare response
    E2ees__CreateGroupResponse *response = (E2ees__CreateGroupResponse *)malloc(sizeof(E2ees__CreateGroupResponse));
    e2ees__create_group_response__init(response);
    response->n_member_info_list = to_member_addresses_total_num;
    copy_group_member_ids(&(response->member_info_list), common_member_ids, to_member_addresses_total_num);
    copy_address_from_address(&(response->group_address), group_address);

    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    // release
    e2ees__create_group_msg__free_unpacked(create_group_msg, NULL);
    free_mem((void **)&to_member_addresses_num_list, sizeof(size_t) * group_members_num);

    for (i = 0; i < to_member_addresses_total_num; i++) {
        e2ees__group_member_info__free_unpacked(common_member_ids[i], NULL);
    }
    free_mem((void **)&common_member_ids, sizeof(E2ees__GroupMemberInfo *) * to_member_addresses_total_num);

    index_node *current, *next;
    for (i = 0; i < group_members_num; i++) {
        current = index_address_list[i];
        while (current != NULL) {
            next = current->next;
            if (current->device_address != NULL) {
                e2ees__e2ee_address__free_unpacked(current->device_address, NULL);
                current->device_address = NULL;
            }
            free_mem((void **)&current, sizeof(index_node));
            current = next;
        }
    }
    free_mem((void **)&index_address_list, sizeof(index_node *) * group_members_num);

    // done
    group_data_set_insert_pos++;
    return response;
}

E2ees__AddGroupMembersResponse *mock_add_group_members(E2ees__E2eeAddress *from, const char *auth, E2ees__AddGroupMembersRequest *request) {
    E2ees__AddGroupMembersMsg *add_group_members_msg = NULL;
    copy_add_group_members_msg(&(add_group_members_msg), request->msg);

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos) {
        if ((group_data_set[group_data_find].group_address) && (add_group_members_msg->group_info->group_address) &&
            compare_address(group_data_set[group_data_find].group_address, add_group_members_msg->group_info->group_address)) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos) {
        E2ees__AddGroupMembersResponse *response = (E2ees__AddGroupMembersResponse *)malloc(sizeof(E2ees__AddGroupMembersResponse));
        e2ees__add_group_members_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    // update the data
    size_t old_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = cur_group_data->group_members_num + add_group_members_msg->n_adding_member_list;
    cur_group_data->group_members_num = new_group_members_num;

    E2ees__GroupMember **temp_group_members = NULL;
    temp_group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    size_t i, j;
    for (i = 0; i < old_group_members_num; i++) {
        E2ees__GroupMember *cur_group_member = (cur_group_data->group_member_list)[i];
        copy_group_member(&(temp_group_members[i]), cur_group_member);
        e2ees__group_member__free_unpacked(cur_group_member, NULL);
        cur_group_member = NULL;
    }
    free_mem((void **)&(cur_group_data->group_member_list), sizeof(E2ees__GroupMember *) * old_group_members_num);
    // update the group members
    cur_group_data->group_member_list = temp_group_members;

    for (i = old_group_members_num; i < new_group_members_num; i++) {
        copy_group_member(&(cur_group_data->group_member_list[i]), (add_group_members_msg->adding_member_list)[i - old_group_members_num]);
    }

    size_t adding_members_num = add_group_members_msg->n_adding_member_list;

    size_t *adding_member_device_num_list = (size_t *)malloc(sizeof(size_t) * adding_members_num);
    size_t *to_member_addresses_num_list = (size_t *)malloc(sizeof(size_t) * new_group_members_num);

    index_node **adding_member_index_address_list = (index_node **)malloc(sizeof(index_node *) * adding_members_num);
    index_node **index_address_list = (index_node **)malloc(sizeof(index_node *) * new_group_members_num);
    size_t adding_member_addresses_total_num = 0;
    size_t to_member_addresses_total_num = 0;

    // only for new members
    for (i = 0; i < adding_members_num; i++) {
        adding_member_index_address_list[i] = NULL;
        adding_member_device_num_list[i] = find_device_index_and_addresses(add_group_members_msg->adding_member_list[i]->user_id, &(adding_member_index_address_list[i]));

        adding_member_addresses_total_num += adding_member_device_num_list[i];
    }
    // for all members, including new members
    for (i = 0; i < new_group_members_num; i++) {
        index_address_list[i] = NULL;
        to_member_addresses_num_list[i] = find_device_index_and_addresses(cur_group_data->group_member_list[i]->user_id, &(index_address_list[i]));

        to_member_addresses_total_num += to_member_addresses_num_list[i];
    }

    add_group_members_msg->n_adding_member_info_list = adding_member_addresses_total_num;

    E2ees__GroupMemberInfo **adding_member_info_list = (E2ees__GroupMemberInfo **)malloc(sizeof(E2ees__GroupMemberInfo *) * adding_member_addresses_total_num);

    index_node *ptr;
    E2ees__E2eeAddress *to_member_address;
    uint8_t member_pos;

    // copy addresses and public key into adding_member_info_list
    size_t member_id_insert_pos = 0;
    for (i = 0; i < adding_member_addresses_total_num; i++) {
        ptr = adding_member_index_address_list[i];

        for (j = 0; j < adding_member_device_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            // insert the group member data
            adding_member_info_list[member_id_insert_pos] = (E2ees__GroupMemberInfo *)malloc(sizeof(E2ees__GroupMemberInfo));
            E2ees__GroupMemberInfo *cur_member_id = adding_member_info_list[member_id_insert_pos];
            e2ees__group_member_info__init(cur_member_id);
            copy_address_from_address(&(cur_member_id->member_address), to_member_address);
            copy_protobuf_from_protobuf(&(cur_member_id->sign_public_key), &(user_data_set[member_pos].identity_key_public->sign_public_key));
            member_id_insert_pos++;

            ptr = ptr->next;
        }
    }

    copy_group_member_ids(&(add_group_members_msg->adding_member_info_list), adding_member_info_list, adding_member_addresses_total_num);

    /* ----------------------------------------- */

    // start packing
    size_t add_group_members_msg_data_len = e2ees__add_group_members_msg__get_packed_size(add_group_members_msg);
    uint8_t add_group_members_msg_data[add_group_members_msg_data_len];
    e2ees__add_group_members_msg__pack(add_group_members_msg, add_group_members_msg_data);

    // send the message to all the other members in the group
    E2ees__E2eeAddress *sender_address = add_group_members_msg->sender_address;
    const char *sender_user_id = sender_address->user->user_id;

    uint8_t *msg = NULL;
    size_t msg_len;
    // send msg to all the other members in the group, including added members
    for (i = 0; i < new_group_members_num; i++) {
        ptr = index_address_list[i];

        for (j = 0; j < to_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            group_record[member_pos][group_data_find] = true;
            if (safe_strcmp(sender_user_id, to_member_address->user->user_id)) {
                if (compare_address(sender_address, to_member_address)) {
                    ptr = ptr->next;
                    continue;
                }
            }

            E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), sender_address);
            copy_address_from_address(&(proto_msg->to), to_member_address);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBERS_MSG;
            proto_msg->add_group_members_msg = e2ees__add_group_members_msg__unpack(NULL, add_group_members_msg_data_len, add_group_members_msg_data);

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->add_group_members_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            ptr = ptr->next;

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
    }

    // prepare response
    E2ees__AddGroupMembersResponse *response = (E2ees__AddGroupMembersResponse *)malloc(sizeof(E2ees__AddGroupMembersResponse));
    e2ees__add_group_members_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
    response->n_group_member_list = new_group_members_num;
    response->group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    for (i = 0; i < new_group_members_num; i++) {
        copy_group_member(&((response->group_member_list)[i]), (cur_group_data->group_member_list)[i]);
    }

    response->n_added_group_member_list = adding_members_num;
    copy_group_members(&(response->added_group_member_list), add_group_members_msg->adding_member_list, adding_members_num);

    copy_group_member_ids(&(response->adding_member_info_list), adding_member_info_list, adding_member_addresses_total_num);
    response->n_adding_member_info_list = adding_member_addresses_total_num;

    // release
    e2ees__add_group_members_msg__free_unpacked(add_group_members_msg, NULL);

    for (i = 0; i < adding_member_addresses_total_num; i++) {
        e2ees__group_member_info__free_unpacked(adding_member_info_list[i], NULL);
    }
    free_mem((void **)&adding_member_info_list, sizeof(E2ees__GroupMemberInfo *) * adding_member_addresses_total_num);

    free_mem((void **)&adding_member_device_num_list, sizeof(size_t) * adding_members_num);
    free_mem((void **)&to_member_addresses_num_list, sizeof(size_t) * new_group_members_num);

    index_node *current, *next;
    for (i = 0; i < adding_members_num; i++) {
        current = adding_member_index_address_list[i];
        while (current != NULL) {
            next = current->next;
            if (current->device_address != NULL) {
                e2ees__e2ee_address__free_unpacked(current->device_address, NULL);
                current->device_address = NULL;
            }
            free_mem((void **)&current, sizeof(index_node));
            current = next;
        }
    }
    free_mem((void **)&adding_member_index_address_list, sizeof(index_node *) * adding_members_num);

    for (i = 0; i < new_group_members_num; i++) {
        current = index_address_list[i];
        while (current != NULL) {
            next = current->next;
            if (current->device_address != NULL) {
                e2ees__e2ee_address__free_unpacked(current->device_address, NULL);
                current->device_address = NULL;
            }
            free_mem((void **)&current, sizeof(index_node));
            current = next;
        }
    }
    free_mem((void **)&index_address_list, sizeof(index_node *) * new_group_members_num);

    return response;
}

E2ees__AddGroupMemberDeviceResponse *mock_add_group_member_device(
    E2ees__E2eeAddress *from, const char *auth, E2ees__AddGroupMemberDeviceRequest *request
) {
    uint8_t device_pos = find_address(request->msg->adding_member_device->member_address);

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos) {
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_info->group_address) &&
            compare_address(group_data_set[group_data_find].group_address, request->msg->group_info->group_address)) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos) {
        E2ees__AddGroupMemberDeviceResponse *response = (E2ees__AddGroupMemberDeviceResponse *)malloc(sizeof(E2ees__AddGroupMemberDeviceResponse));
        e2ees__add_group_member_device_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    if (device_invited_record[device_pos][group_data_find] == true) {
        E2ees__AddGroupMemberDeviceResponse *response = (E2ees__AddGroupMemberDeviceResponse *)malloc(sizeof(E2ees__AddGroupMemberDeviceResponse));
        e2ees__add_group_member_device_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND;
        return response;
    }

    device_invited_record[device_pos][group_data_find] = true;

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    size_t group_members_num = cur_group_data->group_members_num;
    size_t *to_member_addresses_num_list = (size_t *)malloc(sizeof(size_t) * group_members_num);
    index_node **index_address_list = (index_node **)malloc(sizeof(index_node *) * group_members_num);
    size_t to_member_addresses_total_num = 0;

    size_t i, j;
    for (i = 0; i < group_members_num; i++) {
        index_address_list[i] = NULL;
        to_member_addresses_num_list[i] = find_device_index_and_addresses(cur_group_data->group_member_list[i]->user_id, &(index_address_list[i]));

        to_member_addresses_total_num += to_member_addresses_num_list[i];
    }

    E2ees__GroupMemberInfo *adding_member_device_info = (E2ees__GroupMemberInfo *)malloc(sizeof(E2ees__GroupMemberInfo));
    e2ees__group_member_info__init(adding_member_device_info);
    copy_address_from_address(&(adding_member_device_info->member_address), request->msg->adding_member_device->member_address);
    copy_protobuf_from_protobuf(&(adding_member_device_info->sign_public_key), &(user_data_set[device_pos].identity_key_public->sign_public_key));

    E2ees__AddGroupMemberDeviceMsg *add_group_member_device_msg = NULL;
    copy_add_group_member_device_msg(&(add_group_member_device_msg), request->msg);
    // the adding_member_device in request->msg is not completed, so release the adding_member_device in add_group_member_device_msg first
    e2ees__group_member_info__free_unpacked(add_group_member_device_msg->adding_member_device, NULL);
    add_group_member_device_msg->adding_member_device = NULL;
    copy_group_member_id(&(add_group_member_device_msg->adding_member_device), adding_member_device_info);

    // start packing
    size_t add_group_member_device_msg_data_len = e2ees__add_group_member_device_msg__get_packed_size(add_group_member_device_msg);
    uint8_t add_group_member_device_msg_data[add_group_member_device_msg_data_len];
    e2ees__add_group_member_device_msg__pack(add_group_member_device_msg, add_group_member_device_msg_data);

    // send the message to all the other members in the group
    E2ees__E2eeAddress *sender_address = add_group_member_device_msg->sender_address;
    const char *sender_user_id = sender_address->user->user_id;

    uint8_t *msg = NULL;
    size_t msg_len;
    index_node *ptr;
    E2ees__E2eeAddress *to_member_address;
    uint8_t member_pos;
    // send msg to all the other members in the group, including added members
    for (i = 0; i < group_members_num; i++) {
        ptr = index_address_list[i];

        for (j = 0; j < to_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            group_record[member_pos][group_data_find] = true;
            if (safe_strcmp(sender_user_id, to_member_address->user->user_id)) {
                if (compare_address(sender_address, to_member_address)) {
                    ptr = ptr->next;
                    continue;
                }
            }

            E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), sender_address);
            copy_address_from_address(&(proto_msg->to), to_member_address);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBER_DEVICE_MSG;
            proto_msg->add_group_member_device_msg = e2ees__add_group_member_device_msg__unpack(
                NULL, add_group_member_device_msg_data_len, add_group_member_device_msg_data
            );

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->add_group_member_device_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            ptr = ptr->next;

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
    }

    // prepare response
    E2ees__AddGroupMemberDeviceResponse *response = (E2ees__AddGroupMemberDeviceResponse *)malloc(sizeof(E2ees__AddGroupMemberDeviceResponse));
    e2ees__add_group_member_device_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
    response->n_group_member_list = group_members_num;
    response->group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * group_members_num);
    for (i = 0; i < group_members_num; i++) {
        copy_group_member(&((response->group_member_list)[i]), (cur_group_data->group_member_list)[i]);
    }

    copy_group_member_id(&(response->adding_member_device_info), adding_member_device_info);

    // release
    e2ees__add_group_member_device_msg__free_unpacked(add_group_member_device_msg, NULL);
    add_group_member_device_msg = NULL;

    free_mem((void **)&to_member_addresses_num_list, sizeof(size_t) * group_members_num);

    index_node *current, *next;
    for (i = 0; i < group_members_num; i++) {
        current = index_address_list[i];
        while (current != NULL) {
            next = current->next;
            if (current->device_address != NULL) {
                e2ees__e2ee_address__free_unpacked(current->device_address, NULL);
                current->device_address = NULL;
            }
            free_mem((void **)&current, sizeof(index_node));
            current = next;
        }
    }
    free_mem((void **)&index_address_list, sizeof(index_node *) * group_members_num);

    e2ees__group_member_info__free_unpacked(adding_member_device_info, NULL);
    adding_member_device_info = NULL;

    return response;
}

E2ees__RemoveGroupMembersResponse *mock_remove_group_members(E2ees__E2eeAddress *from, const char *auth, E2ees__RemoveGroupMembersRequest *request) {
    // remove_group_members_msg
    E2ees__RemoveGroupMembersMsg *remove_group_members_msg_to_remained = NULL;
    E2ees__RemoveGroupMembersMsg *remove_group_members_msg_to_removed = NULL;

    copy_remove_group_members_msg(&(remove_group_members_msg_to_remained), request->msg);
    copy_remove_group_members_msg(&(remove_group_members_msg_to_removed), request->msg);

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos) {
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_info->group_address) &&
            compare_address(group_data_set[group_data_find].group_address, request->msg->group_info->group_address)) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos) {
        E2ees__RemoveGroupMembersResponse *response = (E2ees__RemoveGroupMembersResponse *)malloc(sizeof(E2ees__RemoveGroupMembersResponse));
        e2ees__remove_group_members_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    size_t original_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = original_group_members_num - request->msg->n_removing_member_list;

    E2ees__GroupMember **temp_group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    size_t i = 0, j = 0;
    size_t cur_removing_member_num;
    while (i < new_group_members_num && j < original_group_members_num) {
        cur_removing_member_num = j - i;
        if (cur_removing_member_num < request->msg->n_removing_member_list) {
            if (!safe_strcmp((cur_group_data->group_member_list)[j]->user_id, request->msg->removing_member_list[cur_removing_member_num]->user_id)) {
                copy_group_member(&(temp_group_members[i]), (cur_group_data->group_member_list)[j]);
                i++;
                j++;
            } else {
                j++;
            }
        } else {
            copy_group_member(&(temp_group_members[i]), (cur_group_data->group_member_list)[j]);
            i++;
            j++;
        }
    }

    /* ------------------------------------ */

    E2ees__E2eeAddress *sender_address = remove_group_members_msg_to_remained->sender_address;
    const char *sender_user_id = sender_address->user->user_id;

    size_t to_member_addresses_total_num = 0;

    // store the number of addresses of each group member remaining
    size_t *to_member_addresses_num_list = (size_t *)malloc(sizeof(size_t) * new_group_members_num);
    index_node **index_address_list = (index_node **)malloc(sizeof(index_node *) * new_group_members_num);

    for (i = 0; i < new_group_members_num; i++) {
        index_address_list[i] = NULL;

        to_member_addresses_num_list[i] = find_device_index_and_addresses(remove_group_members_msg_to_remained->group_info->group_member_list[i]->user_id, &(index_address_list[i]));

        to_member_addresses_total_num += to_member_addresses_num_list[i];
    }

    remove_group_members_msg_to_remained->n_member_info_list = to_member_addresses_total_num;

    remove_group_members_msg_to_remained->member_info_list = (E2ees__GroupMemberInfo **)malloc(sizeof(E2ees__GroupMemberInfo *) * to_member_addresses_total_num);

    size_t member_id_insert_pos = 0;

    // copy data into member_id
    index_node *ptr;
    E2ees__E2eeAddress *to_member_address;
    uint8_t member_pos;
    for (i = 0; i < new_group_members_num; i++) {
        ptr = index_address_list[i];

        for (j = 0; j < to_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            remove_group_members_msg_to_remained->member_info_list[member_id_insert_pos] = (E2ees__GroupMemberInfo *)malloc(sizeof(E2ees__GroupMemberInfo));
            E2ees__GroupMemberInfo *cur_group_member_id = remove_group_members_msg_to_remained->member_info_list[member_id_insert_pos];
            e2ees__group_member_info__init(cur_group_member_id);
            copy_address_from_address(&(cur_group_member_id->member_address), to_member_address);
            copy_protobuf_from_protobuf(&(cur_group_member_id->sign_public_key), &(user_data_set[member_pos].identity_key_public->sign_public_key));
            member_id_insert_pos++;

            ptr = ptr->next;
        }
    }

    size_t removed_group_members_num = request->msg->n_removing_member_list;
    // store the number of addresses of each group member remaining
    size_t *removed_member_addresses_num_list = (size_t *)malloc(sizeof(size_t) * removed_group_members_num);
    index_node **removed_index_address_list = (index_node **)malloc(sizeof(index_node *) * removed_group_members_num);

    for (i = 0; i < removed_group_members_num; i++) {
        removed_index_address_list[i] = NULL;

        removed_member_addresses_num_list[i] = find_device_index_and_addresses(remove_group_members_msg_to_removed->removing_member_list[i]->user_id, &(removed_index_address_list[i]));
    }

    /* ------------------------------------ */
    // start packing
    // send to removed members
    size_t remove_group_members_msg_data_len_to_removed = e2ees__remove_group_members_msg__get_packed_size(remove_group_members_msg_to_removed);
    uint8_t remove_group_members_msg_data_to_removed[remove_group_members_msg_data_len_to_removed];
    e2ees__remove_group_members_msg__pack(remove_group_members_msg_to_removed, remove_group_members_msg_data_to_removed);

    // send to remained members
    size_t remove_group_members_msg_data_len_to_remained = e2ees__remove_group_members_msg__get_packed_size(remove_group_members_msg_to_remained);
    uint8_t remove_group_members_msg_data_to_remained[remove_group_members_msg_data_len_to_remained];
    e2ees__remove_group_members_msg__pack(remove_group_members_msg_to_remained, remove_group_members_msg_data_to_remained);

    uint8_t *msg = NULL;
    size_t msg_len;
    // send to removed members
    for (i = 0; i < removed_group_members_num; i++) {
        ptr = removed_index_address_list[i];

        for (j = 0; j < removed_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            group_record[member_pos][group_data_find] = false;

            if (safe_strcmp(sender_user_id, to_member_address->user->user_id)) {
                if (compare_address(sender_address, to_member_address))
                    continue;
            }
            E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), sender_address);
            copy_address_from_address(&(proto_msg->to), to_member_address);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG;
            proto_msg->remove_group_members_msg = e2ees__remove_group_members_msg__unpack(NULL, remove_group_members_msg_data_len_to_removed, remove_group_members_msg_data_to_removed);

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->remove_group_members_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            ptr = ptr->next;

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
    }

    // send to remain members
    for (i = 0; i < new_group_members_num; i++) {
        ptr = index_address_list[i];

        for (j = 0; j < to_member_addresses_num_list[i]; j++) {
            to_member_address = ptr->device_address;
            member_pos = ptr->index;

            if (safe_strcmp(sender_user_id, to_member_address->user->user_id)) {
                if (compare_address(sender_address, to_member_address)) {
                    ptr = ptr->next;
                    continue;
                }
            }
            E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), sender_address);
            copy_address_from_address(&(proto_msg->to), to_member_address);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG;
            proto_msg->remove_group_members_msg = e2ees__remove_group_members_msg__unpack(NULL, remove_group_members_msg_data_len_to_remained, remove_group_members_msg_data_to_remained);

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->remove_group_members_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            ptr = ptr->next;

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
    }

    // release the old data
    for (i = 0; i < original_group_members_num; i++) {
        e2ees__group_member__free_unpacked((cur_group_data->group_member_list)[i], NULL);
        (cur_group_data->group_member_list)[i] = NULL;
    }
    free(cur_group_data->group_member_list);

    // update new member
    cur_group_data->group_members_num = new_group_members_num;
    cur_group_data->group_member_list = temp_group_members;

    // prepare response
    E2ees__RemoveGroupMembersResponse *response = (E2ees__RemoveGroupMembersResponse *)malloc(sizeof(E2ees__RemoveGroupMembersResponse));
    e2ees__remove_group_members_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
    response->n_group_member_list = new_group_members_num;
    response->group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    for (i = 0; i < new_group_members_num; i++) {
        copy_group_member(&((response->group_member_list)[i]), (cur_group_data->group_member_list)[i]);
    }
    response->n_member_info_list = to_member_addresses_total_num;
    copy_group_member_ids(&(response->member_info_list), remove_group_members_msg_to_remained->member_info_list, to_member_addresses_total_num);
    response->n_removed_group_member_list = removed_group_members_num;
    copy_group_members(&(response->removed_group_member_list), request->msg->removing_member_list, removed_group_members_num);

    // release
    e2ees__remove_group_members_msg__free_unpacked(remove_group_members_msg_to_remained, NULL);
    e2ees__remove_group_members_msg__free_unpacked(remove_group_members_msg_to_removed, NULL);

    free_mem((void **)&to_member_addresses_num_list, sizeof(size_t) * new_group_members_num);
    free_mem((void **)&removed_member_addresses_num_list, sizeof(size_t) * removed_group_members_num);

    index_node *current, *next;
    for (i = 0; i < new_group_members_num; i++) {
        current = index_address_list[i];
        while (current != NULL) {
            next = current->next;
            if (current->device_address != NULL) {
                e2ees__e2ee_address__free_unpacked(current->device_address, NULL);
                current->device_address = NULL;
            }
            free_mem((void **)&current, sizeof(index_node));
            current = next;
        }
    }
    free_mem((void **)&index_address_list, sizeof(index_node *) * new_group_members_num);

    for (i = 0; i < removed_group_members_num; i++) {
        current = removed_index_address_list[i];
        while (current != NULL) {
            next = current->next;
            if (current->device_address != NULL) {
                e2ees__e2ee_address__free_unpacked(current->device_address, NULL);
                current->device_address = NULL;
            }
            free_mem((void **)&current, sizeof(index_node));
            current = next;
        }
    }
    free_mem((void **)&removed_index_address_list, sizeof(index_node *) * removed_group_members_num);

    return response;
}

E2ees__LeaveGroupResponse *mock_leave_group(E2ees__E2eeAddress *from, const char *auth, E2ees__LeaveGroupRequest *request) {
    E2ees__E2eeAddress *sender_address = request->msg->user_address;
    char *user_id = request->msg->user_address->user->user_id;

    // copy leave_group_msg
    E2ees__LeaveGroupMsg *leave_group_msg = NULL;

    copy_leave_group_msg(&(leave_group_msg), request->msg);

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos) {
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_address) &&
            compare_address(group_data_set[group_data_find].group_address, request->msg->group_address)) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos) {
        e2ees__leave_group_msg__free_unpacked(leave_group_msg, NULL);

        E2ees__LeaveGroupResponse *response = (E2ees__LeaveGroupResponse *)malloc(sizeof(E2ees__LeaveGroupResponse));
        e2ees__leave_group_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    size_t original_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = original_group_members_num - 1;

    E2ees__GroupMember **temp_group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    size_t i, j = 0;
    for (i = 0; i < original_group_members_num; i++) {
        if (!safe_strcmp(cur_group_data->group_member_list[i]->user_id, user_id)) {
            if (j == original_group_members_num) {
                // error and release
                e2ees__leave_group_msg__free_unpacked(leave_group_msg, NULL);

                size_t k;
                for (k = 0; k < new_group_members_num; k++) {
                    e2ees__group_member__free_unpacked(temp_group_members[k], NULL);
                }
                free_mem((void **)&temp_group_members, sizeof(E2ees__GroupMember *) * new_group_members_num);

                // return
                E2ees__LeaveGroupResponse *response = (E2ees__LeaveGroupResponse *)malloc(sizeof(E2ees__LeaveGroupResponse));
                e2ees__leave_group_response__init(response);
                response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
                return response;
            }
            copy_group_member(&(temp_group_members[j]), (cur_group_data->group_member_list)[i]);
            j++;
        }
    }

    // we do not release the old data until the group manager sends the remove group member message here

    // find the group manager
    E2ees__GroupMember *group_manager = NULL;
    for (i = 0; i < new_group_members_num; i++) {
        if (temp_group_members[i]->role == E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER) {
            group_manager = temp_group_members[i];
            break;
        }
    }

    // find the group manager device
    E2ees__E2eeAddress **group_manager_device_addresses = NULL;
    size_t group_manager_device_num;
    group_manager_device_num = find_device_addresses(group_manager->user_id, &group_manager_device_addresses);

    // send to the group manager
    size_t leave_group_msg_data_len = e2ees__leave_group_msg__get_packed_size(leave_group_msg);
    uint8_t leave_group_msg_data[leave_group_msg_data_len];
    e2ees__leave_group_msg__pack(leave_group_msg, leave_group_msg_data);

    uint8_t *msg = NULL;
    size_t msg_len;
    E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
    e2ees__proto_msg__init(proto_msg);
    copy_address_from_address(&(proto_msg->from), sender_address);
    copy_address_from_address(&(proto_msg->to), group_manager_device_addresses[0]);
    proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_LEAVE_GROUP_MSG;
    proto_msg->leave_group_msg = e2ees__leave_group_msg__unpack(NULL, leave_group_msg_data_len, leave_group_msg_data);

    proto_msg_hash(
        &msg, &msg_len,
        NULL,
        proto_msg->from,
        proto_msg->to,
        proto_msg->payload_case,
        proto_msg->leave_group_msg
    );
    proto_msg->n_signature_list = 1;
    proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
    mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

    send_proto_msg(proto_msg);

    // prepare response
    E2ees__LeaveGroupResponse *response = (E2ees__LeaveGroupResponse *)malloc(sizeof(E2ees__LeaveGroupResponse));
    e2ees__leave_group_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;
    copy_address_from_address(&(response->leave_group_member_address), sender_address);
    copy_address_from_address(&(response->group_address), leave_group_msg->group_address);

    // release
    e2ees__leave_group_msg__free_unpacked(leave_group_msg, NULL);

    for (i = 0; i < new_group_members_num; i++) {
        e2ees__group_member__free_unpacked(temp_group_members[i], NULL);
    }
    free_mem((void **)&temp_group_members, sizeof(E2ees__GroupMember *) * new_group_members_num);

    for (i = 0; i < group_manager_device_num; i++) {
        e2ees__e2ee_address__free_unpacked(group_manager_device_addresses[i], NULL);
    }
    free_mem((void **)&group_manager_device_addresses, sizeof(E2ees__E2eeAddress *) * group_manager_device_num);

    e2ees__proto_msg__free_unpacked(proto_msg, NULL);
    free_mem((void **)&msg, msg_len);

    return response;
}

E2ees__SendGroupMsgResponse *mock_send_group_msg(E2ees__E2eeAddress *from, const char *auth, E2ees__SendGroupMsgRequest *request) {
    E2ees__E2eeMsg *e2ee_msg = request->msg;
    size_t e2ee_msg_data_len = e2ees__e2ee_msg__get_packed_size(e2ee_msg);
    uint8_t e2ee_msg_data[e2ee_msg_data_len];
    e2ees__e2ee_msg__pack(e2ee_msg, e2ee_msg_data);

    // send the message to all the other members in the group
    E2ees__E2eeAddress *sender_address = e2ee_msg->from;
    E2ees__E2eeAddress *group_address = e2ee_msg->to;

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos) {
        if ((group_data_set[group_data_find].group_address) && group_address && compare_address(group_data_set[group_data_find].group_address, group_address)) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos) {
        E2ees__SendGroupMsgResponse *response = (E2ees__SendGroupMsgResponse *)malloc(sizeof(E2ees__SendGroupMsgResponse));
        e2ees__send_group_msg_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    const char *sender_user_id = sender_address->user->user_id;
    size_t i, j;
    uint8_t *msg = NULL;
    size_t msg_len;
    char *member_user_id = NULL;
    E2ees__E2eeAddress **to_member_addresses = NULL;
    size_t to_member_addresses_num;
    for (i = 0; i < group_data_set[group_data_find].group_members_num; i++) {
        // send to other group members
        member_user_id = cur_group_data->group_member_list[i]->user_id;
        // forward a copy of E2eeMsg
        to_member_addresses_num = find_device_addresses(member_user_id, &to_member_addresses);
        for (j = 0; j < to_member_addresses_num; j++) {
            E2ees__E2eeAddress *to_member_address = to_member_addresses[j];
            if (safe_strcmp(sender_user_id, to_member_address->user->user_id)) {
                if (compare_address(sender_address, to_member_address))
                    continue;
            }
            E2ees__ProtoMsg *proto_msg = (E2ees__ProtoMsg *)malloc(sizeof(E2ees__ProtoMsg));
            e2ees__proto_msg__init(proto_msg);
            copy_address_from_address(&(proto_msg->from), sender_address);
            copy_address_from_address(&(proto_msg->to), to_member_address);
            proto_msg->payload_case = E2EES__PROTO_MSG__PAYLOAD_E2EE_MSG;
            proto_msg->e2ee_msg = e2ees__e2ee_msg__unpack(NULL, e2ee_msg_data_len, e2ee_msg_data);

            proto_msg_hash(
                &msg, &msg_len,
                NULL,
                proto_msg->from,
                proto_msg->to,
                proto_msg->payload_case,
                proto_msg->e2ee_msg
            );
            proto_msg->n_signature_list = 1;
            proto_msg->signature_list = (E2ees__ServerSignedSignature **)malloc(sizeof(E2ees__ServerSignedSignature *) * 1);
            mock_server_signed_signature(&(proto_msg->signature_list[0]), msg, msg_len);

            send_proto_msg(proto_msg);

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            free_mem((void **)&msg, msg_len);
        }
        // release
        if (to_member_addresses != NULL) {
            for (j = 0; j < to_member_addresses_num; j++) {
                e2ees__e2ee_address__free_unpacked(to_member_addresses[j], NULL);
                to_member_addresses[j] = NULL;
            }
            free_mem((void **)&to_member_addresses, sizeof(E2ees__E2eeAddress *) * to_member_addresses_num);
            to_member_addresses = NULL;
        }
    }

    E2ees__SendGroupMsgResponse *response = (E2ees__SendGroupMsgResponse *)malloc(sizeof(E2ees__SendGroupMsgResponse));
    e2ees__send_group_msg_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

E2ees__ConsumeProtoMsgResponse *mock_consume_proto_msg(E2ees__E2eeAddress *from, const char *auth, E2ees__ConsumeProtoMsgRequest *request) {
    size_t request_data_len = e2ees__consume_proto_msg_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    e2ees__consume_proto_msg_request__pack(request, request_data);

    E2ees__ConsumeProtoMsgResponse *response = (E2ees__ConsumeProtoMsgResponse *)malloc(sizeof(E2ees__ConsumeProtoMsgResponse));
    e2ees__consume_proto_msg_response__init(response);
    response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}
