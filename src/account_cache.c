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

#include "e2ees/account_cache.h"

#include <string.h>

#include "e2ees/mem_util.h"

static account_cacheer *account_cacheer_list = NULL;

void store_account_into_cache(E2ees__Account *account) {
    if (account_cacheer_list == NULL) {
        account_cacheer_list = (account_cacheer *)malloc(sizeof(account_cacheer));
        account_cacheer_list->version = strdup(account->version);
        account_cacheer_list->e2ees_pack_id = account->e2ees_pack_id;
        copy_address_from_address(&(account_cacheer_list->address), account->address);
        copy_ik_from_ik(&(account_cacheer_list->identity_key), account->identity_key);

        if (account->server_cert != NULL 
            && account->server_cert->cert != NULL) {
            copy_protobuf_from_protobuf(&(account_cacheer_list->server_public_key), &(account->server_cert->cert->public_key));
        }
        
        account_cacheer_list->next = NULL;
    } else {
        account_cacheer *cur = account_cacheer_list;
        if (compare_address(cur->address, account->address)) {
            // already cached, skip
            return;
        }
        while (cur->next != NULL) {
            cur = cur->next;
            if (compare_address(cur->address, account->address)) {
                // already cached, skip
                return;
            }
        }
        cur->next = (account_cacheer *)malloc(sizeof(account_cacheer));
        cur->next->version = strdup(account->version);
        cur->next->e2ees_pack_id = account->e2ees_pack_id;
        copy_address_from_address(&(cur->next->address), account->address);
        copy_ik_from_ik(&(cur->next->identity_key), account->identity_key);

        if (account->server_cert != NULL 
            && account->server_cert->cert != NULL) {
            copy_protobuf_from_protobuf(&(cur->next->server_public_key), &(account->server_cert->cert->public_key));
        }

        cur->next->next = NULL;
    }
}

void load_version_from_cache(char **version_out, E2ees__E2eeAddress *address) {
    account_cacheer *cur = account_cacheer_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            *version_out = strdup(cur->version);
            return;
        }
        cur = cur->next;
    }
    *version_out = NULL;
}

void load_e2ees_pack_id_from_cache(uint32_t *e2ees_pack_id_out, E2ees__E2eeAddress *address) {
    account_cacheer *cur = account_cacheer_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            *e2ees_pack_id_out = cur->e2ees_pack_id;
            return;
        }
        cur = cur->next;
    }
    *e2ees_pack_id_out = E2EES_PACK_ID_UNSPECIFIED;
}

void load_identity_key_from_cache(E2ees__IdentityKey **identity_key_out, E2ees__E2eeAddress *address) {
    account_cacheer *cur = account_cacheer_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            copy_ik_from_ik(identity_key_out, cur->identity_key);
            return;
        }
        cur = cur->next;
    }
    *identity_key_out = NULL;
}

void load_server_public_key_from_cache(ProtobufCBinaryData *server_public_key, E2ees__E2eeAddress *address) {
    account_cacheer *cur = account_cacheer_list;
    while (cur != NULL) {
        if (compare_address(cur->address, address)) {
            copy_protobuf_from_protobuf(server_public_key, &(cur->server_public_key));
            return;
        }
        cur = cur->next;
    }
}

static void free_account_cacheer(account_cacheer *cacheer) {
    if (cacheer->version != NULL) {
        free(cacheer->version);
        cacheer->version = NULL;
    }
    cacheer->e2ees_pack_id = 0;
    if (cacheer->address != NULL) {
        e2ees__e2ee_address__free_unpacked(cacheer->address, NULL);
        cacheer->address = NULL;
    }
    if (cacheer->identity_key != NULL) {
        e2ees__identity_key__free_unpacked(cacheer->identity_key, NULL);
        cacheer->identity_key = NULL;
    }
    free_protobuf(&(cacheer->server_public_key));
    cacheer = NULL;
}

void free_account_cacheer_list() {
    account_cacheer *cur = account_cacheer_list;
    account_cacheer *temp;
    while (cur != NULL) {
        temp = cur;
        cur = cur->next;
        free_account_cacheer(temp);
    }
}
