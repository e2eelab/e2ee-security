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
#ifndef ACCOUNT_CACHE_H_
#define ACCOUNT_CACHE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

typedef struct account_cacheer {
    char *version;
    uint32_t e2ees_pack_id;
    E2ees__E2eeAddress *address;
    E2ees__IdentityKey *identity_key;
    ProtobufCBinaryData server_public_key;
    struct account_cacheer *next;
} account_cacheer;

/**
 * @brief Store an account into the cache.
 * @param account The account to store.
 */
void store_account_into_cache(E2ees__Account *account);

/**
 * @brief Load the protocol version from the cache for a given address.
 * @param version_out Pointer to string to be allocated and filled.
 * @param address The address to lookup.
 */
void load_version_from_cache(char **version_out, E2ees__E2eeAddress *address);

/**
 * @brief Load the E2EE pack ID from the cache for a given address.
 * @param e2ees_pack_id_out Pointer to the pack ID to be filled.
 * @param address The address to lookup.
 */
void load_e2ees_pack_id_from_cache(uint32_t *e2ees_pack_id_out, E2ees__E2eeAddress *address);

/**
 * @brief Load the identity key from the cache for a given address.
 * @param identity_key_out Pointer to the identity key to be allocated and filled.
 * @param address The address to lookup.
 */
void load_identity_key_from_cache(E2ees__IdentityKey **identity_key_out, E2ees__E2eeAddress *address);

/**
 * @brief Load the server public key from the cache for a given address.
 * @param server_public_key Pointer to the binary data to be filled.
 * @param address The address to lookup.
 */
void load_server_public_key_from_cache(ProtobufCBinaryData *server_public_key, E2ees__E2eeAddress *address);

/**
 * @brief Free all entries in the account cache list.
 */
void free_account_cacheer_list();

#ifdef __cplusplus
}
#endif

#endif /* ACCOUNT_CACHE_H_ */
