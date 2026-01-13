/**
 * @file
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
#ifndef ACCOUNT_H_
#define ACCOUNT_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

void account_begin();

void account_end();

/**
 * @brief Create a new account object
 * This will generate an identity key pair, a signed pre-key pair,
 * a signature, and 100 one-time pre-key pairs.
 * @param account_out The generated account
 * @param e2ees_pack_id The e2ee pack ID
 * @return 0 if success
 */
int create_account(E2ees__Account **account_out, uint32_t e2ees_pack_id);

int generate_identity_key(
    E2ees__IdentityKey **identity_key_out,
    uint32_t e2ees_pack_id
);

/**
 * @brief Generate a new signed pre-key pair and a new signature.
 *
 * @param signed_pre_key_out The generated signed pre-key
 * @param e2ees_pack_id The e2ee pack ID
 * @param cur_spk_id The current signed pre-key ID
 * @param identity_private_key The private part of the identity key
 * @return 0 if success
 */
int generate_signed_pre_key(
    E2ees__SignedPreKey **signed_pre_key_out,
    uint32_t e2ees_pack_id, uint32_t cur_spk_id,
    const uint8_t *identity_private_key
);

/**
 * Purge and renew signed pre-key pair if it is expired.
 * @param account
 */
void purge_signed_pre_key(E2ees__Account *account);

/**
 * @brief Lookup an one-time pre-key with a given public key
 *
 * @param account The account for looking up the one-time pre-key
 * @param one_time_pre_key_id The one-time pre-key id to be matched
 * @return const E2ees__OneTimePreKey* The matched one-time pre-key.
 */
E2ees__OneTimePreKey *lookup_one_time_pre_key(
    E2ees__Account *account,
    uint32_t one_time_pre_key_id
);

/**
 * @brief Generates a number of new one-time pre-keys
 *
 * @param one_time_pre_key_out The generated one-time pre-key list
 * @param number_of_keys The given number
 * @param e2ees_pack_id The e2ee pack ID
 * @param cur_opk_id The current one-time pre-key ID
 * @return 0 if success
 */
int generate_opks(
    E2ees__OneTimePreKey ***one_time_pre_key_out, size_t number_of_keys,
    uint32_t e2ees_pack_id, uint32_t cur_opk_id
);

int insert_opks(E2ees__Account *account, E2ees__OneTimePreKey **src, size_t src_num);

/**
 * @brief Mark one of the one-time pre-key pairs as used given by ID
 *
 * @param account The account to be processed
 * @param id The id of one-time pre-key that will be marked as used.
 * @return value < 0 for error
 */
int mark_opk_as_used(
    E2ees__Account *account,
    uint32_t id
);

/**
 * @brief Purge used one-time pre-keys
 *
 * @param account The account to be processed
 */
void purge_one_time_pre_key(E2ees__Account *account);

#ifdef __cplusplus
}
#endif

#endif /* ACCOUNT_H_ */
