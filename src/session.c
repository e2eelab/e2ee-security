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
#include "e2ees/session.h"

#include <stdio.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/cipher.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/ratchet.h"

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

void initialise_session(
    E2ees__Session *session,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *our_address,
    E2ees__E2eeAddress *their_address) {
    e2ees__session__init(session);
    session->e2ees_pack_id = e2ees_pack_id;
    copy_address_from_address(&(session->our_address), our_address);
    copy_address_from_address(&(session->their_address), their_address);
}

void pack_common_plaintext(
    const uint8_t *plaintext_data,
    size_t plaintext_data_len,
    int plaintext_type,
    uint8_t **common_plaintext_data,
    size_t *common_plaintext_data_len) {
    E2ees__Plaintext *plaintext = (E2ees__Plaintext *)malloc(sizeof(E2ees__Plaintext));
    e2ees__plaintext__init(plaintext);
    plaintext->version      = strdup(E2EES_PLAINTEXT_VERSION);
    plaintext->payload_case = plaintext_type;
    switch (plaintext_type) {
    case E2EES__PLAINTEXT__PAYLOAD_COMMON_MSG:
        plaintext->common_msg.len  = plaintext_data_len;
        plaintext->common_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_data_len);
        memcpy(plaintext->common_msg.data, plaintext_data, plaintext_data_len);
        break;
    case E2EES__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG:
        plaintext->common_sync_msg.len  = plaintext_data_len;
        plaintext->common_sync_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_data_len);
        memcpy(plaintext->common_sync_msg.data, plaintext_data, plaintext_data_len);
        break;
    default:
        // error
        break;
    };

    size_t len                 = e2ees__plaintext__get_packed_size(plaintext);
    *common_plaintext_data_len = len;
    *common_plaintext_data     = (uint8_t *)malloc(sizeof(uint8_t) * len);
    e2ees__plaintext__pack(plaintext, *common_plaintext_data);

    // release
    e2ees__plaintext__free_unpacked(plaintext, NULL);
}
