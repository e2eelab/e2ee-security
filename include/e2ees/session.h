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
#ifndef SESSION_H_
#define SESSION_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/**
 * @brief Type definition of session suite.
 */
typedef struct session_suite_t {
    /**
     * @brief Create a new outbound session.
     *
     * @param response_out The output invite response
     * @param from The sender's address
     * @param their_pre_key_bundle Their pre-key bundle
     * @return 0 if success
     */
    int (*new_outbound_session)(
        E2ees__InviteResponse **, E2ees__E2eeAddress *, E2ees__PreKeyBundle *);

    /**
     * @brief Create a new inbound session.
     *
     * @param inbound_session_out The inbound session
     * @param local_account Our account
     * @param request The invite message
     * @return value < 0 for error
     */
    int (*new_inbound_session)(E2ees__Session **, E2ees__Account *, E2ees__InviteMsg *);

    /**
     * @brief Complete an outbound session.
     *
     * @param outbound_session_out The outbound session
     * @param msg The accept message
     * @return value < 0 for error
     */
    int (*complete_outbound_session)(E2ees__Session **, E2ees__AcceptMsg *);
} session_suite_t;

/* common */
void initialise_session(
    E2ees__Session *session,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *our_address,
    E2ees__E2eeAddress *their_address);

/**
 * @brief Packaging a common plaintext to common_plaintext_data.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param plaintext_type
 * @param common_plaintext_data
 * @param common_plaintext_data_len
 */
void pack_common_plaintext(
    const uint8_t *plaintext_data,
    size_t plaintext_data_len,
    int plaintext_type,
    uint8_t **common_plaintext_data,
    size_t *common_plaintext_data_len);

/* ECC-related */
E2ees__InviteResponse *crypto_curve25519_new_outbound_session(
    E2ees__Session *session,
    const E2ees__Account *local_account,
    E2ees__PreKeyBundle *their_pre_key_bundle);

int crypto_curve25519_new_inbound_session(
    E2ees__Session *session, E2ees__Account *local_account, E2ees__InviteMsg *msg);

int crypto_curve25519_complete_outbound_session(
    E2ees__Session *outbound_session, E2ees__AcceptMsg *msg);

/* PQC-related */
int pqc_new_outbound_session_v2(
    E2ees__InviteResponse **response_out,
    E2ees__E2eeAddress *from,
    E2ees__PreKeyBundle *their_pre_key_bundle);

int pqc_new_inbound_session(
    E2ees__Session **inbound_session_out, E2ees__Account *local_account, E2ees__InviteMsg *msg);

int pqc_complete_outbound_session(E2ees__Session **outbound_session_out, E2ees__AcceptMsg *msg);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_H_ */
