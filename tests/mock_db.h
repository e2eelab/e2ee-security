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
#ifndef MOCK_DB_H_
#define MOCK_DB_H_

#include <sqlite3.h>
#include <stdbool.h>

#include "e2ees/e2ees.h"

void mock_db_begin();
void mock_db_end();
size_t load_address_ids(sqlite_int64 **address_ids);
char *load_version(uint64_t address_id);
protobuf_c_boolean load_saved(uint64_t address_id);
bool load_address(uint64_t address_id, E2ees__E2eeAddress **address);
bool load_group_address(uint64_t address_id, E2ees__E2eeAddress **address);
void load_password(uint64_t address_id, char **password);
uint32_t load_e2ees_pack_id(uint64_t address_id);
void load_identity_key_pair(uint64_t address_id, E2ees__IdentityKey **identity_key_pair);
void load_signed_pre_key_pair(uint64_t address_id, E2ees__SignedPreKey **signed_pre_key);
int load_n_one_time_pre_keys(uint64_t address_id);
size_t load_one_time_pre_keys(uint64_t address_id, E2ees__OneTimePreKey ***one_time_pre_keys);
uint32_t load_next_one_time_pre_key_id(uint64_t address_id);
bool load_address_id(E2ees__E2eeAddress *address, sqlite_int64 *address_id);
sqlite_int64 insert_address(E2ees__E2eeAddress *address);
sqlite_int64 insert_key_pair(E2ees__KeyPair *key_pair);
sqlite_int64 insert_identity_key(E2ees__IdentityKey *identity_key);
sqlite_int64 insert_signed_pre_key(E2ees__SignedPreKey *signed_pre_key);
sqlite_int64 insert_one_time_pre_key(E2ees__OneTimePreKey *one_time_pre_key);
sqlite_int64 insert_account(
    const char *version, protobuf_c_boolean saved, const char *auth, sqlite_int64 address_id,
    const char *password, uint32_t e2ees_pack_id, sqlite_int64 identity_key_pair_id,
    sqlite_int64 signed_pre_key_id, sqlite_int64 next_one_time_pre_key_id
);
void insert_account_identity_key_id(uint64_t address_id, sqlite_int64 identity_key_id);
void insert_account_signed_pre_key_id(uint64_t address_id, sqlite_int64 signed_pre_key_id);
void insert_account_one_time_pre_key_id(uint64_t address_id, sqlite_int64 one_time_pre_key_id);
bool update_signed_pre_key(E2ees__E2eeAddress *address, E2ees__SignedPreKey *signed_pre_key);
void load_signed_pre_key(E2ees__E2eeAddress *address, uint32_t spk_id, E2ees__SignedPreKey **signed_pre_key_pair);
bool remove_expired_signed_pre_key(E2ees__E2eeAddress *address);
bool remove_one_time_pre_key(E2ees__E2eeAddress *address, uint32_t one_time_pre_key_id);
bool update_one_time_pre_key(E2ees__E2eeAddress *address, uint32_t one_time_pre_key_id);
bool add_one_time_pre_key(E2ees__E2eeAddress *address, E2ees__OneTimePreKey *one_time_pre_key);
void store_account(E2ees__Account *account);
void load_account_by_address_id(uint64_t address_id, E2ees__Account **account);
void load_auth(E2ees__E2eeAddress *address, char **auth); // new added
void load_account_by_address(E2ees__E2eeAddress *address, E2ees__Account **account);
size_t load_accounts(E2ees__Account ***accounts);
void load_session(char *session_id, E2ees__E2eeAddress *our_address, E2ees__Session **session);
void load_outbound_session(E2ees__E2eeAddress *our_address, E2ees__E2eeAddress *their_address, E2ees__Session **session);
int load_n_outbound_sessions(E2ees__E2eeAddress *our_address, const char *their_user_id);
size_t load_outbound_sessions(E2ees__E2eeAddress *our_address, const char *their_user_id, const char *their_domain, E2ees__Session ***outbound_sessions);
void store_session(E2ees__Session *session);
void unload_session(E2ees__E2eeAddress *our_address, E2ees__E2eeAddress *their_address);
void unload_old_session(E2ees__E2eeAddress *our_address, E2ees__E2eeAddress *their_address, int64_t invite_t);
void load_group_session_by_address(E2ees__E2eeAddress *sender_address, E2ees__E2eeAddress *owner_address, E2ees__E2eeAddress *group_address, E2ees__GroupSession **group_session);
void load_group_session_by_id(E2ees__E2eeAddress *sender_address, E2ees__E2eeAddress *owner_address, char *session_id, E2ees__GroupSession **group_session);
int load_n_group_sessions(E2ees__E2eeAddress *owner_address, E2ees__E2eeAddress *group_address);
size_t load_group_sessions(E2ees__E2eeAddress *owner_address, E2ees__E2eeAddress *group_address, E2ees__GroupSession ***group_sessions);
int load_n_group_addresses(E2ees__E2eeAddress *sender_address, E2ees__E2eeAddress *owner_address);
size_t load_group_addresses(E2ees__E2eeAddress *sender_address, E2ees__E2eeAddress *owner_address, E2ees__E2eeAddress ***group_addresses);
void store_group_session(E2ees__GroupSession *group_session);
void unload_group_session_by_address(E2ees__E2eeAddress *session_owner, E2ees__E2eeAddress *group_address);
void unload_group_session_by_id(E2ees__E2eeAddress *session_owner, char *session_id);
void unload_group_session_with_no_session_id(
    E2ees__E2eeAddress *sender,
    E2ees__E2eeAddress *session_owner,
    E2ees__E2eeAddress *group_address
);
void store_pending_plaintext_data(
    E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address, char *pending_plaintext_id,
    uint8_t *group_pre_key_plaintext, size_t group_pre_key_plaintext_len, E2ees__NotifLevel notif_level
);
size_t load_pending_plaintext_data(
    E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address, char ***pending_plaintext_id_list,
    uint8_t ***e2ee_plaintext_data_list, size_t **e2ee_plaintext_data_len_list, E2ees__NotifLevel **notif_level_list
);
void unload_pending_plaintext_data(E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address, char *pending_plaintext_id);
void store_pending_request_data(E2ees__E2eeAddress *user_address, char *request_id, uint8_t request_type, uint8_t *request_data, size_t request_data_len);
size_t load_pending_request_data(E2ees__E2eeAddress *user_address, char ***request_id_list, uint8_t **request_type, uint8_t ***request_data_list, size_t **request_data_len_list);
void unload_pending_request_data(E2ees__E2eeAddress *user_address, char *request_id);

#endif /* MOCK_DB_H_ */
