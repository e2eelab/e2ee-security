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
// TODO: UPDATE HEADER FILE
#include "mock_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ees/mem_util.h"

// global variable
// db in memory
// static const char *db_name = (char *)"file:test.db?mode=memory&cache=shared";
static const char *db_name = (char *)":memory:"; // test.db";
static sqlite3 *db;

// util function
static void sqlite_connect(const char *db_name) {
    sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
    int rc = sqlite3_open_v2(db_name, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }
}

static int sqlite_callback(void *data, int argc, char **argv, char **azColName) {
    fprintf(stderr, "%s: ", (const char *)data);
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");

    return 0;
}

static void sqlite_execute(const char *sql) {
    char *errMsg = NULL;
    const char *data = (char *)"Callback function called";

    sqlite3_exec(db, "BEGIN", 0, 0, 0);
    int rc = sqlite3_exec(db, sql, sqlite_callback, (void *)data, &errMsg);
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    sqlite3_exec(db, "COMMIT TRANSACTION;", NULL, NULL, NULL);
}

static bool sqlite_prepare(const char *sql, sqlite3_stmt **stmt) {
    int rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
        return false;
    }

    return true;
}

static bool sqlite_step(sqlite3_stmt *stmt, int return_code) {
    sqlite3_exec(db, "BEGIN", 0, 0, 0);
    int rc = sqlite3_step(stmt);
    if (rc != return_code) {
        // fprintf(stderr, "Cannot step correctly.");
        return false;
    }
    return true;
}

static void sqlite_finalize(sqlite3_stmt *stmt) {
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
    sqlite3_finalize(stmt);
}

// SQLs
// session related
static const char *SESSION_DROP_TABLE = "DROP TABLE IF EXISTS SESSION;";
static const char *SESSION_CREATE_TABLE = "CREATE TABLE SESSION( "
                                          "ID TEXT NOT NULL, "
                                          "OUR_ADDRESS INTEGER NOT NULL, "
                                          "THEIR_ADDRESS INTEGER NOT NULL, "
                                          "INVITE_T INTEGER NOT NULL, "
                                          "DATA BLOB NOT NULL, "
                                          "FOREIGN KEY(OUR_ADDRESS) REFERENCES ADDRESS(ID), "
                                          "FOREIGN KEY(THEIR_ADDRESS) REFERENCES ADDRESS(ID), "
                                          "PRIMARY KEY (ID, OUR_ADDRESS, THEIR_ADDRESS));";

static const char *SESSION_LOAD_DATA_BY_ADDRESSES = "SELECT DATA FROM SESSION "
                                                    "INNER JOIN ADDRESS AS a1 "
                                                    "ON SESSION.OUR_ADDRESS = a1.ID "
                                                    "INNER JOIN ADDRESS AS a2 "
                                                    "ON SESSION.THEIR_ADDRESS = a2.ID "
                                                    "WHERE a1.USER_ID is (?) AND a2.USER_ID is (?) "
                                                    "AND a1.DEVICE_ID is (?) AND a2.DEVICE_ID is (?) "
                                                    "ORDER BY INVITE_T DESC "
                                                    "LIMIT 1;";

static const char *SESSION_INSERT_OR_REPLACE = "INSERT OR REPLACE INTO SESSION "
                                               "(ID, OUR_ADDRESS, THEIR_ADDRESS, INVITE_T, DATA) "
                                               "VALUES (?, ?, ?, ?, ?);";

static const char *SESSION_LOAD_DATA_BY_ADDRESS_AND_ID = "SELECT DATA FROM SESSION "
                                                         "INNER JOIN ADDRESS "
                                                         "ON SESSION.OUR_ADDRESS = ADDRESS.ID "
                                                         "WHERE SESSION.ID is (?) "
                                                         "AND ADDRESS.DOMAIN is (?) "
                                                         "AND ADDRESS.USER_ID is (?) "
                                                         "AND ADDRESS.DEVICE_ID is (?);";

static const char *SESSION_LOAD_N_OUTBOUND_SESSION = "SELECT COUNT(*) "
                                                     "FROM SESSION "
                                                     "INNER JOIN ADDRESS AS a1 "
                                                     "ON SESSION.OUR_ADDRESS = a1.ID "
                                                     "INNER JOIN ADDRESS AS a2 "
                                                     "ON SESSION.THEIR_ADDRESS = a2.ID "
                                                     "WHERE a1.DOMAIN is (?) "
                                                     "AND a1.USER_ID is (?) "
                                                     "AND a1.DEVICE_ID is (?) "
                                                     "AND a2.USER_ID is (?);";

static const char *SESSION_LOAD_OUTBOUND_SESSIONS = "SELECT DATA "
                                                    "FROM SESSION "
                                                    "INNER JOIN ADDRESS AS a1 "
                                                    "ON SESSION.OUR_ADDRESS = a1.ID "
                                                    "INNER JOIN ADDRESS AS a2 "
                                                    "ON SESSION.THEIR_ADDRESS = a2.ID "
                                                    "WHERE a1.DOMAIN is (?) "
                                                    "AND a1.USER_ID is (?) "
                                                    "AND a1.DEVICE_ID is (?) "
                                                    "AND a2.USER_ID is (?);";

static const char *SESSION_DELETE_DATA_BY_ADDRESSES = "DELETE FROM SESSION "
                                                      "WHERE OUR_ADDRESS IN "
                                                      "(SELECT ID FROM ADDRESS WHERE USER_ID is (?) AND DEVICE_ID is (?)) "
                                                      "AND THEIR_ADDRESS IN "
                                                      "(SELECT ID FROM ADDRESS WHERE USER_ID is (?) AND DEVICE_ID is (?));";

static const char *SESSION_DELETE_OLD_DATA = "DELETE FROM SESSION "
                                             "WHERE OUR_ADDRESS IN "
                                             "(SELECT ID FROM ADDRESS WHERE USER_ID is (?) AND DEVICE_ID is (?)) "
                                             "AND THEIR_ADDRESS IN "
                                             "(SELECT ID FROM ADDRESS WHERE USER_ID is (?) AND DEVICE_ID is (?)) "
                                             "AND INVITE_T < (?);";

static const char *GROUP_SESSION_DROP_TABLE = "DROP TABLE IF EXISTS GROUP_SESSION;";
static const char *GROUP_SESSION_CREATE_TABLE = "CREATE TABLE GROUP_SESSION( "
                                                "ID TEXT NOT NULL, "
                                                "SENDER INTEGER NOT NULL, "
                                                "OWNER INTEGER NOT NULL, "
                                                "ADDRESS INTEGER NOT NULL, "
                                                "TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, "
                                                "GROUP_DATA BLOB NOT NULL, "
                                                "FOREIGN KEY(SENDER) REFERENCES ADDRESS(ID), "
                                                "FOREIGN KEY(OWNER) REFERENCES ADDRESS(ID), "
                                                "FOREIGN KEY(ADDRESS) REFERENCES ADDRESS(ID), "
                                                "PRIMARY KEY (ID, ADDRESS, SENDER, OWNER));";

static const char *GROUP_SESSION_INSERT_OR_REPLACE = "INSERT OR REPLACE INTO GROUP_SESSION "
                                                     "(ID, SENDER, OWNER, ADDRESS, GROUP_DATA) "
                                                     "VALUES (?, ?, ?, ?, ?);";

static const char *GROUP_SESSION_LOAD_DATA_BY_ADDRESS = "SELECT GROUP_DATA FROM GROUP_SESSION "
                                                        "INNER JOIN ADDRESS AS a1 "
                                                        "ON GROUP_SESSION.SENDER = a1.ID "
                                                        "INNER JOIN ADDRESS as a2 "
                                                        "ON GROUP_SESSION.OWNER = a2.ID "
                                                        "INNER JOIN ADDRESS as a3 "
                                                        "ON GROUP_SESSION.ADDRESS = a3.ID "
                                                        "WHERE a1.DOMAIN is (?) AND a1.USER_ID is (?) AND a1.DEVICE_ID is (?) AND "
                                                        "a2.DOMAIN is (?) AND a2.USER_ID is (?) AND a2.DEVICE_ID is (?) AND "
                                                        "a3.GROUP_ID is (?);";

static const char *GROUP_SESSION_LOAD_DATA_BY_ID = "SELECT GROUP_DATA FROM GROUP_SESSION "
                                                   "INNER JOIN ADDRESS AS a1 "
                                                   "ON GROUP_SESSION.SENDER = a1.ID "
                                                   "INNER JOIN ADDRESS AS a2 "
                                                   "ON GROUP_SESSION.OWNER = a2.ID "
                                                   "WHERE GROUP_SESSION.ID is (?) AND a1.USER_ID is (?) AND a1.DOMAIN is (?) AND a1.DEVICE_ID is (?) "
                                                   "AND a2.USER_ID is (?) AND a2.DOMAIN is (?) AND a2.DEVICE_ID is (?);";

static const char *N_GROUP_SESSION_LOAD = "SELECT COUNT(*) FROM GROUP_SESSION "
                                          "INNER JOIN ADDRESS as a1 "
                                          "ON GROUP_SESSION.ADDRESS = a1.ID "
                                          "INNER JOIN ADDRESS as a2 "
                                          "ON GROUP_SESSION.OWNER = a2.ID "
                                          "WHERE a1.GROUP_ID is (?) AND a2.USER_ID is (?) AND a2.DOMAIN is (?) AND a2.DEVICE_ID is (?);";

static const char *GROUP_SESSIONS_LOAD = "SELECT GROUP_DATA FROM GROUP_SESSION "
                                         "INNER JOIN ADDRESS as a1 "
                                         "ON GROUP_SESSION.ADDRESS = a1.ID "
                                         "INNER JOIN ADDRESS as a2 "
                                         "ON GROUP_SESSION.OWNER = a2.ID "
                                         "WHERE a1.GROUP_ID is (?) AND a2.USER_ID is (?) AND a2.DOMAIN is (?) AND a2.DEVICE_ID is (?);";

static const char *N_GROUP_ADDRESS_LOAD = "SELECT COUNT(*) FROM GROUP_SESSION "
                                          "INNER JOIN ADDRESS as a1 "
                                          "ON GROUP_SESSION.SENDER = a1.ID "
                                          "INNER JOIN ADDRESS as a2 "
                                          "ON GROUP_SESSION.OWNER = a2.ID "
                                          "WHERE a1.USER_ID is (?) AND a1.DOMAIN is (?) AND a1.DEVICE_ID is (?) "
                                          "AND a2.USER_ID is (?) AND a2.DOMAIN is (?) AND a2.DEVICE_ID is (?);";

static const char *GROUP_ADDRESSES_LOAD = "SELECT ADDRESS FROM GROUP_SESSION "
                                          "INNER JOIN ADDRESS as a1 "
                                          "ON GROUP_SESSION.SENDER = a1.ID "
                                          "INNER JOIN ADDRESS as a2 "
                                          "ON GROUP_SESSION.OWNER = a2.ID "
                                          "WHERE a1.USER_ID is (?) AND a1.DOMAIN is (?) AND a1.DEVICE_ID is (?) "
                                          "AND a2.USER_ID is (?) AND a2.DOMAIN is (?) AND a2.DEVICE_ID is (?);";

static const char *GROUP_SESSION_DELETE_DATA_BY_ADDRESS = "DELETE FROM GROUP_SESSION "
                                                          "WHERE OWNER IN "
                                                          "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                          "AND ADDRESS IN "
                                                          "(SELECT ID FROM ADDRESS WHERE GROUP_ID is (?));";

static const char *GROUP_SESSION_DELETE_DATA_BY_ID = "DELETE FROM GROUP_SESSION "
                                                     "WHERE OWNER IN "
                                                     "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                     "AND ID is (?);";

static const char *GROUP_SESSION_DELETE_DATA_WITH_NO_ID = "DELETE FROM GROUP_SESSION "
                                                          "WHERE SENDER IN "
                                                          "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                          "AND OWNER IN "
                                                          "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                          "AND ADDRESS IN "
                                                          "(SELECT ID FROM ADDRESS WHERE GROUP_ID is (?)) "
                                                          "AND ID is (?);";

// pending data related
static const char *PENDING_PLAINTEXT_DATA_DROP_TABLE = "DROP TABLE IF EXISTS PENDING_PLAINTEXT_DATA;";
static const char *PENDING_PLAINTEXT_DATA_CREATE_TABLE = "CREATE TABLE PENDING_PLAINTEXT_DATA( "
                                                         "PENDING_PLAINTEXT_ID TEXT NOT NULL, "
                                                         "FROM_ADDRESS INTEGER NOT NULL, "
                                                         "TO_ADDRESS INTEGER NOT NULL, "
                                                         "PLAINTEXT_DATA BLOB NOT NULL, "
                                                         "NOTIF_LEVEL INTEGER NOT NULL, "
                                                         "FOREIGN KEY(FROM_ADDRESS) REFERENCES ADDRESS(ID), "
                                                         "FOREIGN KEY(TO_ADDRESS) REFERENCES ADDRESS(ID), "
                                                         "PRIMARY KEY (PENDING_PLAINTEXT_ID, FROM_ADDRESS, TO_ADDRESS));";

static const char *PENDING_PLAINTEXT_DATA_INSERT = "INSERT INTO PENDING_PLAINTEXT_DATA "
                                                   "(PENDING_PLAINTEXT_ID, FROM_ADDRESS, TO_ADDRESS, PLAINTEXT_DATA, NOTIF_LEVEL) "
                                                   "VALUES (?, ? ,?, ?, ?);";

static const char *N_PENDING_PLAINTEXT_DATA_LOAD = "SELECT COUNT(*) "
                                                   "FROM PENDING_PLAINTEXT_DATA "
                                                   "INNER JOIN ADDRESS AS a1 "
                                                   "ON PENDING_PLAINTEXT_DATA.FROM_ADDRESS = a1.ID "
                                                   "INNER JOIN ADDRESS AS a2 "
                                                   "ON PENDING_PLAINTEXT_DATA.TO_ADDRESS = a2.ID "
                                                   "WHERE a1.DOMAIN is (?) AND a1.USER_ID is (?) AND a1.DEVICE_ID is (?) "
                                                   "AND a2.DOMAIN is (?) AND a2.USER_ID is (?) AND a2.DEVICE_ID is (?);";

static const char *PENDING_PLAINTEXT_DATA_LOAD = "SELECT PENDING_PLAINTEXT_ID, "
                                                 "PLAINTEXT_DATA, "
                                                 "NOTIF_LEVEL "
                                                 "FROM PENDING_PLAINTEXT_DATA "
                                                 "INNER JOIN ADDRESS AS a1 "
                                                 "ON PENDING_PLAINTEXT_DATA.FROM_ADDRESS = a1.ID "
                                                 "INNER JOIN ADDRESS AS a2 "
                                                 "ON PENDING_PLAINTEXT_DATA.TO_ADDRESS = a2.ID "
                                                 "WHERE a1.DOMAIN is (?) AND a1.USER_ID is (?) AND a1.DEVICE_ID is (?) "
                                                 "AND a2.DOMAIN is (?) AND a2.USER_ID is (?) AND a2.DEVICE_ID is (?);";

static const char *PENDING_PLAINTEXT_DATA_DELETE = "DELETE FROM PENDING_PLAINTEXT_DATA "
                                                   "WHERE FROM_ADDRESS IN "
                                                   "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                   "AND TO_ADDRESS IN "
                                                   "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                   "AND PENDING_PLAINTEXT_ID is (?);";

static const char *PENDING_REQUEST_DATA_DROP_TABLE = "DROP TABLE IF EXISTS PENDING_REQUEST_DATA;";
static const char *PENDING_REQUEST_DATA_CREATE_TABLE = "CREATE TABLE PENDING_REQUEST_DATA( "
                                                       "PENDING_REQUEST_ID TEXT NOT NULL, "
                                                       "UESR_ADDRESS INTEGER NOT NULL, "
                                                       "REQUEST_TYPE INTEGER NOT NULL, "
                                                       "REQUEST_DATA BLOB NOT NULL, "
                                                       "FOREIGN KEY(UESR_ADDRESS) REFERENCES ADDRESS(ID), "
                                                       "PRIMARY KEY (PENDING_REQUEST_ID, UESR_ADDRESS, REQUEST_TYPE));";

static const char *PENDING_REQUEST_DATA_INSERT = "INSERT INTO PENDING_REQUEST_DATA "
                                                 "(PENDING_REQUEST_ID, UESR_ADDRESS, REQUEST_TYPE, REQUEST_DATA) "
                                                 "VALUES (?, ?, ?, ?);";

static const char *N_PENDING_REQUEST_DATA_LOAD = "SELECT COUNT(*) "
                                                 "FROM PENDING_REQUEST_DATA "
                                                 "INNER JOIN ADDRESS "
                                                 "ON PENDING_REQUEST_DATA.UESR_ADDRESS = ADDRESS.ID "
                                                 "WHERE ADDRESS.DOMAIN is (?) AND "
                                                 "ADDRESS.USER_ID is (?) AND "
                                                 "ADDRESS.DEVICE_ID is (?);";

static const char *PENDING_REQUEST_DATA_LOAD = "SELECT PENDING_REQUEST_ID, "
                                               "REQUEST_TYPE, "
                                               "REQUEST_DATA "
                                               "FROM PENDING_REQUEST_DATA "
                                               "INNER JOIN ADDRESS "
                                               "ON PENDING_REQUEST_DATA.UESR_ADDRESS = ADDRESS.ID "
                                               "WHERE ADDRESS.DOMAIN is (?) AND "
                                               "ADDRESS.USER_ID is (?) AND "
                                               "ADDRESS.DEVICE_ID is (?);";

static const char *PENDING_REQUEST_DATA_DELETE = "DELETE FROM PENDING_REQUEST_DATA "
                                                 "WHERE UESR_ADDRESS IN "
                                                 "(SELECT ID FROM ADDRESS WHERE DOMAIN is (?) AND USER_ID is (?) AND DEVICE_ID is (?)) "
                                                 "AND PENDING_REQUEST_ID is (?);";

// account related
// NOTE: ADDRESS_ID
static const char *ADDRESS_DROP_TABLE = "DROP TABLE IF EXISTS ADDRESS;";
static const char *ADDRESS_CREATE_TABLE = "CREATE TABLE ADDRESS( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "USER_ID TEXT, "
                                          "DOMAIN TEXT NOT NULL, "
                                          "DEVICE_ID TEXT, "
                                          "GROUP_ID TEXT, "
                                          "GROUP_NAME TEXT, "
                                          "UNIQUE (USER_ID, DOMAIN, DEVICE_ID, GROUP_ID));";

static const char *KEYPAIR_DROP_TABLE = "DROP TABLE IF EXISTS KEYPAIR;";
static const char *KEYPAIR_CREATE_TABLE = "CREATE TABLE KEYPAIR( "
                                          "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "PUBLIC_KEY BLOB NOT NULL, "
                                          "PRIVATE_KEY BLOB NOT NULL);";

static const char *IDENTITY_KEY_DROP_TABLE = "DROP TABLE IF EXISTS IDENTITY_KEY;";
static const char *IDENTITY_KEY_CREATE_TABLE = "CREATE TABLE IDENTITY_KEY( "
                                               "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                               "ASYM_KEYPAIR INTEGER NOT NULL, "
                                               "SIGN_KEYPAIR INTEGER NOT NULL, "
                                               "FOREIGN KEY(ASYM_KEYPAIR) REFERENCES KEYPAIR(ID), "
                                               "FOREIGN KEY(SIGN_KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *SIGNED_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS SIGNED_PRE_KEY;";
static const char *SIGNED_PRE_KEY_CREATE_TABLE = "CREATE TABLE SIGNED_PRE_KEY( "
                                                 "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                 "SPK_ID INTEGER NOT NULL, "
                                                 "KEYPAIR INTEGER NOT NULL, "
                                                 "SIGNATURE BLOB NOT NULL, "
                                                 "TTL INTEGER NOT NULL, "
                                                 "FOREIGN KEY(KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *ONETIME_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ONETIME_PRE_KEY;";
static const char *ONETIME_PRE_KEY_CREATE_TABLE = "CREATE TABLE ONETIME_PRE_KEY(  "
                                                  "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                  "OPK_ID INTEGER NOT NULL, "
                                                  "USED INTEGER NOT NULL, "
                                                  "KEYPAIR INTEGER NOT NULL, "
                                                  "FOREIGN KEY(KEYPAIR) REFERENCES KEYPAIR(ID));";

static const char *ACCOUNT_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT;";

static const char *ACCOUNT_CREATE_TABLE = "CREATE TABLE ACCOUNT( "
                                          //   "ACCOUNT_ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                                          "ADDRESS INTEGER PRIMARY KEY NOT NULL, "
                                          "VERSION TEXT NOT NULL, "
                                          "SAVED INTEGER NOT NULL, "
                                          "AUTH TEXT NOT NULL, " // newly added
                                          "PASSWORD TEXT NOT NULL, "
                                          "e2ees_pack_id INTEGER NOT NULL, "
                                          "IDENTITY_KEY INTEGER NOT NULL, "
                                          "SIGNED_PRE_KEY INTEGER NOT NULL, "
                                          "NEXT_ONETIME_PRE_KEY_ID INTEGER NOT NULL, "
                                          "FOREIGN KEY(ADDRESS) REFERENCES ADDRESS(ID), "
                                          "FOREIGN KEY(IDENTITY_KEY) REFERENCES IDENTITY_KEY(ID), "
                                          "FOREIGN KEY(SIGNED_PRE_KEY) REFERENCES SIGNED_PRE_KEY(ID));";

// NOTE: NEW: Change ACCOUNT into ADDRESS_ID
static const char *ACCOUNT_IDENTITY_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_IDENTITY_KEY;";
static const char *ACCOUNT_IDENTITY_KEY_CREATE_TABLE = "CREATE TABLE ACCOUNT_IDENTITY_KEY( "
                                                       "ADDRESS_ID INTEGER NOT NULL, "
                                                       "IDENTITY_KEY INTEGER NOT NULL, "
                                                       "FOREIGN KEY(ADDRESS_ID) REFERENCES ACCOUNT(ADDRESS), "
                                                       "FOREIGN KEY(IDENTITY_KEY) REFERENCES IDENTITY_KEY(ID));";

static const char *ACCOUNT_SIGNED_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_SIGNED_PRE_KEY;";
static const char *ACCOUNT_SIGNED_PRE_KEY_CREATE_TABLE = "CREATE TABLE ACCOUNT_SIGNED_PRE_KEY( "
                                                         "ADDRESS_ID INTEGER NOT NULL, "
                                                         "SIGNED_PRE_KEY INTEGER NOT NULL, "
                                                         "FOREIGN KEY(ADDRESS_ID) REFERENCES ACCOUNT(ADDRESS), "
                                                         "FOREIGN KEY(SIGNED_PRE_KEY) REFERENCES SIGNED_PRE_KEY(ID));";

static const char *ACCOUNT_ONETIME_PRE_KEY_DROP_TABLE = "DROP TABLE IF EXISTS ACCOUNT_ONETIME_PRE_KEY;";
static const char *ACCOUNT_ONETIME_PRE_KEY_CREATE_TABLE = "CREATE TABLE ACCOUNT_ONETIME_PRE_KEY( "
                                                          "ADDRESS_ID INTEGER NOT NULL, "
                                                          "ONETIME_PRE_KEY INTEGER NOT NULL, "
                                                          "FOREIGN KEY(ADDRESS_ID) REFERENCES ACCOUNT(ADDRESS), "
                                                          "FOREIGN KEY(ONETIME_PRE_KEY) REFERENCES ONETIME_PRE_KEY(ID));";

static const char *ACCOUNTS_NUM = "SELECT COUNT(*) FROM ACCOUNT;";

// NOTE: ADDRESS_ID == ADDRESS (INT)
static const char *ACCOUNT_LOAD_ALL_ADDRESS_ID = "SELECT ADDRESS FROM ACCOUNT;";

// new
static const char *LOAD_VERSION_BY_ADDRESS_ID = "SELECT VERSION "
                                                "FROM ACCOUNT "
                                                "WHERE ACCOUNT.ADDRESS is (?);";

// new
static const char *LOAD_SAVED_BY_ADDRESS_ID = "SELECT SAVED "
                                              "FROM ACCOUNT "
                                              "WHERE ACCOUNT.ADDRESS is (?);";

// new
static const char *LOAD_ADDRESS = "SELECT "
                                  "DOMAIN, "
                                  "USER_ID, "
                                  "DEVICE_ID "
                                  "FROM ADDRESS "
                                  "WHERE ADDRESS.ID is (?);";

static const char *LOAD_GROUP_ADDRESS = "SELECT "
                                        "DOMAIN, "
                                        "GROUP_NAME, "
                                        "GROUP_ID "
                                        "FROM ADDRESS "
                                        "WHERE ADDRESS.ID is (?);";

static const char *LOAD_PASSWORD_BY_ADDRESS_ID = "SELECT PASSWORD "
                                                 "FROM ACCOUNT "
                                                 "WHERE ACCOUNT.ADDRESS is (?);";
// newly added
static const char *LOAD_AUTH_BY_ADDRESS_ID = "SELECT AUTH "
                                             "FROM ACCOUNT "
                                             "WHERE ACCOUNT.ADDRESS is (?);";

static const char *LOAD_e2ees_pack_id_BY_ADDRESS_ID = "SELECT e2ees_pack_id "
                                                     "FROM ACCOUNT "
                                                     "WHERE ACCOUNT.ADDRESS is (?);";
// not used
static const char *ACCOUNT_LOAD_KEYPAIR = "SELECT KEYPAIR.PUBLIC_KEY, "
                                          "KEYPAIR.PRIVATE_KEY "
                                          "FROM ACCOUNT "
                                          "INNER JOIN KEYPAIR "
                                          "ON ACCOUNT.IDENTITY_KEY = KEYPAIR.ID "
                                          "WHERE ACCOUNT.ADDRESS is (?);";

static const char *LOAD_IDENTITY_KEY_BY_ADDRESS_ID = "SELECT IDENTITY_KEY "
                                                     "FROM ACCOUNT "
                                                     "INNER JOIN IDENTITY_KEY "
                                                     "ON ACCOUNT.IDENTITY_KEY = IDENTITY_KEY.ID "
                                                     "WHERE ACCOUNT.ADDRESS is (?);";

static const char *ACCOUNT_LOAD_IDENTITY_KEY_ASYM = "SELECT "
                                                    "KEYPAIR.PUBLIC_KEY, "
                                                    "KEYPAIR.PRIVATE_KEY "
                                                    "FROM IDENTITY_KEY "
                                                    "INNER JOIN KEYPAIR "
                                                    "ON IDENTITY_KEY.ASYM_KEYPAIR = KEYPAIR.ID "
                                                    "WHERE IDENTITY_KEY.ID is (?);";

static const char *ACCOUNT_LOAD_IDENTITY_KEY_SIGN = "SELECT "
                                                    "KEYPAIR.PUBLIC_KEY, "
                                                    "KEYPAIR.PRIVATE_KEY "
                                                    "FROM IDENTITY_KEY "
                                                    "INNER JOIN KEYPAIR "
                                                    "ON IDENTITY_KEY.SIGN_KEYPAIR = KEYPAIR.ID "
                                                    "WHERE IDENTITY_KEY.ID is (?);";

static const char *LOAD_SIGNED_PRE_KEY_BY_ADDRESS_ID = "SELECT SIGNED_PRE_KEY.SPK_ID, "
                                                       "KEYPAIR.PUBLIC_KEY, "
                                                       "KEYPAIR.PRIVATE_KEY, "
                                                       "SIGNED_PRE_KEY.SIGNATURE, "
                                                       "SIGNED_PRE_KEY.TTL "
                                                       "FROM ACCOUNT "
                                                       "INNER JOIN SIGNED_PRE_KEY "
                                                       "ON ACCOUNT.SIGNED_PRE_KEY = SIGNED_PRE_KEY.ID "
                                                       "INNER JOIN KEYPAIR "
                                                       "ON SIGNED_PRE_KEY.KEYPAIR = KEYPAIR.ID "
                                                       "WHERE ACCOUNT.ADDRESS is (?);";

static const char *LOAD_N_ONETIME_PRE_KEYS_BY_ADDRESS_ID = "SELECT COUNT(*) "
                                                           "FROM ACCOUNT_ONETIME_PRE_KEY "
                                                           "INNER JOIN ACCOUNT "
                                                           "ON ACCOUNT_ONETIME_PRE_KEY.ADDRESS_ID = ACCOUNT.ADDRESS "
                                                           "WHERE ACCOUNT.ADDRESS is (?);";

static const char *LOAD_ONETIME_PRE_KEYS_BY_ADDRESS_ID = "SELECT ONETIME_PRE_KEY.OPK_ID, "
                                                         "ONETIME_PRE_KEY.USED, "
                                                         "KEYPAIR.PUBLIC_KEY, "
                                                         "KEYPAIR.PRIVATE_KEY "
                                                         "FROM ACCOUNT_ONETIME_PRE_KEY "
                                                         "INNER JOIN ACCOUNT "
                                                         "ON ACCOUNT_ONETIME_PRE_KEY.ADDRESS_ID = ACCOUNT.ADDRESS "
                                                         "INNER JOIN ONETIME_PRE_KEY "
                                                         "ON ACCOUNT_ONETIME_PRE_KEY.ONETIME_PRE_KEY = "
                                                         "ONETIME_PRE_KEY.ID "
                                                         "INNER JOIN KEYPAIR "
                                                         "ON ONETIME_PRE_KEY.KEYPAIR = KEYPAIR.ID "
                                                         "WHERE ACCOUNT.ADDRESS is (?);";

// static const char *ACCOUNT_LOAD_ONETIME_PRE_KEY = "SELECT ONETIME_PRE_KEY.ID "
static const char *LOAD_ONETIME_PRE_KEY_BY_ADDRESS_ID = "SELECT ONETIME_PRE_KEY.ID "
                                                        "FROM ACCOUNT_ONETIME_PRE_KEY "
                                                        "INNER JOIN ACCOUNT "
                                                        "ON ACCOUNT_ONETIME_PRE_KEY.ADDRESS_ID = ACCOUNT.ADDRESS "
                                                        "INNER JOIN ONETIME_PRE_KEY "
                                                        "ON ACCOUNT_ONETIME_PRE_KEY.ONETIME_PRE_KEY = "
                                                        "ONETIME_PRE_KEY.ID "
                                                        "WHERE ACCOUNT.ADDRESS is (?) AND ONETIME_PRE_KEY.OPK_ID is (?);";

static const char *LOAD_NEXT_ONETIME_PRE_KEY_ID_BY_ADDRESS_ID = "SELECT NEXT_ONETIME_PRE_KEY_ID "
                                                                "FROM ACCOUNT "
                                                                "WHERE ADDRESS is (?);";

static const char *LOAD_ADDRESS_ID = "SELECT ADDRESS "
                                     "FROM ACCOUNT "
                                     "INNER JOIN ADDRESS "
                                     "ON ACCOUNT.ADDRESS = ADDRESS.ID "
                                     "WHERE ADDRESS.DOMAIN is (?) AND "
                                     "ADDRESS.USER_ID is (?) AND "
                                     "ADDRESS.DEVICE_ID is (?);";

static const char *ADDRESS_LOAD = "SELECT ROWID "
                                  "FROM ADDRESS "
                                  "WHERE ADDRESS.DOMAIN is (?) AND "
                                  "ADDRESS.USER_ID is (?) AND "
                                  "ADDRESS.DEVICE_ID is (?) AND "
                                  "ADDRESS.GROUP_ID is (?);";

static const char *ADDRESS_INSERT = "INSERT OR IGNORE INTO ADDRESS "
                                    "(DOMAIN, USER_ID, DEVICE_ID, GROUP_ID, GROUP_NAME) "
                                    "VALUES (?, ?, ?, ?, ?);";

static const char *IDENTITY_KEY_INSERT = "INSERT INTO IDENTITY_KEY "
                                         "(ASYM_KEYPAIR, SIGN_KEYPAIR) "
                                         "VALUES (?, ?);";

static const char *SIGNED_PRE_KEY_INSERT = "INSERT INTO SIGNED_PRE_KEY "
                                           "(SPK_ID, KEYPAIR, SIGNATURE, TTL) "
                                           "VALUES (?, ?, ?, ?);";

static const char *SIGNED_PRE_KEY_DELETE = "DELETE FROM SIGNED_PRE_KEY "
                                           "WHERE ID is (?);";

static const char *KEYPAIR_INSERT = "INSERT INTO KEYPAIR "
                                    "(PUBLIC_KEY, PRIVATE_KEY) "
                                    "VALUES (?, ?);";

static const char *ONETIME_PRE_KEY_INSERT = "INSERT INTO ONETIME_PRE_KEY "
                                            "(OPK_ID, USED, KEYPAIR) "
                                            "VALUES (?, ?, ?);";

static const char *ONETIME_PRE_KEY_DELETE = "DELETE FROM ONETIME_PRE_KEY "
                                            "WHERE ID is (?);";

// NOTE: NEW
static const char *ACCOUNT_INSERT = "INSERT INTO ACCOUNT "
                                    "(VERSION, "
                                    "SAVED, "
                                    "AUTH, "
                                    "ADDRESS, "
                                    "PASSWORD, "
                                    "e2ees_pack_id, "
                                    "IDENTITY_KEY, "
                                    "SIGNED_PRE_KEY, "
                                    "NEXT_ONETIME_PRE_KEY_ID) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

static const char *ADDRESS_ID_IDENTITY_KEY_INSERT = "INSERT INTO ACCOUNT_IDENTITY_KEY "
                                                    "(ADDRESS_ID, IDENTITY_KEY) "
                                                    "VALUES (?, ?);";

static const char *ADDRESS_ID_SIGNED_PRE_KEY_INSERT = "INSERT INTO ACCOUNT_SIGNED_PRE_KEY "
                                                      "(ADDRESS_ID, SIGNED_PRE_KEY) "
                                                      "VALUES (?, ?);";

static const char *ADDRESS_ID_SIGNED_PRE_KEY_DELETE = "DELETE FROM ACCOUNT_SIGNED_PRE_KEY "
                                                      "WHERE ADDRESS_ID is (?) AND SIGNED_PRE_KEY is (?);";

static const char *ADDRESS_ID_SIGNED_PRE_KEY_SELECT_MORE_THAN_2 = "SELECT SIGNED_PRE_KEY "
                                                                  "FROM ACCOUNT_SIGNED_PRE_KEY "
                                                                  "WHERE ADDRESS_ID is (?) AND "
                                                                  "(SIGNED_PRE_KEY < ((SELECT MAX(SIGNED_PRE_KEY) FROM ACCOUNT_SIGNED_PRE_KEY) - 1));";

static const char *ADDRESS_ID_ONETIME_PRE_KEY_INSERT = "INSERT INTO ACCOUNT_ONETIME_PRE_KEY "
                                                       "(ADDRESS_ID, ONETIME_PRE_KEY) "
                                                       "VALUES (?, ?);";

static const char *ADDRESS_ID_ONETIME_PRE_KEY_DELETE = "DELETE FROM ACCOUNT_ONETIME_PRE_KEY "
                                                       "WHERE ADDRESS_ID is (?) AND ONETIME_PRE_KEY is (?);";

static const char *ADDRESS_ID_UPDATE_ADDRESS = "UPDATE ACCOUNT "
                                               "SET ADDRESS = (?) "
                                               "WHERE ADDRESS is (?);";

static const char *ADDRESS_ID_UPDATE_SIGNED_PRE_KEY = "UPDATE ACCOUNT "
                                                      "SET SIGNED_PRE_KEY = (?) "
                                                      "WHERE ADDRESS is (?);";

static const char *ADDRESS_ID_UPDATE_NEXT_ONETIME_PRE_KEY_ID = "UPDATE ACCOUNT "
                                                               "SET NEXT_ONETIME_PRE_KEY_ID = (?) "
                                                               "WHERE ADDRESS is (?);";

static const char *LOAD_OLD_SIGNED_PRE_KEY = "SELECT SIGNED_PRE_KEY.SPK_ID, "
                                             "KEYPAIR.PUBLIC_KEY, "
                                             "KEYPAIR.PRIVATE_KEY, "
                                             "SIGNED_PRE_KEY.SIGNATURE, "
                                             "SIGNED_PRE_KEY.TTL "
                                             "FROM ACCOUNT_SIGNED_PRE_KEY "
                                             "INNER JOIN ACCOUNT "
                                             "ON ACCOUNT_SIGNED_PRE_KEY.ADDRESS_ID = ACCOUNT.ADDRESS "
                                             "INNER JOIN SIGNED_PRE_KEY "
                                             "ON ACCOUNT_SIGNED_PRE_KEY.SIGNED_PRE_KEY = SIGNED_PRE_KEY.ID "
                                             "INNER JOIN KEYPAIR "
                                             "ON SIGNED_PRE_KEY.KEYPAIR = KEYPAIR.ID "
                                             "WHERE ACCOUNT.ADDRESS is (?) AND SIGNED_PRE_KEY.SPK_ID is (?);";

static const char *ADDRESS_ID_UPDATE_IDENTITY_KEY = "UPDATE ACCOUNT "
                                                    "SET IDENTITY_KEY = (?) "
                                                    "WHERE ADDRESS is (?);";

static const char *ONETIME_PRE_KEY_UPDATE_USED = "UPDATE ONETIME_PRE_KEY "
                                                 "SET USED = 1 "
                                                 "WHERE ID is (?);";

void mock_db_begin() {
    sqlite3_initialize();

    // connect
    sqlite_connect(db_name);

    // session
    sqlite_execute(SESSION_DROP_TABLE);
    sqlite_execute(SESSION_CREATE_TABLE);

    // group_session
    sqlite_execute(GROUP_SESSION_DROP_TABLE);
    sqlite_execute(GROUP_SESSION_CREATE_TABLE);

    // pending_plaintext_data
    sqlite_execute(PENDING_PLAINTEXT_DATA_DROP_TABLE);
    sqlite_execute(PENDING_PLAINTEXT_DATA_CREATE_TABLE);

    // pending_request_data
    sqlite_execute(PENDING_REQUEST_DATA_DROP_TABLE);
    sqlite_execute(PENDING_REQUEST_DATA_CREATE_TABLE);

    // address
    sqlite_execute(ADDRESS_DROP_TABLE);
    sqlite_execute(ADDRESS_CREATE_TABLE);

    // key pair
    sqlite_execute(KEYPAIR_DROP_TABLE);
    sqlite_execute(KEYPAIR_CREATE_TABLE);

    // identity_key
    sqlite_execute(IDENTITY_KEY_DROP_TABLE);
    sqlite_execute(IDENTITY_KEY_CREATE_TABLE);

    // signed_pre_key
    sqlite_execute(SIGNED_PRE_KEY_DROP_TABLE);
    sqlite_execute(SIGNED_PRE_KEY_CREATE_TABLE);

    // one_time_pre_key
    sqlite_execute(ONETIME_PRE_KEY_DROP_TABLE);
    sqlite_execute(ONETIME_PRE_KEY_CREATE_TABLE);

    // account
    sqlite_execute(ACCOUNT_DROP_TABLE);
    sqlite_execute(ACCOUNT_CREATE_TABLE);

    // account_identity_key_pair
    sqlite_execute(ACCOUNT_IDENTITY_KEY_DROP_TABLE);
    sqlite_execute(ACCOUNT_IDENTITY_KEY_CREATE_TABLE);

    // account_signed_pre_key_pair
    sqlite_execute(ACCOUNT_SIGNED_PRE_KEY_DROP_TABLE);
    sqlite_execute(ACCOUNT_SIGNED_PRE_KEY_CREATE_TABLE);

    // account_one_time_pre_key_pair
    sqlite_execute(ACCOUNT_ONETIME_PRE_KEY_DROP_TABLE);
    sqlite_execute(ACCOUNT_ONETIME_PRE_KEY_CREATE_TABLE);
}

void mock_db_end() {
    sqlite3_close(db);
    sqlite3_shutdown();
}
// NOTE: NEW
size_t load_address_ids(sqlite_int64 **address_ids) {
    // find num of address_ids
    // prepare
    sqlite3_stmt *stmt1;
    sqlite_prepare(ACCOUNTS_NUM, &stmt1);
    // step
    sqlite_step(stmt1, SQLITE_ROW);
    size_t num = (size_t)sqlite3_column_int64(stmt1, 0);
    // release
    sqlite_finalize(stmt1);

    if (num == 0) {
        *address_ids = NULL;
        return num;
    }

    // allocate memory
    *address_ids = (sqlite_int64 *)malloc(sizeof(sqlite_int64) * num);

    // prepare
    sqlite3_stmt *stmt2;
    sqlite_prepare(ACCOUNT_LOAD_ALL_ADDRESS_ID, &stmt2);
    // step
    int i = 0;
    while (sqlite3_step(stmt2) != SQLITE_DONE) {
        sqlite_int64 address_id = sqlite3_column_int64(stmt2, 0);
        (*address_ids)[i++] = address_id;
    }
    // release
    sqlite_finalize(stmt2);

    // done
    return num;
}

char *load_version(uint64_t address_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_VERSION_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    char *version = succ ? strdup((char *)sqlite3_column_text(stmt, 0)) : NULL;

    // release
    sqlite_finalize(stmt);

    return version;
}

protobuf_c_boolean load_saved(uint64_t address_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_SAVED_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    protobuf_c_boolean saved = (protobuf_c_boolean)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return saved;
}

bool load_address(uint64_t address_id, E2ees__E2eeAddress **address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ADDRESS, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    if (succ) {
        // allocate memory
        *address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
        e2ees__e2ee_address__init(*address);

        (*address)->user = (E2ees__PeerUser *)malloc(sizeof(E2ees__PeerUser));
        e2ees__peer_user__init((*address)->user);
        (*address)->peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
        (*address)->domain = strdup((char *)sqlite3_column_text(stmt, 0));
        (*address)->user->user_id = strdup((char *)sqlite3_column_text(stmt, 1));
        (*address)->user->device_id = strdup((char *)sqlite3_column_text(stmt, 2));
    }

    // release
    sqlite_finalize(stmt);

    return succ;
}

bool load_group_address(uint64_t address_id, E2ees__E2eeAddress **address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_GROUP_ADDRESS, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    if (succ) {
        // allocate memory
        *address = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
        e2ees__e2ee_address__init(*address);

        (*address)->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
        e2ees__peer_group__init((*address)->group);
        (*address)->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
        (*address)->domain = strdup((char *)sqlite3_column_text(stmt, 0));
        (*address)->group->group_name = strdup((char *)sqlite3_column_text(stmt, 1));
        (*address)->group->group_id = strdup((char *)sqlite3_column_text(stmt, 2));
    }

    // release
    sqlite_finalize(stmt);

    return succ;
}

void load_password(uint64_t address_id, char **password) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_PASSWORD_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    *password = succ ? strdup((char *)sqlite3_column_text(stmt, 0)) : NULL;

    // release
    sqlite_finalize(stmt);
}

uint32_t load_e2ees_pack_id(uint64_t address_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_e2ees_pack_id_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    uint32_t e2ees_pack_id = (uint32_t)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return e2ees_pack_id;
}

static void load_identity_key_asym(sqlite_int64 identity_key_id, E2ees__KeyPair **asym_key_pair) {
    // allocate memory
    *asym_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(*asym_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_IDENTITY_KEY_ASYM, &stmt);
    sqlite3_bind_int64(stmt, 1, identity_key_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(&((*asym_key_pair)->public_key), (uint8_t *)sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));
    copy_protobuf_from_array(&((*asym_key_pair)->private_key), (uint8_t *)sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));

    // release
    sqlite_finalize(stmt);
}

static void load_identity_key_sign(sqlite_int64 identity_key_id, E2ees__KeyPair **sign_key_pair) {
    // allocate memory
    *sign_key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(*sign_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_LOAD_IDENTITY_KEY_SIGN, &stmt);
    sqlite3_bind_int64(stmt, 1, identity_key_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    copy_protobuf_from_array(&((*sign_key_pair)->public_key), (uint8_t *)sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));
    copy_protobuf_from_array(&((*sign_key_pair)->private_key), (uint8_t *)sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));

    // release
    sqlite_finalize(stmt);
}

void load_identity_key_pair(uint64_t address_id, E2ees__IdentityKey **identity_key) {
    // allocate memory
    *identity_key = (E2ees__IdentityKey *)malloc(sizeof(E2ees__IdentityKey));
    e2ees__identity_key__init(*identity_key);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_IDENTITY_KEY_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);
    sqlite_int64 identity_key_id = sqlite3_column_int(stmt, 0);

    // load
    load_identity_key_asym(identity_key_id, &((*identity_key)->asym_key_pair));
    load_identity_key_sign(identity_key_id, &((*identity_key)->sign_key_pair));

    // release
    sqlite_finalize(stmt);
}

void load_signed_pre_key_pair(uint64_t address_id, E2ees__SignedPreKey **signed_pre_key) {
    // allocate memory
    *signed_pre_key = (E2ees__SignedPreKey *)malloc(sizeof(E2ees__SignedPreKey));
    e2ees__signed_pre_key__init(*signed_pre_key);

    E2ees__KeyPair *key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(key_pair);
    (*signed_pre_key)->key_pair = key_pair;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_SIGNED_PRE_KEY_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    (*signed_pre_key)->spk_id = (uint32_t)sqlite3_column_int(stmt, 0);
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
    copy_protobuf_from_array(&((*signed_pre_key)->signature), (uint8_t *)sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));
    int64_t ttl = (int64_t)sqlite3_column_int64(stmt, 4);
    if (ttl < 0)
        ttl = (0xffffffff + ttl + 1);
    (*signed_pre_key)->ttl = ttl;
    // release
    sqlite_finalize(stmt);
}

int load_n_one_time_pre_keys(uint64_t address_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_N_ONETIME_PRE_KEYS_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_one_time_pre_key_list = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_one_time_pre_key_list;
}

size_t load_one_time_pre_keys(uint64_t address_id, E2ees__OneTimePreKey ***one_time_pre_key_list) {
    // allocate memory
    size_t n_one_time_pre_key_list = load_n_one_time_pre_keys(address_id);
    (*one_time_pre_key_list) = (E2ees__OneTimePreKey **)malloc(n_one_time_pre_key_list * sizeof(E2ees__OneTimePreKey *));

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ONETIME_PRE_KEYS_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    for (int i = 0; i < n_one_time_pre_key_list; i++) {
        sqlite3_step(stmt);

        // allocate
        (*one_time_pre_key_list)[i] = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
        e2ees__one_time_pre_key__init((*one_time_pre_key_list)[i]);

        E2ees__KeyPair *key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
        e2ees__key_pair__init(key_pair);
        (*one_time_pre_key_list)[i]->key_pair = key_pair;

        // load
        (*one_time_pre_key_list)[i]->opk_id = (uint32_t)sqlite3_column_int(stmt, 0);
        (*one_time_pre_key_list)[i]->used = sqlite3_column_int(stmt, 1);
        copy_protobuf_from_array(&((*one_time_pre_key_list)[i]->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
        copy_protobuf_from_array(&((*one_time_pre_key_list)[i]->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));
    }

    // release
    sqlite_finalize(stmt);

    return n_one_time_pre_key_list;
}

uint32_t load_next_one_time_pre_key_id(uint64_t address_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_NEXT_ONETIME_PRE_KEY_ID_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    uint32_t next_one_time_pre_key_id = (uint32_t)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return next_one_time_pre_key_id;
}

bool load_address_id(E2ees__E2eeAddress *address, sqlite_int64 *address_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ADDRESS_ID, &stmt);
    sqlite3_bind_text(stmt, 1, address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    if (succ)
        *address_id = sqlite3_column_int64(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return succ;
}

static sqlite_int64 address_row_id(E2ees__E2eeAddress *address) {
    sqlite_int64 rol_id = 0;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_LOAD, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, address->domain, -1, SQLITE_TRANSIENT);
    if (address->peer_case == E2EES__E2EE_ADDRESS__PEER_USER) {
        sqlite3_bind_text(stmt, 2, address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, address->user->device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_null(stmt, 4);
    } else if (address->peer_case == E2EES__E2EE_ADDRESS__PEER_GROUP) {
        sqlite3_bind_null(stmt, 2);
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_text(stmt, 4, address->group->group_id, -1, SQLITE_TRANSIENT);
    }

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);
    if (succ)
        rol_id = (sqlite_int64)sqlite3_column_int64(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return rol_id;
}

sqlite_int64 insert_address(E2ees__E2eeAddress *address) {
    // address exists
    sqlite_int64 row_id = address_row_id(address);
    if (row_id > 0)
        return row_id;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_INSERT, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, address->domain, -1, SQLITE_TRANSIENT);
    if (address->peer_case == E2EES__E2EE_ADDRESS__PEER_USER) {
        sqlite3_bind_text(stmt, 2, address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, address->user->device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_null(stmt, 4);
    } else if (address->peer_case == E2EES__E2EE_ADDRESS__PEER_GROUP) {
        sqlite3_bind_null(stmt, 2);
        sqlite3_bind_null(stmt, 3);
        sqlite3_bind_text(stmt, 4, address->group->group_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, address->group->group_name, -1, SQLITE_TRANSIENT);
    }

    // step
    bool succ = sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_key_pair(E2ees__KeyPair *key_pair) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(KEYPAIR_INSERT, &stmt);

    // bind
    sqlite3_bind_blob(stmt, 1, key_pair->public_key.data, (int)key_pair->public_key.len, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, key_pair->private_key.data, (int)key_pair->private_key.len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_identity_key(E2ees__IdentityKey *identity_key) {
    sqlite_int64 key_pair_id_1 = insert_key_pair(identity_key->asym_key_pair);
    sqlite_int64 key_pair_id_2 = insert_key_pair(identity_key->sign_key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(IDENTITY_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, key_pair_id_1);
    sqlite3_bind_int64(stmt, 2, key_pair_id_2);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_signed_pre_key(E2ees__SignedPreKey *signed_pre_key) {
    sqlite_int64 key_pair_id = insert_key_pair(signed_pre_key->key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SIGNED_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, signed_pre_key->spk_id);
    sqlite3_bind_int64(stmt, 2, key_pair_id);
    sqlite3_bind_blob(stmt, 3, signed_pre_key->signature.data, (int)signed_pre_key->signature.len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)(signed_pre_key->ttl));

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_one_time_pre_key(E2ees__OneTimePreKey *one_time_pre_key) {
    sqlite_int64 key_pair_id = insert_key_pair(one_time_pre_key->key_pair);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, one_time_pre_key->opk_id);
    sqlite3_bind_int64(stmt, 2, one_time_pre_key->used);
    sqlite3_bind_int64(stmt, 3, key_pair_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

sqlite_int64 insert_account(
    const char *version, protobuf_c_boolean saved, const char *auth, sqlite_int64 address_id,
    const char *password, uint32_t e2ees_pack_id, sqlite_int64 identity_key_pair_id,
    sqlite_int64 signed_pre_key_id, sqlite_int64 next_one_time_pre_key_id
) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ACCOUNT_INSERT, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, version, (int)strlen(version), NULL);
    sqlite3_bind_int64(stmt, 2, (int)saved);
    sqlite3_bind_text(stmt, 3, auth, (int)strlen(auth), NULL);
    sqlite3_bind_int64(stmt, 4, address_id);
    sqlite3_bind_text(stmt, 5, password, (int)strlen(password), NULL);
    sqlite3_bind_int64(stmt, 6, e2ees_pack_id);
    sqlite3_bind_int64(stmt, 7, identity_key_pair_id);
    sqlite3_bind_int64(stmt, 8, signed_pre_key_id);
    sqlite3_bind_int64(stmt, 9, next_one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return sqlite3_last_insert_rowid(db);
}

void insert_account_identity_key_id(uint64_t address_id, sqlite_int64 identity_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_IDENTITY_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, identity_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void insert_account_signed_pre_key_id(uint64_t address_id, sqlite_int64 signed_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_SIGNED_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void insert_account_one_time_pre_key_id(uint64_t address_id, sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_ONETIME_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

bool update_signed_pre_key(E2ees__E2eeAddress *address, E2ees__SignedPreKey *signed_pre_key) {
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);

    if (succ == false)
        return false;

    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(signed_pre_key);

    insert_account_signed_pre_key_id(address_id, signed_pre_key_id);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_UPDATE_SIGNED_PRE_KEY, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, signed_pre_key_id);
    sqlite3_bind_int64(stmt, 2, address_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return true;
}

void load_signed_pre_key(E2ees__E2eeAddress *address, uint32_t spk_id, E2ees__SignedPreKey **signed_pre_key) {
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);

    if (succ == false)
        *signed_pre_key = NULL;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_OLD_SIGNED_PRE_KEY, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, spk_id);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *signed_pre_key = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // allocate memory
    *signed_pre_key = (E2ees__SignedPreKey *)malloc(sizeof(E2ees__SignedPreKey));
    e2ees__signed_pre_key__init(*signed_pre_key);

    E2ees__KeyPair *key_pair = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(key_pair);
    (*signed_pre_key)->key_pair = key_pair;

    // load
    (*signed_pre_key)->spk_id = (uint32_t)sqlite3_column_int(stmt, 0);
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->public_key), (uint8_t *)sqlite3_column_blob(stmt, 1), sqlite3_column_bytes(stmt, 1));
    copy_protobuf_from_array(&((*signed_pre_key)->key_pair->private_key), (uint8_t *)sqlite3_column_blob(stmt, 2), sqlite3_column_bytes(stmt, 2));
    copy_protobuf_from_array(&((*signed_pre_key)->signature), (uint8_t *)sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));
    int64_t ttl = (int64_t)sqlite3_column_int64(stmt, 4);
    if (ttl < 0)
        ttl = (0xffffffff + ttl + 1);
    (*signed_pre_key)->ttl = ttl;

    // release
    sqlite_finalize(stmt);
}

static void delete_signed_pre_key(sqlite_int64 signed_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SIGNED_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int64(stmt, 1, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

static void delete_account_signed_pre_key(uint64_t address_id, sqlite_int64 signed_pre_key_id) {
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_SIGNED_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, signed_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

bool remove_expired_signed_pre_key(E2ees__E2eeAddress *address) {
    // delete old signed pre-keys and keep last two
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);

    if (succ == false)
        return false;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_SIGNED_PRE_KEY_SELECT_MORE_THAN_2, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite_int64 signed_pre_key_id = sqlite3_column_int(stmt, 0);
        delete_signed_pre_key(signed_pre_key_id);
        delete_account_signed_pre_key(address_id, signed_pre_key_id);
    }

    // release
    sqlite_finalize(stmt);

    return true;
}

static bool update_next_one_time_pre_key_id(uint64_t address_id, uint32_t next_opk_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_UPDATE_NEXT_ONETIME_PRE_KEY_ID, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, next_opk_id);
    sqlite3_bind_int64(stmt, 2, address_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return true;
}

bool add_one_time_pre_key(E2ees__E2eeAddress *address, E2ees__OneTimePreKey *one_time_pre_key) {
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);

    if (succ == false)
        return false;

    sqlite_int64 one_time_pre_key_id = insert_one_time_pre_key(one_time_pre_key);

    succ = update_next_one_time_pre_key_id(address_id, one_time_pre_key->opk_id + 1);

    if (succ == false)
        return false;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_ONETIME_PRE_KEY_INSERT, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);

    return true;
}

static void delete_one_time_pre_key(sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int64(stmt, 1, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

static void delete_account_one_time_pre_key(uint64_t address_id, sqlite_int64 one_time_pre_key_id) {
    sqlite3_stmt *stmt;
    sqlite_prepare(ADDRESS_ID_ONETIME_PRE_KEY_DELETE, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

bool remove_one_time_pre_key(E2ees__E2eeAddress *address, uint32_t one_time_pre_key_id) {
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);

    if (succ == false)
        return false;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ONETIME_PRE_KEY_BY_ADDRESS_ID, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, one_time_pre_key_id);

    // step
    if ((sqlite3_step(stmt) != SQLITE_DONE)) {
        sqlite_int64 id = sqlite3_column_int(stmt, 0);
        delete_one_time_pre_key(id);
        delete_account_one_time_pre_key(address_id, id);
    }

    // release
    sqlite_finalize(stmt);

    return true;
}

static void mark_one_time_pre_key_as_used(sqlite_int64 one_time_pre_key_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(ONETIME_PRE_KEY_UPDATE_USED, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, one_time_pre_key_id);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

bool update_one_time_pre_key(E2ees__E2eeAddress *address, uint32_t one_time_pre_key_id) {
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);

    if (succ == false)
        return false;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_ONETIME_PRE_KEY_BY_ADDRESS_ID, &stmt);

    // bind
    sqlite3_bind_int64(stmt, 1, address_id);
    sqlite3_bind_int64(stmt, 2, one_time_pre_key_id);

    // step
    if ((sqlite3_step(stmt) != SQLITE_DONE)) {
        sqlite_int64 id = sqlite3_column_int(stmt, 0);
        mark_one_time_pre_key_as_used(id);
    }

    // release
    sqlite_finalize(stmt);

    return true;
}

void store_account(E2ees__Account *account) {
    // insert address
    sqlite_int64 address_id = insert_address(account->address);

    // insert identity_key
    sqlite_int64 identity_key_pair_id = insert_identity_key(account->identity_key);

    // insert signed_pre_key
    sqlite_int64 signed_pre_key_id = insert_signed_pre_key(account->signed_pre_key);

    // insert one_time_pre_key_list
    sqlite_int64 one_time_pre_key_ids[account->n_one_time_pre_key_list];
    for (int i = 0; i < account->n_one_time_pre_key_list; i++) {
        one_time_pre_key_ids[i] = insert_one_time_pre_key(account->one_time_pre_key_list[i]);
    }

    // insert account
    insert_account(
        account->version, account->saved, account->auth, address_id,
        account->password, account->e2ees_pack_id,
        identity_key_pair_id, signed_pre_key_id, account->next_one_time_pre_key_id
    );

    // insert ACCOUNT_SIGNED_PRE_KEY_PAIR
    insert_account_signed_pre_key_id(address_id, signed_pre_key_id);

    // insert ACCOUNT_ONE_TIME_PRE_KEY_PAIR
    for (int i = 0; i < account->n_one_time_pre_key_list; i++) {
        insert_account_one_time_pre_key_id(address_id, one_time_pre_key_ids[i]);
    }
}
// NOTE: new
void load_account_by_address_id(uint64_t address_id, E2ees__Account **account) {
    E2ees__E2eeAddress *address = NULL;
    bool succ = load_address(address_id, &address);
    if (succ) {
        *account = (E2ees__Account *)malloc(sizeof(E2ees__Account));
        e2ees__account__init((*account));

        (*account)->version = load_version(address_id);
        (*account)->saved = load_saved(address_id);
        (*account)->e2ees_pack_id = load_e2ees_pack_id(address_id);
        (*account)->address = address;
        load_password(address_id, &((*account)->password));

        load_signed_pre_key_pair(address_id, &((*account)->signed_pre_key));
        load_identity_key_pair(address_id, &((*account)->identity_key));
        (*account)->n_one_time_pre_key_list = load_one_time_pre_keys(address_id, &((*account)->one_time_pre_key_list));
        (*account)->next_one_time_pre_key_id = load_next_one_time_pre_key_id(address_id);
    } else {
        *account = NULL;
    }
}

// DONE: load auth , in Account.proto
void load_auth(E2ees__E2eeAddress *address, char **auth) {
    sqlite_int64 address_id;
    if (load_address_id(address, &address_id) == false) {
        *auth = NULL;
        return;
    }

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(LOAD_AUTH_BY_ADDRESS_ID, &stmt);
    sqlite3_bind_int64(stmt, 1, address_id);

    // step
    bool succ = sqlite_step(stmt, SQLITE_ROW);

    // load
    *auth = succ ? strdup((char *)sqlite3_column_text(stmt, 0)) : NULL;

    // release
    sqlite_finalize(stmt);
}

void load_account_by_address(E2ees__E2eeAddress *address, E2ees__Account **account) {
    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);
    if (succ) {
        *account = (E2ees__Account *)malloc(sizeof(E2ees__Account));
        e2ees__account__init((*account));

        (*account)->version = load_version(address_id);
        (*account)->saved = load_saved(address_id);
        (*account)->e2ees_pack_id = load_e2ees_pack_id(address_id);
        copy_address_from_address(&((*account)->address), address);
        load_auth((*account)->address, &((*account)->auth));
        load_password(address_id, &((*account)->password));

        load_signed_pre_key_pair(address_id, &((*account)->signed_pre_key));
        load_identity_key_pair(address_id, &((*account)->identity_key));
        (*account)->n_one_time_pre_key_list = load_one_time_pre_keys(address_id, &((*account)->one_time_pre_key_list));
        (*account)->next_one_time_pre_key_id = load_next_one_time_pre_key_id(address_id);
    } else {
        *account = NULL;
    }
}
// NOTE:NEW
size_t load_accounts(E2ees__Account ***accounts) {
    // load all address_ids
    sqlite_int64 *address_ids;
    size_t num = load_address_ids(&address_ids);

    // load all account by address_ids
    if (num == 0) {
        *accounts = NULL;
    } else {
        *accounts = (E2ees__Account **)malloc(sizeof(E2ees__Account *) * num);
        for (int i = 0; i < num; i++) {
            load_account_by_address_id(address_ids[i], &(*accounts)[i]);
        }

        // release address_ids array
        free(address_ids);
    }

    // done
    return num;
}

// session related handlers
void load_session(
    char *session_id, E2ees__E2eeAddress *our_address, E2ees__Session **session
) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(SESSION_LOAD_DATA_BY_ADDRESS_AND_ID, &stmt)) {
        *session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, our_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, our_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, our_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (session_data_len == 0) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *session = e2ees__session__unpack(NULL, session_data_len, session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

// return the lastest updated session
void load_outbound_session(
    E2ees__E2eeAddress *our_address, E2ees__E2eeAddress *their_address, E2ees__Session **session
) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(SESSION_LOAD_DATA_BY_ADDRESSES, &stmt)) {
        *session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, our_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, their_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, our_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, their_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (session_data_len == 0) {
        *session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *session = e2ees__session__unpack(NULL, session_data_len, session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

int load_n_outbound_sessions(
    E2ees__E2eeAddress *our_address, const char *their_user_id
) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_LOAD_N_OUTBOUND_SESSION, &stmt);
    sqlite3_bind_text(stmt, 1, our_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, our_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, our_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, their_user_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_outbound_sessions = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_outbound_sessions;
}

size_t load_outbound_sessions(
    E2ees__E2eeAddress *our_address,
    const char *their_user_id, const char *their_domain,
    E2ees__Session ***outbound_sessions
) {
    // allocate memory
    size_t n_outbound_sessions = load_n_outbound_sessions(our_address, their_user_id);

    if (n_outbound_sessions > 0) {
        (*outbound_sessions) = (E2ees__Session **)malloc(sizeof(E2ees__Session *) * n_outbound_sessions);

        // prepare
        sqlite3_stmt *stmt;
        sqlite_prepare(SESSION_LOAD_OUTBOUND_SESSIONS, &stmt);
        sqlite3_bind_text(stmt, 1, our_address->domain, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, our_address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, our_address->user->device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, their_user_id, -1, SQLITE_TRANSIENT);

        // step
        for (int i = 0; i < n_outbound_sessions; i++) {
            sqlite3_step(stmt);

            // load
            size_t session_data_len = sqlite3_column_bytes(stmt, 0);
            uint8_t *session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

            // unpack
            (*outbound_sessions)[i] = e2ees__session__unpack(NULL, session_data_len, session_data);
        }

        // release
        sqlite_finalize(stmt);
    }

    return n_outbound_sessions;
}

void store_session(E2ees__Session *session) {
    // pack
    char *session_id = session->session_id;
    size_t session_data_len = e2ees__session__get_packed_size(session);
    uint8_t *session_data = (uint8_t *)malloc(session_data_len);
    e2ees__session__pack(session, session_data);

    sqlite_int64 our_id = insert_address(session->our_address);
    sqlite_int64 their_id = insert_address(session->their_address);
    sqlite_int64 invite_t = session->invite_t;

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_INSERT_OR_REPLACE, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, our_id);
    sqlite3_bind_int64(stmt, 3, their_id);
    sqlite3_bind_int64(stmt, 4, invite_t);
    sqlite3_bind_blob(stmt, 5, session_data, (int)session_data_len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
    free_mem((void **)&session_data, session_data_len);
}

void unload_session(E2ees__E2eeAddress *our_address, E2ees__E2eeAddress *their_address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_DELETE_DATA_BY_ADDRESSES, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, our_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, our_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, their_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, their_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void unload_old_session(E2ees__E2eeAddress *our_address, E2ees__E2eeAddress *their_address, int64_t invite_t) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(SESSION_DELETE_OLD_DATA, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, our_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, our_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, their_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, their_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, invite_t - (int64_t)86400000);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

// group session
void load_group_session_by_address(
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *owner_address,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupSession **group_session
) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(GROUP_SESSION_LOAD_DATA_BY_ADDRESS, &stmt)) {
        *group_session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, sender_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sender_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sender_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, owner_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, owner_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, owner_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, group_address->group->group_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (group_session_data_len == 0) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *group_session = e2ees__group_session__unpack(NULL, group_session_data_len, group_session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

void load_group_session_by_id(
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *owner_address,
    char *session_id,
    E2ees__GroupSession **group_session
) {
    // prepare
    sqlite3_stmt *stmt;
    if (!sqlite_prepare(GROUP_SESSION_LOAD_DATA_BY_ID, &stmt)) {
        *group_session = NULL;
        return;
    }

    // bind
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sender_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sender_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, sender_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, owner_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, owner_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, owner_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    if (!sqlite_step(stmt, SQLITE_ROW)) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // load
    size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
    uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

    // no data
    if (group_session_data_len == 0) {
        *group_session = NULL;
        sqlite_finalize(stmt);
        return;
    }

    // unpack
    *group_session = e2ees__group_session__unpack(NULL, group_session_data_len, group_session_data);

    // release
    sqlite_finalize(stmt);

    return;
}

int load_n_group_sessions(
    E2ees__E2eeAddress *owner_address,
    E2ees__E2eeAddress *group_address
) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(N_GROUP_SESSION_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, group_address->group->group_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, owner_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, owner_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_group_sessions = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_group_sessions;
}

size_t load_group_sessions(
    E2ees__E2eeAddress *owner_address,
    E2ees__E2eeAddress *group_address,
    E2ees__GroupSession ***group_sessions
) {
    size_t n_group_sessions = load_n_group_sessions(owner_address, group_address);

    if (n_group_sessions > 0) {
        (*group_sessions) = (E2ees__GroupSession **)malloc(sizeof(E2ees__GroupSession *) * n_group_sessions);

        // prepare
        sqlite3_stmt *stmt;
        sqlite_prepare(GROUP_SESSIONS_LOAD, &stmt);
        sqlite3_bind_text(stmt, 1, group_address->group->group_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, owner_address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, owner_address->domain, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, owner_address->user->device_id, -1, SQLITE_TRANSIENT);

        // step
        for (int i = 0; i < n_group_sessions; i++) {
            sqlite3_step(stmt);

            // load
            size_t group_session_data_len = sqlite3_column_bytes(stmt, 0);
            uint8_t *group_session_data = (uint8_t *)sqlite3_column_blob(stmt, 0);

            // unpack
            (*group_sessions)[i] = e2ees__group_session__unpack(NULL, group_session_data_len, group_session_data);
        }

        // release
        sqlite_finalize(stmt);
    }

    return n_group_sessions;
}

int load_n_group_addresses(
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *owner_address
) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(N_GROUP_ADDRESS_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, sender_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sender_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sender_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, owner_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, owner_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, owner_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_group_addresses = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_group_addresses;
}

size_t load_group_addresses(
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *owner_address,
    E2ees__E2eeAddress ***group_addresses
) {
    size_t n_group_addresses = load_n_group_addresses(sender_address, owner_address);

    if (n_group_addresses > 0) {
        (*group_addresses) = (E2ees__E2eeAddress **)malloc(sizeof(E2ees__E2eeAddress *) * n_group_addresses);

        // prepare
        sqlite3_stmt *stmt;
        sqlite_prepare(GROUP_ADDRESSES_LOAD, &stmt);
        sqlite3_bind_text(stmt, 1, sender_address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, sender_address->domain, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, sender_address->user->device_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, owner_address->user->user_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, owner_address->domain, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, owner_address->user->device_id, -1, SQLITE_TRANSIENT);

        // step
        for (int i = 0; i < n_group_addresses; i++) {
            sqlite3_step(stmt);

            // load
            sqlite_int64 address_id = sqlite3_column_int64(stmt, 0);

            load_group_address(address_id, &((*group_addresses)[i]));
        }

        // release
        sqlite_finalize(stmt);
    }

    return n_group_addresses;
}

void store_group_session(E2ees__GroupSession *group_session) {
    // pack
    size_t group_session_data_len = e2ees__group_session__get_packed_size(group_session);
    uint8_t *group_session_data = (uint8_t *)malloc(group_session_data_len);
    e2ees__group_session__pack(group_session, group_session_data);

    sqlite_int64 sender_id = insert_address(group_session->sender);
    sqlite_int64 owner_id = insert_address(group_session->session_owner);
    sqlite_int64 address_id = insert_address(group_session->group_info->group_address);

    char *session_id = group_session->session_id;

    // unload the group session with no session id in it if necessary
    if (session_id[0] != '\0') {
        unload_group_session_with_no_session_id(
            group_session->sender, group_session->session_owner, group_session->group_info->group_address
        );
    }

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_INSERT_OR_REPLACE, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, sender_id);
    sqlite3_bind_int64(stmt, 3, owner_id);
    sqlite3_bind_int64(stmt, 4, address_id);
    sqlite3_bind_blob(stmt, 5, group_session_data, (int)group_session_data_len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
    free_mem((void **)&group_session_data, group_session_data_len);
}

void unload_group_session_by_address(
    E2ees__E2eeAddress *session_owner,
    E2ees__E2eeAddress *group_address
) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_BY_ADDRESS, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, session_owner->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session_owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session_owner->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, group_address->group->group_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void unload_group_session_by_id(
    E2ees__E2eeAddress *session_owner,
    char *session_id
) {
    if (session_id == NULL) {
        return;
    }
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_BY_ID, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, session_owner->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session_owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session_owner->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, session_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void unload_group_session_with_no_session_id(
    E2ees__E2eeAddress *sender,
    E2ees__E2eeAddress *session_owner,
    E2ees__E2eeAddress *group_address
) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(GROUP_SESSION_DELETE_DATA_WITH_NO_ID, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, sender->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sender->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sender->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, session_owner->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, session_owner->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, session_owner->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, group_address->group->group_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, "", -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void store_pending_plaintext_data(
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    char *pending_plaintext_id,
    uint8_t *group_pre_key_plaintext,
    size_t group_pre_key_plaintext_len,
    E2ees__NotifLevel notif_level
) {
    // insert the sender's and the receiver's address
    sqlite_int64 from_address_id = insert_address(from_address);
    sqlite_int64 to_address_id = insert_address(to_address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_PLAINTEXT_DATA_INSERT, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, pending_plaintext_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, from_address_id);
    sqlite3_bind_int64(stmt, 3, to_address_id);
    sqlite3_bind_blob(stmt, 4, group_pre_key_plaintext, (int)group_pre_key_plaintext_len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, notif_level);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

int load_n_group_pre_keys(E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(N_PENDING_PLAINTEXT_DATA_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, from_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, from_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, from_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, to_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, to_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, to_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_group_pre_keys = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_group_pre_keys;
}

size_t load_pending_plaintext_data(
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    char ***pending_plaintext_id_list,
    uint8_t ***e2ee_plaintext_data_list,
    size_t **e2ee_plaintext_data_len_list,
    E2ees__NotifLevel **notif_level_list
) {
    // allocate memory
    size_t n_group_pre_keys = load_n_group_pre_keys(from_address, to_address);
    if (n_group_pre_keys == 0) {
        *pending_plaintext_id_list = NULL;
        *e2ee_plaintext_data_list = NULL;
        *e2ee_plaintext_data_len_list = NULL;
        return 0;
    }
    (*pending_plaintext_id_list) = (char **)malloc(sizeof(char *) * n_group_pre_keys);

    (*e2ee_plaintext_data_list) = (uint8_t **)malloc(sizeof(uint8_t *) * n_group_pre_keys);

    *e2ee_plaintext_data_len_list = (size_t *)malloc(sizeof(size_t) * n_group_pre_keys);

    *notif_level_list = (E2ees__NotifLevel *)malloc(sizeof(E2ees__NotifLevel) * n_group_pre_keys);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_PLAINTEXT_DATA_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, from_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, from_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, from_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, to_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, to_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, to_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    for (int i = 0; i < n_group_pre_keys; i++) {
        sqlite3_step(stmt);

        // load
        (*pending_plaintext_id_list)[i] = strdup((char *)sqlite3_column_text(stmt, 0));
        size_t e2ee_plaintext_data_len = sqlite3_column_bytes(stmt, 1);
        uint8_t *e2ee_plaintext_data = (uint8_t *)sqlite3_column_blob(stmt, 1);
        (*notif_level_list)[i] = sqlite3_column_int(stmt, 2);

        // assign
        (*e2ee_plaintext_data_list)[i] = (uint8_t *)malloc(e2ee_plaintext_data_len * sizeof(uint8_t));
        memcpy((*e2ee_plaintext_data_list)[i], e2ee_plaintext_data, e2ee_plaintext_data_len);
        (*e2ee_plaintext_data_len_list)[i] = e2ee_plaintext_data_len;
    }

    // release
    sqlite_finalize(stmt);

    return n_group_pre_keys;
}

void unload_pending_plaintext_data(E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address, char *pending_plaintext_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_PLAINTEXT_DATA_DELETE, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, from_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, from_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, from_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, to_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, to_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, to_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, pending_plaintext_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

void store_pending_request_data(E2ees__E2eeAddress *user_address, char *pending_request_id, uint8_t request_type, uint8_t *request_data, size_t request_data_len) {
    // insert user's address
    sqlite_int64 user_address_id = insert_address(user_address);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_REQUEST_DATA_INSERT, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, pending_request_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, user_address_id);
    sqlite3_bind_int64(stmt, 3, request_type);
    sqlite3_bind_blob(stmt, 4, request_data, (int)request_data_len, SQLITE_STATIC);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}

int load_n_pending_request_data(E2ees__E2eeAddress *user_address) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(N_PENDING_REQUEST_DATA_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, user_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_ROW);

    // load
    int n_pending_request_data = (int)sqlite3_column_int(stmt, 0);

    // release
    sqlite_finalize(stmt);

    return n_pending_request_data;
}

size_t load_pending_request_data(E2ees__E2eeAddress *user_address, char ***request_id_list, uint8_t **request_type_list, uint8_t ***request_data_list, size_t **request_data_len_list) {
    // allocate memory
    size_t n_pending_request_data = load_n_pending_request_data(user_address);
    if (n_pending_request_data == 0) {
        *request_data_list = NULL;
        *request_data_len_list = NULL;
        return 0;
    }
    *request_id_list = (char **)malloc(sizeof(char *) * n_pending_request_data);

    *request_type_list = (uint8_t *)malloc(sizeof(uint8_t) * n_pending_request_data);

    (*request_data_list) = (uint8_t **)malloc(sizeof(uint8_t *) * n_pending_request_data);

    *request_data_len_list = (size_t *)malloc(sizeof(size_t) * n_pending_request_data);

    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_REQUEST_DATA_LOAD, &stmt);
    sqlite3_bind_text(stmt, 1, user_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user_address->user->device_id, -1, SQLITE_TRANSIENT);

    // step
    for (int i = 0; i < n_pending_request_data; i++) {
        sqlite3_step(stmt);

        // load
        (*request_id_list)[i] = strdup((char *)sqlite3_column_text(stmt, 0));
        (*request_type_list)[i] = sqlite3_column_int(stmt, 1);

        size_t e2ee_plaintext_data_len = sqlite3_column_bytes(stmt, 2);
        uint8_t *e2ee_plaintext_data = (uint8_t *)sqlite3_column_blob(stmt, 2);

        // assign
        (*request_data_list)[i] = (uint8_t *)malloc(e2ee_plaintext_data_len * sizeof(uint8_t));
        memcpy((*request_data_list)[i], e2ee_plaintext_data, e2ee_plaintext_data_len);
        (*request_data_len_list)[i] = e2ee_plaintext_data_len;
    }

    // release
    sqlite_finalize(stmt);

    return n_pending_request_data;
}

void unload_pending_request_data(E2ees__E2eeAddress *user_address, char *pending_request_id) {
    // prepare
    sqlite3_stmt *stmt;
    sqlite_prepare(PENDING_REQUEST_DATA_DELETE, &stmt);

    // bind
    sqlite3_bind_text(stmt, 1, user_address->domain, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_address->user->user_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user_address->user->device_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, pending_request_id, -1, SQLITE_TRANSIENT);

    // step
    sqlite_step(stmt, SQLITE_DONE);

    // release
    sqlite_finalize(stmt);
}
