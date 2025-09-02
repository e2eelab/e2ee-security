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
#include "e2ees/log_code.h"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#else
#include <execinfo.h>
#endif

#include <stdlib.h>
#include <string.h>

const char* logcode_string(LogCode log_code) {
    switch (log_code) {
        case DEBUG_LOG: return "DEBUG";
        case BAD_CIPHER_SUITE: return "BAD_CIPHER_SUITE";
        case BAD_E2EES_PACK: return "BAD_E2EES_PACK";
            // account
        case BAD_ACCOUNT: return "BAD_ACCOUNT";
        case BAD_KEY_PAIR: return "BAD_KEY_PAIR";
        case BAD_SIGNED_PRE_KEY: return "BAD_SIGNED_PRE_KEY";
        case BAD_SIGNATURE: return "BAD_SIGNATURE";
        case BAD_ONE_TIME_PRE_KEY: return "BAD_ONE_TIME_PRE_KEY";
        case BAD_AUTH: return "BAD_AUTH";
        case BAD_AUTHENTICATOR: return "BAD_AUTHENTICATOR";
        case BAD_PRIVATE_KEY: return "BAD_PRIVATE_KEY";
        case BAD_PUBLIC_KEY: return "BAD_PUBLIC_KEY";
        case BAD_REMOVE_OPK: return "BAD_REMOVE_OPK";
            // address
        case BAD_ADDRESS: return "BAD_ADDRESS";
        case BAD_USER_ID: return "BAD_USER_ID";
        case BAD_DEVICE_ID: return "BAD_DEVICE_ID";
        case BAD_DOMAIN: return "BAD_DOMAIN";
        case BAD_USER_NAME: return "BAD_USER_NAME";
            // ratchet
        case BAD_MESSAGE_ENCRYPTION: return "BAD_MESSAGE_ENCRYPTION";
        case BAD_MESSAGE_DECRYPTION: return "BAD_MESSAGE_DECRYPTION";
        case BAD_FILE_ENCRYPTION: return "BAD_FILE_ENCRYPTION";
        case BAD_FILE_DECRYPTION: return "BAD_FILE_DECRYPTION";
        case BAD_MESSAGE_KEY: return "BAD_MESSAGE_KEY";
        case BAD_MESSAGE_SEQUENCE: return "BAD_MESSAGE_SEQUENCE";
        case BAD_RATCHET_KEY: return "BAD_RATCHET_KEY";
            // session
        case BAD_SESSION: return "BAD_SESSION";
        case BAD_SESSION_ID: return "BAD_SESSION_ID";
        case BAD_PRE_KEY_BUNDLE: return "BAD_PRE_KEY_BUNDLE";
            // group session
        case BAD_GROUP_SESSION: return "BAD_GROUP_SESSION";
        case BAD_GROUP_SESSION_ID: return "BAD_GROUP_SESSION_ID";
        case BAD_GROUP_NAME: return "BAD_GROUP_NAME";
        case BAD_GROUP_ADDRESS: return "BAD_GROUP_ADDRESS";
        case BAD_GROUP_MEMBERS: return "BAD_GROUP_MEMBERS";
        case BAD_GROUP_MEMBER_INFO: return "BAD_GROUP_MEMBER_INFO";
        case BAD_GROUP_INFO: return "BAD_GROUP_INFO";
        case BAD_GROUP_SEED: return "BAD_GROUP_SEED";
        case BAD_GROUP_CHAIN_KEY: return "BAD_GROUP_CHAIN_KEY";
        case BAD_GROUP_PRE_KEY_BUNDLE: return "BAD_GROUP_PRE_KEY_BUNDLE";
        case BAD_GROUP_UPDATE_KEY_BUNDLE: return "BAD_GROUP_UPDATE_KEY_BUNDLE";
            // request
        case BAD_ACCEPT_REQUEST: return "BAD_ACCEPT_REQUEST";
        case BAD_ADD_GROUP_MEMBER_DEVICE_REQUEST: return "BAD_ADD_GROUP_MEMBER_DEVICE_REQUEST";
        case BAD_ADD_GROUP_MEMBERS_REQUEST: return "BAD_ADD_GROUP_MEMBERS_REQUEST";
        case BAD_CONSUME_PROTO_MSG_REQUEST: return "BAD_CONSUME_PROTO_MSG_REQUEST";
        case BAD_CREATE_GROUP_REQUEST: return "BAD_CREATE_GROUP_REQUEST";
        case BAD_GET_GROUP_REQUEST: return "BAD_GET_GROUP_REQUEST";
        case BAD_GET_PRE_KEY_BUNDLE_REQUEST: return "BAD_GET_PRE_KEY_BUNDLE_REQUEST";
        case BAD_INVITE_REQUEST: return "BAD_INVITE_REQUEST";
        case BAD_LEAVE_GROUP_REQUEST: return "BAD_LEAVE_GROUP_REQUEST";
        case BAD_PUBLISH_SPK_REQUEST: return "BAD_PUBLISH_SPK_REQUEST";
        case BAD_REGISTER_USER_REQUEST: return "BAD_REGISTER_USER_REQUEST";
        case BAD_REMOVE_GROUP_MEMBERS_REQUEST: return "BAD_REMOVE_GROUP_MEMBERS_REQUEST";
        case BAD_SEND_GROUP_MSG_REQUEST: return "BAD_SEND_GROUP_MSG_REQUEST";
        case BAD_SEND_ONE2ONE_MSG_REQUEST: return "BAD_SEND_ONE2ONE_MSG_REQUEST";
        case BAD_SUPPLY_OPKS_REQUEST: return "BAD_SUPPLY_OPKS_REQUEST";
        case BAD_UPDATE_USER_REQUEST: return "BAD_UPDATE_USER_REQUEST";
            // response
        case BAD_ACCEPT_RESPONSE: return "BAD_ACCEPT_RESPONSE";
        case BAD_ADD_GROUP_MEMBER_DEVICE_RESPONSE: return "BAD_ADD_GROUP_MEMBER_DEVICE_RESPONSE";
        case BAD_ADD_GROUP_MEMBERS_RESPONSE: return "BAD_ADD_GROUP_MEMBERS_RESPONSE";
        case BAD_CONSUME_PROTO_MSG_RESPONSE: return "BAD_CONSUME_PROTO_MSG_RESPONSE";
        case BAD_CREATE_GROUP_RESPONSE: return "BAD_CREATE_GROUP_RESPONSE";
        case BAD_GET_GROUP_RESPONSE: return "BAD_GET_GROUP_RESPONSE";
        case BAD_GET_PRE_KEY_BUNDLE_RESPONSE: return "BAD_GET_PRE_KEY_BUNDLE_RESPONSE";
        case BAD_INVITE_RESPONSE: return "BAD_INVITE_RESPONSE";
        case BAD_LEAVE_GROUP_RESPONSE: return "BAD_LEAVE_GROUP_RESPONSE";
        case BAD_PUBLISH_SPK_RESPONSE: return "BAD_PUBLISH_SPK_RESPONSE";
        case BAD_REGISTER_USER_RESPONSE: return "BAD_REGISTER_USER_RESPONSE";
        case BAD_REMOVE_GROUP_MEMBERS_RESPONSE: return "BAD_REMOVE_GROUP_MEMBERS_RESPONSE";
        case BAD_SEND_GROUP_MSG_RESPONSE: return "BAD_SEND_GROUP_MSG_RESPONSE";
        case BAD_SEND_ONE2ONE_MSG_RESPONSE: return "BAD_SEND_ONE2ONE_MSG_RESPONSE";
        case BAD_SUPPLY_OPKS_RESPONSE: return "DEBBAD_SUPPLY_OPKS_RESPONSEUG";
        case BAD_UPDATE_USER_RESPONSE: return "BAD_UPDATE_USER_RESPONSE";
            // msg
        case BAD_ACCEPT_MSG: return "BAD_ACCEPT_MSG";
        case BAD_ADD_GROUP_MEMBER_DEVICE_MSG: return "BAD_ADD_GROUP_MEMBER_DEVICE_MSG";
        case BAD_ADD_GROUP_MEMBERS_MSG: return "BAD_ADD_GROUP_MEMBERS_MSG";
        case BAD_ADD_USER_DEVICE_MSG: return "BAD_ADD_USER_DEVICE_MSG";
        case BAD_CREATE_GROUP_MSG: return "BAD_CREATE_GROUP_MSG";
        case BAD_GET_GROUP_MSG: return "BAD_GET_GROUP_MSG";
        case BAD_GET_PRE_KEY_BUNDLE_MSG: return "BAD_GET_PRE_KEY_BUNDLE_MSG";
        case BAD_INVITE_MSG: return "BAD_INVITE_MSG";
        case BAD_LEAVE_GROUP_MSG: return "BAD_LEAVE_GROUP_MSG";
        case BAD_PUBLISH_SPK_MSG: return "BAD_PUBLISH_SPK_MSG";
        case BAD_REGISTER_USER_MSG: return "BAD_REGISTER_USER_MSG";
        case BAD_REMOVE_GROUP_MEMBERS_MSG: return "BAD_REMOVE_GROUP_MEMBERS_MSG";
        case BAD_SUPPLY_OPKS_MSG: return "BAD_SUPPLY_OPKS_MSG";
        case BAD_UPDATE_USER_MSG: return "BAD_UPDATE_USER_MSG";
            // plaintext
        case BAD_PLAINTEXT: return "BAD_PLAINTEXT";
            // server signature
        case BAD_SERVER_SIGNATURE: return "BAD_SERVER_SIGNATURE";
        default: return "UNKNOWN";
    }
}

void get_stack_trace(char* buffer, size_t buffer_len) {
#ifdef __EMSCRIPTEN__
    char* stack = emscripten_run_script_string("stackTrace()");
    if (stack == NULL) {
        snprintf(buffer, buffer_len, "Failed to get stack trace\n");
    }
    else {
        snprintf(buffer, buffer_len, "%s", stack);
        free(stack);
    }
    buffer[buffer_len - 1] = '\0';
#else
    void* stack[64];
    int stack_size = backtrace(stack, 64);
    char** symbols = backtrace_symbols(stack, stack_size);

    if (symbols == NULL) {
        strncpy(buffer, "Failed to get stack trace", buffer_len);
        buffer[buffer_len - 1] = '\0';
        return;
    }

    size_t offset = 0;
    for (int i = 0; i < stack_size; i++) {
        size_t remaining = buffer_len - offset;
        if (remaining <= 1) break;
        int written = snprintf(buffer + offset, remaining, "%s\n", symbols[i]);
        if (written < 0 || (size_t)written >= remaining) break;
        offset += written;
    }
    buffer[buffer_len - 1] = '\0';

    // release
    free(symbols);
#endif
}