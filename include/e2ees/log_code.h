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
#ifndef LOG_CODE_H_
#define LOG_CODE_H_

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

enum LogCode {
  DEBUG_LOG = 0,

  // cipher suite
  BAD_CIPHER_SUITE = 1001,
  BAD_E2EES_PACK = 1002,

  // account
  BAD_ACCOUNT = 2001,
  BAD_KEY_PAIR = 2002,
  BAD_SIGNED_PRE_KEY = 2003,
  BAD_SIGNATURE = 2004,
  BAD_ONE_TIME_PRE_KEY = 2005,
  BAD_AUTH = 2006,
  BAD_AUTHENTICATOR = 2007,
  BAD_PRIVATE_KEY = 2008,
  BAD_PUBLIC_KEY = 2009,
  BAD_REMOVE_OPK = 2010,

  // address
  BAD_ADDRESS = 3001,
  BAD_USER_ID = 3002,
  BAD_DEVICE_ID = 3003,
  BAD_DOMAIN = 3004,
  BAD_USER_NAME = 3005,

  // ratchet
  BAD_MESSAGE_ENCRYPTION = 4001,
  BAD_MESSAGE_DECRYPTION = 4002,
  BAD_FILE_ENCRYPTION = 4003,
  BAD_FILE_DECRYPTION = 4004,
  BAD_MESSAGE_KEY = 4005,
  BAD_MESSAGE_SEQUENCE = 4006,
  BAD_RATCHET_KEY = 4007,

  // session
  BAD_SESSION = 5001,
  BAD_SESSION_ID = 5002,
  BAD_PRE_KEY_BUNDLE = 5101,

  // group session
  BAD_GROUP_SESSION = 6001,
  BAD_GROUP_SESSION_ID = 6002,
  BAD_GROUP_NAME = 6003,
  BAD_GROUP_ADDRESS = 6004,
  BAD_GROUP_MEMBERS = 6005,
  BAD_GROUP_MEMBER_INFO = 6006,
  BAD_GROUP_INFO = 6007,
  BAD_GROUP_SEED = 6008,
  BAD_GROUP_CHAIN_KEY = 6009,
  BAD_GROUP_PRE_KEY_BUNDLE = 6101,
  BAD_GROUP_UPDATE_KEY_BUNDLE = 6102,

  // request
  BAD_ACCEPT_REQUEST = 7001,
  BAD_ADD_GROUP_MEMBER_DEVICE_REQUEST = 7011,
  BAD_ADD_GROUP_MEMBERS_REQUEST = 7021,
  BAD_CONSUME_PROTO_MSG_REQUEST = 7031,
  BAD_CREATE_GROUP_REQUEST = 7041,
  BAD_GET_GROUP_REQUEST = 7051,
  BAD_GET_PRE_KEY_BUNDLE_REQUEST = 7061,
  BAD_INVITE_REQUEST = 7071,
  BAD_LEAVE_GROUP_REQUEST = 7081,
  BAD_PUBLISH_SPK_REQUEST = 7091,
  BAD_REGISTER_USER_REQUEST = 7101,
  BAD_REMOVE_GROUP_MEMBERS_REQUEST = 7111,
  BAD_SEND_GROUP_MSG_REQUEST = 7121,
  BAD_SEND_ONE2ONE_MSG_REQUEST = 7131,
  BAD_SUPPLY_OPKS_REQUEST = 7141,
  BAD_UPDATE_USER_REQUEST = 7151,
  // response
  BAD_ACCEPT_RESPONSE = 7301,
  BAD_ADD_GROUP_MEMBER_DEVICE_RESPONSE = 7311,
  BAD_ADD_GROUP_MEMBERS_RESPONSE = 7321,
  BAD_CONSUME_PROTO_MSG_RESPONSE = 7331,
  BAD_CREATE_GROUP_RESPONSE = 7341,
  BAD_GET_GROUP_RESPONSE = 7351,
  BAD_GET_PRE_KEY_BUNDLE_RESPONSE = 7361,
  BAD_INVITE_RESPONSE = 7371,
  BAD_LEAVE_GROUP_RESPONSE = 7381,
  BAD_PUBLISH_SPK_RESPONSE = 7391,
  BAD_REGISTER_USER_RESPONSE = 7401,
  BAD_REMOVE_GROUP_MEMBERS_RESPONSE = 7411,
  BAD_SEND_GROUP_MSG_RESPONSE = 7421,
  BAD_SEND_ONE2ONE_MSG_RESPONSE = 7431,
  BAD_SUPPLY_OPKS_RESPONSE = 7441,
  BAD_UPDATE_USER_RESPONSE = 7451,
  // msg
  BAD_ACCEPT_MSG = 7601,
  BAD_ADD_GROUP_MEMBER_DEVICE_MSG = 7611,
  BAD_ADD_GROUP_MEMBERS_MSG = 7621,
  BAD_ADD_USER_DEVICE_MSG = 7631,
  BAD_CREATE_GROUP_MSG = 7641,
  BAD_GET_GROUP_MSG = 7651,
  BAD_GET_PRE_KEY_BUNDLE_MSG = 7661,
  BAD_INVITE_MSG = 7671,
  BAD_LEAVE_GROUP_MSG = 7681,
  BAD_PUBLISH_SPK_MSG = 7691,
  BAD_REGISTER_USER_MSG = 7701,
  BAD_REMOVE_GROUP_MEMBERS_MSG = 7711,
  BAD_SUPPLY_OPKS_MSG = 7741,
  BAD_UPDATE_USER_MSG = 7751,

  // plaintext
  BAD_PLAINTEXT = 8001,

  // server signature
  BAD_SERVER_SIGNATURE = 9001
};

typedef enum LogCode LogCode;

typedef struct stack_frame {
    const char *function_name;
    const char *file_name;
    int line_number;
    struct stack_frame *prev;
} stack_frame_t;

// Global stack top
extern __thread stack_frame_t *current_stack_top;

#ifdef ENABLE_TRACE
#define TRACE_ENTER() \
        do { \
            stack_frame_t new_frame = {__func__, __FILE__, __LINE__, current_stack_top}; \
            current_stack_top = &new_frame; \
        } while(0)

#define TRACE_EXIT() \
        do { \
            if (current_stack_top != NULL) { \
                current_stack_top = current_stack_top->prev; \
            } \
        } while(0)
#else
#define TRACE_ENTER() do { } while(0)
#define TRACE_EXIT() do { } while(0)
#endif

/**
 * @brief Get the string representation of a given log code.
 *
 * @param log_code The log code
 * @return The log code string
 */
const char *logcode_string(LogCode log_code);

/**
 * @brief Capture and format stack trace
 * @param buffer the buffer to keep stack trace msg
 * @param buffer_len the length of buffer
 */
void get_stack_trace(char *buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif /* LOG_CODE_H_ */
