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
#include "e2ees/e2ees.h"
#include "e2ees/log_code.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

__thread stack_frame_t *current_stack_top = NULL;

const char* logcode_string(LogCode log_code) {
    switch (log_code) {
        case DEBUG_LOG: return "DEBUG";
        case VERBOSE_LOG: return "VERBOSE_LOG";
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
        case BAD_RATCHET: return "BAD_RATCHET";
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
        case BAD_E2EE_MSG: return "BAD_E2EE_MSG";
        case BAD_GET_GROUP_MSG: return "BAD_GET_GROUP_MSG";
        case BAD_GET_PRE_KEY_BUNDLE_MSG: return "BAD_GET_PRE_KEY_BUNDLE_MSG";
        case BAD_INVITE_MSG: return "BAD_INVITE_MSG";
        case BAD_LEAVE_GROUP_MSG: return "BAD_LEAVE_GROUP_MSG";
        case BAD_PROTO_MSG: return "BAD_PROTO_MSG";
        case BAD_PUBLISH_SPK_MSG: return "BAD_PUBLISH_SPK_MSG";
        case BAD_REGISTER_USER_MSG: return "BAD_REGISTER_USER_MSG";
        case BAD_REMOVE_GROUP_MEMBERS_MSG: return "BAD_REMOVE_GROUP_MEMBERS_MSG";
        case BAD_SUPPLY_OPKS_MSG: return "BAD_SUPPLY_OPKS_MSG";
        case BAD_UPDATE_USER_MSG: return "BAD_UPDATE_USER_MSG";
            // consume
        case BAD_CONSUME: return "BAD_CONSUME";
            // plaintext
        case BAD_PLAINTEXT: return "BAD_PLAINTEXT";
            // server signature
        case BAD_SERVER_SIGNATURE: return "BAD_SERVER_SIGNATURE";
        default: return "UNKNOWN";
    }
}

const char* account_action_to_string(AccountAction action) {
    switch (action) {
        case ACCOUNT_ACTION_REGISTER:    return "Register User";
        case ACCOUNT_ACTION_PUBLISH_SPK: return "Publish Spk";
        case ACCOUNT_ACTION_SUPPLY_OPKS: return "Supply Opks";
        default:                         return "UnknownAction";
    }
}

const char* session_action_to_string(SessionAction action) {
    switch (action) {
        case SESSION_ACTION_GET_BUNDLE: return "Get Pre-key Bundle";
        case SESSION_ACTION_INVITE:     return "Invite";
        case SESSION_ACTION_ACCEPT:     return "Accept";
        case SESSION_ACTION_SEND_MSG:   return "Send One2one Msg";
        default:                        return "UnknownAction";
    }
}

void get_stack_trace(char* buffer, size_t buffer_len) {
#ifdef ENABLE_TRACE
    stack_frame_t *frame = current_stack_top;

    if (frame == NULL) {
        strncpy(buffer, "no stack trace", buffer_len);
        buffer[buffer_len - 1] = '\0';
        return;
    }

    size_t offset = 0;
    while (frame != NULL) {
        size_t remaining = buffer_len - offset;
        if (remaining <= 1) break;
        int written = snprintf(buffer + offset, remaining, "  at %s (%s:%d)\n", frame->function_name, frame->file_name, frame->line_number);
        if (written < 0 || (size_t)written >= remaining) break;
        offset += written;

        frame = frame->prev;
    }
    buffer[buffer_len - 1] = '\0';

    while (frame != NULL) {
        printf("  at %s (%s:%d)\n", frame->function_name, frame->file_name, frame->line_number);
        frame = frame->prev;
    }
#else
    // stack tracing is disabled
#endif
}

// helper function: Handle indentation and safe writing
static void dump_printf(dump_context_t *ctx, const char *fmt, ...) {
    if (ctx->offset >= ctx->size - 64) return; // warning: Insufficient space / Out of memory safeguard
    
    // handle indentation first
    for (int i = 0; i < ctx->indent && ctx->offset < ctx->size; i++) {
        ctx->buf[ctx->offset++] = ' ';
        ctx->buf[ctx->offset++] = ' ';
    }

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(ctx->buf + ctx->offset, ctx->size - ctx->offset, fmt, args);
    va_end(args);

    if (written > 0) ctx->offset += written;
}

// core recursive function
static void dump_message_recursive(const ProtobufCMessage *msg, dump_context_t *ctx) {
    if (!msg) {
        dump_printf(ctx, "NULL\n");
        return;
    }

    const ProtobufCMessageDescriptor *desc = msg->descriptor;
    dump_printf(ctx, "--- %s ---\n", desc->name);
    ctx->indent++;

    for (unsigned i = 0; i < desc->n_fields; i++) {
        const ProtobufCFieldDescriptor *f = &desc->fields[i];

        // handle oneof (union)
        if (f->quantifier_offset != 0 && f->label != PROTOBUF_C_LABEL_REPEATED) {
            // get the value of the case variable
            const uint32_t *case_value = (const uint32_t *)((const char *)msg + f->quantifier_offset);
            
            // f->id represents the tag number defined in the .proto file
            // if the current case_value does not match this field's ID, it means this field is not the active member of the union
            if (*case_value != f->id) {
                continue; // skip
            }
        }

        const void *member = ((const char *)msg) + f->offset;
        const void *qmember = ((const char *)msg) + f->quantifier_offset;

        // handle empty/null optional fields
        if (f->label == PROTOBUF_C_LABEL_OPTIONAL && f->quantifier_offset != 0) {
            if (!*(const protobuf_c_boolean *)qmember) continue;
        }

        // handle repeated (array) fields
        if (f->label == PROTOBUF_C_LABEL_REPEATED) {
            size_t n = *(const size_t *)qmember;
            dump_printf(ctx, "%s: [Array, count=%zu]\n", f->name, n);
            
            ctx->indent++;
            const void *array = *(const void * const *)member;
            for (size_t j = 0; j < n; j++) {
                dump_printf(ctx, "[%zu]: ", j);
                
                // process array elements based on type
                if (f->type == PROTOBUF_C_TYPE_MESSAGE) {
                    const ProtobufCMessage *sub = ((const ProtobufCMessage * const *)array)[j];
                    // disable indentation before recursion to maintain formatting
                    int old_indent = ctx->indent; ctx->indent = 0;
                    dump_message_recursive(sub, ctx);
                    ctx->indent = old_indent;
                } else if (f->type == PROTOBUF_C_TYPE_STRING) {
                    dump_printf(ctx, "\"%s\"\n", ((const char * const *)array)[j]);
                } else {
                    dump_printf(ctx, "<other type in array>\n");
                }
            }
            ctx->indent--;
            continue;
        }

        // handle single (non-array) fields
        dump_printf(ctx, "%s: ", f->name);
        switch (f->type) {
            case PROTOBUF_C_TYPE_STRING:
                dump_printf(ctx, "\"%s\"\n", *(const char * const *)member);
                break;
            case PROTOBUF_C_TYPE_INT32:
            case PROTOBUF_C_TYPE_UINT32:
                dump_printf(ctx, "%u\n", *(const uint32_t *)member);
                break;
            case PROTOBUF_C_TYPE_BYTES: {
                const ProtobufCBinaryData *bd = (const ProtobufCBinaryData *)member;
                dump_printf(ctx, "<bytes len=%zu, hex_head=%02X%02X...>\n", 
                            bd->len, bd->len > 0 ? bd->data[0] : 0, bd->len > 1 ? bd->data[1] : 0);
                break;
            }
            case PROTOBUF_C_TYPE_MESSAGE: {
                const ProtobufCMessage *sub = *(const ProtobufCMessage * const *)member;
                int old_indent = ctx->indent; ctx->indent = 0;
                dump_message_recursive(sub, ctx);
                ctx->indent = old_indent;
                break;
            }
            case PROTOBUF_C_TYPE_ENUM: {
                int val = *(const int *)member;
                const ProtobufCEnumDescriptor *ed = (const ProtobufCEnumDescriptor *)f->descriptor;
                const char *ename = "UNK";
                for (unsigned k = 0; k < ed->n_values; k++) 
                    if (ed->values[k].value == val) ename = ed->values[k].name;
                dump_printf(ctx, "%s(%d)\n", ename, val);
                break;
            }
            default: dump_printf(ctx, "<type %d>\n", f->type); break;
        }
    }
    ctx->indent--;
}

void log_proto(E2ees__E2eeAddress *addr, const ProtobufCMessage *msg) {
    if (!msg){ 
        return;
    }

    const char *title = msg->descriptor->name;

    // allocate 8KB buffer for VERBOSE logging
    char *big_buffer = malloc(8192);
    if (!big_buffer) return;
    
    dump_context_t ctx = { .buf = big_buffer, .size = 8192, .offset = 0, .indent = 0 };
    
    // cast to ProtobufCMessage
    dump_message_recursive(msg, &ctx);
    
    // invoke e2ees_notify_log
    e2ees_notify_log(addr, VERBOSE_LOG, "%s\n%s", title, big_buffer);
    
    free(big_buffer);
}

