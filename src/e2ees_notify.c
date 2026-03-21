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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/mem_util.h"
#include "e2ees/log_code.h"
#include "e2ees/async_queue.h"

void e2ees_notify_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *msg_fmt, ...) {
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin == NULL) {
        return;
    }

    char msg[4096] = {0};
    va_list arg;
    va_start(arg, msg_fmt);
    vsnprintf(msg, sizeof(msg), msg_fmt, arg);
    va_end(arg);

    const char *logcode_str = logcode_string(log_code);
    if (log_code == DEBUG_LOG || log_code == VERBOSE_LOG) {
        char log_msg[4096 + 64] = {0};
        snprintf(log_msg, sizeof(log_msg), "<%s> %s", logcode_str, msg);
        plugin->event_handler.on_log(user_address, log_code, log_msg);
    } else {
        char stack_trace[512] = {0};
        get_stack_trace(stack_trace, sizeof(stack_trace));

        char log_msg[4096 + 512] = {0};
        snprintf(log_msg, sizeof(log_msg), "<%s> %s\nStack trace:\n%s", logcode_str, msg, stack_trace);
        plugin->event_handler.on_log(user_address, log_code, log_msg);
    }
}

typedef struct {
    E2ees__Account *account;
} notify_user_registered_ctx_t;

static void async_notify_user_registered(void *context) {
    notify_user_registered_ctx_t *ctx = (notify_user_registered_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_user_registered) {
        plugin->event_handler.on_user_registered(ctx->account);
    }
    if (ctx->account) e2ees__account__free_unpacked(ctx->account, NULL);
    free(ctx);
}

void e2ees_notify_user_registered(E2ees__Account *account) {
    notify_user_registered_ctx_t *ctx = (notify_user_registered_ctx_t *)malloc(sizeof(notify_user_registered_ctx_t));
    copy_account_from_account(&ctx->account, account);
    dispatch_async(async_notify_user_registered, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__E2eeAddress *from;
} notify_inbound_session_invited_ctx_t;

static void async_notify_inbound_session_invited(void *context) {
    notify_inbound_session_invited_ctx_t *ctx = (notify_inbound_session_invited_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_inbound_session_invited) {
        plugin->event_handler.on_inbound_session_invited(ctx->user_address, ctx->from);
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->from) e2ees__e2ee_address__free_unpacked(ctx->from, NULL);
    free(ctx);
}

void e2ees_notify_inbound_session_invited(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from) {
    notify_inbound_session_invited_ctx_t *ctx = (notify_inbound_session_invited_ctx_t *)malloc(sizeof(notify_inbound_session_invited_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->from, from);
    dispatch_async(async_notify_inbound_session_invited, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__Session *inbound_session;
} notify_inbound_session_ready_ctx_t;

static void async_notify_inbound_session_ready(void *context) {
    notify_inbound_session_ready_ctx_t *ctx = (notify_inbound_session_ready_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_inbound_session_ready) {
        plugin->event_handler.on_inbound_session_ready(ctx->user_address, ctx->inbound_session);
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->inbound_session) e2ees__session__free_unpacked(ctx->inbound_session, NULL);
    free(ctx);
}

void e2ees_notify_inbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *inbound_session) {
    notify_inbound_session_ready_ctx_t *ctx = (notify_inbound_session_ready_ctx_t *)malloc(sizeof(notify_inbound_session_ready_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_session_from_session(&ctx->inbound_session, inbound_session);
    dispatch_async(async_notify_inbound_session_ready, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__Session *outbound_session;
} notify_outbound_session_ready_ctx_t;

static void async_notify_outbound_session_ready(void *context) {
    notify_outbound_session_ready_ctx_t *ctx = (notify_outbound_session_ready_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_outbound_session_ready) {
        plugin->event_handler.on_outbound_session_ready(ctx->user_address, ctx->outbound_session);
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->outbound_session) e2ees__session__free_unpacked(ctx->outbound_session, NULL);
    free(ctx);
}

void e2ees_notify_outbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *outbound_session) {
    notify_outbound_session_ready_ctx_t *ctx = (notify_outbound_session_ready_ctx_t *)malloc(sizeof(notify_outbound_session_ready_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_session_from_session(&ctx->outbound_session, outbound_session);
    dispatch_async(async_notify_outbound_session_ready, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__E2eeAddress *from_address;
    E2ees__E2eeAddress *target_address;
    uint8_t *plaintext;
    size_t plaintext_len;
} msg_dispatch_ctx_t;

static void async_notify_one2one_msg(void *context) {
    msg_dispatch_ctx_t *ctx = (msg_dispatch_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_one2one_msg_received) {
        plugin->event_handler.on_one2one_msg_received(
            ctx->user_address, ctx->from_address, ctx->target_address,
            ctx->plaintext, ctx->plaintext_len
        );
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->from_address) e2ees__e2ee_address__free_unpacked(ctx->from_address, NULL);
    if (ctx->target_address) e2ees__e2ee_address__free_unpacked(ctx->target_address, NULL);
    if (ctx->plaintext) free(ctx->plaintext);
    free(ctx);
}

static void async_notify_other_device_msg(void *context) {
    msg_dispatch_ctx_t *ctx = (msg_dispatch_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_other_device_msg_received) {
        plugin->event_handler.on_other_device_msg_received(
            ctx->user_address, ctx->from_address, ctx->target_address,
            ctx->plaintext, ctx->plaintext_len
        );
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->from_address) e2ees__e2ee_address__free_unpacked(ctx->from_address, NULL);
    if (ctx->target_address) e2ees__e2ee_address__free_unpacked(ctx->target_address, NULL);
    if (ctx->plaintext) free(ctx->plaintext);
    free(ctx);
}

static void async_notify_group_msg(void *context) {
    msg_dispatch_ctx_t *ctx = (msg_dispatch_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_group_msg_received) {
        plugin->event_handler.on_group_msg_received(
            ctx->user_address, ctx->from_address, ctx->target_address,
            ctx->plaintext, ctx->plaintext_len
        );
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->from_address) e2ees__e2ee_address__free_unpacked(ctx->from_address, NULL);
    if (ctx->target_address) e2ees__e2ee_address__free_unpacked(ctx->target_address, NULL);
    if (ctx->plaintext) free(ctx->plaintext);
    free(ctx);
}

void e2ees_notify_one2one_msg(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    msg_dispatch_ctx_t *ctx = (msg_dispatch_ctx_t *)malloc(sizeof(msg_dispatch_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->from_address, from_address);
    copy_address_from_address(&ctx->target_address, to_address);
    ctx->plaintext_len = plaintext_len;
    ctx->plaintext = (uint8_t *)malloc(plaintext_len);
    memcpy(ctx->plaintext, plaintext, plaintext_len);

    dispatch_async(async_notify_one2one_msg, ctx);
}

void e2ees_notify_other_device_msg(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    msg_dispatch_ctx_t *ctx = (msg_dispatch_ctx_t *)malloc(sizeof(msg_dispatch_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->from_address, from_address);
    copy_address_from_address(&ctx->target_address, to_address);
    ctx->plaintext_len = plaintext_len;
    ctx->plaintext = (uint8_t *)malloc(plaintext_len);
    memcpy(ctx->plaintext, plaintext, plaintext_len);

    dispatch_async(async_notify_other_device_msg, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__E2eeAddress *group_address;
    char *group_name;
    E2ees__GroupMember **group_members;
    size_t group_members_num;
} notify_group_created_ctx_t;

static void async_notify_group_created(void *context) {
    notify_group_created_ctx_t *ctx = (notify_group_created_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_group_created) {
        plugin->event_handler.on_group_created(
            ctx->user_address, ctx->group_address, ctx->group_name,
            ctx->group_members, ctx->group_members_num
        );
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->group_address) e2ees__e2ee_address__free_unpacked(ctx->group_address, NULL);
    if (ctx->group_name) free(ctx->group_name);
    if (ctx->group_members) free_group_member_list(&ctx->group_members, ctx->group_members_num);
    free(ctx);
}

void e2ees_notify_group_created(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num
) {
    notify_group_created_ctx_t *ctx = (notify_group_created_ctx_t *)malloc(sizeof(notify_group_created_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->group_address, group_address);
    ctx->group_name = strdup(group_name);
    ctx->group_members_num = group_members_num;
    copy_group_members(&ctx->group_members, group_members, group_members_num);
    dispatch_async(async_notify_group_created, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__E2eeAddress *group_address;
    char *group_name;
    E2ees__GroupMember **group_members;
    size_t group_members_num;
    E2ees__GroupMember **added_group_members;
    size_t added_group_members_num;
} notify_group_members_added_ctx_t;

static void async_notify_group_members_added(void *context) {
    notify_group_members_added_ctx_t *ctx = (notify_group_members_added_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_group_members_added) {
        plugin->event_handler.on_group_members_added(
            ctx->user_address, ctx->group_address, ctx->group_name,
            ctx->group_members, ctx->group_members_num,
            ctx->added_group_members, ctx->added_group_members_num
        );
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->group_address) e2ees__e2ee_address__free_unpacked(ctx->group_address, NULL);
    if (ctx->group_name) free(ctx->group_name);
    if (ctx->group_members) free_group_member_list(&ctx->group_members, ctx->group_members_num);
    if (ctx->added_group_members) free_group_member_list(&ctx->added_group_members, ctx->added_group_members_num);
    free(ctx);
}

void e2ees_notify_group_members_added(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **added_group_members, size_t added_group_members_num
) {
    notify_group_members_added_ctx_t *ctx = (notify_group_members_added_ctx_t *)malloc(sizeof(notify_group_members_added_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->group_address, group_address);
    ctx->group_name = strdup(group_name);
    ctx->group_members_num = group_members_num;
    copy_group_members(&ctx->group_members, group_members, group_members_num);
    ctx->added_group_members_num = added_group_members_num;
    copy_group_members(&ctx->added_group_members, added_group_members, added_group_members_num);
    dispatch_async(async_notify_group_members_added, ctx);
}

typedef struct {
    E2ees__E2eeAddress *user_address;
    E2ees__E2eeAddress *group_address;
    char *group_name;
    E2ees__GroupMember **group_members;
    size_t group_members_num;
    E2ees__GroupMember **removed_group_members;
    size_t removed_group_members_num;
} notify_group_members_removed_ctx_t;

static void async_notify_group_members_removed(void *context) {
    notify_group_members_removed_ctx_t *ctx = (notify_group_members_removed_ctx_t *)context;
    e2ees_plugin_t *plugin = get_e2ees_plugin();
    if (plugin != NULL && plugin->event_handler.on_group_members_removed) {
        plugin->event_handler.on_group_members_removed(
            ctx->user_address, ctx->group_address, ctx->group_name,
            ctx->group_members, ctx->group_members_num,
            ctx->removed_group_members, ctx->removed_group_members_num
        );
    }
    if (ctx->user_address) e2ees__e2ee_address__free_unpacked(ctx->user_address, NULL);
    if (ctx->group_address) e2ees__e2ee_address__free_unpacked(ctx->group_address, NULL);
    if (ctx->group_name) free(ctx->group_name);
    if (ctx->group_members) free_group_member_list(&ctx->group_members, ctx->group_members_num);
    if (ctx->removed_group_members) free_group_member_list(&ctx->removed_group_members, ctx->removed_group_members_num);
    free(ctx);
}

void e2ees_notify_group_members_removed(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **removed_group_members, size_t removed_group_members_num
) {
    notify_group_members_removed_ctx_t *ctx = (notify_group_members_removed_ctx_t *)malloc(sizeof(notify_group_members_removed_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->group_address, group_address);
    ctx->group_name = strdup(group_name);
    ctx->group_members_num = group_members_num;
    copy_group_members(&ctx->group_members, group_members, group_members_num);
    ctx->removed_group_members_num = removed_group_members_num;
    copy_group_members(&ctx->removed_group_members, removed_group_members, removed_group_members_num);
    dispatch_async(async_notify_group_members_removed, ctx);
}

void e2ees_notify_group_msg(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *group_address,
    uint8_t *plaintext, size_t plaintext_len
) {
    msg_dispatch_ctx_t *ctx = (msg_dispatch_ctx_t *)malloc(sizeof(msg_dispatch_ctx_t));
    copy_address_from_address(&ctx->user_address, user_address);
    copy_address_from_address(&ctx->from_address, from_address);
    copy_address_from_address(&ctx->target_address, group_address);
    ctx->plaintext_len = plaintext_len;
    ctx->plaintext = (uint8_t *)malloc(plaintext_len);
    memcpy(ctx->plaintext, plaintext, plaintext_len);

    dispatch_async(async_notify_group_msg, ctx);
}