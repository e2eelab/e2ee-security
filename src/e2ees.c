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

#include "e2ees/account.h"
#include "e2ees/log_code.h"
#include "e2ees/mem_util.h"

extern struct ds_suite_t E2EES_DS_CURVE25519;
extern struct ds_suite_t E2EES_DS_MLDSA44;
extern struct ds_suite_t E2EES_DS_MLDSA65;
extern struct ds_suite_t E2EES_DS_MLDSA87;
extern struct ds_suite_t E2EES_DS_FALCON512;
extern struct ds_suite_t E2EES_DS_FALCON1024;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHA2_128F;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHA2_128S;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHA2_192F;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHA2_192S;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHA2_256F;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHA2_256S;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_128F;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_128S;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_192F;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_192S;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_256F;
extern struct ds_suite_t E2EES_DS_SPHINCS_SHAKE_256S;

extern struct kem_suite_t E2EES_KEM_CURVE25519_ECDH;
extern struct kem_suite_t E2EES_KEM_HQC128;
extern struct kem_suite_t E2EES_KEM_HQC192;
extern struct kem_suite_t E2EES_KEM_HQC256;
extern struct kem_suite_t E2EES_KEM_MLKEM512;
extern struct kem_suite_t E2EES_KEM_MLKEM768;
extern struct kem_suite_t E2EES_KEM_MLKEM1024;
extern struct kem_suite_t E2EES_KEM_MCELIECE348864;
extern struct kem_suite_t E2EES_KEM_MCELIECE348864F;
extern struct kem_suite_t E2EES_KEM_MCELIECE460896;
extern struct kem_suite_t E2EES_KEM_MCELIECE460896F;
extern struct kem_suite_t E2EES_KEM_MCELIECE6688128;
extern struct kem_suite_t E2EES_KEM_MCELIECE6688128F;
extern struct kem_suite_t E2EES_KEM_MCELIECE6960119;
extern struct kem_suite_t E2EES_KEM_MCELIECE6960119F;
extern struct kem_suite_t E2EES_KEM_MCELIECE8192128;
extern struct kem_suite_t E2EES_KEM_MCELIECE8192128F;

extern struct se_suite_t E2EES_SE_AES256_SHA256;

extern struct hf_suite_t E2EES_HF_SHA256;

cipher_suite_t E2EES_CIPHER_SUITE = { NULL, NULL, NULL };

e2ees_pack_t E2EES_PACK           = { NULL, NULL };

extern struct session_suite_t E2EES_SESSION_ECC;
extern struct session_suite_t E2EES_SESSION_PQC;

static e2ees_plugin_t *e2ees_plugin;

void e2ees_begin(e2ees_plugin_t *plugin) {
    e2ees_plugin = plugin;
    account_begin();
}

void e2ees_end() {
    e2ees_plugin = NULL;
    account_end();
}

e2ees_plugin_t *get_e2ees_plugin() { return e2ees_plugin; }

ds_suite_t *get_ds_suite(unsigned digital_signature_id) {
    if (digital_signature_id == E2EES_PACK_ALG_DS_CURVE25519) {
        return &E2EES_DS_CURVE25519;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_MLDSA44) {
        return &E2EES_DS_MLDSA44;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_MLDSA65) {
        return &E2EES_DS_MLDSA65;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_MLDSA87) {
        return &E2EES_DS_MLDSA87;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_FALCON512) {
        return &E2EES_DS_FALCON512;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_FALCON1024) {
        return &E2EES_DS_FALCON1024;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHA2_128F) {
        return &E2EES_DS_SPHINCS_SHA2_128F;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHA2_128S) {
        return &E2EES_DS_SPHINCS_SHA2_128S;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHA2_192F) {
        return &E2EES_DS_SPHINCS_SHA2_192F;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHA2_192S) {
        return &E2EES_DS_SPHINCS_SHA2_192S;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHA2_256F) {
        return &E2EES_DS_SPHINCS_SHA2_256F;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHA2_256S) {
        return &E2EES_DS_SPHINCS_SHA2_256S;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHAKE_128F) {
        return &E2EES_DS_SPHINCS_SHAKE_128F;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHAKE_128S) {
        return &E2EES_DS_SPHINCS_SHAKE_128S;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHAKE_192F) {
        return &E2EES_DS_SPHINCS_SHAKE_192F;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHAKE_192S) {
        return &E2EES_DS_SPHINCS_SHAKE_192S;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256F) {
        return &E2EES_DS_SPHINCS_SHAKE_256F;
    } else if (digital_signature_id == E2EES_PACK_ALG_DS_SPHINCS_SHAKE_256S) {
        return &E2EES_DS_SPHINCS_SHAKE_256S;
    } else {
        return NULL;
    }
}

kem_suite_t *get_kem_suite(unsigned kem_id) {
    if (kem_id == E2EES_PACK_ALG_KEM_CURVE25519) {
        return &E2EES_KEM_CURVE25519_ECDH;
    } else if (kem_id == E2EES_PACK_ALG_KEM_HQC128) {
        return &E2EES_KEM_HQC128;
    } else if (kem_id == E2EES_PACK_ALG_KEM_HQC192) {
        return &E2EES_KEM_HQC192;
    } else if (kem_id == E2EES_PACK_ALG_KEM_HQC256) {
        return &E2EES_KEM_HQC256;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MLKEM512) {
        return &E2EES_KEM_MLKEM512;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MLKEM768) {
        return &E2EES_KEM_MLKEM768;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MLKEM1024) {
        return &E2EES_KEM_MLKEM1024;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE348864) {
        return &E2EES_KEM_MCELIECE348864;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE348864F) {
        return &E2EES_KEM_MCELIECE348864F;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE460896) {
        return &E2EES_KEM_MCELIECE460896;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE460896F) {
        return &E2EES_KEM_MCELIECE460896F;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE6688128) {
        return &E2EES_KEM_MCELIECE6688128;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE6688128F) {
        return &E2EES_KEM_MCELIECE6688128F;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE6960119) {
        return &E2EES_KEM_MCELIECE6960119;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE6960119F) {
        return &E2EES_KEM_MCELIECE6960119F;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE8192128) {
        return &E2EES_KEM_MCELIECE8192128;
    } else if (kem_id == E2EES_PACK_ALG_KEM_MCELIECE8192128F) {
        return &E2EES_KEM_MCELIECE8192128F;
    } else {
        return NULL;
    }
}

se_suite_t *get_se_suite(unsigned symmetric_encryption_id) {
    if (symmetric_encryption_id == E2EES_PACK_ALG_SE_AES256GCM) {
        return &E2EES_SE_AES256_SHA256;
    } else {
        return NULL;
    }
}

hf_suite_t *get_hf_suite(unsigned hf_id) {
    if (hf_id == E2EES_PACK_ALG_HASH_SHA2_256) {
        return &E2EES_HF_SHA256;
    } else {
        return NULL;
    }
}

cipher_suite_t *get_cipher_suite(e2ees_pack_id_t e2ees_pack_id) {
    E2EES_CIPHER_SUITE.ds_suite  = get_ds_suite(e2ees_pack_id.ds);
    E2EES_CIPHER_SUITE.kem_suite = get_kem_suite(e2ees_pack_id.kem);
    E2EES_CIPHER_SUITE.se_suite  = get_se_suite(e2ees_pack_id.se);
    E2EES_CIPHER_SUITE.hf_suite  = get_hf_suite(e2ees_pack_id.hash);

    return &E2EES_CIPHER_SUITE;
}

uint32_t e2ees_pack_id_to_raw(e2ees_pack_id_t e2ees_pack_id) {
    return (0xff000000 & (e2ees_pack_id.ver << (E2EES_CIPHER_SUITE_PART_LEN_IN_BITS * 3))) |
           (0x00ff0000 & (e2ees_pack_id.ds << (E2EES_CIPHER_SUITE_PART_LEN_IN_BITS * 2))) |
           (0x0000ff00 & (e2ees_pack_id.kem << E2EES_CIPHER_SUITE_PART_LEN_IN_BITS)) |
           (0x000000f0 & (e2ees_pack_id.se << E2EES_CIPHER_SUITE_PART_HALF_LEN_IN_BITS)) |
           (0x0000000f & (e2ees_pack_id.hash));
}

e2ees_pack_id_t raw_to_e2ees_pack_id(uint32_t e2ees_pack_id_raw) {
    e2ees_pack_id_t e2ees_pack_id;
    e2ees_pack_id.ver =
        (0xff000000 & e2ees_pack_id_raw) >> (E2EES_CIPHER_SUITE_PART_LEN_IN_BITS * 3);
    e2ees_pack_id.ds =
        (0x00ff0000 & e2ees_pack_id_raw) >> (E2EES_CIPHER_SUITE_PART_LEN_IN_BITS * 2);
    e2ees_pack_id.kem = (0x0000ff00 & e2ees_pack_id_raw) >> (E2EES_CIPHER_SUITE_PART_LEN_IN_BITS);
    e2ees_pack_id.se =
        (0x000000f0 & e2ees_pack_id_raw) >> (E2EES_CIPHER_SUITE_PART_HALF_LEN_IN_BITS);
    e2ees_pack_id.hash = 0x0000000f & e2ees_pack_id_raw;

    return e2ees_pack_id;
}

uint32_t
gen_e2ees_pack_id_raw(unsigned ver, unsigned ds, unsigned kem, unsigned se, unsigned hash) {
    e2ees_pack_id_t e2ees_pack_id;
    e2ees_pack_id.ver  = ver;
    e2ees_pack_id.ds   = ds;
    e2ees_pack_id.kem  = kem;
    e2ees_pack_id.se   = se;
    e2ees_pack_id.hash = hash;

    return e2ees_pack_id_to_raw(e2ees_pack_id);
}

e2ees_pack_t *get_e2ees_pack(uint32_t e2ees_pack_id_raw) {
    e2ees_pack_id_t e2ees_pack_id = raw_to_e2ees_pack_id(e2ees_pack_id_raw);

    E2EES_PACK.cipher_suite       = get_cipher_suite(e2ees_pack_id);
    if (e2ees_pack_id.kem != E2EES_PACK_ALG_KEM_CURVE25519) {
        E2EES_PACK.session_suite = &E2EES_SESSION_PQC;
    } else {
        E2EES_PACK.session_suite = &E2EES_SESSION_ECC;
    }

    return &E2EES_PACK;
}

void e2ees_randombytes(uint8_t *rand_data, size_t rand_data_len) {
    get_e2ees_plugin()->common_handler.gen_rand(rand_data, rand_data_len);
}

void e2ees_notify_log(
    E2ees__E2eeAddress *user_address, LogCode log_code, const char *msg_fmt, ...) {
    if (e2ees_plugin == NULL) {
        return;
    }

    char msg[4096] = { 0 };
    va_list arg;
    va_start(arg, msg_fmt);
    vsnprintf(msg, sizeof(msg), msg_fmt, arg);
    va_end(arg);

    const char *logcode_str = logcode_string(log_code);
    if (log_code == DEBUG_LOG || log_code == VERBOSE_LOG) {
        char log_msg[4096 + 64] = { 0 };
        snprintf(log_msg, sizeof(log_msg), "<%s> %s", logcode_str, msg);
        e2ees_plugin->event_handler.on_log(user_address, log_code, log_msg);
    } else {
        char stack_trace[512] = { 0 };
        get_stack_trace(stack_trace, sizeof(stack_trace));

        char log_msg[4096 + 512 + 128] = { 0 };
        snprintf(
            log_msg, sizeof(log_msg), "<%s> %s\nStack trace:\n%s", logcode_str, msg, stack_trace);
        e2ees_plugin->event_handler.on_log(user_address, log_code, log_msg);
    }
}

void e2ees_notify_user_registered(E2ees__Account *account) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_user_registered(account);
}

void e2ees_notify_inbound_session_invited(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_inbound_session_invited(user_address, from);
}

void e2ees_notify_inbound_session_ready(
    E2ees__E2eeAddress *user_address, E2ees__Session *inbound_session) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_inbound_session_ready(user_address, inbound_session);
}

void e2ees_notify_outbound_session_ready(
    E2ees__E2eeAddress *user_address, E2ees__Session *outbound_session) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_outbound_session_ready(user_address, outbound_session);
}

void e2ees_notify_one2one_msg(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    uint8_t *plaintext,
    size_t plaintext_len) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_one2one_msg_received(
            user_address, from_address, to_address, plaintext, plaintext_len);
}

void e2ees_notify_other_device_msg(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *to_address,
    uint8_t *plaintext,
    size_t plaintext_len) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_other_device_msg_received(
            user_address, from_address, to_address, plaintext, plaintext_len);
}

void e2ees_notify_group_created(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *group_address,
    const char *group_name,
    E2ees__GroupMember **group_members,
    size_t group_members_num) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_group_created(
            user_address, group_address, group_name, group_members, group_members_num);
}

void e2ees_notify_group_members_added(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *group_address,
    const char *group_name,
    E2ees__GroupMember **group_members,
    size_t group_members_num,
    E2ees__GroupMember **added_group_members,
    size_t added_group_members_num) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_group_members_added(
            user_address,
            group_address,
            group_name,
            group_members,
            group_members_num,
            added_group_members,
            added_group_members_num);
}

void e2ees_notify_group_members_removed(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *group_address,
    const char *group_name,
    E2ees__GroupMember **group_members,
    size_t group_members_num,
    E2ees__GroupMember **removed_group_members,
    size_t removed_group_members_num) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_group_members_removed(
            user_address,
            group_address,
            group_name,
            group_members,
            group_members_num,
            removed_group_members,
            removed_group_members_num);
}

void e2ees_notify_group_msg(
    E2ees__E2eeAddress *user_address,
    E2ees__E2eeAddress *from_address,
    E2ees__E2eeAddress *group_address,
    uint8_t *plaintext,
    size_t plaintext_len) {
    if (e2ees_plugin != NULL)
        e2ees_plugin->event_handler.on_group_msg_received(
            user_address, from_address, group_address, plaintext, plaintext_len);
}
