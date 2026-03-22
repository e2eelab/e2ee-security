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
#include "e2ees/mem_util.h"

#include <string.h>

#include "e2ees/crypto.h"

bool is_equal(const uint8_t *buffer_a, const uint8_t *buffer_b, size_t len) {
    uint8_t volatile result = 0;
    while (len--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }

    return result == 0;
}

char *generate_uuid_str() {
    uint8_t uuid[E2EES_UUID_LEN];
    get_e2ees_plugin()->common_handler.gen_uuid(uuid);
    // to base64
    return crypto_base64_encode(uuid, E2EES_UUID_LEN);
}

size_t to_hex_str(const uint8_t *buffer, size_t buffer_len, char **hex_str) {
    size_t hex_str_len = buffer_len * 2 + 1;
    *hex_str = (char *)malloc(hex_str_len * sizeof(char));
    char *p = &(*hex_str[0]);
    int i, n;
    size_t output_len = 0;
    for (i = 0; (i < buffer_len) && (output_len <= hex_str_len); i++) {
        n = sprintf(p, "%02X", buffer[i]);
        p += n;
        output_len += n;
    }
    *p = '\0';

    return hex_str_len;
}

///-----------------compare-----------------///

bool compare_protobuf(ProtobufCBinaryData *src_1, ProtobufCBinaryData *src_2) {
    if (src_1 == NULL && src_2 == NULL)
        return true;
    if (src_1 != NULL && src_2 != NULL) {
        if (src_1->len == src_2->len) {
            if (memcmp(src_1->data, src_2->data, src_1->len) == 0) {
                return true;
            }
        }
    }
    return false;
}

bool safe_strcmp(const char *str_1, const char *str_2) {
    if (str_1 == NULL && str_2 == NULL)
        return true;
    if (str_1 != NULL && str_2 != NULL) {
        return strcmp(str_1, str_2) == 0;
    }
    return false;
}

bool compare_user_id(E2ees__E2eeAddress *address, const char *user_id, const char *domain) {
    if (address == NULL && user_id == NULL && domain == NULL)
        return true;
    if ((user_id == NULL && domain != NULL) || (user_id != NULL && domain == NULL))
        return false;
    if ((address == NULL && user_id != NULL) || (address != NULL && user_id == NULL))
        return false;

    return safe_strcmp(address->domain, domain) && (address->peer_case == E2EES__E2EE_ADDRESS__PEER_USER) && (safe_strcmp(address->user->user_id, user_id));
}

bool compare_address(E2ees__E2eeAddress *address_1, E2ees__E2eeAddress *address_2) {
    if (address_1 == NULL && address_2 == NULL)
        return true;
    if ((address_1 == NULL && address_2 != NULL) || (address_1 != NULL && address_2 == NULL))
        return false;

    return safe_strcmp(address_1->domain, address_2->domain) && (address_1->peer_case == address_2->peer_case) &&
        (((address_1->peer_case == E2EES__E2EE_ADDRESS__PEER_USER) &&
        (safe_strcmp(address_1->user->user_id, address_2->user->user_id) && safe_strcmp(address_1->user->device_id, address_2->user->device_id))) ||
        ((address_1->peer_case == E2EES__E2EE_ADDRESS__PEER_GROUP) && (safe_strcmp(address_1->group->group_id, address_2->group->group_id))));
}

bool compare_group_member(E2ees__GroupMember **group_members_1, size_t group_member_num_1, E2ees__GroupMember **group_members_2, size_t group_member_num_2) {
    if (group_members_1 == NULL && group_members_2 == NULL)
        return true;
    if ((group_members_1 == NULL && group_members_2 != NULL) || (group_members_1 != NULL && group_members_2 == NULL))
        return false;
    if (group_member_num_1 != group_member_num_2)
        return false;

    size_t i, j;
    bool matched = true;
    for (i = 0; i < group_member_num_1; i++) {
        if (matched) {
            matched = false;
            for (j = 0; j < group_member_num_2; j++) {
                if (safe_strcmp(group_members_1[i]->user_id, group_members_2[j]->user_id) && safe_strcmp(group_members_1[i]->domain, group_members_2[j]->domain)) {
                    matched = true;
                    break;
                }
            }
        } else {
            return false;
        }
    }
    return true;
}

///-----------------init protobuf-----------------///
void init_protobuf(ProtobufCBinaryData *dest) {
    dest->data = NULL;
    dest->len = 0;
}

void malloc_protobuf(ProtobufCBinaryData *dest, size_t len) {
    dest->len = len;
    dest->data = (uint8_t *)malloc(sizeof(uint8_t) * len);
}

///-----------------get keys-----------------///
uint8_t *get_identity_public_key_ds_uint8_from_account(E2ees__Account *src) {
    if (src != NULL) {
        if (src->identity_key != NULL) {
            if (src->identity_key->sign_key_pair != NULL) {
                if (src->identity_key->sign_key_pair->public_key.data != NULL) {
                    return src->identity_key->sign_key_pair->public_key.data;
                }
            }
        }
    }
    return NULL;
}

ProtobufCBinaryData *get_identity_public_key_ds_bytes_from_account(E2ees__Account *src) {
    if (src != NULL) {
        if (src->identity_key != NULL) {
            if (src->identity_key->sign_key_pair != NULL) {
                if (src->identity_key->sign_key_pair->public_key.data != NULL) {
                    return &(src->identity_key->sign_key_pair->public_key);
                }
            }
        }
    }
    return NULL;
}

///-----------------copy protobuf-----------------///

void copy_protobuf_from_protobuf(ProtobufCBinaryData *dest, const ProtobufCBinaryData *src) {
    if (src->len == 0)
        return;
    dest->len = src->len;
    dest->data = (uint8_t *)malloc(sizeof(uint8_t) * src->len);
    memcpy(dest->data, src->data, src->len);
}

void copy_protobuf_from_bool(ProtobufCBinaryData *dest, bool src) {
    dest->len = 1;
    dest->data = (uint8_t *)malloc(sizeof(uint8_t));
    if (src) {
        (dest->data)[0] = 'T';
    } else {
        (dest->data)[0] = 'F';
    }
}

void copy_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src, size_t len) {
    dest->len = len;
    dest->data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    memcpy(dest->data, src, len);
}

void overwrite_protobuf_from_array(ProtobufCBinaryData *dest, const uint8_t *src) { memcpy(dest->data, src, dest->len); }

void copy_protobuf_list_from_protobuf_list(
    ProtobufCBinaryData *dest, const ProtobufCBinaryData *src, size_t protobuf_num
) {
    size_t i;
    for (i = 0; i < protobuf_num; i++) {
        copy_protobuf_from_protobuf(&dest[i], &src[i]);
    }
}

///-----------------copy address-----------------///

void copy_address_from_address(E2ees__E2eeAddress **dest, const E2ees__E2eeAddress *src) {
    *dest = (E2ees__E2eeAddress *)malloc(sizeof(E2ees__E2eeAddress));
    e2ees__e2ee_address__init(*dest);
    if (src != NULL) {
        if (src->domain != NULL)
            (*dest)->domain = strdup(src->domain);
        if (src->peer_case == E2EES__E2EE_ADDRESS__PEER_USER) {
            (*dest)->user = (E2ees__PeerUser *)malloc(sizeof(E2ees__PeerUser));
            e2ees__peer_user__init((*dest)->user);
            (*dest)->peer_case = E2EES__E2EE_ADDRESS__PEER_USER;
            if (src->user->user_name != NULL)
                (*dest)->user->user_name = strdup(src->user->user_name);
            if (src->user->user_id != NULL)
                (*dest)->user->user_id = strdup(src->user->user_id);
            if (src->user->device_id != NULL)
                (*dest)->user->device_id = strdup(src->user->device_id);
        } else if (src->peer_case == E2EES__E2EE_ADDRESS__PEER_GROUP) {
            (*dest)->group = (E2ees__PeerGroup *)malloc(sizeof(E2ees__PeerGroup));
            e2ees__peer_group__init((*dest)->group);
            (*dest)->peer_case = E2EES__E2EE_ADDRESS__PEER_GROUP;
            if (src->group->group_name != NULL)
                (*dest)->group->group_name = strdup(src->group->group_name);
            if (src->group->group_id != NULL)
                (*dest)->group->group_id = strdup(src->group->group_id);
        }
    }
}

///-----------------copy key pair, ik, spk, opk-----------------///

void copy_key_pair_from_key_pair(E2ees__KeyPair **dest, E2ees__KeyPair *src) {
    *dest = (E2ees__KeyPair *)malloc(sizeof(E2ees__KeyPair));
    e2ees__key_pair__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->private_key), &(src->private_key));
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

void copy_ik_from_ik(E2ees__IdentityKey **dest, E2ees__IdentityKey *src) {
    *dest = (E2ees__IdentityKey *)malloc(sizeof(E2ees__IdentityKey));
    e2ees__identity_key__init(*dest);
    copy_key_pair_from_key_pair(&((*dest)->asym_key_pair), src->asym_key_pair);
    copy_key_pair_from_key_pair(&((*dest)->sign_key_pair), src->sign_key_pair);
}

void copy_spk_from_spk(E2ees__SignedPreKey **dest, E2ees__SignedPreKey *src) {
    *dest = (E2ees__SignedPreKey *)malloc(sizeof(E2ees__SignedPreKey));
    e2ees__signed_pre_key__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_key_pair_from_key_pair(&((*dest)->key_pair), src->key_pair);
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
    (*dest)->ttl = src->ttl;
}

void copy_opks_from_opks(E2ees__OneTimePreKey ***dest, E2ees__OneTimePreKey **src, size_t opk_num) {
    *dest = (E2ees__OneTimePreKey **)malloc(sizeof(E2ees__OneTimePreKey *) * opk_num);
    size_t i;
    for (i = 0; i < opk_num; i++) {
        (*dest)[i] = (E2ees__OneTimePreKey *)malloc(sizeof(E2ees__OneTimePreKey));
        e2ees__one_time_pre_key__init((*dest)[i]);
        (*dest)[i]->opk_id = src[i]->opk_id;
        (*dest)[i]->used = src[i]->used;
        copy_key_pair_from_key_pair(&((*dest)[i]->key_pair), src[i]->key_pair);
    }
}

///-----------------copy certificate-----------------///

void copy_subject_from_subject(E2ees__Subject **dest, E2ees__Subject *src) {
    *dest = (E2ees__Subject *)malloc(sizeof(E2ees__Subject));
    e2ees__subject__init(*dest);
    if (src->cn != NULL) {
        (*dest)->cn = strdup(src->cn);
    } else {
        (*dest)->cn = NULL;
    }
    if (src->domain != NULL) {
        (*dest)->domain = strdup(src->domain);
    } else {
        (*dest)->domain = NULL;
    }
    if (src->o != NULL) {
        (*dest)->o = strdup(src->o);
    } else {
        (*dest)->o = NULL;
    }
    if(src->n_ou >= 0) {
        size_t n_ou = src->n_ou;
        (*dest)->n_ou = n_ou;
        (*dest)->ou = (char **)malloc(sizeof(char *) * n_ou);
        size_t i;
        for (i = 0; i < n_ou; i++) {
            if ((src->ou)[i] != NULL) {
                ((*dest)->ou)[i] = strdup((src->ou)[i]);
            } else {
                ((*dest)->ou)[i] = NULL;
            }
        }
    }
}

void copy_cert_from_cert(E2ees__Cert **dest, E2ees__Cert *src) {
    *dest = (E2ees__Cert *)malloc(sizeof(E2ees__Cert));
    e2ees__cert__init(*dest);
    copy_subject_from_subject(&((*dest)->issuee), src->issuee);
    (*dest)->public_key_alg = src->public_key_alg;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
    copy_subject_from_subject(&((*dest)->issuer), src->issuer);
    (*dest)->not_before = src->not_before;
    (*dest)->not_after = src->not_after;
}

void copy_certificate_from_certificate(E2ees__Certificate **dest, E2ees__Certificate *src) {
    *dest = (E2ees__Certificate *)malloc(sizeof(E2ees__Certificate));
    e2ees__certificate__init(*dest);
    (*dest)->version = src->version;
    (*dest)->hash_alg = src->hash_alg;
    (*dest)->signing_alg = src->signing_alg;
    copy_cert_from_cert(&((*dest)->cert), src->cert);
    copy_protobuf_from_protobuf(&((*dest)->cert_fingerprint), &(src->cert_fingerprint));
    copy_protobuf_from_protobuf(&((*dest)->signing_public_key_fingerprint), &(src->signing_public_key_fingerprint));
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
    (*dest)->ts = src->ts;
    (*dest)->valid = src->valid;
}

///-----------------copy account-----------------///

void copy_account_from_account(E2ees__Account **dest, E2ees__Account *src) {
    *dest = (E2ees__Account *)malloc(sizeof(E2ees__Account));
    e2ees__account__init(*dest);
    (*dest)->version = strdup(src->version);
    (*dest)->saved = src->saved;
    if (src->address) {
        copy_address_from_address(&((*dest)->address), src->address);
    }
    (*dest)->password = strdup(src->password);
    (*dest)->e2ees_pack_id = src->e2ees_pack_id;
    if (src->identity_key) {
        copy_ik_from_ik(&((*dest)->identity_key), src->identity_key);
    }
    if (src->signed_pre_key) {
        copy_spk_from_spk(&((*dest)->signed_pre_key), src->signed_pre_key);
    }
    if (src->one_time_pre_key_list) {
        copy_opks_from_opks(&((*dest)->one_time_pre_key_list), src->one_time_pre_key_list, src->n_one_time_pre_key_list);
    }
    (*dest)->n_one_time_pre_key_list = src->n_one_time_pre_key_list;
    (*dest)->next_one_time_pre_key_id = src->next_one_time_pre_key_id;
}

///-----------------copy chain key, message key, ratchet, session-----------------///

void copy_chain_key_from_chain_key(E2ees__ChainKey **dest, E2ees__ChainKey *src) {
    *dest = (E2ees__ChainKey *)malloc(sizeof(E2ees__ChainKey));
    e2ees__chain_key__init(*dest);
    (*dest)->index = src->index;
    copy_protobuf_from_protobuf(&((*dest)->shared_key), &(src->shared_key));
}

void copy_msg_key_from_msg_key(E2ees__MsgKey **dest, E2ees__MsgKey *src) {
    *dest = (E2ees__MsgKey *)malloc(sizeof(E2ees__MsgKey));
    e2ees__msg_key__init(*dest);
    (*dest)->index = src->index;
    copy_protobuf_from_protobuf(&((*dest)->derived_key), &(src->derived_key));
}

void copy_sender_chain_from_sender_chain(E2ees__SenderChainNode **dest, E2ees__SenderChainNode *src) {
    *dest = (E2ees__SenderChainNode *)malloc(sizeof(E2ees__SenderChainNode));
    e2ees__sender_chain_node__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->our_ratchet_public_key), &(src->our_ratchet_public_key));
    copy_protobuf_from_protobuf(&((*dest)->their_ratchet_public_key), &(src->their_ratchet_public_key));
    copy_chain_key_from_chain_key(&((*dest)->chain_key), src->chain_key);
}

void copy_receiver_chain_from_receiver_chain(E2ees__ReceiverChainNode **dest, E2ees__ReceiverChainNode *src) {
    *dest = (E2ees__ReceiverChainNode *)malloc(sizeof(E2ees__ReceiverChainNode));
    e2ees__receiver_chain_node__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->their_ratchet_public_key), &(src->their_ratchet_public_key));
    copy_protobuf_from_protobuf(&((*dest)->our_ratchet_private_key), &(src->our_ratchet_private_key));
    copy_chain_key_from_chain_key(&((*dest)->chain_key), src->chain_key);
}

void copy_skipped_msg_keys_from_skipped_msg_keys(E2ees__SkippedMsgKeyNode ***dest, E2ees__SkippedMsgKeyNode **src, size_t skipped_msg_keys_num) {
    *dest = (E2ees__SkippedMsgKeyNode **)malloc(sizeof(E2ees__SkippedMsgKeyNode *) * skipped_msg_keys_num);
    size_t i;
    for (i = 0; i < skipped_msg_keys_num; i++) {
        (*dest)[i] = (E2ees__SkippedMsgKeyNode *)malloc(sizeof(E2ees__SkippedMsgKeyNode));
        e2ees__skipped_msg_key_node__init((*dest)[i]);
        copy_protobuf_from_protobuf(&((*dest)[i]->ratchet_key_public), &(src[i]->ratchet_key_public));
        copy_msg_key_from_msg_key(&((*dest)[i]->msg_key), src[i]->msg_key);
    }
}

void copy_ratchet_from_ratchet(E2ees__Ratchet **dest, E2ees__Ratchet *src) {
    *dest = (E2ees__Ratchet *)malloc(sizeof(E2ees__Ratchet));
    e2ees__ratchet__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->root_key), &(src->root_key));
    (*dest)->root_sequence = src->root_sequence;
    // message_sequence???????
    copy_sender_chain_from_sender_chain(&((*dest)->sender_chain), src->sender_chain);
    copy_receiver_chain_from_receiver_chain(&((*dest)->receiver_chain), src->receiver_chain);
    (*dest)->n_skipped_msg_key_list = src->n_skipped_msg_key_list;
    copy_skipped_msg_keys_from_skipped_msg_keys(&((*dest)->skipped_msg_key_list), src->skipped_msg_key_list, src->n_skipped_msg_key_list);
}

void copy_session_from_session(E2ees__Session **dest, E2ees__Session *src) {
    *dest = (E2ees__Session *)malloc(sizeof(E2ees__Session));
    e2ees__session__init(*dest);
    (*dest)->version = strdup(src->version);
    (*dest)->e2ees_pack_id = src->e2ees_pack_id;
    (*dest)->session_id = strdup(src->session_id);
    copy_address_from_address(&((*dest)->our_address), src->our_address);
    copy_address_from_address(&((*dest)->their_address), src->their_address);
    copy_ratchet_from_ratchet(&((*dest)->ratchet), src->ratchet);
    copy_protobuf_from_protobuf(&((*dest)->associated_data), &(src->associated_data));
    copy_protobuf_from_protobuf(&((*dest)->temp_shared_secret), &(src->temp_shared_secret));
    copy_key_pair_from_key_pair(&((*dest)->alice_base_key), src->alice_base_key);
    (*dest)->bob_signed_pre_key_id = src->bob_signed_pre_key_id;
    (*dest)->bob_one_time_pre_key_id = src->bob_one_time_pre_key_id;
    (*dest)->n_pre_shared_input_list = src->n_pre_shared_input_list;
    (*dest)->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData) * src->n_pre_shared_input_list);
    size_t i;
    for (i = 0; i < src->n_pre_shared_input_list; i++) {
        copy_protobuf_from_protobuf(&((*dest)->pre_shared_input_list[i]), &(src->pre_shared_input_list[i]));
    }
    (*dest)->f2f = src->f2f;
    (*dest)->responded = src->responded;
    (*dest)->invite_t = src->invite_t;
}

///-----------------copy public key-----------------///

void copy_ik_public_from_ik_public(E2ees__IdentityKeyPublic **dest, E2ees__IdentityKeyPublic *src) {
    *dest = (E2ees__IdentityKeyPublic *)malloc(sizeof(E2ees__IdentityKeyPublic));
    e2ees__identity_key_public__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->asym_public_key), &(src->asym_public_key));
    copy_protobuf_from_protobuf(&((*dest)->sign_public_key), &(src->sign_public_key));
}

void copy_spk_public_from_spk_public(E2ees__SignedPreKeyPublic **dest, E2ees__SignedPreKeyPublic *src) {
    *dest = (E2ees__SignedPreKeyPublic *)malloc(sizeof(E2ees__SignedPreKeyPublic));
    e2ees__signed_pre_key_public__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
}

void copy_opk_public_from_opk_public(E2ees__OneTimePreKeyPublic **dest, E2ees__OneTimePreKeyPublic *src) {
    *dest = (E2ees__OneTimePreKeyPublic *)malloc(sizeof(E2ees__OneTimePreKeyPublic));
    e2ees__one_time_pre_key_public__init(*dest);
    (*dest)->opk_id = src->opk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->public_key));
}

void copy_ik_to_public(E2ees__IdentityKeyPublic **dest, E2ees__IdentityKey *src) {
    *dest = (E2ees__IdentityKeyPublic *)malloc(sizeof(E2ees__IdentityKeyPublic));
    e2ees__identity_key_public__init(*dest);
    copy_protobuf_from_protobuf(&((*dest)->asym_public_key), &(src->asym_key_pair->public_key));
    copy_protobuf_from_protobuf(&((*dest)->sign_public_key), &(src->sign_key_pair->public_key));
}

void copy_spk_to_public(E2ees__SignedPreKeyPublic **dest, E2ees__SignedPreKey *src) {
    *dest = (E2ees__SignedPreKeyPublic *)malloc(sizeof(E2ees__SignedPreKeyPublic));
    e2ees__signed_pre_key_public__init(*dest);
    (*dest)->spk_id = src->spk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->key_pair->public_key));
    copy_protobuf_from_protobuf(&((*dest)->signature), &(src->signature));
}

void copy_opk_to_public(E2ees__OneTimePreKeyPublic **dest, E2ees__OneTimePreKey *src) {
    *dest = (E2ees__OneTimePreKeyPublic *)malloc(sizeof(E2ees__OneTimePreKeyPublic));
    e2ees__one_time_pre_key_public__init(*dest);
    (*dest)->opk_id = src->opk_id;
    copy_protobuf_from_protobuf(&((*dest)->public_key), &(src->key_pair->public_key));
}

void copy_opk_list_to_public(E2ees__OneTimePreKeyPublic ***dest, E2ees__OneTimePreKey **src, size_t opk_num) {
    *dest = (E2ees__OneTimePreKeyPublic **)malloc(sizeof(E2ees__OneTimePreKeyPublic *) * opk_num);
    size_t i;
    for (i = 0; i < opk_num; i++) {
        copy_opk_to_public(&(*dest)[i], src[i]);
    }
}

///-----------------copy group member id-----------------///

void copy_group_member_id(E2ees__GroupMemberInfo **dest, E2ees__GroupMemberInfo *src) {
    *dest = (E2ees__GroupMemberInfo *)malloc(sizeof(E2ees__GroupMemberInfo));
    e2ees__group_member_info__init(*dest);

    copy_address_from_address(&((*dest)->member_address), src->member_address);
    copy_protobuf_from_protobuf(&((*dest)->sign_public_key), &(src->sign_public_key));
}

void copy_group_member_ids(E2ees__GroupMemberInfo ***dest, E2ees__GroupMemberInfo **src, size_t to_member_addresses_total_num) {
    *dest = (E2ees__GroupMemberInfo **)malloc(sizeof(E2ees__GroupMemberInfo *) * to_member_addresses_total_num);
    size_t i;
    for (i = 0; i < to_member_addresses_total_num; i++) {
        copy_group_member_id(&((*dest)[i]), src[i]);
    }
}

///-----------------group member, group info-----------------///

void copy_group_member(E2ees__GroupMember **dest, E2ees__GroupMember *src) {
    *dest = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(*dest);
    if (src != NULL) {
        if (src->user_id != NULL)
            (*dest)->user_id = strdup(src->user_id);
        if (src->domain != NULL)
            (*dest)->domain = strdup(src->domain);
        (*dest)->role = src->role;
    }
}

void copy_group_members(E2ees__GroupMember ***dest, E2ees__GroupMember **src, size_t group_members_num) {
    *dest = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * group_members_num);
    size_t i;
    for (i = 0; i < group_members_num; i++) {
        copy_group_member(&((*dest)[i]), src[i]);
    }
}

void copy_group_info(E2ees__GroupInfo **dest, E2ees__GroupInfo *src) {
    *dest = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    e2ees__group_info__init(*dest);
    if (src != NULL) {
        if (src->group_name != NULL)
            (*dest)->group_name = strdup(src->group_name);
        if (src->group_address != NULL)
            copy_address_from_address(&((*dest)->group_address), src->group_address);
        (*dest)->n_group_member_list = src->n_group_member_list;
        if (src->group_member_list != NULL)
            copy_group_members(&((*dest)->group_member_list), src->group_member_list, src->n_group_member_list);
    }
}

///---------------------copy msg---------------------///

void copy_create_group_msg(E2ees__CreateGroupMsg **dest, E2ees__CreateGroupMsg *src) {
    *dest = (E2ees__CreateGroupMsg *)malloc(sizeof(E2ees__CreateGroupMsg));
    e2ees__create_group_msg__init(*dest);
    if (src != NULL) {
        (*dest)->e2ees_pack_id = src->e2ees_pack_id;
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        (*dest)->n_member_info_list = src->n_member_info_list;
        if (src->member_info_list != NULL)
            copy_group_member_ids(&((*dest)->member_info_list), src->member_info_list, src->n_member_info_list);
    }
}

void copy_renew_group_msg(E2ees__RenewGroupMsg **dest, E2ees__RenewGroupMsg *src) {
    *dest = (E2ees__RenewGroupMsg *)malloc(sizeof(E2ees__RenewGroupMsg));
    e2ees__renew_group_msg__init(*dest);
    if (src != NULL) {
        (*dest)->e2ees_pack_id = src->e2ees_pack_id;
        
        if (src->sender_address != NULL) {
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        }
            
        if (src->group_info != NULL) {
            copy_group_info(&((*dest)->group_info), src->group_info);
        }
            
        (*dest)->n_member_info_list = src->n_member_info_list;
        
        if (src->member_info_list != NULL) {
            copy_group_member_ids(&((*dest)->member_info_list), src->member_info_list, src->n_member_info_list);
        }
    }
}

void copy_add_group_members_msg(E2ees__AddGroupMembersMsg **dest, E2ees__AddGroupMembersMsg *src) {
    *dest = (E2ees__AddGroupMembersMsg *)malloc(sizeof(E2ees__AddGroupMembersMsg));
    e2ees__add_group_members_msg__init(*dest);
    if (src != NULL) {
        (*dest)->e2ees_pack_id = src->e2ees_pack_id;
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        (*dest)->sequence = src->sequence;
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        (*dest)->n_adding_member_info_list = src->n_adding_member_info_list;
        if (src->adding_member_info_list != NULL)
            copy_group_member_ids(&((*dest)->adding_member_info_list), src->adding_member_info_list, src->n_adding_member_info_list);
        (*dest)->n_adding_member_list = src->n_adding_member_list;
        if (src->adding_member_list != NULL)
            copy_group_members(&((*dest)->adding_member_list), src->adding_member_list, src->n_adding_member_list);
    }
}

void copy_add_group_member_device_msg(E2ees__AddGroupMemberDeviceMsg **dest, E2ees__AddGroupMemberDeviceMsg *src) {
    *dest = (E2ees__AddGroupMemberDeviceMsg *)malloc(sizeof(E2ees__AddGroupMemberDeviceMsg));
    e2ees__add_group_member_device_msg__init(*dest);
    if (src != NULL) {
        (*dest)->e2ees_pack_id = src->e2ees_pack_id;
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        (*dest)->sequence = src->sequence;
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        if (src->adding_member_device != NULL)
            copy_group_member_id(&((*dest)->adding_member_device), src->adding_member_device);
    }
}

void copy_remove_group_members_msg(E2ees__RemoveGroupMembersMsg **dest, E2ees__RemoveGroupMembersMsg *src) {
    *dest = (E2ees__RemoveGroupMembersMsg *)malloc(sizeof(E2ees__RemoveGroupMembersMsg));
    e2ees__remove_group_members_msg__init(*dest);
    if (src != NULL) {
        (*dest)->e2ees_pack_id = src->e2ees_pack_id;
        if (src->sender_address != NULL)
            copy_address_from_address(&((*dest)->sender_address), src->sender_address);
        if (src->group_info != NULL)
            copy_group_info(&((*dest)->group_info), src->group_info);
        (*dest)->n_member_info_list = src->n_member_info_list;
        if (src->member_info_list != NULL)
            copy_group_member_ids(&((*dest)->member_info_list), src->member_info_list, src->n_member_info_list);
        (*dest)->n_removing_member_list = src->n_removing_member_list;
        if (src->removing_member_list != NULL)
            copy_group_members(&((*dest)->removing_member_list), src->removing_member_list, src->n_removing_member_list);
    }
}

void copy_leave_group_msg(E2ees__LeaveGroupMsg **dest, E2ees__LeaveGroupMsg *src) {
    *dest = (E2ees__LeaveGroupMsg *)malloc(sizeof(E2ees__LeaveGroupMsg));
    e2ees__leave_group_msg__init(*dest);
    if (src != NULL) {
        if (src->user_address != NULL)
            copy_address_from_address(&((*dest)->user_address), src->user_address);
        if (src->group_address != NULL)
            copy_address_from_address(&((*dest)->group_address), src->group_address);
    }
}

///-----------------add or remove group members-----------------///

void add_group_members_to_group_info(
    E2ees__GroupInfo **dest,
    E2ees__GroupInfo *old_group_info,
    E2ees__GroupMember **adding_member_list,
    size_t adding_members_num
) {
    size_t old_group_members_num = old_group_info->n_group_member_list;
    size_t new_group_members_num = old_group_members_num + adding_members_num;
    *dest = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    e2ees__group_info__init(*dest);
    if (old_group_info->group_name != NULL)
        (*dest)->group_name = strdup(old_group_info->group_name);
    if (old_group_info->group_address != NULL)
        copy_address_from_address(&((*dest)->group_address), old_group_info->group_address);
    (*dest)->n_group_member_list = new_group_members_num;
    (*dest)->group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    size_t i;
    for (i = 0; i < old_group_members_num; i++) {
        copy_group_member(&(((*dest)->group_member_list)[i]), (old_group_info->group_member_list)[i]);
    }
    for (i = old_group_members_num; i < new_group_members_num; i++) {
        copy_group_member(&(((*dest)->group_member_list)[i]), adding_member_list[i - old_group_members_num]);
    }
}

void remove_group_members_from_group_info(
    E2ees__GroupInfo **dest,
    E2ees__GroupInfo *old_group_info,
    E2ees__GroupMember **removing_member_list,
    size_t removing_members_num
) {
    size_t old_group_members_num = old_group_info->n_group_member_list;
    size_t new_group_members_num = old_group_members_num - removing_members_num;
    *dest = (E2ees__GroupInfo *)malloc(sizeof(E2ees__GroupInfo));
    e2ees__group_info__init(*dest);
    if (old_group_info->group_name != NULL)
        (*dest)->group_name = strdup(old_group_info->group_name);
    if (old_group_info->group_address != NULL)
        copy_address_from_address(&((*dest)->group_address), old_group_info->group_address);
    (*dest)->n_group_member_list = new_group_members_num;
    (*dest)->group_member_list = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * new_group_members_num);
    size_t i, cur_pos = 0;
    for (i = 0; i < old_group_members_num; i++) {
        if ((cur_pos == removing_members_num) || ((old_group_info->group_member_list)[i]->role != removing_member_list[cur_pos]->role) ||
            !safe_strcmp((old_group_info->group_member_list)[i]->user_id, removing_member_list[cur_pos]->user_id) ||
            !safe_strcmp((old_group_info->group_member_list)[i]->domain, removing_member_list[cur_pos]->domain)) {
            copy_group_member(&(((*dest)->group_member_list)[i - cur_pos]), (old_group_info->group_member_list)[i]);
        } else {
            cur_pos++;
        }
    }
}

E2ees__GroupMember *member_info_to_group_member(E2ees__GroupMemberInfo *member_info) {
    if (member_info == NULL)
        return NULL;
    if (member_info->member_address == NULL)
        return NULL;
    if (member_info->member_address->user == NULL)
        return NULL;
    if (member_info->member_address->user->user_id == NULL)
        return NULL;
    if (member_info->member_address->domain == NULL)
        return NULL;

    E2ees__GroupMember *group_member = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_member);
    group_member->user_id = strdup(member_info->member_address->user->user_id);
    group_member->domain = strdup(member_info->member_address->domain);
    return group_member;
}

size_t member_info_to_group_members(
    E2ees__GroupMember ***dest,
    E2ees__GroupMemberInfo **member_info_list, size_t member_info_list_num,
    E2ees__GroupMember **member_list, size_t member_list_num
) {
    size_t dest_num = 0;
    size_t i, j, k, l;
    if (member_info_list_num > 0) {
        dest_num = 1;
        for (i = 1; i < member_info_list_num; i++) {
            E2ees__GroupMemberInfo *member_info = member_info_list[i];
            bool exist = false;
            for (j = 0; j < member_info_list_num && j != i; j++) {
                E2ees__GroupMemberInfo *scan_member_info = member_info_list[j];
                if (compare_user_id(
                        member_info->member_address,
                        scan_member_info->member_address->user->user_id,
                        scan_member_info->member_address->domain
                    )
                ) {
                    exist = true;
                    break;
                }
            }
            if (!exist) {
                dest_num++;
            }
        }
    }

    *dest = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * dest_num);
    k = 0;
    for (i = 0; i < member_info_list_num; i++) {
        E2ees__GroupMemberInfo *member_info = member_info_list[i];
        bool exist = false;
        for (j = 0; j < k; j++) {
            E2ees__GroupMember *scan_member = (*dest)[j];
            if (compare_user_id(member_info->member_address, scan_member->user_id, scan_member->domain)) {
                exist = true;
                break;
            }
        }
        if (!exist) {
            E2ees__GroupMember *group_member = member_info_to_group_member(member_info);
            bool role_set = false;
            for(l = 0; l < member_list_num; l++) {
                E2ees__GroupMember *scan_member = member_list[l];
                if (compare_user_id(member_info->member_address, scan_member->user_id, scan_member->domain)) {
                    group_member->role = scan_member->role;
                    role_set = true;
                    break;
                }
            }
            if (!role_set) {
                e2ees_notify_log(NULL, DEBUG_LOG, "member_info_to_group_members() group member has no member info: %s@%s", group_member->user_id, group_member->domain);
            }
            (*dest)[k] = group_member;
            k++;
        }
    }

    // done
    return dest_num;
}

///-----------------release-----------------///

void free_e2ee_addresses(E2ees__E2eeAddress ***dest, size_t e2ee_addresses_num) {
    if (*dest != NULL) {
        size_t i;
        for (i = 0; i < e2ee_addresses_num; i++) {
            E2ees__E2eeAddress *temp = (*dest)[i];
            if (temp != NULL) {
                e2ees__e2ee_address__free_unpacked(temp, NULL);
                temp = NULL;
            }
        }
        free_mem((void **)&(*dest), sizeof(E2ees__E2eeAddress *) * e2ee_addresses_num);
    }
}

void free_invite_response_list(E2ees__InviteResponse ***dest, size_t invite_response_num) {
    if (*dest != NULL) {
        size_t i;
        for (i = 0; i < invite_response_num; i++) {
            E2ees__InviteResponse *temp = (*dest)[i];
            if (temp != NULL) {
                e2ees__invite_response__free_unpacked(temp, NULL);
                temp = NULL;
            }
        }
        free_mem((void **)&(*dest), sizeof(E2ees__InviteResponse *) * invite_response_num);
    }
}

void free_one_time_pre_key_list(E2ees__OneTimePreKey ***dest, uint32_t opks_num) {
    if (*dest != NULL) {
        size_t i;
        for (i = 0; i < opks_num; i++) {
            E2ees__OneTimePreKey *temp = (*dest)[i];
            e2ees__one_time_pre_key__free_unpacked(temp, NULL);
            temp = NULL;
        }
        free_mem((void **)&(*dest), sizeof(E2ees__OneTimePreKey *) * opks_num);
    }
}

void free_group_member_list(E2ees__GroupMember ***dest, size_t group_members_num) {
    if (*dest != NULL) {
        size_t i;
        for (i = 0; i < group_members_num; i++) {
            E2ees__GroupMember *temp = (*dest)[i];
            e2ees__group_member__free_unpacked(temp, NULL);
            temp = NULL;
        }
        free_mem((void **)&(*dest), sizeof(E2ees__GroupMember *) * group_members_num);
    }
}

void free_protobuf(ProtobufCBinaryData *output) {
    if (output != NULL) {
        if (output->data) {
            unset(output->data, output->len);
            free(output->data);
        }
        output->len = 0;
        output->data = NULL;
    }
}

void free_protobuf_list(ProtobufCBinaryData **output, size_t protobuf_num) {
    size_t i;
    for (i = 0; i < protobuf_num; i++) {
        free_protobuf(&(*output)[i]);
    }
    free(*output);
    *output = NULL;
}

void free_mem(void **buffer, size_t buffer_len) {
    if (buffer == NULL || *buffer == NULL || buffer_len == 0) {
        // skip
        return;
    }

    if (buffer_len > 0) {
        volatile unsigned char *p = (volatile unsigned char *)*buffer;
        size_t n = buffer_len;
        while (n--) {
            *p++ = 0;
        }

#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(*buffer) : "memory");
#endif
    }

    free(*buffer);
    *buffer = NULL;
}

void unset(void volatile *buffer, size_t buffer_len) {
    char volatile *pos = (char volatile *)(buffer);
    char volatile *end = pos + buffer_len;
    while (pos != end) {
        *(pos++) = 0;
    }
}

void secure_unset(void *buffer, size_t len) {
    if (!buffer || len == 0) return;

    volatile unsigned char *p = (volatile unsigned char *)buffer;
    while (len--) {
        *p++ = 0;
    }

    // memory barrier
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(buffer) : "memory");
#elif defined(_MSC_VER)
    MemoryBarrier();
#endif
}
