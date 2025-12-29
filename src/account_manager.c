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
#include "e2ees/account_manager.h"

#include <string.h>

#include "e2ees/account.h"
#include "e2ees/account_cache.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/e2ees_client_internal.h"
#include "e2ees/group_session.h"
#include "e2ees/mem_util.h"
#include "e2ees/validation.h"

int produce_register_request(E2ees__RegisterUserRequest **request_out, E2ees__Account *account) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__IdentityKey *identity_key = NULL;
    E2ees__KeyPair *identity_key_pair_asym = NULL;
    E2ees__KeyPair *identity_key_pair_sign = NULL;
    E2ees__SignedPreKey *signed_pre_key = NULL;
    E2ees__KeyPair *signed_pre_key_pair = NULL;
    E2ees__OneTimePreKey *one_time_pre_key = NULL;

    if (is_valid_unregistered_account(account)) {
        identity_key = account->identity_key;
        identity_key_pair_asym = identity_key->asym_key_pair;
        identity_key_pair_sign = identity_key->sign_key_pair;
        signed_pre_key = account->signed_pre_key;
        signed_pre_key_pair = signed_pre_key->key_pair;
    } else {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "produce_register_request()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        E2ees__RegisterUserRequest *request = (E2ees__RegisterUserRequest *)malloc(sizeof(E2ees__RegisterUserRequest));
        e2ees__register_user_request__init(request);

        // copy identity public key
        request->identity_key_public = (E2ees__IdentityKeyPublic *)malloc(sizeof(E2ees__IdentityKeyPublic));
        e2ees__identity_key_public__init(request->identity_key_public);
        copy_protobuf_from_protobuf(&(request->identity_key_public->asym_public_key), &(identity_key_pair_asym->public_key));
        copy_protobuf_from_protobuf(&(request->identity_key_public->sign_public_key), &(identity_key_pair_sign->public_key));

        // copy signed pre-key
        request->signed_pre_key_public = (E2ees__SignedPreKeyPublic *)malloc(sizeof(E2ees__SignedPreKeyPublic));
        e2ees__signed_pre_key_public__init(request->signed_pre_key_public);
        request->signed_pre_key_public->spk_id = account->signed_pre_key->spk_id;
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(signed_pre_key_pair->public_key));
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(signed_pre_key->signature));

        // copy one-time pre-key
        request->n_one_time_pre_key_list = account->n_one_time_pre_key_list;
        request->one_time_pre_key_list = (E2ees__OneTimePreKeyPublic **)malloc(sizeof(E2ees__OneTimePreKeyPublic *) * request->n_one_time_pre_key_list);
        size_t i;
        for (i = 0; i < request->n_one_time_pre_key_list; i++) {
            request->one_time_pre_key_list[i] = (E2ees__OneTimePreKeyPublic *)malloc(sizeof(E2ees__OneTimePreKeyPublic));
            e2ees__one_time_pre_key_public__init(request->one_time_pre_key_list[i]);

            one_time_pre_key = account->one_time_pre_key_list[i];
            request->one_time_pre_key_list[i]->opk_id = one_time_pre_key->opk_id;
            copy_protobuf_from_protobuf(&(request->one_time_pre_key_list[i]->public_key), &(one_time_pre_key->key_pair->public_key));
        }

        *request_out = request;
    } else {
        *request_out = NULL;
    }

    return ret;
}

bool consume_register_response(E2ees__Account *account, E2ees__RegisterUserResponse *response) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__E2eeAddress *address = NULL;
    char *auth = NULL;
    E2ees__E2eeAddress *other_device_address = NULL;
    E2ees__E2eeAddress *to_address = NULL;
    E2ees__InviteResponse **invite_response_list = NULL;
    size_t invite_response_num = 0;
    size_t i;

    if (!is_valid_unregistered_account(account)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "consume_register_response()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_register_user_response(response)) {
        e2ees_notify_log(NULL, BAD_REGISTER_USER_RESPONSE, "consume_register_response()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // insert the address the server gave to our account
        copy_address_from_address(&(account->address), response->address);
        if (is_valid_certificate(response->server_cert)) {
            copy_certificate_from_certificate(&(account->server_cert), response->server_cert);
        }
        account->saved = true;
        account->password = strdup(response->password);
        account->auth = strdup(response->auth);
        account->expires_in = response->expires_in;
        // save to db
        get_e2ees_plugin()->db_handler.store_account(account);
        e2ees_notify_user_registered(account);

        // store into cache
        store_account_into_cache(account);

        // create outbound sessions to other devices
        address = account->address;
        auth = account->auth;
        if (response->n_other_device_address_list > 0) {
            for (i = 0; i < response->n_other_device_address_list; i++) {
                other_device_address = (response->other_device_address_list)[i];
                e2ees_notify_log(
                    address, DEBUG_LOG, "consume_register_response() other_device_address_list %zu of %zu: address [%s:%s]",
                    i + 1, response->n_other_device_address_list,
                    other_device_address->user->user_id,
                    other_device_address->user->device_id
                );
                ret = get_pre_key_bundle_internal(
                    &invite_response_list,
                    &invite_response_num,
                    address,
                    auth,
                    other_device_address->user->user_id,
                    other_device_address->domain,
                    other_device_address->user->device_id,
                    false,
                    NULL, 0
                );
                
                // release
                free_invite_response_list(&invite_response_list, invite_response_num);
            }
        }

        // send to other friends if necessary
        if (response->n_other_user_address_list > 0) {
            for (i = 0; i < response->n_other_user_address_list; i++) {
                to_address = (response->other_user_address_list)[i];
                e2ees_notify_log(
                    address, DEBUG_LOG, "consume_register_response() other_user_address_list %zu of %zu: address [%s@%s]",
                    i + 1, response->n_other_user_address_list,
                    to_address->user->user_id,
                    to_address->domain
                );
                // skip the same user device
                if (compare_address(address, to_address)) {
                    e2ees_notify_log(
                        address,
                        DEBUG_LOG,
                        "consume_register_response(): skip invite the same user device: %s",
                        to_address->user->device_id
                    );
                    continue;
                }

                ret = get_pre_key_bundle_internal(
                    &invite_response_list,
                    &invite_response_num,
                    address,
                    auth,
                    to_address->user->user_id,
                    to_address->domain,
                    to_address->user->device_id,
                    false,
                    NULL, 0
                );
                // release
                free_invite_response_list(&invite_response_list, invite_response_num);
            }
        }
        return true;
    } else {
        return false;
    }
}

int produce_publish_spk_request(
    E2ees__PublishSpkRequest **request_out,
    E2ees__Account *account
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__SignedPreKey *signed_pre_key = NULL;
    E2ees__KeyPair *signed_pre_key_pair = NULL;

    if (is_valid_registered_account(account)) {
        signed_pre_key = account->signed_pre_key;
        signed_pre_key_pair = signed_pre_key->key_pair;
    } else {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "produce_publish_spk_request()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        E2ees__PublishSpkRequest *request = (E2ees__PublishSpkRequest *)malloc(sizeof(E2ees__PublishSpkRequest));
        e2ees__publish_spk_request__init(request);

        // copy the new signed pre-key to the message which will be sent to the server
        copy_address_from_address(&(request->user_address), account->address);
        request->signed_pre_key_public = (E2ees__SignedPreKeyPublic *)malloc(sizeof(E2ees__SignedPreKeyPublic));
        e2ees__signed_pre_key_public__init(request->signed_pre_key_public);
        request->signed_pre_key_public->spk_id = signed_pre_key->spk_id;
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(signed_pre_key_pair->public_key));
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(signed_pre_key->signature));

        *request_out = request;
    } else {
        *request_out = NULL;
    }

    return ret;
}

int consume_publish_spk_response(
    E2ees__Account *account,
    E2ees__PublishSpkResponse *response
) {
    int ret = E2EES_RESULT_SUCC;

    if (!is_valid_publish_spk_response(response)) {
        e2ees_notify_log(NULL, BAD_PUBLISH_SPK_RESPONSE, "consume_publish_spk_response()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_registered_account(account)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "consume_publish_spk_response()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // save to db
        if (account->saved == true) {
            E2ees__SignedPreKey *signed_pre_key = account->signed_pre_key;
            get_e2ees_plugin()->db_handler.update_signed_pre_key(account->address, signed_pre_key);
        }
    }

    return ret;
}

int produce_supply_opks_request(
    E2ees__SupplyOpksRequest **request_out,
    E2ees__OneTimePreKey ***one_time_pre_key_list_out,
    E2ees__Account *account,
    uint32_t opks_num
) {
    int ret = E2EES_RESULT_SUCC;

    E2ees__SupplyOpksRequest *request = NULL;
    uint32_t e2ees_pack_id;
    uint32_t cur_opk_id;

    if (is_valid_registered_account(account)) {
        e2ees_pack_id = account->e2ees_pack_id;
        cur_opk_id = account->next_one_time_pre_key_id;
    } else {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "produce_supply_opks_request()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // generate a given number of new one-time pre-keys
        ret = generate_opks(one_time_pre_key_list_out, opks_num, e2ees_pack_id, cur_opk_id);
    }

    if (ret == E2EES_RESULT_SUCC) {
        request = (E2ees__SupplyOpksRequest *)malloc(sizeof(E2ees__SupplyOpksRequest));
        e2ees__supply_opks_request__init(request);

        request->e2ees_pack_id = account->e2ees_pack_id;
        request->n_one_time_pre_key_public_list = (size_t)opks_num;
        request->one_time_pre_key_public_list = (E2ees__OneTimePreKeyPublic **)malloc(sizeof(E2ees__OneTimePreKeyPublic *) * opks_num);

        copy_address_from_address(&(request->user_address), account->address);

        // copy the new one-time pre-keys to the message which will be sent to the server
        uint32_t i;
        for (i = 0; i < opks_num; i++) {
            request->one_time_pre_key_public_list[i] = (E2ees__OneTimePreKeyPublic *)malloc(sizeof(E2ees__OneTimePreKeyPublic));
            e2ees__one_time_pre_key_public__init(request->one_time_pre_key_public_list[i]);
            request->one_time_pre_key_public_list[i]->opk_id = (*one_time_pre_key_list_out)[i]->opk_id;
            copy_protobuf_from_protobuf(&(request->one_time_pre_key_public_list[i]->public_key), &((*one_time_pre_key_list_out)[i]->key_pair->public_key));
        }

        *request_out = request;
    }

    return ret;
}

int consume_supply_opks_response(E2ees__Account *account, E2ees__OneTimePreKey **one_time_pre_key_list, uint32_t opks_num, E2ees__SupplyOpksResponse *response) {
    int ret = E2EES_RESULT_SUCC;

    if (!is_valid_registered_account(account)) {
        e2ees_notify_log(NULL, BAD_ACCOUNT, "consume_supply_opks_response()");
        ret = E2EES_RESULT_FAIL;
    }
    if (!is_valid_supply_opks_response(response)) {
        e2ees_notify_log(NULL, BAD_SUPPLY_OPKS_RESPONSE, "consume_supply_opks_response()");
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        // save to db
        size_t i;
        for (i = 0; i < opks_num; i++) {
            get_e2ees_plugin()->db_handler.add_one_time_pre_key(account->address, one_time_pre_key_list[i]);
        }
        // skip saving one_time_pre_key_list to account
    }

    return ret;
}

bool consume_supply_opks_msg(E2ees__E2eeAddress *receiver_address, E2ees__SupplyOpksMsg *msg) {
    /** The server notifies us to generate some new one-time pre-keys 
        since our published one-time pre-keys are going to used up. */

    if (!is_valid_address(receiver_address)) {
        e2ees_notify_log(NULL, BAD_ADDRESS, "consume_supply_opks_msg()");
        return true;
    }
    if (is_valid_supply_opks_msg(msg)) {
        if (!compare_address(receiver_address, msg->user_address)){
            e2ees_notify_log(receiver_address, BAD_SUPPLY_OPKS_MSG, "consume_supply_opks_msg()");
            return true;
        }
    }

    uint32_t opks_num = msg->opks_num;
    E2ees__Account *account = NULL;
    get_e2ees_plugin()->db_handler.load_account_by_address(receiver_address, &account);

    if (!is_valid_registered_account(account)) {
        e2ees_notify_log(receiver_address, BAD_ACCOUNT, "consume_supply_opks_msg()");
        return true;
    }

    E2ees__SupplyOpksResponse *supply_opks_response = NULL;
    supply_opks_internal(&supply_opks_response, account, opks_num);

    // release
    free_proto(account);
    free_proto(supply_opks_response);

    // done
    return true;
}
