#include "e2ees/e2ees_client_internal.h"

#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/account_manager.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/group_session_manager.h"
#include "e2ees/mem_util.h"
#include "e2ees/ratchet.h"
#include "e2ees/session_manager.h"
#include "e2ees/validation.h"

void *dispatch_proto_request(void *handler_ptr, const void *request, ...) {
    if (!handler_ptr || !request) {
        return NULL;
    }

    E2ees__E2eeAddress *sender_address = NULL;
    const char *auth                   = NULL;
    void *response                     = NULL;

    if (handler_ptr == get_e2ees_plugin()->proto_handler.register_user) {
        // register_user: (handler, request)
        typedef void *(*proto_fun_reg_t)(const void *);
        proto_fun_reg_t proto_fun = (proto_fun_reg_t)handler_ptr;

        log_proto(NULL, (const ProtobufCMessage *)request);
        response = proto_fun(request);
        log_proto(NULL, (const ProtobufCMessage *)response);
    } else {
        // standard: (handler, request, sender_address, auth)
        va_list args;
        va_start(args, request);
        sender_address = va_arg(args, E2ees__E2eeAddress *);
        auth           = va_arg(args, const char *);
        va_end(args);

        typedef void *(*proto_fun_std_t)(E2ees__E2eeAddress *, const char *, const void *);
        proto_fun_std_t proto_fun = (proto_fun_std_t)handler_ptr;

        log_proto(sender_address, (const ProtobufCMessage *)request);
        response = proto_fun(sender_address, auth, request);
        log_proto(sender_address, (const ProtobufCMessage *)response);
    }

    if (response == NULL) {
        e2ees_notify_log(sender_address, VERBOSE_LOG, "response is NULL");
    }

    return response;
}

int publish_spk_internal(
    E2ees__PublishSpkResponse **response_out,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *user_address,
    E2ees__SignedPreKey *new_spk_pair) {
    int ret                                       = E2EES_RESULT_SUCC;

    E2ees__PublishSpkRequest *publish_spk_request = NULL;
    E2ees__PublishSpkResponse *response           = NULL;
    char *auth                                    = NULL;
    publish_spk_params_t params                   = { .e2ees_pack_id = e2ees_pack_id,
                                                      .user_address  = user_address,
                                                      .new_spk       = new_spk_pair };

    if (!is_valid_publish_spk_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    get_e2ees_plugin()->db_handler.load_auth(user_address, &auth);
    if (!is_valid_string(auth)) {
        e2ees_notify_log(NULL, BAD_AUTH, "publish_spk_internal(): invalid auth");
        free_string(auth);
        return E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_publish_spk_request(&publish_spk_request, &params);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.publish_spk, publish_spk_request, user_address, auth);

        if (is_valid_publish_spk_response(response)) {
            ret = consume_publish_spk_response(user_address, new_spk_pair, response);

            if (ret == E2EES_RESULT_FAIL) {
                e2ees__publish_spk_response__free_unpacked(response, NULL);
                response = NULL;
                // we do not store pending request here
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "publish_spk_internal() failed, do it on next start");
            }
        } else {
            if (response != NULL) {
                e2ees__publish_spk_response__free_unpacked(response, NULL);
                response = NULL;
            }
        }

        // output publish_spk response
        *response_out = response;
    }

    // release
    free_string(auth);
    free_proto(publish_spk_request);

    // done
    return ret;
}

int supply_opks_internal(
    E2ees__SupplyOpksResponse **response_out, E2ees__Account *account, uint32_t opks_num) {
    int ret                                       = E2EES_RESULT_SUCC;

    E2ees__OneTimePreKey **one_time_pre_key_list  = NULL;
    E2ees__SupplyOpksRequest *supply_opks_request = NULL;
    E2ees__SupplyOpksResponse *response           = NULL;
    supply_opks_params_t params                   = { .account = account, .opks_num = opks_num };

    if (!is_valid_supply_opks_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = generate_opks(
            &one_time_pre_key_list,
            (size_t)opks_num,
            account->e2ees_pack_id,
            account->next_one_time_pre_key_id);
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_supply_opks_request(&supply_opks_request, &params, one_time_pre_key_list);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.supply_opks,
            supply_opks_request,
            account->address,
            account->auth);

        if (is_valid_supply_opks_response(response)) {
            ret = consume_supply_opks_response(
                account->address, one_time_pre_key_list, opks_num, response);
        }

        // output supply_opks response
        *response_out = response;
    }

    // release
    free_one_time_pre_key_list(&one_time_pre_key_list, opks_num);
    free_proto(supply_opks_request);

    // done
    return ret;
}

int get_pre_key_bundle_internal(
    E2ees__InviteResponse ***invite_response_list_out,
    size_t *invite_response_num_out,
    E2ees__E2eeAddress *from,
    const char *auth,
    const char *to_user_id,
    const char *to_domain,
    const char *to_device_id,
    bool active,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len) {
    int ret                                                     = E2EES_RESULT_SUCC;

    *invite_response_list_out                                   = NULL;
    *invite_response_num_out                                    = 0;
    E2ees__GetPreKeyBundleRequest *get_pre_key_bundle_request   = NULL;
    E2ees__GetPreKeyBundleResponse *get_pre_key_bundle_response = NULL;
    E2ees__InviteResponse **invite_response_list                = NULL;
    size_t invite_response_num;
    get_pre_key_bundle_params_t params = { .from         = from,
                                           .auth         = auth,
                                           .to_user_id   = to_user_id,
                                           .to_domain    = to_domain,
                                           .to_device_id = to_device_id };

    if (!is_valid_get_pre_key_bundle_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_get_pre_key_bundle_request(&get_pre_key_bundle_request, &params);
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_pre_key_bundle_response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.get_pre_key_bundle,
            get_pre_key_bundle_request,
            from,
            auth);

        if (!is_valid_get_pre_key_bundle_response(get_pre_key_bundle_response)) {
            e2ees_notify_log(
                NULL,
                BAD_GET_PRE_KEY_BUNDLE_RESPONSE,
                "get_pre_key_bundle_internal(): invalid "
                "get_pre_key_bundle_response");
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = consume_get_pre_key_bundle_response(
            &invite_response_list,
            &invite_response_num,
            from,
            group_pre_key_plaintext_data,
            group_pre_key_plaintext_data_len,
            get_pre_key_bundle_response);

        // output invite_response_list
        *invite_response_list_out = invite_response_list;
        *invite_response_num_out  = invite_response_num;
    }

    if (ret == E2EES_RESULT_SUCC) {
        if (active == true) {
            size_t their_device_num = get_pre_key_bundle_response->n_pre_key_bundles;
            char **their_device_id  = (char **)malloc(sizeof(char *) * their_device_num);
            E2ees__PreKeyBundle *cur_pre_key_bundle = NULL;
            size_t i;
            for (i = 0; i < their_device_num; i++) {
                cur_pre_key_bundle = get_pre_key_bundle_response->pre_key_bundles[i];
                their_device_id[i] = strdup(cur_pre_key_bundle->user_address->user->device_id);
            }
            // send to other devices in order to create sessions
            send_sync_invite_msg(from, to_user_id, to_domain, their_device_id, their_device_num);

            // release
            for (i = 0; i < their_device_num; i++) {
                free(their_device_id[i]);
                their_device_id[i] = NULL;
            }
            free_mem((void **)&their_device_id, sizeof(char *) * their_device_num);
        }
    } else {
        if (get_pre_key_bundle_response != NULL) {
            if (get_pre_key_bundle_response->code !=
                E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                e2ees_notify_log(
                    from,
                    DEBUG_LOG,
                    "get_pre_key_bundle_internal() get_pre_key_bundle_response "
                    "got error, pending request will be stored.");
                // pack request to get_pre_key_bundle_request_data which will be
                // freed inside store_pending_request_internal
                size_t get_pre_key_bundle_request_data_len =
                    e2ees__get_pre_key_bundle_request__get_packed_size(get_pre_key_bundle_request);
                uint8_t *get_pre_key_bundle_request_data =
                    (uint8_t *)malloc(sizeof(uint8_t) * get_pre_key_bundle_request_data_len);
                e2ees__get_pre_key_bundle_request__pack(
                    get_pre_key_bundle_request, get_pre_key_bundle_request_data);

                ProtobufCBinaryData *request_arg_list = NULL;
                size_t request_arg_list_len           = 0;
                if (group_pre_key_plaintext_data != NULL) {
                    request_arg_list_len = 2;
                    request_arg_list     = (ProtobufCBinaryData *)malloc(
                        sizeof(ProtobufCBinaryData) * request_arg_list_len);
                    copy_protobuf_from_bool(&(request_arg_list[0]), active);
                    copy_protobuf_from_array(
                        &(request_arg_list[1]),
                        group_pre_key_plaintext_data,
                        group_pre_key_plaintext_data_len);
                } else {
                    request_arg_list_len = 1;
                    request_arg_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
                    copy_protobuf_from_bool(&(request_arg_list[0]), active);
                }

                store_pending_request_internal(
                    from,
                    E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_GET_PRE_KEY_BUNDLE,
                    get_pre_key_bundle_request_data,
                    get_pre_key_bundle_request_data_len,
                    request_arg_list,
                    request_arg_list_len);

                // release
                if (request_arg_list != NULL) {
                    free_protobuf_list(&request_arg_list, request_arg_list_len);
                }
                free_mem(
                    (void **)&get_pre_key_bundle_request_data, get_pre_key_bundle_request_data_len);
            }
        }
        // What if get_pre_key_bundle_response is NULL? Should we store pending
        // request?
    }

    // release
    free_proto(get_pre_key_bundle_request);
    free_proto(get_pre_key_bundle_response);

    // done
    return ret;
}

int invite_internal(E2ees__InviteResponse **response_out, E2ees__Session *outbound_session) {
    int ret                              = E2EES_RESULT_SUCC;

    E2ees__InviteRequest *invite_request = NULL;
    E2ees__InviteResponse *response      = NULL;
    char *auth                           = NULL;

    if (!is_valid_uncompleted_session(outbound_session)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(outbound_session->our_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "invite_internal: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_invite_request(&invite_request, outbound_session);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.invite,
            invite_request,
            outbound_session->our_address,
            auth);

        ret = consume_invite_response(outbound_session->our_address, response);
        if (ret == E2EES_RESULT_FAIL) {
            // pack invite_request to request_data
            size_t request_data_len = e2ees__invite_request__get_packed_size(invite_request);
            uint8_t *request_data   = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            e2ees__invite_request__pack(invite_request, request_data);

            // store the request_data into pending
            store_pending_request_internal(
                outbound_session->our_address,
                E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_INVITE,
                request_data,
                request_data_len,
                NULL,
                0);
            // release
            free_mem((void **)&request_data, request_data_len);
        }

        // release
        free_proto(invite_request);

        // output invite response
        *response_out = response;
    }

    // release
    free_string(auth);

    // done
    return ret;
}

int accept_internal(
    E2ees__AcceptResponse **response_out,
    uint32_t e2ees_pack_id,
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    char *session_id,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key) {
    int ret                              = E2EES_RESULT_SUCC;

    E2ees__AcceptRequest *accept_request = NULL;
    E2ees__AcceptResponse *response      = NULL;
    char *auth                           = NULL;
    accept_params_t params               = { .e2ees_pack_id   = e2ees_pack_id,
                                             .from            = from,
                                             .to              = to,
                                             .session_id      = session_id,
                                             .ciphertext_1    = ciphertext_1,
                                             .our_ratchet_key = our_ratchet_key };

    if (!is_valid_accept_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(from, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "accept_internal: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_accept_request(&accept_request, &params);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.accept, accept_request, from, auth);

        ret = consume_accept_response(from, response);
        if (ret == E2EES_RESULT_FAIL) {
            // pack accept_request to request_data
            size_t request_data_len = e2ees__accept_request__get_packed_size(accept_request);
            uint8_t *request_data   = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            e2ees__accept_request__pack(accept_request, request_data);

            store_pending_request_internal(
                from,
                E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT,
                request_data,
                request_data_len,
                NULL,
                0);
            // release
            free_mem((void **)&request_data, request_data_len);
        }

        // release
        free_proto(accept_request);

        // output accept response
        *response_out = response;
    }

    // release
    free_string(auth);

    // done
    return ret;
}

E2ees__SendOne2oneMsgResponse *send_one2one_msg_internal(
    E2ees__Session *outbound_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len) {
    int ret                                                = E2EES_RESULT_SUCC;

    E2ees__SendOne2oneMsgRequest *send_one2one_msg_request = NULL;
    E2ees__One2oneMsgPayload *payload_out                  = NULL;
    char *auth                                             = NULL;

    if (!is_valid_completed_session(outbound_session)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(outbound_session->our_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "accept_internal: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    // encrypt the plaintext
    if (ret == E2EES_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite =
            get_e2ees_pack(outbound_session->e2ees_pack_id)->cipher_suite;
        ret = encrypt_ratchet(
            &payload_out,
            cipher_suite,
            outbound_session->ratchet,
            outbound_session->associated_data,
            plaintext_data,
            plaintext_data_len);
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_send_one2one_msg_request(
            &send_one2one_msg_request, outbound_session, notif_level, payload_out);
    }

    E2ees__SendOne2oneMsgResponse *response = NULL;
    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.send_one2one_msg,
            send_one2one_msg_request,
            outbound_session->our_address,
            auth);

        bool succ = consume_send_one2one_msg_response(outbound_session, response);
        if (!succ) {
            // pack send_one2one_msg_request to request_data
            size_t request_data_len =
                e2ees__send_one2one_msg_request__get_packed_size(send_one2one_msg_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            e2ees__send_one2one_msg_request__pack(send_one2one_msg_request, request_data);

            store_pending_request_internal(
                outbound_session->our_address,
                E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_ONE2ONE_MSG,
                request_data,
                request_data_len,
                NULL,
                0);

            // release
            free_mem((void **)&request_data, request_data_len);
        }
    }

    // ensure response is not NULL
    if (response == NULL) {
        response = (E2ees__SendOne2oneMsgResponse *)malloc(sizeof(E2ees__SendOne2oneMsgResponse));
        e2ees__send_one2one_msg_response__init(response);
        response->code = E2EES__RESPONSE_CODE__RESPONSE_CODE_SERVICE_UNAVAILABLE;
    }

    // release
    free_proto(send_one2one_msg_request);
    free_string(auth);

    // done
    return response;
}

int add_group_member_device_internal(
    E2ees__AddGroupMemberDeviceResponse **response_out,
    E2ees__E2eeAddress *sender_address,
    E2ees__E2eeAddress *group_address,
    E2ees__E2eeAddress *new_device_address) {
    int ret                                                             = E2EES_RESULT_SUCC;

    E2ees__AddGroupMemberDeviceRequest *add_group_member_device_request = NULL;
    E2ees__AddGroupMemberDeviceResponse *response                       = NULL;
    char *auth                                                          = NULL;
    E2ees__GroupSession *outbound_group_session                         = NULL;
    add_group_member_device_params_t params = { .sender_address     = sender_address,
                                                .group_address      = group_address,
                                                .new_device_address = new_device_address };

    if (!is_valid_add_group_member_device_inputs(&params)) {
        ret = E2EES_RESULT_FAIL;
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_auth(sender_address, &auth);
        if (!is_valid_string(auth)) {
            e2ees_notify_log(NULL, BAD_AUTH, "add_group_member_device_internal: invalid auth");
            free_string(auth);
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        get_e2ees_plugin()->db_handler.load_group_session_by_address(
            sender_address, sender_address, group_address, &outbound_group_session);
        if (!is_valid_group_session(outbound_group_session)) {
            ret = E2EES_RESULT_FAIL;
        }
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = produce_add_group_member_device_request(
            &add_group_member_device_request, &params, outbound_group_session);
    }

    if (ret == E2EES_RESULT_SUCC) {
        response = dispatch_proto_request(
            get_e2ees_plugin()->proto_handler.add_group_member_device,
            add_group_member_device_request,
            sender_address,
            auth);

        if (!is_valid_add_group_member_device_response(response)) {
            e2ees_notify_log(
                NULL,
                BAD_ADD_GROUP_MEMBER_DEVICE_RESPONSE,
                "add_group_member_device_internal(): invalid "
                "add_group_member_device_response");
            ret = E2EES_RESULT_FAIL;
            // note that packing the pending request will be skipped in some
            // cases pack add_group_member_device_request to request_data
            size_t request_data_len = e2ees__add_group_member_device_request__get_packed_size(
                add_group_member_device_request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            e2ees__add_group_member_device_request__pack(
                add_group_member_device_request, request_data);

            store_pending_request_internal(
                sender_address,
                E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBER_DEVICE,
                request_data,
                request_data_len,
                NULL,
                0);
            // release
            free_mem((void **)&request_data, request_data_len);
        }

        // output add_group_member_device response
        *response_out = response;
    }

    if (ret == E2EES_RESULT_SUCC) {
        ret = consume_add_group_member_device_response(outbound_group_session, response);
    }

    // release
    free_proto(add_group_member_device_request);
    free_string(auth);
    if (outbound_group_session) {
        e2ees__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    return ret;
}

void store_pending_common_plaintext_data_internal(
    E2ees__E2eeAddress *from,
    E2ees__E2eeAddress *to,
    uint8_t *common_plaintext_data,
    size_t common_plaintext_data_len,
    E2ees__NotifLevel notif_level) {
    char *pending_plaintext_id = generate_uuid_str();
    get_e2ees_plugin()->db_handler.store_pending_plaintext_data(
        from,
        to,
        pending_plaintext_id,
        common_plaintext_data,
        common_plaintext_data_len,
        notif_level);

    // release
    free(pending_plaintext_id);
}

void store_pending_request_internal(
    E2ees__E2eeAddress *user_address,
    E2ees__PendingRequestType type,
    uint8_t *request_data,
    size_t request_data_len,
    ProtobufCBinaryData *request_arg_list,
    size_t request_arg_list_len) {
    E2ees__PendingRequest *pending_request =
        (E2ees__PendingRequest *)malloc(sizeof(E2ees__PendingRequest));
    e2ees__pending_request__init(pending_request);
    // pending request type
    pending_request->type = type;
    // request_data
    copy_protobuf_from_array(&(pending_request->request_data), request_data, request_data_len);
    // args
    pending_request->n_request_arg_list = request_arg_list_len;
    if (request_arg_list_len > 0) {
        pending_request->request_arg_list =
            (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData) * request_arg_list_len);
        copy_protobuf_list_from_protobuf_list(
            pending_request->request_arg_list, request_arg_list, request_arg_list_len);
    }

    // pack pending_request
    size_t pending_request_data_len = e2ees__pending_request__get_packed_size(pending_request);
    uint8_t *pending_request_data   = (uint8_t *)malloc(sizeof(uint8_t) * pending_request_data_len);
    e2ees__pending_request__pack(pending_request, pending_request_data);

    char *pending_request_id = generate_uuid_str();
    get_e2ees_plugin()->db_handler.store_pending_request_data(
        user_address, pending_request_id, type, pending_request_data, pending_request_data_len);
    // release
    e2ees__pending_request__free_unpacked(pending_request, NULL);
    free_mem((void **)(&pending_request_data), pending_request_data_len);
    free(pending_request_id);
}

static void resend_pending_request(
    const uint32_t e2ees_pack_id, E2ees__E2eeAddress *user_address, const char *auth) {
    // load all pending request data
    char **pending_request_id_list  = NULL;
    uint8_t *request_type_list      = NULL;
    uint8_t **request_data_list     = NULL;
    size_t *request_data_len_list   = NULL;
    size_t pending_request_data_num = get_e2ees_plugin()->db_handler.load_pending_request_data(
        user_address,
        &pending_request_id_list,
        &request_type_list,
        &request_data_list,
        &request_data_len_list);
    // send the pending request data
    int ret                            = E2EES_RESULT_SUCC;
    bool succ                          = false;
    E2ees__GroupSession *group_session = NULL;
    size_t i, j;
    for (i = 0; i < pending_request_data_num; i++) {
        ret  = E2EES_RESULT_SUCC;
        succ = false;
        E2ees__PendingRequest *pending_request =
            e2ees__pending_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
        if (pending_request == NULL) {
            e2ees_notify_log(
                user_address, DEBUG_LOG, "resend_pending_request() unpack failed for index %zu", i);
            get_e2ees_plugin()->db_handler.unload_pending_request_data(
                user_address, pending_request_id_list[i]);
            free(pending_request_id_list[i]);
            free_mem((void **)&(request_data_list[i]), request_data_len_list[i]);
            continue;
        }
        e2ees_notify_log(
            user_address,
            DEBUG_LOG,
            "resend_pending_request() request_type: %d",
            request_type_list[i]);
        switch (request_type_list[i]) {
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_GET_PRE_KEY_BUNDLE: {
            size_t their_device_num;
            E2ees__GetPreKeyBundleRequest *get_pre_key_bundle_request =
                e2ees__get_pre_key_bundle_request__unpack(
                    NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__GetPreKeyBundleResponse *get_pre_key_bundle_response =
                get_e2ees_plugin()->proto_handler.get_pre_key_bundle(
                    user_address, auth, get_pre_key_bundle_request);
            // check if pre_key_bundles is empty
            if (!is_valid_get_pre_key_bundle_response(get_pre_key_bundle_response)) {
                ret = E2EES_RESULT_FAIL;
            }
            if (ret == E2EES_RESULT_SUCC) {
                their_device_num = get_pre_key_bundle_response->n_pre_key_bundles;
                E2ees__InviteResponse **invite_response_list = NULL;
                size_t invite_response_num                   = 0;
                size_t arg_num                               = pending_request->n_request_arg_list;
                size_t group_pre_key_plaintext_data_len      = 0;
                uint8_t *group_pre_key_plaintext_data        = NULL;
                if (arg_num == 2) {
                    group_pre_key_plaintext_data     = pending_request->request_arg_list[1].data;
                    group_pre_key_plaintext_data_len = pending_request->request_arg_list[1].len;
                }
                ret = consume_get_pre_key_bundle_response(
                    &invite_response_list,
                    &invite_response_num,
                    user_address,
                    group_pre_key_plaintext_data,
                    group_pre_key_plaintext_data_len,
                    get_pre_key_bundle_response);

                // release
                free_invite_response_list(&invite_response_list, invite_response_num);

                if (ret == E2EES_RESULT_SUCC) {
                    if (pending_request->n_request_arg_list > 0 &&
                        pending_request->request_arg_list[0].data != NULL &&
                        pending_request->request_arg_list[0].data[0] == 'T') {
                        their_device_num       = get_pre_key_bundle_response->n_pre_key_bundles;
                        char **their_device_id = (char **)malloc(sizeof(char *) * their_device_num);
                        E2ees__PreKeyBundle *cur_pre_key_bundle = NULL;
                        for (j = 0; j < their_device_num; j++) {
                            cur_pre_key_bundle = get_pre_key_bundle_response->pre_key_bundles[j];
                            their_device_id[j] =
                                strdup(cur_pre_key_bundle->user_address->user->device_id);
                        }
                        // send to other devices in order to create sessions
                        send_sync_invite_msg(
                            user_address,
                            get_pre_key_bundle_request->user_id,
                            get_pre_key_bundle_request->domain,
                            their_device_id,
                            their_device_num);

                        // release
                        for (j = 0; j < their_device_num; j++) {
                            free(their_device_id[j]);
                        }
                        free_mem((void **)&their_device_id, sizeof(char *) * their_device_num);
                    }
                }
            } else {
                // if the get_pre_key_bundle_response code is no content, we
                // will unload the pending request data
                if (get_pre_key_bundle_response != NULL) {
                    if (get_pre_key_bundle_response->code ==
                        E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                        e2ees_notify_log(
                            user_address,
                            DEBUG_LOG,
                            "consume_get_pre_key_bundle_response() got empty "
                            "pre_key_bundles, remove pending request");
                        succ = true;
                    }
                }
            }

            if (ret == E2EES_RESULT_SUCC || succ) {
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending get_pre_key_bundle_request failed");
            }

            // release
            free_proto(get_pre_key_bundle_request);
            free_proto(get_pre_key_bundle_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_INVITE: {
            E2ees__InviteRequest *invite_request = e2ees__invite_request__unpack(
                NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__InviteResponse *invite_response =
                get_e2ees_plugin()->proto_handler.invite(user_address, auth, invite_request);
            ret = consume_invite_response(user_address, invite_response);
            if (ret == E2EES_RESULT_SUCC) {
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                e2ees_notify_log(user_address, DEBUG_LOG, "handle pending invite_request failed");
            }

            // release
            free_proto(invite_request);
            free_proto(invite_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT: {
            E2ees__AcceptRequest *accept_request = e2ees__accept_request__unpack(
                NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__AcceptResponse *accept_response =
                get_e2ees_plugin()->proto_handler.accept(user_address, auth, accept_request);
            ret = consume_accept_response(accept_request->msg->from, accept_response);
            if (ret == E2EES_RESULT_SUCC) {
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                e2ees_notify_log(user_address, DEBUG_LOG, "handle pending accept_request failed");
            }

            // release
            free_proto(accept_request);
            free_proto(accept_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_PUBLISH_SPK: {
            // E2ees__PublishSpkRequest *publish_spk_request =
            // e2ees__publish_spk_request__unpack(NULL,
            // pending_request->request_data.len,
            // pending_request->request_data.data); E2ees__PublishSpkResponse
            // *publish_spk_response =
            // get_e2ees_plugin()->proto_handler.publish_spk(user_address, auth,
            // publish_spk_request); succ =
            // is_valid_publish_spk_response(publish_spk_response); if (succ) {
            //     ret = consume_publish_spk_response(account,
            //     publish_spk_response);
            //     get_e2ees_plugin()->db_handler.unload_pending_request_data(user_address,
            //     pending_request_id_list[i]);
            // } else {
            //     e2ees_notify_log(user_address, DEBUG_LOG, "handle pending
            //     publish_spk_request failed");
            // }

            // // release
            // free_proto(publish_spk_request);
            // free_proto(publish_spk_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SUPPLY_OPKS: {
            E2ees__SupplyOpksRequest *supply_opks_request = e2ees__supply_opks_request__unpack(
                NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__SupplyOpksResponse *supply_opks_response =
                get_e2ees_plugin()->proto_handler.supply_opks(
                    user_address, auth, supply_opks_request);
            succ = is_valid_supply_opks_response(supply_opks_response);
            if (succ) {
                size_t opks_num = pending_request->n_request_arg_list;
                E2ees__OneTimePreKey **one_time_pre_key_list =
                    (E2ees__OneTimePreKey **)malloc(sizeof(E2ees__OneTimePreKey *) * opks_num);
                for (j = 0; j < opks_num; j++) {
                    size_t one_time_pre_key_data_len = pending_request->request_arg_list[j].len;
                    uint8_t *one_time_pre_key_data   = pending_request->request_arg_list[j].data;
                    one_time_pre_key_list[j]         = e2ees__one_time_pre_key__unpack(
                        NULL, one_time_pre_key_data_len, one_time_pre_key_data);
                }
                ret = consume_supply_opks_response(
                    user_address, one_time_pre_key_list, opks_num, supply_opks_response);
                if (ret == E2EES_RESULT_SUCC) {
                    get_e2ees_plugin()->db_handler.unload_pending_request_data(
                        user_address, pending_request_id_list[i]);
                }
                // release
                free_one_time_pre_key_list(&one_time_pre_key_list, opks_num);
            } else {
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending supply_opks_request failed");
            }

            // release
            free_proto(supply_opks_request);
            free_proto(supply_opks_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_ONE2ONE_MSG: {
            E2ees__SendOne2oneMsgRequest *send_one2one_msg_request =
                e2ees__send_one2one_msg_request__unpack(
                    NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__SendOne2oneMsgResponse *send_one2one_msg_response =
                get_e2ees_plugin()->proto_handler.send_one2one_msg(
                    user_address, auth, send_one2one_msg_request);
            if (send_one2one_msg_response != NULL &&
                send_one2one_msg_response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
                succ = true;
            }
            if (succ) {
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending send_one2one_msg_request failed");
            }

            // release
            free_proto(send_one2one_msg_request);
            free_proto(send_one2one_msg_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_CREATE_GROUP: {
            E2ees__CreateGroupRequest *create_group_request = e2ees__create_group_request__unpack(
                NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__CreateGroupResponse *create_group_response =
                get_e2ees_plugin()->proto_handler.create_group(
                    user_address, auth, create_group_request);
            succ = is_valid_create_group_response(create_group_response);
            if (succ) {
                ret = consume_create_group_response(
                    e2ees_pack_id,
                    user_address,
                    create_group_request->msg->group_info->group_name,
                    create_group_request->msg->group_info->group_member_list,
                    create_group_request->msg->group_info->n_group_member_list,
                    create_group_response);
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                if (create_group_response != NULL &&
                    create_group_response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                    // At least one member with group manager role,
                    // or some error happened on creating group.
                    get_e2ees_plugin()->db_handler.unload_pending_request_data(
                        user_address, pending_request_id_list[i]);
                }
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending create_group_request failed");
            }

            // release
            free_proto(create_group_request);
            free_proto(create_group_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBERS: {
            E2ees__AddGroupMembersRequest *add_group_members_request =
                e2ees__add_group_members_request__unpack(
                    NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__AddGroupMembersResponse *add_group_members_response =
                get_e2ees_plugin()->proto_handler.add_group_members(
                    user_address, auth, add_group_members_request);
            succ = is_valid_add_group_members_response(add_group_members_response);
            if (succ) {
                E2ees__AddGroupMembersMsg *add_group_members_msg = add_group_members_request->msg;
                get_e2ees_plugin()->db_handler.load_group_session_by_address(
                    user_address,
                    user_address,
                    add_group_members_msg->group_info->group_address,
                    &group_session);
                ret = consume_add_group_members_response(
                    group_session,
                    add_group_members_response,
                    add_group_members_msg->adding_member_list,
                    add_group_members_msg->n_adding_member_list);
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                if (add_group_members_response != NULL &&
                    add_group_members_response->code ==
                        E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                    // Only the group member with GROUP_ROLE_MANAGER role can
                    // add group members, or member inexists.
                    get_e2ees_plugin()->db_handler.unload_pending_request_data(
                        user_address, pending_request_id_list[i]);
                }
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending add_group_members_request failed");
            }

            // release
            free_proto(add_group_members_request);
            free_proto(add_group_members_response);
            free_proto(group_session);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBER_DEVICE: {
            E2ees__AddGroupMemberDeviceRequest *add_group_member_device_request =
                e2ees__add_group_member_device_request__unpack(
                    NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__AddGroupMemberDeviceResponse *add_group_member_device_response =
                get_e2ees_plugin()->proto_handler.add_group_member_device(
                    user_address, auth, add_group_member_device_request);
            succ = is_valid_add_group_member_device_response(add_group_member_device_response);
            if (succ) {
                get_e2ees_plugin()->db_handler.load_group_session_by_address(
                    user_address,
                    user_address,
                    add_group_member_device_request->msg->group_info->group_address,
                    &group_session);
                ret = consume_add_group_member_device_response(
                    group_session, add_group_member_device_response);
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                if (add_group_member_device_response != NULL &&
                    add_group_member_device_response->code ==
                        E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                    // Can not collect group member info, or member device
                    // already added.
                    get_e2ees_plugin()->db_handler.unload_pending_request_data(
                        user_address, pending_request_id_list[i]);
                }
                e2ees_notify_log(
                    user_address,
                    DEBUG_LOG,
                    "handle pending add_group_member_device_request failed");
            }

            // release
            free_proto(add_group_member_device_request);
            free_proto(add_group_member_device_response);
            free_proto(group_session);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_REMOVE_GROUP_MEMBERS: {
            E2ees__RemoveGroupMembersRequest *remove_group_members_request =
                e2ees__remove_group_members_request__unpack(
                    NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__RemoveGroupMembersResponse *remove_group_members_response =
                get_e2ees_plugin()->proto_handler.remove_group_members(
                    user_address, auth, remove_group_members_request);
            succ = is_valid_remove_group_members_response(remove_group_members_response);
            if (succ) {
                E2ees__RemoveGroupMembersMsg *remove_group_members_msg =
                    remove_group_members_request->msg;
                get_e2ees_plugin()->db_handler.load_group_session_by_address(
                    user_address,
                    user_address,
                    remove_group_members_msg->group_info->group_address,
                    &group_session);
                ret = consume_remove_group_members_response(
                    group_session,
                    remove_group_members_response,
                    remove_group_members_msg->removing_member_list,
                    remove_group_members_msg->n_removing_member_list);
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                if (remove_group_members_response != NULL &&
                    remove_group_members_response->code ==
                        E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                    // Only the group member with GROUP_ROLE_MANAGER role can
                    // remove group members, user can not remove himself, or
                    // member is not in removing member list.
                    get_e2ees_plugin()->db_handler.unload_pending_request_data(
                        user_address, pending_request_id_list[i]);
                }
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending remove_group_members_request failed");
            }

            // release
            free_proto(remove_group_members_request);
            free_proto(remove_group_members_response);
            free_proto(group_session);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_LEAVE_GROUP: {
            E2ees__LeaveGroupRequest *leave_group_request = e2ees__leave_group_request__unpack(
                NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__LeaveGroupResponse *leave_group_response =
                get_e2ees_plugin()->proto_handler.leave_group(
                    user_address, auth, leave_group_request);
            succ = is_valid_leave_group_response(leave_group_response);
            if (succ) {
                ret = consume_leave_group_response(user_address, leave_group_response);
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                if (leave_group_response != NULL &&
                    leave_group_response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
                    // Only the group member can leave the group.
                    get_e2ees_plugin()->db_handler.unload_pending_request_data(
                        user_address, pending_request_id_list[i]);
                }
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending leave_group_request failed");
            }

            // release
            free_proto(leave_group_request);
            free_proto(leave_group_response);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_GROUP_MSG: {
            E2ees__SendGroupMsgRequest *send_group_msg_request =
                e2ees__send_group_msg_request__unpack(
                    NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__SendGroupMsgResponse *send_group_msg_response =
                get_e2ees_plugin()->proto_handler.send_group_msg(
                    user_address, auth, send_group_msg_request);
            succ = is_valid_send_group_msg_response(send_group_msg_response);
            if (succ) {
                get_e2ees_plugin()->db_handler.load_group_session_by_address(
                    user_address, user_address, send_group_msg_request->msg->to, &group_session);
                ret = consume_send_group_msg_response(group_session, send_group_msg_response);
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            } else {
                e2ees_notify_log(
                    user_address, DEBUG_LOG, "handle pending send_group_msg_request failed");
            }

            // release
            free_proto(send_group_msg_request);
            free_proto(send_group_msg_response);
            free_proto(group_session);
            break;
        }
        case E2EES__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_PROTO_MSG: {
            E2ees__ProtoMsg *proto_msg = e2ees__proto_msg__unpack(
                NULL, pending_request->request_data.len, pending_request->request_data.data);
            E2ees__ConsumeProtoMsgResponse *consume_proto_msg_response =
                consume_proto_msg(proto_msg->to, proto_msg->tag->proto_msg_id);
            if (consume_proto_msg_response != NULL &&
                consume_proto_msg_response->code == E2EES__RESPONSE_CODE__RESPONSE_CODE_OK) {
                get_e2ees_plugin()->db_handler.unload_pending_request_data(
                    user_address, pending_request_id_list[i]);
            }
            // release
            free_proto(proto_msg);
            free_proto(consume_proto_msg_response);
            break;
        }
        default:
            e2ees_notify_log(
                user_address,
                DEBUG_LOG,
                "resend_pending_request() unknown pending request type: %d, %s",
                request_type_list[i]);
            break;
        };
        // release
        e2ees__pending_request__free_unpacked(pending_request, NULL);
        free(pending_request_id_list[i]);
        free_mem((void **)&(request_data_list[i]), request_data_len_list[i]);
    }

    // release
    if (pending_request_data_num > 0) {
        free_mem((void **)&pending_request_id_list, sizeof(char *) * pending_request_data_num);
        free_mem((void **)&request_type_list, sizeof(uint8_t) * pending_request_data_num);
        free_mem((void **)&request_data_list, sizeof(uint8_t *) * pending_request_data_num);
        free_mem((void **)&request_data_len_list, sizeof(size_t) * pending_request_data_num);
    }
}

void resume_connection_internal(E2ees__Account *account) {
    if (account == NULL)
        return;

    // renew and purge signed pre-keys
    purge_signed_pre_key(account);

    // check if there are too many "used" one-time pre-keys
    purge_one_time_pre_key(account);

    // try resend pending request from db
    uint32_t e2ees_pack_id           = account->e2ees_pack_id;
    E2ees__E2eeAddress *user_address = account->address;
    char *auth                       = account->auth;
    resend_pending_request(e2ees_pack_id, user_address, auth);
}
