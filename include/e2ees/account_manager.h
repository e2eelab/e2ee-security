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

#ifndef ACCOUNT_MANAGER_H_
#define ACCOUNT_MANAGER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "e2ees/e2ees.h"

/**
 * @brief Create a RegisterUserRequest message to be sent to server.
 *
 * @param request_out
 * @param params
 * @param account
 * @return 0 if success
 */
int produce_register_request(
    E2ees__RegisterUserRequest **request_out,
    register_user_params *params,
    E2ees__Account *account
);

/**
 * @brief Process an incoming RegisterUserResponse message.
 *
 * @param account
 * @param payload
 * @return true
 * @return false
 */
bool consume_register_response(E2ees__Account *account, E2ees__RegisterUserResponse *payload);

/**
 * @brief Create a PublishSpkRequest message to be sent to server.
 *
 * @param request_out
 * @param params
 * @return 0 if success
 */
int produce_publish_spk_request(
    E2ees__PublishSpkRequest **request_out,
    publish_spk_params *params
);

/**
 * @brief Process an incoming PublishSpkResponse message.
 *
 * @param account
 * @param response
 * @return 0 if success
 */
int consume_publish_spk_response(
    E2ees__E2eeAddress *user_address,
    E2ees__SignedPreKey *signed_pre_key,
    E2ees__PublishSpkResponse *response
);

/**
 * @brief Create a SupplyOpksRequest message to be sent to server.
 *
 * @param request_out
 * @param params
 * @param one_time_pre_key_list
 * @return 0 if success
 */
int produce_supply_opks_request(
    E2ees__SupplyOpksRequest **request_out,
    supply_opks_params *params,
    E2ees__OneTimePreKey **one_time_pre_key_list
);

/**
 * @brief Process an incoming SupplyOpksResponse message.
 *
 * @param account
 * @param one_time_pre_key_list
 * @param opks_num
 * @param response
 * @return 0 if success
 */
int consume_supply_opks_response(E2ees__Account *account, E2ees__OneTimePreKey **one_time_pre_key_list, uint32_t opks_num, E2ees__SupplyOpksResponse *response);

/**
 * @brief Process an incoming SupplyOpksMsg message.
 *
 * @param receiver_address
 * @param msg
 * @return true
 * @return false
 */
bool consume_supply_opks_msg(E2ees__E2eeAddress *receiver_address, E2ees__SupplyOpksMsg *msg);

#ifdef __cplusplus
}
#endif

#endif // ACCOUNT_MANAGER_H_
