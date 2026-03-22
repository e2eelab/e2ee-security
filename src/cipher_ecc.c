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
#include "e2ees/cipher_ecc.h"

#include <stdbool.h>
#include <string.h>

#include <additions/curve_sigs.h>
#include <curve25519-donna.h>

#include "e2ees/cipher.h"
#include "e2ees/crypto.h"

static const uint8_t CURVE25519_BASEPOINT[32]  = { 9 };

static crypto_ds_param_t curve25519_sign_param = {
    false, CURVE25519_KEY_LENGTH, CURVE25519_KEY_LENGTH, CURVE_SIGNATURE_LENGTH
};

static crypto_ds_param_t crypto_ds_params_curve25519() { return curve25519_sign_param; }

static crypto_kem_param_t curve25519_ECDH_param = {
    false, CURVE25519_KEY_LENGTH, CURVE25519_KEY_LENGTH, 0, CURVE25519_KEY_LENGTH
};

static crypto_kem_param_t crypto_kem_params_curve25519() { return curve25519_ECDH_param; }

// default digital signature suite with ecc
struct ds_suite_t E2EES_DS_CURVE25519 = { crypto_ds_params_curve25519,
                                          crypto_ds_key_gen_curve25519,
                                          crypto_ds_sign_curve25519,
                                          crypto_ds_verify_curve25519 };

// default kem suite with ecc
struct kem_suite_t E2EES_KEM_CURVE25519_ECDH = { crypto_kem_params_curve25519,
                                                 crypto_kem_asym_key_gen_curve25519,
                                                 NULL,
                                                 crypto_kem_decaps_curve25519 };