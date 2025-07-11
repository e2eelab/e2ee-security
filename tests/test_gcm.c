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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "e2ees/mem_util.h"
#include "e2ees/crypto.h"
#include "gcm.h"
#include "config.h"
#include "platform.h"

#include "test_util.h"

static void test_file(){
    uint8_t key[32] = "aes_gcm_key_aes_gcm_key_aes_keys";
    uint8_t iv[16] = "aes_gcm_iv_aesiv";
    uint8_t AD[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01";
    uint8_t *plaintext, *ciphertext, *decrypted_plaintext;
    size_t plaintext_len, ciphertext_len, decrypted_plaintext_len;

    size_t tot_test = 2000;
    FILE *fptr;
    int i;
    for (i = 0; i < tot_test; i++){
        char str[20];
        sprintf(str, "./data/%d", i);
        if ((fptr = fopen(str, "r")) == NULL){
            printf("Error! opening file");
            // Program exits if the file pointer returns NULL.
            exit(1);
        } else{
            fseek(fptr, 0, SEEK_END);
            plaintext_len = ftell(fptr);
            fseek(fptr, 0, SEEK_SET);
            plaintext = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_len);
            fread(plaintext, 1, plaintext_len, fptr);
            fclose(fptr);
        }
        ciphertext_len = plaintext_len + AES256_GCM_TAG_LENGTH;
        ciphertext = (uint8_t *)malloc(sizeof(uint8_t) * ciphertext_len);
        crypto_aes_encrypt_gcm(plaintext, plaintext_len, key, iv, AD, 64, ciphertext);

        decrypted_plaintext = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_len);
        crypto_aes_decrypt_gcm(ciphertext, ciphertext_len, key, iv, AD, 64, decrypted_plaintext, &decrypted_plaintext_len);

        assert(decrypted_plaintext_len == plaintext_len);
        assert(memcmp(plaintext, decrypted_plaintext, plaintext_len) == 0);

        print_hex("plaintext", plaintext, plaintext_len);
        print_hex("decrypted_plaintext", decrypted_plaintext, decrypted_plaintext_len);

        free_mem((void **)&plaintext, plaintext_len);
        free_mem((void **)&ciphertext, ciphertext_len);
        free_mem((void **)&decrypted_plaintext, decrypted_plaintext_len);
    }
}

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/*
 * AES-GCM test vectors from:
 *
 * http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 */
#define MAX_TESTS   6

static const int key_index_test_data[MAX_TESTS] =
    { 0, 0, 1, 1, 1, 1 };

static const unsigned char key_test_data[MAX_TESTS][32] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 },
};

static const size_t iv_len_test_data[MAX_TESTS] =
    { 12, 12, 12, 12, 8, 60 };

static const int iv_index_test_data[MAX_TESTS] =
    { 0, 0, 1, 1, 1, 2 };

static const unsigned char iv_test_data[MAX_TESTS][64] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00 },
    { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
      0xde, 0xca, 0xf8, 0x88 },
    { 0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
      0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
      0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
      0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
      0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
      0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
      0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
      0xa6, 0x37, 0xb3, 0x9b },
};

static const size_t add_len_test_data[MAX_TESTS] =
    { 0, 0, 0, 20, 20, 20 };

static const int add_index_test_data[MAX_TESTS] =
    { 0, 0, 0, 1, 1, 1 };

static const unsigned char additional_test_data[MAX_TESTS][64] =
{
    { 0x00 },
    { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
      0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
      0xab, 0xad, 0xda, 0xd2 },
};

static const size_t pt_len_test_data[MAX_TESTS] =
    { 0, 16, 64, 60, 60, 60 };

static const int pt_index_test_data[MAX_TESTS] =
    { 0, 0, 1, 1, 1, 1 };

static const unsigned char pt_test_data[MAX_TESTS][64] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
      0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
      0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
      0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
      0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
      0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
      0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
      0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 },
};

static const unsigned char ct_test_data[MAX_TESTS * 3][64] =
{
    { 0x00 },
    { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78 },
    { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
      0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
      0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
      0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
      0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
      0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
      0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
      0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85 },
    { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
      0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
      0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
      0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
      0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
      0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
      0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
      0x3d, 0x58, 0xe0, 0x91 },
    { 0x61, 0x35, 0x3b, 0x4c, 0x28, 0x06, 0x93, 0x4a,
      0x77, 0x7f, 0xf5, 0x1f, 0xa2, 0x2a, 0x47, 0x55,
      0x69, 0x9b, 0x2a, 0x71, 0x4f, 0xcd, 0xc6, 0xf8,
      0x37, 0x66, 0xe5, 0xf9, 0x7b, 0x6c, 0x74, 0x23,
      0x73, 0x80, 0x69, 0x00, 0xe4, 0x9f, 0x24, 0xb2,
      0x2b, 0x09, 0x75, 0x44, 0xd4, 0x89, 0x6b, 0x42,
      0x49, 0x89, 0xb5, 0xe1, 0xeb, 0xac, 0x0f, 0x07,
      0xc2, 0x3f, 0x45, 0x98 },
    { 0x8c, 0xe2, 0x49, 0x98, 0x62, 0x56, 0x15, 0xb6,
      0x03, 0xa0, 0x33, 0xac, 0xa1, 0x3f, 0xb8, 0x94,
      0xbe, 0x91, 0x12, 0xa5, 0xc3, 0xa2, 0x11, 0xa8,
      0xba, 0x26, 0x2a, 0x3c, 0xca, 0x7e, 0x2c, 0xa7,
      0x01, 0xe4, 0xa9, 0xa4, 0xfb, 0xa4, 0x3c, 0x90,
      0xcc, 0xdc, 0xb2, 0x81, 0xd4, 0x8c, 0x7c, 0x6f,
      0xd6, 0x28, 0x75, 0xd2, 0xac, 0xa4, 0x17, 0x03,
      0x4c, 0x34, 0xae, 0xe5 },
    { 0x00 },
    { 0x98, 0xe7, 0x24, 0x7c, 0x07, 0xf0, 0xfe, 0x41,
      0x1c, 0x26, 0x7e, 0x43, 0x84, 0xb0, 0xf6, 0x00 },
    { 0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41,
      0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a, 0x27, 0x57,
      0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84,
      0x62, 0x85, 0x93, 0xb4, 0x0c, 0xa1, 0xe1, 0x9c,
      0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25,
      0xac, 0x61, 0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47,
      0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
      0xcc, 0xda, 0x27, 0x10, 0xac, 0xad, 0xe2, 0x56 },
    { 0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41,
      0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a, 0x27, 0x57,
      0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84,
      0x62, 0x85, 0x93, 0xb4, 0x0c, 0xa1, 0xe1, 0x9c,
      0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25,
      0xac, 0x61, 0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47,
      0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
      0xcc, 0xda, 0x27, 0x10 },
    { 0x0f, 0x10, 0xf5, 0x99, 0xae, 0x14, 0xa1, 0x54,
      0xed, 0x24, 0xb3, 0x6e, 0x25, 0x32, 0x4d, 0xb8,
      0xc5, 0x66, 0x63, 0x2e, 0xf2, 0xbb, 0xb3, 0x4f,
      0x83, 0x47, 0x28, 0x0f, 0xc4, 0x50, 0x70, 0x57,
      0xfd, 0xdc, 0x29, 0xdf, 0x9a, 0x47, 0x1f, 0x75,
      0xc6, 0x65, 0x41, 0xd4, 0xd4, 0xda, 0xd1, 0xc9,
      0xe9, 0x3a, 0x19, 0xa5, 0x8e, 0x8b, 0x47, 0x3f,
      0xa0, 0xf0, 0x62, 0xf7 },
    { 0xd2, 0x7e, 0x88, 0x68, 0x1c, 0xe3, 0x24, 0x3c,
      0x48, 0x30, 0x16, 0x5a, 0x8f, 0xdc, 0xf9, 0xff,
      0x1d, 0xe9, 0xa1, 0xd8, 0xe6, 0xb4, 0x47, 0xef,
      0x6e, 0xf7, 0xb7, 0x98, 0x28, 0x66, 0x6e, 0x45,
      0x81, 0xe7, 0x90, 0x12, 0xaf, 0x34, 0xdd, 0xd9,
      0xe2, 0xf0, 0x37, 0x58, 0x9b, 0x29, 0x2d, 0xb3,
      0xe6, 0x7c, 0x03, 0x67, 0x45, 0xfa, 0x22, 0xe7,
      0xe9, 0xb7, 0x37, 0x3b },
    { 0x00 },
    { 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
      0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18 },
    { 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
      0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
      0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
      0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
      0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
      0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
      0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
      0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad },
    { 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
      0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
      0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
      0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
      0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
      0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
      0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
      0xbc, 0xc9, 0xf6, 0x62 },
    { 0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32,
      0xae, 0x47, 0xc1, 0x3b, 0xf1, 0x98, 0x44, 0xcb,
      0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa,
      0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0,
      0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0,
      0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78,
      0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99,
      0xf4, 0x7c, 0x9b, 0x1f },
    { 0x5a, 0x8d, 0xef, 0x2f, 0x0c, 0x9e, 0x53, 0xf1,
      0xf7, 0x5d, 0x78, 0x53, 0x65, 0x9e, 0x2a, 0x20,
      0xee, 0xb2, 0xb2, 0x2a, 0xaf, 0xde, 0x64, 0x19,
      0xa0, 0x58, 0xab, 0x4f, 0x6f, 0x74, 0x6b, 0xf4,
      0x0f, 0xc0, 0xc3, 0xb7, 0x80, 0xf2, 0x44, 0x45,
      0x2d, 0xa3, 0xeb, 0xf1, 0xc5, 0xd8, 0x2c, 0xde,
      0xa2, 0x41, 0x89, 0x97, 0x20, 0x0e, 0xf8, 0x2e,
      0x44, 0xae, 0x7e, 0x3f },
};

static const unsigned char tag_test_data[MAX_TESTS * 3][16] =
{
    { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
      0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a },
    { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
      0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf },
    { 0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
      0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4 },
    { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
      0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47 },
    { 0x36, 0x12, 0xd2, 0xe7, 0x9e, 0x3b, 0x07, 0x85,
      0x56, 0x1b, 0xe1, 0x4a, 0xac, 0xa2, 0xfc, 0xcb },
    { 0x61, 0x9c, 0xc5, 0xae, 0xff, 0xfe, 0x0b, 0xfa,
      0x46, 0x2a, 0xf4, 0x3c, 0x16, 0x99, 0xd0, 0x50 },
    { 0xcd, 0x33, 0xb2, 0x8a, 0xc7, 0x73, 0xf7, 0x4b,
      0xa0, 0x0e, 0xd1, 0xf3, 0x12, 0x57, 0x24, 0x35 },
    { 0x2f, 0xf5, 0x8d, 0x80, 0x03, 0x39, 0x27, 0xab,
      0x8e, 0xf4, 0xd4, 0x58, 0x75, 0x14, 0xf0, 0xfb },
    { 0x99, 0x24, 0xa7, 0xc8, 0x58, 0x73, 0x36, 0xbf,
      0xb1, 0x18, 0x02, 0x4d, 0xb8, 0x67, 0x4a, 0x14 },
    { 0x25, 0x19, 0x49, 0x8e, 0x80, 0xf1, 0x47, 0x8f,
      0x37, 0xba, 0x55, 0xbd, 0x6d, 0x27, 0x61, 0x8c },
    { 0x65, 0xdc, 0xc5, 0x7f, 0xcf, 0x62, 0x3a, 0x24,
      0x09, 0x4f, 0xcc, 0xa4, 0x0d, 0x35, 0x33, 0xf8 },
    { 0xdc, 0xf5, 0x66, 0xff, 0x29, 0x1c, 0x25, 0xbb,
      0xb8, 0x56, 0x8f, 0xc3, 0xd3, 0x76, 0xa6, 0xd9 },
    { 0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
      0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b },
    { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
      0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19 },
    { 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
      0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c },
    { 0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
      0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b },
    { 0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4,
      0x5e, 0x45, 0x49, 0x13, 0xfe, 0x2e, 0xa8, 0xf2 },
    { 0xa4, 0x4a, 0x82, 0x66, 0xee, 0x1c, 0x8e, 0xb0,
      0xc8, 0xb5, 0xd4, 0xcf, 0x5a, 0xe9, 0xf1, 0x9a },
};

int mbedtls_gcm_self_test( int verbose )
{
    mbedtls_gcm_context ctx;
    unsigned char buf[64];
    unsigned char tag_buf[16];
    int i, j, ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    for( j = 0; j < 3; j++ )
    {
        int key_len = 128 + 64 * j;

        for( i = 0; i < MAX_TESTS; i++ )
        {
            mbedtls_gcm_init( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "  AES-GCM-%3d #%d (%s): ",
                                key_len, i, "enc" );

            ret = mbedtls_gcm_setkey( &ctx, cipher,
                                      key_test_data[key_index_test_data[i]],
                                      key_len );
            /*
             * AES-192 is an optional feature that may be unavailable when
             * there is an alternative underlying implementation i.e. when
             * MBEDTLS_AES_ALT is defined.
             */
            if( ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && key_len == 192 )
            {
                mbedtls_printf( "skipped\n" );
                break;
            }
            else if( ret != 0 )
            {
                goto exit;
            }

            ret = mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_ENCRYPT,
                                pt_len_test_data[i],
                                iv_test_data[iv_index_test_data[i]],
                                iv_len_test_data[i],
                                additional_test_data[add_index_test_data[i]],
                                add_len_test_data[i],
                                pt_test_data[pt_index_test_data[i]],
                                buf, 16, tag_buf );

            if( ret != 0 )
                goto exit;

            if ( memcmp( buf, ct_test_data[j * 6 + i],
                         pt_len_test_data[i] ) != 0 ||
                 memcmp( tag_buf, tag_test_data[j * 6 + i], 16 ) != 0 )
            {
                ret = 1;
                goto exit;
            }

            mbedtls_gcm_free( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "passed\n" );

            mbedtls_gcm_init( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "  AES-GCM-%3d #%d (%s): ",
                                key_len, i, "dec" );

            ret = mbedtls_gcm_setkey( &ctx, cipher,
                                      key_test_data[key_index_test_data[i]],
                                      key_len );
            if( ret != 0 )
                goto exit;

            ret = mbedtls_gcm_crypt_and_tag( &ctx, MBEDTLS_GCM_DECRYPT,
                                pt_len_test_data[i],
                                iv_test_data[iv_index_test_data[i]],
                                iv_len_test_data[i],
                                additional_test_data[add_index_test_data[i]],
                                add_len_test_data[i],
                                ct_test_data[j * 6 + i], buf, 16, tag_buf );

            if( ret != 0 )
                goto exit;

            if( memcmp( buf, pt_test_data[pt_index_test_data[i]],
                        pt_len_test_data[i] ) != 0 ||
                memcmp( tag_buf, tag_test_data[j * 6 + i], 16 ) != 0 )
            {
                ret = 1;
                goto exit;
            }

            mbedtls_gcm_free( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "passed\n" );

            mbedtls_gcm_init( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "  AES-GCM-%3d #%d split (%s): ",
                                key_len, i, "enc" );

            ret = mbedtls_gcm_setkey( &ctx, cipher,
                                      key_test_data[key_index_test_data[i]],
                                      key_len );
            if( ret != 0 )
                goto exit;

            ret = mbedtls_gcm_starts( &ctx, MBEDTLS_GCM_ENCRYPT,
                                  iv_test_data[iv_index_test_data[i]],
                                  iv_len_test_data[i],
                                  additional_test_data[add_index_test_data[i]],
                                  add_len_test_data[i] );
            if( ret != 0 )
                goto exit;

            if( pt_len_test_data[i] > 32 )
            {
                size_t rest_len = pt_len_test_data[i] - 32;
                ret = mbedtls_gcm_update( &ctx, 32,
                                          pt_test_data[pt_index_test_data[i]],
                                          buf );
                if( ret != 0 )
                    goto exit;

                ret = mbedtls_gcm_update( &ctx, rest_len,
                                      pt_test_data[pt_index_test_data[i]] + 32,
                                      buf + 32 );
                if( ret != 0 )
                    goto exit;
            }
            else
            {
                ret = mbedtls_gcm_update( &ctx, pt_len_test_data[i],
                                          pt_test_data[pt_index_test_data[i]],
                                          buf );
                if( ret != 0 )
                    goto exit;
            }

            ret = mbedtls_gcm_finish( &ctx, tag_buf, 16 );
            if( ret != 0 )
                goto exit;

            if( memcmp( buf, ct_test_data[j * 6 + i],
                        pt_len_test_data[i] ) != 0 ||
                memcmp( tag_buf, tag_test_data[j * 6 + i], 16 ) != 0 )
            {
                ret = 1;
                goto exit;
            }

            mbedtls_gcm_free( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "passed\n" );

            mbedtls_gcm_init( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "  AES-GCM-%3d #%d split (%s): ",
                                key_len, i, "dec" );

            ret = mbedtls_gcm_setkey( &ctx, cipher,
                                      key_test_data[key_index_test_data[i]],
                                      key_len );
            if( ret != 0 )
                goto exit;

            ret = mbedtls_gcm_starts( &ctx, MBEDTLS_GCM_DECRYPT,
                              iv_test_data[iv_index_test_data[i]],
                              iv_len_test_data[i],
                              additional_test_data[add_index_test_data[i]],
                              add_len_test_data[i] );
            if( ret != 0 )
                goto exit;

            if( pt_len_test_data[i] > 32 )
            {
                size_t rest_len = pt_len_test_data[i] - 32;
                ret = mbedtls_gcm_update( &ctx, 32, ct_test_data[j * 6 + i],
                                          buf );
                if( ret != 0 )
                    goto exit;

                ret = mbedtls_gcm_update( &ctx, rest_len,
                                          ct_test_data[j * 6 + i] + 32,
                                          buf + 32 );
                if( ret != 0 )
                    goto exit;
            }
            else
            {
                ret = mbedtls_gcm_update( &ctx, pt_len_test_data[i],
                                          ct_test_data[j * 6 + i],
                                          buf );
                if( ret != 0 )
                    goto exit;
            }

            ret = mbedtls_gcm_finish( &ctx, tag_buf, 16 );
            if( ret != 0 )
                goto exit;

            if( memcmp( buf, pt_test_data[pt_index_test_data[i]],
                        pt_len_test_data[i] ) != 0 ||
                memcmp( tag_buf, tag_test_data[j * 6 + i], 16 ) != 0 )
            {
                ret = 1;
                goto exit;
            }

            mbedtls_gcm_free( &ctx );

            if( verbose != 0 )
                mbedtls_printf( "passed\n" );
        }
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    ret = 0;

exit:
    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );
        mbedtls_gcm_free( &ctx );
    }

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

int main(){
    test_file();
    assert(mbedtls_gcm_self_test(1) == 0);
    return 0;
}
