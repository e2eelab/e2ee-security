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
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "e2ees/crypto.h"
#include "e2ees/mem_util.h"

static void test_file(){
    uint8_t key[AES256_KEY_LENGTH] = "aes_gcm_key_aes_gcm_key_aes_keys";
    uint8_t AD[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0";

    uint8_t *plaintext, *decrypted_plaintext;
    size_t plaintext_len, decrypted_plaintext_len;

    char *cur_path = getcwd(NULL, 0);
    size_t cur_path_len = strlen(cur_path);

    size_t tot_test = 2000;
    FILE *fptr;
    int i;
    for (i = 0; i < tot_test; i++){
        char in_file_path[20], out_file_path[cur_path_len + 50];
        sprintf(in_file_path, "./data/%d", i);
        if ((fptr = fopen(in_file_path, "r")) == NULL){
            printf("Error! Opening file in the data folder failed!\n");
            // Program exits if the file pointer returns NULL.
            exit(1);
        } else{
            fseek(fptr, 0, SEEK_END);
            plaintext_len = ftell(fptr);
            fseek(fptr, 0, SEEK_SET);
            plaintext = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_len);
            size_t bytes_read = fread(plaintext, 1, plaintext_len, fptr);
            if (bytes_read != plaintext_len && ferror(fptr)) {
                e2ees_notify_log(NULL, DEBUG_LOG, "[Error] Failed to read expected bytes from fptr.\n");
            }
            fclose(fptr);
        }

        sprintf(out_file_path, "%s/encrypted_file_%d", cur_path, i);
        crypto_encrypt_aes_file(in_file_path, out_file_path, key);

        char decrypted_file[cur_path_len + 50];
        sprintf(decrypted_file, "%s/decrypted_file_%d", cur_path, i);
        if (crypto_decrypt_aes_file(out_file_path, decrypted_file, key) == -1) {
            printf("Fail decryption!!!\n");
        }
        if ((fptr = fopen(decrypted_file, "r")) == NULL){
            printf("Error! Opening the decrypted file failed!\n");
            // Program exits if the file pointer returns NULL.
            exit(1);
        } else{
            fseek(fptr, 0, SEEK_END);
            decrypted_plaintext_len = ftell(fptr);
            fseek(fptr, 0, SEEK_SET);
            decrypted_plaintext = (uint8_t *)malloc(sizeof(uint8_t) * decrypted_plaintext_len);
            size_t bytes_read = fread(decrypted_plaintext, 1, decrypted_plaintext_len, fptr);
            if (bytes_read != decrypted_plaintext_len && ferror(fptr)) {
                e2ees_notify_log(NULL, DEBUG_LOG, "[Error] Failed to read expected bytes from fptr.\n");
            }
            fclose(fptr);
        }

        assert(decrypted_plaintext_len == plaintext_len);
        assert(memcmp(plaintext, decrypted_plaintext, plaintext_len) == 0);

        // release
        free_mem((void **)&plaintext, plaintext_len);
        free_mem((void **)&decrypted_plaintext, decrypted_plaintext_len);
    }

    free(cur_path);
}

int main() {
    test_file();

    return 0;
}
