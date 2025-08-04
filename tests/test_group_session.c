/**
 * @file
 * @copyright © 2020-2021 by Academia Sinica
 * @brief group session test
 *
 * @page test_group_session group session documentation
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
 * 
 * @section test_create_group
 * Alice creates a group with four members in it. Everyone in the group sends a message to the group.
 * 
 * @section test_add_group_members
 * Alice creates a group with three members in it. Then Alice adds a group member. Next, everyone in the group sends a message to the group.
 * 
 * @section test_remove_group_members
 * Alice creates a group with four members in it. Then Alice removes a group member. Next, everyone in the group sends a message to the group.
 * 
 * @section test_create_add_remove
 * Alice creates a group with two members in it. Then Alice adds a group member. Next, everyone in the group sends a message to the group. Then Alice removes a group member. Next, everyone in the group sends a message to the group.
 * 
 * @section test_leave_group
 * Alice creates a group with four members in it. Then one of the group members leaves the group. Next, everyone in the group sends a message to the group.
 * 
 * @section test_continual
 * Alice creates a group with three members in it. Then everyone in the group sends 1000 messages to the group.
 * 
 * @section test_multiple_devices
 * Everyone in the three-member group has two devices. Everyone in the group sends a message to the group.
 * 
 * @section test_add_new_device
 * One of the group members adds a new device.
 * 
 * @section test_medium_group
 * 
 * 
 * 
 * 
 * @defgroup group_session_int group session integration test
 * @ingroup Integration
 * This includes integration tests about group session.
 * 
 * @defgroup group_session_test_create_group create group test
 * @ingroup group_session_int
 * @{
 * @section sec41001 Test Case ID
 * v1.0ig01
 * @section sec41002 Test Case Title
 * test_create_group
 * @section sec41003 Test Description
 * Alice creates a group with four members in it. Everyone in the group sends a message to the group.
 * @section sec41004 Test Objectives
 * To verify the create group protocol.
 * @section sec41005 Preconditions
 * @section sec41006 Test Steps
 * Step 1: Alice invites Bob, Claire and David to create a group.\n
 * Step 2: Everyone in the group sends a message to the group.
 * @section sec41007 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_add_group_members add group members test
 * @ingroup group_session_int
 * @{
 * @section sec41101 Test Case ID
 * v1.0ig02
 * @section sec41102 Test Case Title
 * test_add_group_members
 * @section sec41103 Test Description
 * Alice creates a group with three members in it. Then Alice adds a group member.
 * Next, everyone in the group sends a message to the group.
 * @section sec41104 Test Objectives
 * To verify the add group members protocol.
 * @section sec41105 Preconditions
 * @section sec41106 Test Steps
 * Step 1: Alice invites Bob and Claire to create a group.\n
 * Step 2: Alice invites David to join the group.\n
 * Step 3: Everyone in the group sends a message to the group.
 * @section sec41107 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_remove_group_members remove group members test
 * @ingroup group_session_int
 * @{
 * @section sec41201 Test Case ID
 * v1.0ig03
 * @section sec41202 Test Case Title
 * test_remove_group_members
 * @section sec41203 Test Description
 * Alice creates a group with four members in it. Then Alice removes a group member.
 * Next, everyone in the group sends a message to the group.
 * @section sec41204 Test Objectives
 * To verify the remove group members protocol.
 * @section sec41205 Preconditions
 * @section sec41206 Test Steps
 * Step 1: Alice invites Bob, Claire and David to create a group.\n
 * Step 2: Alice removes Claire out of the group.\n
 * Step 3: Everyone in the group sends a message to the group.
 * @section sec41207 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_create_add_remove group test
 * @ingroup group_session_int
 * @{
 * @section sec41301 Test Case ID
 * v1.0ig04
 * @section sec41302 Test Case Title
 * test_create_add_remove
 * @section sec41303 Test Description
 * Alice creates a group with two members in it. Then Alice adds a group member.
 * Next, everyone in the group sends a message to the group. Then Alice removes a group member.
 * Next, everyone in the group sends a message to the group.
 * @section sec41304 Test Objectives
 * To assure that the action of creating a group, adding group members and removing group members can be processed in a small group.
 * @section sec41305 Preconditions
 * @section sec41306 Test Steps
 * Step 1: Alice invites Bob to create a group.\n
 * Step 2: Alice sends a message to the group.\n
 * Step 3: Alice invites Claire to join the group.\n
 * Step 4: Alice sends a message to the group.\n
 * Step 5: Alice removes Bob out of the group.\n
 * Step 6: Alice sends a message to the group.
 * @section sec41307 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_leave_group leave group test
 * @ingroup group_session_int
 * @{
 * @section sec41401 Test Case ID
 * v1.0ig05
 * @section sec41402 Test Case Title
 * test_leave_group
 * @section sec41403 Test Description
 * Alice creates a group with four members in it. Then one of the group members leaves the group.
 * Next, everyone in the group sends a message to the group.
 * @section sec41404 Test Objectives
 * To verify the leave group protocol.
 * @section sec41405 Preconditions
 * @section sec41406 Test Steps
 * Step 1: Alice invites Bob, Claire and David to create a group.\n
 * Step 2: Claire leaves the group.\n
 * Step 3: Everyone in the group sends a message to the group.
 * @section sec41407 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_continual continual messages test
 * @ingroup group_session_int
 * @{
 * @section sec41501 Test Case ID
 * v1.0ig06
 * @section sec41502 Test Case Title
 * test_continual
 * @section sec41503 Test Description
 * Alice creates a group with three members in it. Then everyone in the group sends 1000 messages to the group.
 * @section sec41504 Test Objectives
 * To assure that a large number of messages can be decrypted by every group member.
 * @section sec41505 Preconditions
 * @section sec41506 Test Steps
 * Step 1: Alice invites Bob and Claire to create a group.\n
 * Step 2: Everyone in the group sends 1000 messages to the group.
 * @section sec41507 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_multiple_devices multiple devices test
 * @ingroup group_session_int
 * @{
 * @section sec41601 Test Case ID
 * v1.0ig07
 * @section sec41602 Test Case Title
 * test_multiple_devices
 * @section sec41603 Test Description
 * Everyone in the three-member group has two devices. Everyone in the group sends a message to the group.
 * @section sec41604 Test Objectives
 * To assure that the group session mechanism is applicable to multiple devices.
 * @section sec41605 Preconditions
 * @section sec41606 Test Steps
 * Step 1: Alice invites Bob and Claire to create a group.\n
 * Step 2: Alice sends a message to the group with her first device.\n
 * Step 3: Bob sends a message to the group with his second device.\n
 * Step 4: Claire sends a message to the group with her second device.
 * @section sec41607 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_add_new_device new devices test
 * @ingroup group_session_int
 * @{
 * @section sec41701 Test Case ID
 * v1.0ig08
 * @section sec41702 Test Case Title
 * test_add_new_device
 * @section sec41703 Test Description
 * One of the group members adds a new device.
 * @section sec41704 Test Objectives
 * To assure that the group session can be used once one of the group members adds a new device.
 * @section sec41705 Preconditions
 * @section sec41706 Test Steps
 * Step 1: Alice invites Bob and Claire to create a group.\n
 * Step 2: Alice adds a new device.\n
 * Step 3: Alice sends a message to the group with her first device.
 * @section sec41707 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 * @defgroup group_session_test_medium_group a medium group test
 * @ingroup group_session_int
 * @{
 * @section sec41801 Test Case ID
 * v1.0ig09
 * @section sec41802 Test Case Title
 * test_medium_group
 * @section sec41803 Test Description
 * There are 14 members in the test. Some group action such as group creation, adding group members, 
 * removing group members will be implemented.
 * @section sec41804 Test Objectives
 * To verify that a group session with twenty members or so can be used.
 * @section sec41805 Preconditions
 * @section sec41806 Test Steps
 * Step 1: Alice invites Bob, Claire, David, Emily, Frank, Grace, Harry, Ivy, Jack to create a group.\n
 * Step 2: Alice, David and Grace send a message to the group.\n
 * Step 3: Alice invites Karen, Leo, Mary, Nick to join the group.\n
 * Step 4: Jack, Karen and Nick send a message to the group.\n
 * Step 5: Alice removes David, Ivy, Karen, Leo out of the group.\n
 * Step 6: Bob and Mary send a message to the group.
 * @section sec41807 Expected Results
 * The output of the decrypted messages.
 * @}
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "e2ees/account.h"
#include "e2ees/account_manager.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/group_session.h"
#include "e2ees/group_session_manager.h"
#include "e2ees/mem_util.h"

#include "mock_server_sending.h"
#include "test_util.h"
#include "test_plugin.h"

#define account_data_max 205

static char *mock_user_name[200] = {
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "AA", "AB", "AC", "AD", "AE", "AF", "AG", "AH", "AI", "AJ", "AK", "AL", "AM", "AN", "AO", "AP", "AQ", "AR", "AS", "AT", "AU", "AV", "AW", "AX", "AY", "AZ",
    "BA", "BB", "BC", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BK", "BL", "BM", "BN", "BO", "BP", "BQ", "BR", "BS", "BT", "BU", "BV", "BW", "BX", "BY", "BZ",
    "CA", "CB", "CC", "CD", "CE", "CF", "CG", "CH", "CI", "CJ", "CK", "CL", "CM", "CN", "CO", "CP", "CQ", "CR", "CS", "CT", "CU", "CV", "CW", "CX", "CY", "CZ",
    "DA", "DB", "DC", "DD", "DE", "DF", "DG", "DH", "DI", "DJ", "DK", "DL", "DM", "DN", "DO", "DP", "DQ", "DR", "DS", "DT", "DU", "DV", "DW", "DX", "DY", "DZ",
    "EA", "EB", "EC", "ED", "EE", "EF", "EG", "EH", "EI", "EJ", "EK", "EL", "EM", "EN", "EO", "EP", "EQ", "ER", "ES", "ET", "EU", "EV", "EW", "EX", "EY", "EZ",
    "FA", "FB", "FC", "FD", "FE", "FF", "FG", "FH", "FI", "FJ", "FK", "FL", "FM", "FN", "FO", "FP", "FQ", "FR", "FS", "FT", "FU", "FV", "FW", "FX", "FY", "FZ",
    "GA", "GB", "GC", "GD", "GE", "GF", "GG", "GH", "GI", "GJ", "GK", "GL", "GM", "GN", "GO", "GP", "GQ", "GR"
};

static char *mock_authenticator[200] = {
    "a@domain.com.tw", "b@domain.com.tw", "c@domain.com.tw", "d@domain.com.tw", "e@domain.com.tw",
    "f@domain.com.tw", "g@domain.com.tw", "h@domain.com.tw", "i@domain.com.tw", "j@domain.com.tw",
    "k@domain.com.tw", "l@domain.com.tw", "m@domain.com.tw", "n@domain.com.tw", "o@domain.com.tw",
    "p@domain.com.tw", "q@domain.com.tw", "r@domain.com.tw", "s@domain.com.tw", "t@domain.com.tw",
    "u@domain.com.tw", "v@domain.com.tw", "w@domain.com.tw", "x@domain.com.tw", "y@domain.com.tw",
    "z@domain.com.tw", "aa@domain.com.tw", "ab@domain.com.tw", "ac@domain.com.tw", "ad@domain.com.tw",
    "ae@domain.com.tw", "af@domain.com.tw", "ag@domain.com.tw", "ah@domain.com.tw", "ai@domain.com.tw",
    "aj@domain.com.tw", "ak@domain.com.tw", "al@domain.com.tw", "am@domain.com.tw", "an@domain.com.tw",
    "ao@domain.com.tw", "ap@domain.com.tw", "aq@domain.com.tw", "ar@domain.com.tw", "as@domain.com.tw",
    "at@domain.com.tw", "au@domain.com.tw", "av@domain.com.tw", "aw@domain.com.tw", "ax@domain.com.tw",
    "ay@domain.com.tw", "az@domain.com.tw", "ba@domain.com.tw", "bb@domain.com.tw", "bc@domain.com.tw",
    "bd@domain.com.tw", "be@domain.com.tw", "bf@domain.com.tw", "bg@domain.com.tw", "bh@domain.com.tw",
    "bi@domain.com.tw", "bj@domain.com.tw", "bk@domain.com.tw", "bl@domain.com.tw", "bm@domain.com.tw",
    "bn@domain.com.tw", "bo@domain.com.tw", "bp@domain.com.tw", "bq@domain.com.tw", "br@domain.com.tw",
    "bs@domain.com.tw", "bt@domain.com.tw", "bu@domain.com.tw", "bv@domain.com.tw", "bw@domain.com.tw",
    "bx@domain.com.tw", "by@domain.com.tw", "bz@domain.com.tw", "ca@domain.com.tw", "cb@domain.com.tw",
    "cc@domain.com.tw", "cd@domain.com.tw", "ce@domain.com.tw", "cf@domain.com.tw", "cg@domain.com.tw",
    "ch@domain.com.tw", "ci@domain.com.tw", "cj@domain.com.tw", "ck@domain.com.tw", "cl@domain.com.tw",
    "cm@domain.com.tw", "cn@domain.com.tw", "co@domain.com.tw", "cp@domain.com.tw", "cqe@domain.com.tw",
    "cr@domain.com.tw", "cs@domain.com.tw", "ct@domain.com.tw", "cu@domain.com.tw", "cv@domain.com.tw",
    "cw@domain.com.tw", "cx@domain.com.tw", "cy@domain.com.tw", "cz@domain.com.tw", "da@domain.com.tw",
    "db@domain.com.tw", "dc@domain.com.tw", "dd@domain.com.tw", "de@domain.com.tw", "df@domain.com.tw",
    "dg@domain.com.tw", "dh@domain.com.tw", "di@domain.com.tw", "dj@domain.com.tw", "dk@domain.com.tw",
    "dl@domain.com.tw", "dm@domain.com.tw", "dn@domain.com.tw", "do@domain.com.tw", "dp@domain.com.tw",
    "dq@domain.com.tw", "dr@domain.com.tw", "ds@domain.com.tw", "dt@domain.com.tw", "du@domain.com.tw",
    "dv@domain.com.tw", "dw@domain.com.tw", "dx@domain.com.tw", "dy@domain.com.tw", "dz@domain.com.tw",
    "ea@domain.com.tw", "eb@domain.com.tw", "ec@domain.com.tw", "ed@domain.com.tw", "ee@domain.com.tw",
    "ef@domain.com.tw", "eg@domain.com.tw", "eh@domain.com.tw", "ei@domain.com.tw", "ej@domain.com.tw",
    "ek@domain.com.tw", "el@domain.com.tw", "em@domain.com.tw", "en@domain.com.tw", "eo@domain.com.tw",
    "ep@domain.com.tw", "eq@domain.com.tw", "er@domain.com.tw", "es@domain.com.tw", "et@domain.com.tw",
    "eu@domain.com.tw", "ev@domain.com.tw", "ew@domain.com.tw", "ex@domain.com.tw", "ey@domain.com.tw",
    "ez@domain.com.tw", "fa@domain.com.tw", "fb@domain.com.tw", "fc@domain.com.tw", "fd@domain.com.tw",
    "fe@domain.com.tw", "ff@domain.com.tw", "fg@domain.com.tw", "fh@domain.com.tw", "fi@domain.com.tw",
    "fj@domain.com.tw", "fk@domain.com.tw", "fl@domain.com.tw", "fm@domain.com.tw", "fn@domain.com.tw",
    "fo@domain.com.tw", "fp@domain.com.tw", "fq@domain.com.tw", "fr@domain.com.tw", "fs@domain.com.tw",
    "ft@domain.com.tw", "fu@domain.com.tw", "fv@domain.com.tw", "fw@domain.com.tw", "fx@domain.com.tw",
    "fy@domain.com.tw", "fz@domain.com.tw", "ga@domain.com.tw", "gb@domain.com.tw", "gc@domain.com.tw",
    "gd@domain.com.tw", "ge@domain.com.tw", "gf@domain.com.tw", "gg@domain.com.tw", "gh@domain.com.tw",
    "gi@domain.com.tw", "gj@domain.com.tw", "gk@domain.com.tw", "gl@domain.com.tw", "gm@domain.com.tw",
    "gn@domain.com.tw", "go@domain.com.tw", "gp@domain.com.tw", "gq@domain.com.tw", "gr@domain.com.tw"
};

static char *mock_auth_code[200] = {
    "000001", "000002", "000003", "000004", "000005", "000006", "000007", "000008", "000009", "000010",
    "000011", "000012", "000013", "000014", "000015", "000016", "000017", "000018", "000019", "000020",
    "000021", "000022", "000023", "000024", "000025", "000026", "000027", "000028", "000029", "000030",
    "000031", "000032", "000033", "000034", "000035", "000036", "000037", "000038", "000039", "000040",
    "000041", "000042", "000043", "000044", "000045", "000046", "000047", "000048", "000049", "000050",
    "000051", "000052", "000053", "000054", "000055", "000056", "000057", "000058", "000059", "000060",
    "000061", "000062", "000063", "000064", "000065", "000066", "000067", "000068", "000069", "000070",
    "000071", "000072", "000073", "000074", "000075", "000076", "000077", "000078", "000079", "000080",
    "000081", "000082", "000083", "000084", "000085", "000086", "000087", "000088", "000089", "000090",
    "000091", "000092", "000093", "000094", "000095", "000096", "000097", "000098", "000099", "000100",
    "000101", "000102", "000103", "000104", "000105", "000106", "000107", "000108", "000109", "000110",
    "000111", "000112", "000113", "000114", "000115", "000116", "000117", "000118", "000119", "000120",
    "000121", "000122", "000123", "000124", "000125", "000126", "000127", "000128", "000129", "000130",
    "000131", "000132", "000133", "000134", "000135", "000136", "000137", "000138", "000139", "000140",
    "000141", "000142", "000143", "000144", "000145", "000146", "000147", "000148", "000149", "000150",
    "000151", "000152", "000153", "000154", "000155", "000156", "000157", "000158", "000159", "000160",
    "000161", "000162", "000163", "000164", "000165", "000166", "000167", "000168", "000169", "000170",
    "000171", "000172", "000173", "000174", "000175", "000176", "000177", "000178", "000179", "000180",
    "000181", "000182", "000183", "000184", "000185", "000186", "000187", "000188", "000189", "000190",
    "000191", "000192", "000193", "000194", "000195", "000196", "000197", "000198", "000199", "000200"
};

static int ret;

static E2ees__Account *account_data[account_data_max];

static uint8_t account_data_insert_pos;

typedef struct store_group {
    E2ees__E2eeAddress *group_address;
    char *group_name;
} store_group;

store_group group = {NULL, NULL};

static void on_log(E2ees__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    if (log_code == 0)
        return;
    print_log((char *)log_msg, log_code);
}

static void on_user_registered(E2ees__Account *account) {
    print_msg("on_user_registered: user_id", (uint8_t *)account->address->user->user_id, strlen(account->address->user->user_id));

    copy_account_from_account(&(account_data[account_data_insert_pos]), account);
    account_data_insert_pos++;
}

static void on_inbound_session_invited(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from){
    printf("on_inbound_session_invited\n");
}

static void on_inbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *inbound_session){
    printf("on_inbound_session_ready\n");
}

static void on_outbound_session_ready(E2ees__E2eeAddress *user_address, E2ees__Session *outbound_session){
    printf("on_outbound_session_ready\n");
}

static void on_one2one_msg_received(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_one2one_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_other_device_msg_received(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *to_address, uint8_t *plaintext, size_t plaintext_len) {
    print_msg("on_other_device_msg_received: plaintext", plaintext, plaintext_len);
}

static void on_group_msg_received(E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *from_address, E2ees__E2eeAddress *group_address, uint8_t *plaintext, size_t plaintext_len) {
    if (safe_strcmp(user_address->user->user_id, from_address->user->user_id)) {
        print_msg("on_group_msg_received(from other devices): plaintext", plaintext, plaintext_len);
    } else {
        print_msg("on_group_msg_received(from other users): plaintext", plaintext, plaintext_len);
    }
}

static void on_group_created(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num
) {
    print_msg("on_group_created: group_name", (uint8_t *)group_name, strlen(group_name));

    copy_address_from_address(&(group.group_address), group_address);
    group.group_name = strdup(group_name);
}

static void on_group_members_added(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **added_group_members, size_t added_group_members_num
) {
    print_msg("on_group_members_added: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < added_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(added_group_members[i]->user_id), strlen(added_group_members[i]->user_id));
    }
}

static void on_group_members_removed(
    E2ees__E2eeAddress *user_address, E2ees__E2eeAddress *group_address, const char *group_name,
    E2ees__GroupMember **group_members, size_t group_members_num,
    E2ees__GroupMember **removed_group_members, size_t removed_group_members_num
) {
    print_msg("on_group_members_removed: group_name", (uint8_t *)group_name, strlen(group_name));
    size_t i;
    for (i = 0; i < removed_group_members_num; i++) {
        print_msg("    member_id", (uint8_t *)(removed_group_members[i]->user_id), strlen(removed_group_members[i]->user_id));
    }
}

static e2ees_event_handler_t test_event_handler = {
    on_log,
    on_user_registered,
    on_inbound_session_invited,
    on_inbound_session_ready,
    on_outbound_session_ready,
    on_one2one_msg_received,
    on_other_device_msg_received,
    on_group_msg_received,
    on_group_created,
    on_group_members_added,
    on_group_members_removed
};

static void test_begin() {
    ret = 0;

    int i;
    for (i = 0; i < account_data_max; i++) {
        account_data[i] = NULL;
    }
    account_data_insert_pos = 0;

    group.group_address = NULL;
    group.group_name = NULL;

    get_e2ees_plugin()->event_handler = test_event_handler;

    start_mock_server_sending();
}

static void test_end() {
    stop_mock_server_sending();

    ret = 0;

    int i;
    for (i = 0; i < account_data_max; i++) {
        if (account_data[i] != NULL) {
            e2ees__account__free_unpacked(account_data[i], NULL);
            account_data[i] = NULL;
        }
    }
    account_data_insert_pos = 0;

    if (group.group_address != NULL) {
        e2ees__e2ee_address__free_unpacked(group.group_address, NULL);
    }
    if (group.group_name != NULL) {
        free(group.group_name);
    }
}

static void mock_user_pqc_account(const char *user_name, const char *authenticator, const char *auth_code) {
    uint32_t e2ees_pack_id = gen_e2ees_pack_id_pqc();
    char *device_id = generate_uuid_str();
    E2ees__RegisterUserResponse *response = NULL;
    ret = register_user(
        &response,
        e2ees_pack_id,
        user_name,
        user_name,
        device_id,
        authenticator,
        auth_code
    );
    assert(ret == 0);
    printf("Test user registered: \"%s@%s\"\n", response->address->user->user_id, response->address->domain);

    // release
    free(device_id);
    e2ees__register_user_response__free_unpacked(response, NULL);
}

static void test_encryption(
    E2ees__E2eeAddress *sender_address, E2ees__E2eeAddress *group_address,
    uint8_t *plaintext_data, size_t plaintext_data_len
) {
    E2ees__SendGroupMsgResponse *response = NULL;
    ret = send_group_msg(
        &response,
        sender_address,
        group_address,
        E2EES__NOTIF_LEVEL__NOTIF_LEVEL_NORMAL,
        plaintext_data, plaintext_data_len
    );

    assert(ret == 0);
    
    // release
    if (response != NULL) {
        e2ees__send_group_msg_response__free_unpacked(response, NULL);
        response = NULL;
    }
}

static void test_create_group() {
    // test start
    printf("test_create_group begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    int i;
    E2ees__E2eeAddress *address_list[4];
    char *user_id_list[4];
    char *domain_list[4];
    for (i = 0; i < 4; i++) {
        address_list[i] = account_data[i]->address;
        user_id_list[i] = account_data[i]->address->user->user_id;
        domain_list[i] = account_data[i]->address->domain;
    }

    sleep(2);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(4);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 4);

    assert(ret == 0);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(5);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(PQC version).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(PQC version).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(address_list[1], group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_3[] = "Claire's message(PQC version).";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(address_list[2], group_address, plaintext_3, plaintext_3_len);

    uint8_t plaintext_4[] = "David's message(PQC version).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(address_list[3], group_address, plaintext_4, plaintext_4_len);

    // release
    free_group_member_list(&group_members, 4);
    free_proto(create_group_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_add_group_members() {
    // test start
    printf("test_add_group_members begin!!!\n");
    tear_up();
    test_begin();

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    int i;
    E2ees__E2eeAddress *address_list[4];
    char *user_id_list[4];
    char *domain_list[4];
    char *new_user_id_list[1];
    char *new_domain_list[1];
    for (i = 0; i < 4; i++) {
        address_list[i] = account_data[i]->address;
        if (i < 3) {
            user_id_list[i] = account_data[i]->address->user->user_id;
            domain_list[i] = account_data[i]->address->domain;
        } else {
            new_user_id_list[0] = account_data[i]->address->user->user_id;
            new_domain_list[0] = account_data[i]->address->domain;
        }
    }

    sleep(2);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(3);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 3);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(4);
    E2ees__GroupMember **new_group_members = NULL;
    malloc_new_group_members(1);
    size_t new_group_member_num = 1;
    // add the new group member to the group
    E2ees__AddGroupMembersResponse *add_group_members_response = NULL;
    ret = add_group_members(&add_group_members_response, address_list[0], group_address, new_group_members, new_group_member_num);
    assert(ret == 0);

    sleep(3);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(David joined).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(David joined).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(address_list[1], group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_3[] = "Claire's message(David joined).";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(address_list[2], group_address, plaintext_3, plaintext_3_len);

    uint8_t plaintext_4[] = "David's message(David joined).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(address_list[3], group_address, plaintext_4, plaintext_4_len);

    // release
    free_group_member_list(&group_members, 3);
    free_group_member_list(&new_group_members, 1);
    free_proto(create_group_response);
    free_proto(add_group_members_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_remove_group_members() {
    // test start
    printf("test_remove_group_members begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    sleep(5);
    
    int i;
    E2ees__E2eeAddress *address_list[4];
    char *user_id_list[4];
    char *domain_list[4];
    char *removing_user_id_list[1];
    char *removing_domain_list[1];
    for (i = 0; i < 4; i++) {
        address_list[i] = account_data[i]->address;
        user_id_list[i] = account_data[i]->address->user->user_id;
        domain_list[i] = account_data[i]->address->domain;
    }
    removing_user_id_list[0] = account_data[2]->address->user->user_id;
    removing_domain_list[0] = account_data[2]->address->domain;

    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(4);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 4);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(5);
    E2ees__GroupMember **removing_group_members = NULL;
    malloc_removing_group_members(1);
    size_t removing_group_member_num = 1;
    // Alice removes Claire out of the group
    E2ees__RemoveGroupMembersResponse *remove_group_members_response = NULL;
    ret = remove_group_members(
        &remove_group_members_response, address_list[0], group_address, removing_group_members, removing_group_member_num
    );
    assert(ret == 0);

    sleep(4);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(Claire removed).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(Claire removed).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(address_list[1], group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_4[] = "David's message(Claire removed).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(address_list[3], group_address, plaintext_4, plaintext_4_len);

    // release
    free_group_member_list(&group_members, 4);
    free_group_member_list(&removing_group_members, 1);
    free_proto(create_group_response);
    free_proto(remove_group_members_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_create_add_remove() {
    // test start
    printf("test_create_add_remove begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");

    int i;
    E2ees__E2eeAddress *address_list[3];
    char *user_id_list[3];
    char *domain_list[3];
    char *new_user_id_list[1];
    char *new_domain_list[1];
    char *removing_user_id_list[1];
    char *removing_domain_list[1];
    for (i = 0; i < 3; i++) {
        address_list[i] = account_data[i]->address;
        if (i < 2) {
            user_id_list[i] = account_data[i]->address->user->user_id;
            domain_list[i] = account_data[i]->address->domain;
        } else {
            new_user_id_list[0] = account_data[i]->address->user->user_id;
            new_domain_list[0] = account_data[i]->address->domain;
        }
    }
    removing_user_id_list[0] = account_data[1]->address->user->user_id;
    removing_domain_list[0] = account_data[1]->address->domain;

    sleep(2);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(2);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 2);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(2);
    // Alice sends a message to the group
    uint8_t plaintext[] = "Group: Alice and Bob.";
    size_t plaintext_len = sizeof(plaintext) - 1;
    test_encryption(address_list[0], group_address, plaintext, plaintext_len);

    sleep(1);
    E2ees__GroupMember **new_group_members = NULL;
    malloc_new_group_members(1);
    size_t new_group_member_num = 1;
    // add the new group member to the group
    E2ees__AddGroupMembersResponse *add_group_members_response = NULL;
    ret = add_group_members(&add_group_members_response, address_list[0], group_address, new_group_members, new_group_member_num);

    sleep(4);
    // Alice sends a message to the group
    uint8_t plaintext_2[] = "Group: Alice, Bob and Claire.";
    size_t plaintext_len_2 = sizeof(plaintext_2) - 1;
    test_encryption(address_list[0], group_address, plaintext_2, plaintext_len_2);

    sleep(1);
    E2ees__GroupMember **removing_group_members = NULL;
    malloc_removing_group_members(1);
    size_t removing_group_member_num = 1;
    E2ees__RemoveGroupMembersResponse *remove_group_members_response = NULL;
    ret = remove_group_members(&remove_group_members_response, address_list[0], group_address, removing_group_members, removing_group_member_num);

    sleep(2);
    // Alice sends a message to the group
    uint8_t plaintext_3[] = "Group: Alice and Claire.";
    size_t plaintext_len_3 = sizeof(plaintext_3) - 1;
    test_encryption(address_list[0], group_address, plaintext_3, plaintext_len_3);

    // release
    free_group_member_list(&group_members, 2);
    free_group_member_list(&new_group_members, 1);
    free_group_member_list(&removing_group_members, 1);
    free_proto(create_group_response);
    free_proto(add_group_members_response);
    free_proto(remove_group_members_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_leave_group() {
    // test start
    printf("test_leave_group begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");

    int i;
    E2ees__E2eeAddress *address_list[4];
    char *user_id_list[4];
    char *domain_list[4];
    for (i = 0; i < 4; i++) {
        address_list[i] = account_data[i]->address;
        user_id_list[i] = account_data[i]->address->user->user_id;
        domain_list[i] = account_data[i]->address->domain;
    }

    sleep(2);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(4);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 4);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(5);
    // Claire leaves the group
    E2ees__LeaveGroupResponse *leave_group_response = NULL;
    ret = leave_group(&leave_group_response, address_list[2], group_address);

    sleep(4);
    // Everyone sends a message to the group
    uint8_t plaintext_1[] = "Alice's message(Claire removed her self).";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "Bob's message(Claire removed her self).";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(address_list[1], group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_4[] = "David's message(Claire removed her self).";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(address_list[3], group_address, plaintext_4, plaintext_4_len);

    // release
    free_group_member_list(&group_members, 4);
    free_proto(create_group_response);
    free_proto(leave_group_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_continual() {
    // test start
    printf("test_continual begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");

    int i;
    E2ees__E2eeAddress *address_list[3];
    char *user_id_list[3];
    char *domain_list[3];
    for (i = 0; i < 3; i++) {
        address_list[i] = account_data[i]->address;
        user_id_list[i] = account_data[i]->address->user->user_id;
        domain_list[i] = account_data[i]->address->domain;
    }

    sleep(2);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(3);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 3);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(2);

    // Alice sends a message to the group
    uint8_t plaintext_data_a[] = "This message will be sent to Bob and Claire by 1000 times.";
    size_t plaintext_data_a_len = sizeof(plaintext_data_a) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(address_list[0], group_address, plaintext_data_a, plaintext_data_a_len);
    }

    // Bob sends a message to the group
    uint8_t plaintext_data_b[] = "This message will be sent to Alice and Claire by 1000 times.";
    size_t plaintext_data_b_len = sizeof(plaintext_data_b) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(address_list[1], group_address, plaintext_data_b, plaintext_data_b_len);
    }

    // Claire sends a message to the group
    uint8_t plaintext_data_c[] = "This message will be sent to Alice and Bob by 1000 times.";
    size_t plaintext_data_c_len = sizeof(plaintext_data_c) - 1;
    for (i = 0; i < 1000; i++) {
        test_encryption(address_list[2], group_address, plaintext_data_c, plaintext_data_c_len);
    }

    // release
    free_group_member_list(&group_members, 3);
    free_proto(create_group_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_multiple_devices() {
    // test start
    printf("test_multiple_devices begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");

    int i;
    E2ees__E2eeAddress *address_list[3];
    char *user_id_list[3];
    char *domain_list[3];
    for (i = 0; i < 3; i++) {
        address_list[i] = account_data[i]->address;
        user_id_list[i] = account_data[i]->address->user->user_id;
        domain_list[i] = account_data[i]->address->domain;
    }

    sleep(3);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(3);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 3);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(2);
    // Alice sends a message to the group via the first device
    uint8_t plaintext_1[] = "This message is from Alice's first device via pqc session.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    // Bob sends a message to the group via the second device
    uint8_t plaintext_2[] = "This message is from Bob's second device via pqc session.";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(address_list[1], group_address, plaintext_2, plaintext_2_len);

    // Claire sends a message to the group via the second device
    uint8_t plaintext_3[] = "This message is from Claire's second device via pqc session.";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(address_list[2], group_address, plaintext_3, plaintext_3_len);

    // release
    free_group_member_list(&group_members, 3);
    free_proto(create_group_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_add_new_device() {
    // test start
    printf("test_add_new_device begin!!!\n");
    tear_up();
    test_begin();

    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");

    int i;
    E2ees__E2eeAddress *address_list[3];
    char *user_id_list[3];
    char *domain_list[3];
    for (i = 0; i < 3; i++) {
        address_list[i] = account_data[i]->address;
        user_id_list[i] = account_data[i]->address->user->user_id;
        domain_list[i] = account_data[i]->address->domain;
    }

    sleep(2);
    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(3);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 3);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(2);
    // add new device
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");

    sleep(2);
    // Alice sends a message to the group via the first device
    uint8_t plaintext_1[] = "This message is from Alice's first device via pqc session.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    // release
    free_group_member_list(&group_members, 3);
    free_proto(create_group_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_medium_group() {
    // test start
    printf("test_medium_group begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    mock_user_pqc_account("Alice", "alice@domain.com.tw", "123456");
    mock_user_pqc_account("Bob", "bob@domain.com.tw", "234567");
    mock_user_pqc_account("Claire", "claire@domain.com.tw", "345678");
    mock_user_pqc_account("David", "david@domain.com.tw", "456789");
    mock_user_pqc_account("Emily", "emily@domain.com.tw", "567890");
    mock_user_pqc_account("Frank", "frank@domain.com.tw", "678901");
    mock_user_pqc_account("Grace", "grace@domain.com.tw", "789012");
    mock_user_pqc_account("Harry", "harry@domain.com.tw", "890123");
    mock_user_pqc_account("Ivy", "ivy@domain.com.tw", "901234");
    mock_user_pqc_account("Jack", "jack@domain.com.tw", "012345");
    mock_user_pqc_account("Karen", "karen@domain.com.tw", "111111");
    mock_user_pqc_account("Leo", "leo@domain.com.tw", "222222");
    mock_user_pqc_account("Mary", "mary@domain.com.tw", "333333");
    mock_user_pqc_account("Nick", "nick@domain.com.tw", "444444");

    sleep(10);

    int i;
    E2ees__E2eeAddress *address_list[14];
    char *user_id_list[14];
    char *domain_list[14];
    char *new_user_id_list[4];
    char *new_domain_list[4];
    char *removing_user_id_list[4];
    char *removing_domain_list[4];
    for (i = 0; i < 14; i++) {
        address_list[i] = account_data[i]->address;
        if (i < 10) {
            user_id_list[i] = account_data[i]->address->user->user_id;
            domain_list[i] = account_data[i]->address->domain;
        } else {
            new_user_id_list[i - 10] = account_data[i]->address->user->user_id;
            new_domain_list[i - 10] = account_data[i]->address->domain;
        }
    }
    removing_user_id_list[0] = account_data[3]->address->user->user_id;
    removing_domain_list[0] = account_data[3]->address->domain;
    removing_user_id_list[1] = account_data[8]->address->user->user_id;
    removing_domain_list[1] = account_data[8]->address->domain;
    removing_user_id_list[2] = account_data[10]->address->user->user_id;
    removing_domain_list[2] = account_data[10]->address->domain;
    removing_user_id_list[3] = account_data[11]->address->user->user_id;
    removing_domain_list[3] = account_data[11]->address->domain;

    E2ees__GroupMember **group_members = NULL;
    malloc_group_members(10);

    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, address_list[0], "Group name", group_members, 10);
    E2ees__E2eeAddress *group_address = create_group_response->group_address;

    sleep(10);

    // group message
    uint8_t plaintext_1[] = "Alice's message.";
    size_t plaintext_1_len = sizeof(plaintext_1) - 1;
    test_encryption(address_list[0], group_address, plaintext_1, plaintext_1_len);

    uint8_t plaintext_2[] = "David's message.";
    size_t plaintext_2_len = sizeof(plaintext_2) - 1;
    test_encryption(address_list[3], group_address, plaintext_2, plaintext_2_len);

    uint8_t plaintext_3[] = "Grace's message.";
    size_t plaintext_3_len = sizeof(plaintext_3) - 1;
    test_encryption(address_list[6], group_address, plaintext_3, plaintext_3_len);

    sleep(3);

    // new group members
    E2ees__GroupMember **new_group_members = NULL;
    malloc_new_group_members(4);
    size_t new_group_member_num = 4;

    // add new group members to the group
    E2ees__AddGroupMembersResponse *add_group_members_response = NULL;
    ret = add_group_members(
        &add_group_members_response, address_list[0], group.group_address, new_group_members, new_group_member_num
    );

    sleep(10);

    // group message
    uint8_t plaintext_4[] = "Jack's message.";
    size_t plaintext_4_len = sizeof(plaintext_4) - 1;
    test_encryption(address_list[9], group.group_address, plaintext_4, plaintext_4_len);

    uint8_t plaintext_5[] = "Karen's message.";
    size_t plaintext_5_len = sizeof(plaintext_5) - 1;
    test_encryption(address_list[10], group.group_address, plaintext_5, plaintext_5_len);

    uint8_t plaintext_6[] = "Nick's message.";
    size_t plaintext_6_len = sizeof(plaintext_6) - 1;
    test_encryption(address_list[13], group.group_address, plaintext_6, plaintext_6_len);

    sleep(5);

    // remove group members
    E2ees__GroupMember **removing_group_members = NULL;
    malloc_removing_group_members(4);
    size_t removing_group_member_num = 4;

    E2ees__RemoveGroupMembersResponse *remove_group_members_response = NULL;
    ret = remove_group_members(
        &remove_group_members_response, address_list[0], group.group_address, removing_group_members, removing_group_member_num
    );

    sleep(10);

    // group message
    uint8_t plaintext_7[] = "Bob's message.";
    size_t plaintext_7_len = sizeof(plaintext_7) - 1;
    test_encryption(address_list[1], group.group_address, plaintext_7, plaintext_7_len);

    uint8_t plaintext_8[] = "Mary's message.";
    size_t plaintext_8_len = sizeof(plaintext_8) - 1;
    test_encryption(address_list[12], group.group_address, plaintext_8, plaintext_8_len);

    // release
    free_group_member_list(&group_members, 10);
    free_group_member_list(&new_group_members, 4);
    free_group_member_list(&removing_group_members, 4);
    free_proto(create_group_response);
    free_proto(add_group_members_response);
    free_proto(remove_group_members_response);

    // test stop
    test_end();
    tear_down();
    printf("====================================\n");
}

static void test_create_group_time() {
    // test start
    printf("test_create_group_time begin!!!\n");
    tear_up();
    test_begin();

    // prepare account
    int i;
    for (i = 0; i < 200; i++) {
        mock_user_pqc_account(mock_user_name[i], mock_authenticator[i], mock_auth_code[i]);
    }

    sleep(10);

    E2ees__GroupMember **group_members = (E2ees__GroupMember **)malloc(sizeof(E2ees__GroupMember *) * 200);
    group_members[0] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
    e2ees__group_member__init(group_members[0]);
    group_members[0]->user_id = strdup(account_data[0]->address->user->user_id);
    group_members[0]->domain = strdup(account_data[0]->address->domain);
    group_members[0]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MANAGER;
    for (i = 1; i < 200; i++) {
        group_members[i] = (E2ees__GroupMember *)malloc(sizeof(E2ees__GroupMember));
        e2ees__group_member__init(group_members[i]);
        group_members[i]->user_id = strdup(account_data[i]->address->user->user_id);
        group_members[i]->domain = strdup(account_data[i]->address->domain);
        group_members[i]->role = E2EES__GROUP_ROLE__GROUP_ROLE_MEMBER;
    }

    time_t start, end;
    start = time(NULL);
    // create the group
    E2ees__CreateGroupResponse *create_group_response = NULL;
    ret = create_group(&create_group_response, account_data[0]->address, "Group name", group_members, 200);

    // test stop
    test_end();
    tear_down();

    end = time(NULL);
    printf("Creating group time: %ld seconds\n\n", end - start);

    printf("====================================\n");
}

int main() {
    test_create_group();
    test_add_group_members();
    test_remove_group_members();
    test_create_add_remove();
    test_leave_group();
    test_continual();
    test_multiple_devices();
    test_add_new_device();
    test_medium_group();
    // test_create_group_time();

    return 0;
}
