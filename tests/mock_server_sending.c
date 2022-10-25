/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "mock_server_sending.h"

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>

#include "skissm/e2ee_client.h"

#define QUEUE_SIZE 1024

pthread_mutex_t lock;
bool running;
pthread_t thread;

Skissm__ProtoMsg *proto_msg_queue[QUEUE_SIZE];
int proto_msg_queue_insert_head = 0;
int proto_msg_queue_insert_tail = 0;

void send_proto_msg(Skissm__ProtoMsg *proto_msg) {
    // clone proto_msg
    size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    skissm__proto_msg__pack(proto_msg, proto_msg_data);
    Skissm__ProtoMsg *cloned_proto_msg = skissm__proto_msg__unpack(NULL, proto_msg_data_len, proto_msg_data);

    //pthread_mutex_lock(&lock);
    // keep proto_msg in proto_msg_queue
    printf("tail: %d", proto_msg_queue_insert_tail);
    proto_msg_queue[proto_msg_queue_insert_tail] = cloned_proto_msg;
    pthread_mutex_lock(&lock);
    proto_msg_queue_insert_tail++;
    if (proto_msg_queue_insert_tail == QUEUE_SIZE)
        proto_msg_queue_insert_tail = 0;
    pthread_mutex_unlock(&lock);
    assert(proto_msg_queue_insert_tail != proto_msg_queue_insert_head);
    printf(" -> %d\n", proto_msg_queue_insert_tail);
    //pthread_mutex_unlock(&lock);
}

static bool has_proto_msg_data() {
    bool has_data = false;
    pthread_mutex_lock(&lock);
    has_data = (proto_msg_queue_insert_tail != proto_msg_queue_insert_head);
    pthread_mutex_unlock(&lock);
    return has_data;    
}

void *process_outgoing_queue() {
    while (running || has_proto_msg_data()) {
        //pthread_mutex_lock(&lock);

        Skissm__ProtoMsg *proto_msg = proto_msg_queue[proto_msg_queue_insert_head];

        if (proto_msg != NULL) {
            printf("head: %d", proto_msg_queue_insert_head);
            // send proto_msg to client
            size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
            uint8_t proto_msg_data[proto_msg_data_len];
            skissm__proto_msg__pack(proto_msg, proto_msg_data);
            Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

            // release
            skissm__proto_msg__free_unpacked(proto_msg, NULL);
            skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
            // remove processed proto_msg
            proto_msg_queue[proto_msg_queue_insert_head] = NULL;

            pthread_mutex_lock(&lock);
            proto_msg_queue_insert_head++;
            if (proto_msg_queue_insert_head == QUEUE_SIZE)
                proto_msg_queue_insert_head = 0;
            pthread_mutex_unlock(&lock);
            printf(" -> %d\n", proto_msg_queue_insert_head);
        } else {
            // printf("sleep\n");
            usleep(100000);
        }

        //pthread_mutex_unlock(&lock);
    }
}

void start_mock_server_sending() {
    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }
    running = true;
    pthread_create(&thread, NULL, process_outgoing_queue, "process outgoing queue");
}

void stop_mock_server_sending() {
    running = false;
    pthread_join(thread, 0);
    pthread_mutex_destroy(&lock);
}
