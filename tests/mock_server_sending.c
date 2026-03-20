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
#include "mock_server_sending.h"

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

#include "e2ees/e2ees_client.h"

#define QUEUE_SIZE 16384

pthread_mutex_t lock;
pthread_cond_t cond;
bool running;
pthread_t thread;
bool thread_started = false;

E2ees__ProtoMsg *proto_msg_queue[QUEUE_SIZE];
int proto_msg_queue_insert_head = 0;
int proto_msg_queue_insert_tail = 0;

void send_proto_msg(E2ees__ProtoMsg *proto_msg) {
    // clone proto_msg
    size_t proto_msg_data_len = e2ees__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    e2ees__proto_msg__pack(proto_msg, proto_msg_data);
    E2ees__ProtoMsg *cloned_proto_msg = e2ees__proto_msg__unpack(NULL, proto_msg_data_len, proto_msg_data);

    pthread_mutex_lock(&lock);
    
    int next_tail = (proto_msg_queue_insert_tail + 1) % QUEUE_SIZE;
    assert(next_tail != proto_msg_queue_insert_head); // Ensure queue is not full
    
    proto_msg_queue[proto_msg_queue_insert_tail] = cloned_proto_msg;
    proto_msg_queue_insert_tail = next_tail;
    
    pthread_cond_signal(&cond); // Wake up the processing thread
    pthread_mutex_unlock(&lock);
}

void *process_outgoing_queue(void *arg) {
    while (true) {
        E2ees__ProtoMsg *proto_msg = NULL;

        pthread_mutex_lock(&lock);
        while (running && proto_msg_queue_insert_head == proto_msg_queue_insert_tail) {
            pthread_cond_wait(&cond, &lock);
        }

        if (!running && proto_msg_queue_insert_head == proto_msg_queue_insert_tail) {
            pthread_mutex_unlock(&lock);
            break;
        }

        proto_msg = proto_msg_queue[proto_msg_queue_insert_head];
        proto_msg_queue[proto_msg_queue_insert_head] = NULL;
        
        proto_msg_queue_insert_head = (proto_msg_queue_insert_head + 1) % QUEUE_SIZE;
        pthread_mutex_unlock(&lock);

        if (proto_msg != NULL) {
            // send proto_msg to client
            size_t proto_msg_data_len = e2ees__proto_msg__get_packed_size(proto_msg);
            uint8_t proto_msg_data[proto_msg_data_len];
            e2ees__proto_msg__pack(proto_msg, proto_msg_data);
            E2ees__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

            // release
            e2ees__proto_msg__free_unpacked(proto_msg, NULL);
            if (consume_proto_msg_response != NULL) {
                e2ees__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
            }
        }
    }
    return NULL;
}

void start_mock_server_sending() {
    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("\n mutex init failed\n");
        return;
    }
    if (pthread_cond_init(&cond, NULL) != 0) {
        printf("\n cond init failed\n");
        return;
    }
    running = true;
    if (pthread_create(&thread, NULL, process_outgoing_queue, NULL) == 0) {
        thread_started = true;
    }
}

void stop_mock_server_sending() {
    pthread_mutex_lock(&lock);
    running = false;
    pthread_cond_broadcast(&cond); // Wake up the thread so it can exit
    pthread_mutex_unlock(&lock);

    if (thread_started) {
        pthread_join(thread, NULL);
        thread_started = false;
    }

    pthread_mutex_destroy(&lock);
    pthread_cond_destroy(&cond);
}
