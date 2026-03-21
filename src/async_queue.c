#include "e2ees/async_queue.h"
#include <stdlib.h>

static app_message_queue_t *app_message_queue = NULL;

static void* worker_thread_func(void *arg) {
    app_message_queue_t *q = (app_message_queue_t *)arg;

    while (true) {
        pthread_mutex_lock(&q->lock);
        while (q->head == NULL && !q->stop) {
            pthread_cond_wait(&q->cond, &q->lock);
        }

        if (q->stop && q->head == NULL) {
            pthread_mutex_unlock(&q->lock);
            break;
        }

        task_node_t *task = q->head;
        if (task != NULL) {
            q->head = task->next;
            if (q->head == NULL) {
                q->tail = NULL;
            }
        }
        pthread_mutex_unlock(&q->lock);

        if (task != NULL) {
            if (task->func) {
                task->func(task->context);
            }
            free(task);
        }
    }
    return NULL;
}

void app_message_queue_create(void) {
    if (app_message_queue != NULL) return;

    app_message_queue = (app_message_queue_t *)malloc(sizeof(app_message_queue_t));
    if (app_message_queue == NULL) return;

    pthread_mutex_init(&app_message_queue->lock, NULL);
    pthread_cond_init(&app_message_queue->cond, NULL);
    app_message_queue->head = NULL;
    app_message_queue->tail = NULL;
    app_message_queue->stop = false;

    pthread_create(&app_message_queue->worker_thread, NULL, worker_thread_func, app_message_queue);
}

void dispatch_async(dispatch_function_t func, void *context) {
    if (app_message_queue == NULL || func == NULL) return;
    task_node_t *node = (task_node_t *)malloc(sizeof(task_node_t));
    if (node == NULL) return;
    node->func = func;
    node->context = context;
    node->next = NULL;

    pthread_mutex_lock(&app_message_queue->lock);
    if (app_message_queue->tail != NULL) {
        app_message_queue->tail->next = node;
    } else {
        app_message_queue->head = node;
    }
    app_message_queue->tail = node;
    pthread_cond_signal(&app_message_queue->cond);
    pthread_mutex_unlock(&app_message_queue->lock);
}

void app_message_queue_destroy(void) {
    if (app_message_queue == NULL) return;

    pthread_mutex_lock(&app_message_queue->lock);
    app_message_queue->stop = true;
    pthread_cond_signal(&app_message_queue->cond);
    pthread_mutex_unlock(&app_message_queue->lock);

    pthread_join(app_message_queue->worker_thread, NULL);

    pthread_mutex_destroy(&app_message_queue->lock);
    pthread_cond_destroy(&app_message_queue->cond);

    task_node_t *current = app_message_queue->head;
    while (current != NULL) {
        task_node_t *next = current->next;
        free(current);
        current = next;
    }
    free(app_message_queue);
    app_message_queue = NULL;
}
