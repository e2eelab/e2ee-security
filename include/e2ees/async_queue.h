#ifndef E2EES_ASYNC_QUEUE_H
#define E2EES_ASYNC_QUEUE_H

#include <pthread.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Dispatches a function to be executed asynchronously.
 * @param context Pointer to the function context.
 */
typedef void (*dispatch_function_t)(void *context);

/**
 * @brief A node representing a single task in the asynchronous queue.
 */
typedef struct task_node_t {
    dispatch_function_t func; /**< The function to execute. */
    void *context;            /**< The context passed to the function. */
    struct task_node_t *next; /**< Pointer to the next task in the queue. */
} task_node_t;

/**
 * @brief Structure representing the asynchronous message queue.
 */
typedef struct app_message_queue_t {
    pthread_mutex_t lock;     /**< Mutex to protect queue operations. */
    pthread_cond_t cond;      /**< Condition variable to signal new tasks. */
    pthread_t worker_thread;  /**< The background thread processing the queue. */
    task_node_t *head;        /**< Pointer to the head of the queue. */
    task_node_t *tail;        /**< Pointer to the tail of the queue. */
    bool stop;                /**< Flag indicating if the queue should stop processing. */
} app_message_queue_t;

/**
 * @brief Creates and starts the background message queue.
 */
void app_message_queue_create(void);

/**
 * @brief Destroys the queue and stops the background thread.
 */
void app_message_queue_destroy(void);

/**
 * @brief Dispatches a function to be executed asynchronously on the queue.
 * @param func The function to execute.
 * @param context The context to pass to the function.
 */
void dispatch_async(dispatch_function_t func, void *context);

#ifdef __cplusplus
}
#endif

#endif // E2EES_ASYNC_QUEUE_H