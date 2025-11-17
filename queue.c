// system/netd/ioemnetd/queue.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "queue.h"

static int lock;
#define atomic_cas(dst, old, new) __sync_bool_compare_and_swap((dst), (old), (new))
#define atomic_lock(ptr)\
while(!atomic_cas(ptr,0,1))
#define atomic_unlock(ptr)\
while(!atomic_cas(ptr,1,0))

void atomic_lock_api(void)
{
    atomic_lock(&lock);
}

void atomic_unlock_api(void)
{
    atomic_unlock(&lock);
}

BUF_LIST *g_queue; // 全局队列指针

ERROR_MESSAGE_T QueueInit()
{
    ERROR_MESSAGE_T ret = SUCCESS;

    g_queue = malloc(sizeof(BUF_LIST));
    if (g_queue == NULL)
    {
        printf("bufferInit error");
        ret = MEM_MALLOC_FAIL;
    }
    else
    {
        g_queue->head = NULL;
        g_queue->tail = NULL;
        g_queue->len = 0;
        g_queue->size = 0;
    }
    return ret;
}

/*
 * Modified BufferInQueue to accept client sockaddr and length,
 * store them inside the List_Node so that consumers can reply to client.
 */
ERROR_MESSAGE_T BufferInQueue(const uint8 *data, uint32 len, const struct sockaddr *cli, socklen_t cli_len)
{
    ERROR_MESSAGE_T ret = SUCCESS;
    BUF_LIST *list = g_queue;
    do
    {
        if (list == NULL)
        {
            printf("g_queue is NULL!");
            ret = BUF_EMPTY;
            break;
        }

        if ((len > 1024) || (len < 20)) // 单个报文最大/最小校验
        {
            printf("packet is too long or too small\n");
            ret = DATA_INVALID;
            break;
        }

        // allocate node with room for addr and data
        struct List_Node *pnew = (struct List_Node *)malloc(sizeof(struct List_Node) + len);
        if (pnew == NULL)
        {
            ret = MEM_MALLOC_FAIL;
            break;
        }

        // initialize node fields
        pnew->len = len;
        // copy client addr (if provided). If cli is NULL, zero addr_len.
        if (cli != NULL && cli_len > 0 && cli_len <= sizeof(pnew->addr)) {
            memcpy(&pnew->addr, cli, cli_len);
            pnew->addr_len = cli_len;
        } else {
            memset(&pnew->addr, 0, sizeof(pnew->addr));
            pnew->addr_len = 0;
        }

        // copy payload
        memcpy(pnew->data, data, len);

        // push into list
        LOCK();
        LIST_RPUSH(list, pnew);
        UNLOCK();
        printf("bufferInQueue success, len =%d, addr %p, len = %d\n", list->len, pnew, len);
    } while (0);

    return ret;
}

uint8 IsEmptyQueue()
{
    ERROR_MESSAGE_T ret = TRUE;
    if (g_queue == NULL)
    {
        ret = TRUE;
    }
    else
    {
        LOCK();
        int len = g_queue->size;
        UNLOCK();
        ret = len ? FALSE : TRUE;
    }

    return ret;
}

ERROR_MESSAGE_T BufferOutQueue(struct List_Node **node)
{
    ERROR_MESSAGE_T ret = SUCCESS;
    BUF_LIST *list = g_queue;

    do
    {
        if (IsEmptyQueue() == TRUE) // 队列为空
        {
            ret = BUF_EMPTY;
            break;
        }

        struct List_Node *ppop = NULL; // 出队节点
        LOCK();
        LIST_LPOP(list, ppop);
        UNLOCK();

        if (ppop == NULL)
        {
            ret = BUF_EMPTY;
        }
        else
        {
            *node = ppop;
        }

    } while (0);

    return ret;
}

int GetQueueSize(void)
{
    int size = 0;
    if (g_queue != NULL)
    {
        LOCK();
        size = g_queue->size;
        UNLOCK();
    }
    return size;
}

void bufferDestroy(void)
{
    if (g_queue != NULL)
    {
        LIST_DESTROY(g_queue);
    }
}

#ifdef DEBUG
void ShowQueue(void)
{
    BUF_LIST *list = g_queue;
    if (IsEmptyQueue() == TRUE)
    {
        printf("Queue is empty\n");
    }
    else
    {
        printf("in buffer packet len = %d\n", g_queue->len);
        LOCK();
        LIST_FOR_EACH(list)
        {
            printf("node %p, len %d\n", curr, curr->len);
        }
        UNLOCK();
    }
}
#endif