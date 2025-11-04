/**
 * @file queue.c
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2025-07-15
 *
 * @copyright Copyright (c) 2025
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

static int lock;
#define atomic_cas(dst, old, new) __sync_bool_compare_and_swap((dst), (old), (new))
#define atomic_lock(ptr)\
while(!atomic_cas(ptr,0,1))
#define atomic_unlock(ptr)\
while(!atomic_cas(ptr,1,0))

/**
 * 原子锁加锁
 * @param 
 * null
 * @return 
 * null
 */
void atomic_lock_api(void)
{
    atomic_lock(&lock);
}

/**
 * 原子锁解锁
 * @param 
 * null
 * @return 
 * null
 */
void atomic_unlock_api(void)
{
    atomic_unlock(&lock);
}

BUF_LIST *g_queue; // 全局队列指针

/**
 * @brief 初始化队列
 *
 * @return ERROR_MESSAGE_T
 */
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

/**
 * @brief 入队列
 *
 * @param data 数据指针
 * @param len 数据长度
 * @return ERROR_MESSAGE_T 错误码
 * @note
 */
ERROR_MESSAGE_T BufferInQueue(const uint8 *data, uint32 len)
{
    ERROR_MESSAGE_T ret = SUCCESS;
    BUF_LIST *list = g_queue;
    do
    {
        //* 空的队列头
        if (list == NULL)
        {
            printf("g_queue is NULL!");
            ret = BUF_EMPTY;
            break;
        }

        if ((len > 1024) || (len < 20)) // 单个报文最大
        {
            printf("packet is to long.or too small\n");
            ret = DATA_INVALID;
            break;
        }

        struct List_Node *pnew = (struct List_Node *)malloc(sizeof(struct List_Node) + len);
        if (pnew == NULL)
        {
            ret = MEM_MALLOC_FAIL;
            break;
        }

        memcpy(pnew->data, data, len); // 入队的数据
        pnew->len = len;

        //* 进入临界区
        LOCK();
        LIST_RPUSH(list, pnew);
        UNLOCK();
        printf("bufferInQueue success, len =%d, addr %p, len = %d\n", list->len, pnew, len);
    } while (0);

    return ret;
}

/**
 * @brief 判断长度是为为空
 *
 * @return ERROR_MESSAGE_T TRUE为空，FALSE不为空
 * @note
 */
uint8 IsEmptyQueue()
{
    ERROR_MESSAGE_T ret = TRUE;
    if (g_queue == NULL)
    {
        ret = TRUE;
    }
    else
    {
        //* 进入临界区
        LOCK();
        int len = g_queue->size;
        UNLOCK();
        ret = len ? FALSE : TRUE;
    }

    return ret;
}

/**
 * @brief 出队列
 *
 * @param node 指向节点指针的指针
 * @return ERROR_MESSAGE_T
 * @note
 */
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

        struct List_Node *ppop = NULL; // 出对的节点
        LOCK();
        LIST_LPOP(list, ppop);
        UNLOCK();

        //! 出对前判断队列不为空，但是出现了出队失败
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
/**
 * @brief 队列销毁
 *
 * @return void
 * @note
 */
void bufferDestroy(void)
{
    if (g_queue != NULL)
    {
        LIST_DESTROY(g_queue);
    }
}

#ifdef DEBUG
/**
 * @brief 显示队列内容
 *
 * @note
 */
void ShowQueue(void)
{
    BUF_LIST *list = g_queue;
    if (IsEmptyQueue() == TRUE) // 队列为空
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
