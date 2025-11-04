/**
 * @file queue.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-07-15
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef QUEUE_H
#define QUEUE_H


typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

typedef enum ERROR_MESSAGE{
    SUCCESS,            //成功
    FAIL,               //失败
    TRUE,
    FALSE,
    INIT_FAIL,          //初始化失败
    DATA_INVALID,           //无效
    BUF_EMPTY,          //缓冲区空
    BUF_FULL,           //缓冲区满
    MEM_MALLOC_FAIL,    //内存分配失败
    FILE_OPEN_FAIL,     //文件打开失败
}ERROR_MESSAGE_T;

//* 判断是否可入队
#define LIST_JUDGE_IN(max_pck, max_len, list, ret)       \
    do                                                       \
    {                                                        \
        if ((list->size > max_pck) || (list->len > max_len)) \
            ret = ETH_TRUE;                              \
        else                                                 \
            ret = ETH_FALSE;                             \
    } while (0);

//* 列表队尾入队
#define LIST_RPUSH(list, node)          \
    do                                      \
    {                                       \
        if (list->head)                     \
        {                                   \
            node->prev = list->tail;        \
            node->next = NULL;              \
            list->tail->next = node;        \
            list->tail = node;              \
        }                                   \
        else                                \
        {                                   \
            list->head = list->tail = node; \
            node->prev = node->next = NULL; \
        }                                   \
        ++list->size;                       \
        list->len += node->len;             \
    } while (0)

//* 列表队尾出队，node使用前赋空
#define LIST_RPOP(list, node)                       \
    do                                                  \
    {                                                   \
        if (list->size)                                 \
        {                                               \
            node = list->tail;                          \
            if (--self->size)                           \
                (self->tail = node->prev)->next = NULL; \
            else                                        \
                self->tail = self->head = NULL;         \
            node->next = node->prev = NULL;             \
            list->len -= node->len;                     \
        }                                               \
    } while (0)

//* 列表对首入队
#define LIST_LPUSH(list, node)          \
    do                                      \
    {                                       \
        if (list->size)                     \
        {                                   \
            node->next = list->head;        \
            node->prev = NULL;              \
            list->head->prev = node;        \
            list->head = node;              \
        }                                   \
        else                                \
        {                                   \
            list->head = list->tail = node; \
            node->prev = node->next = NULL; \
        }                                   \
        ++list->len;                        \
        list->len += node->len;             \
    } while (0)

//* 列表对首出队，node使用前赋空
#define LIST_LPOP(list, node)                       \
    do                                                  \
    {                                                   \
        if (list->size)                                 \
        {                                               \
            node = list->head;                          \
            if (--list->size)                           \
                (list->head = node->next)->prev = NULL; \
            else                                        \
                list->head = list->tail = NULL;         \
            node->next = node->prev = NULL;             \
            list->len -= node->len;                     \
        }                                               \
    } while (0)

//* 直接访问列表成员
#define LIST_GET(list, node)   \
    do                             \
    {                              \
        node = list->worked;       \
        list->worked = node->next; \
        list->offset++;            \
    } while (0)

//* 移除列表成员，使用前确定入参非空
#define LIST_REMOVE_NODE(list, node)                                          \
    do                                                                            \
    {                                                                             \
        node->prev ? (node->prev->next = node->next) : (list->head = node->next); \
        node->next ? (node->next->prev = node->prev) : (list->tail = node->prev); \
        list->len -= node->len;                                                   \
        free(node);                                                               \
        node = NULL;                                                              \
        --list->size;                                                             \
    } while (0)

//* 列表节点释放
#define LIST_NODE_FREE(node) \
    do                           \
    {                            \
        if (node != NULL)        \
            free(node);          \
        node = NULL;             \
    } while (0)

//* 队列销毁
#define LIST_DESTROY(list)               \
    struct List_Node *next;              \
    struct List_Node *curr = list->head; \
    while (list->size--)                     \
    {                                        \
        next = curr->next;                   \
        LIST_NODE_FREE(curr);            \
        curr = next;                         \
    }                                        \
    list->len = 0;                           \
    free(list);                              \
    list = NULL;

//* 队列遍历
#define LIST_FOR_EACH(list) for (struct List_Node *curr = list->head; curr != NULL; curr = curr->next)

// 数据节点
typedef struct List_Node
{
    struct List_Node *prev;
    struct List_Node *next;

    unsigned int len; // 数据长度
    unsigned char data[];
} __attribute__((packed)) List_Node_ST;

// 队列结构
typedef struct BUF_LIST_ST
{
    struct List_Node *head; // 对列头节点
    struct List_Node *tail; // 队列尾节点
    int size; //* 包数
    int len;  //* 总长度
} BUF_LIST;

/*************************************
* @brief 原子锁加锁
* @param 参数1：NULL
* @return 无
*************************************/
void atomic_lock_api(void);
/*************************************
* @brief 原子锁解锁
* @param 参数1：NULL
* @return 无
*************************************/
void atomic_unlock_api(void);

#define LOCK()      atomic_lock_api()
#define UNLOCK()    atomic_unlock_api()

//* TODO:区分不同编译器对likely的命名
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/****************************函数接口定义************************************************************/
ERROR_MESSAGE_T QueueInit(void);
ERROR_MESSAGE_T BufferInQueue(const uint8 *data, uint32 len);
ERROR_MESSAGE_T BufferOutQueue(struct List_Node **node);
uint8 IsEmptyQueue(void);
void bufferDestroy(void);
int GetQueueSize(void);
#ifdef DEBUG
void ShowQueue(void);
#endif
#endif
