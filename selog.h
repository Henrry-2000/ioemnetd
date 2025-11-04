/*============================================================================*/
/** Copyright (C) 2016-2023, Vecentek Information CO.,LTD.
 *
 *  All rights reserved. This software is Vecentek property. Duplication
 *  or disclosure without Vecentek written authorization is prohibited.
 *
 *  @file       <selog.h>
 *  @brief      <Briefly describe file(one line)>
 *
 *
 *  @author     <fupw@vecentek.com>
 *  @date       <2019-09-06>
 */
/*============================================================================*/
#ifndef _SELOG_H_
#define _SELOG_H_

/*=======[M A C R O S]============================================================================*/
#define selog_handle void *
#define SELOG_VERSION "SELOG:V4.0.7"

/*=======[I N T E R N A L   F U N C T I O N   D E C L A R A T I O N S]============================*/
#ifdef __cplusplus
extern "C"
{
#endif
    extern int _Selog_Conf_SetCommon(selog_handle lhs, int option, ...);
#ifdef __cplusplus
}
#endif

/*=======[M A C R O S]============================================================================*/
#define SELOG_APP_TAGS_SIZE (8)      // app标识的最大长度，不包含结束符
#define SELOG_SINGLE_LOG_SIZE (5000) // 单条日志的最大长度，不包含结束符
#define SELOG_LOG_NUM_MIN (1)        // 单次读取日志最小条数
#define SELOG_AUDITLOG_LEN_MIN (1)   // 单次读取审计日志最小长度
#ifdef SELOG_TRUE
#undef SELOG_TRUE
#endif
#define SELOG_TRUE 1

#ifdef SELOG_FALSE
#undef SELOG_FALSE
#endif
#define SELOG_FALSE 0

#define Selog_SetConfCommon(handle, option, value) \
    _Selog_Conf_SetCommon(handle, option, value, 0xFFFF0C0A);

#define Selog_SetConfChain(handle, option, eventid, user_eventid, aggregation_time, threshold_count, threshold_time, sampling_count) \
    _Selog_Conf_SetCommon(handle, option, eventid, user_eventid, aggregation_time, threshold_count, threshold_time, sampling_count, 0xFFFF0C0A);

#define Selog_SetConfAudit(handle, option, auditlogPath, auditlogType, auditlogLevel) \
    _Selog_Conf_SetCommon(handle, option, auditlogPath, auditlogType, auditlogLevel, 0xFFFF0C0A);

/*=======[T Y P E   D E F I N I T I O N S]========================================================*/
typedef char SELOG_S8;            /*        -128 .. +127           */
typedef unsigned char SELOG_U8;   /*           0 .. 255            */
typedef short SELOG_S16;          /*      -32768 .. +32767         */
typedef unsigned short SELOG_U16; /*           0 .. 65535          */
typedef int SELOG_S32;            /* -2147483648 .. +2147483647    */
typedef unsigned int SELOG_U32;   /*           0 .. 4294967295     */
typedef unsigned long SELOG_U64;
typedef long SELOG_S64;
typedef float SELOG_F32;
typedef double SELOG_F64;
typedef unsigned char SELOG_bool; /* for use with SELOG_TRUE/SELOG_FALSE  */

/* selog return code*/
typedef enum
{
    SELOG_SUCESS = 0,
    SELOG_FAIL = 0XF0000000,             // 失败,如设置打印级别失败、清除读取缓冲区失败
    SELOG_MODE_ERROR,                    // 模式错误，如创建句柄时指定不存在的模式
    SELOG_HANDLE_ERROR,                  // 无效句柄
    SELOG_HANDLE_POOL_FULL,              // 句柄池已满，无法创建新句柄
    SELOG_PARAM_ERROR,                   // 参数错误,如空指针
    SELOG_HANDLE_UNINIT,                 // 句柄未初始化
    SELOG_MALLOC_ERROR,                  // 内存开辟失败
    SELOG_CFG_ERROR = 0XF1000000,        // 配置错误
    SELOG_CFG_FILTER_FULL,               // 抑制模块配置已达到上限
    SELOG_CFG_AUDIT_FULL,                // 审计日志配置已达到上限
    SELOG_CFG_TYPE_ERROR,                // 配置类型错误
    SELOG_SIZE_OVER = 0XF2000000,        // 输入日志长度超限
    SELOG_ADDINFO_ERROR,                 // 输入日志附加信息错误
    SELOG_READ_NOT_SUPPORT = 0XF3000000, // 模式不支持读取
    SELOG_READ_ADUITLOG_CONF_NULL,       // 未配置审计日志文件调用读取接口
} Selog_RetCodeType;

/* selog model type*/
typedef enum
{
    SELOG_MODEL_INDEPEND = 1,
    SELOG_MODEL_SERVER,
    SELOG_MODEL_CLIENT,
} Selog_ModeType;

/*debug log level*/
typedef enum
{
    SELOG_DEBUG_LEVEL_VERBOSE = 0,
    SELOG_DEBUG_LEVEL_DEBUG,
    SELOG_DEBUG_LEVEL_INFO,
    SELOG_DEBUG_LEVEL_WARN,
    SELOG_DEBUG_LEVEL_ERROR,
    SELOG_DEBUG_LEVEL_FATAL,
} Selog_DebugLevelType;

typedef enum
{
    SELOG_CFG_MANAGER_PORT = 0x01,
    SELOG_CFG_CAPACITY,
    SELOG_CFG_PATH,
    SELOG_CFG_ENC_FLAG,
    SELOG_CFG_FUN_ENC,
    SELOG_CFG_FUN_DEC,
    SELOG_CFG_FILTER_ENABLE,
    SELOG_CFG_FILTER_EVENTID,
    SELOG_CFG_FILTER_BLOCK_EVENTID,
    SELOG_CFG_FILTER_RATE_BYTE,
    SELOG_CFG_FILTER_RATE_BYTE_TIME,
    SELOG_CFG_FILTER_RATE_COUNT,
    SELOG_CFG_FILTER_RATE_COUNT_TIME,
    SELOG_CFG_FILTER_CHAIN_ARRARY,
    SELOG_CFG_AUDITLOG_ARRARY,
} Selog_CfgCodeType;

typedef enum
{
    SELOG_LOG_LEVEL_FATAL = 0,  // 致命
    SELOG_LOG_LEVEL_ERROR = 1,  // 错误
    SELOG_LOG_LEVEL_WARN = 2,   // 告警
    SELOG_LOG_LEVEL_INFO = 3,   // 信息
    SELOG_LOG_LEVEL_HIGH = 10,  // 高
    SELOG_LOG_LEVEL_MIDDLE,     // 中
    SELOG_LOG_LEVEL_LOW,        // 低
    SELOG_LOG_LEVEL_PROMPT      // 提示
} Selog_LogLevelType;

typedef enum
{
    SELOG_LOG_TYPE_SYSTEM = 0, // 系统安全类
    SELOG_LOG_TYPE_APP,        // 应用安全类
    SELOG_LOG_TYPE_COMM,       // 通信安全类
    SELOG_LOG_TYPE_DATA,       // 数据安全类
    SELOG_LOG_TYPE_BUSINESS,   // 业务安全类
    SELOG_LOG_TYPE_IDSM,       // IDSM类
    SELOG_LOG_TYPE_DEBUG,      // 调试类
} Selog_LogType;

typedef enum
{
    SELOG_AUDITLOG_LEVEL_FATAL = 0, // 致命
    SELOG_AUDITLOG_LEVEL_ERROR,     // 错误
    SELOG_AUDITLOG_LEVEL_WARN,      // 告警
    SELOG_AUDITLOG_LEVEL_INFO,      // 信息
    SELOG_AUDITLOG_LEVEL_HIGH = 10, // 高
    SELOG_AUDITLOG_LEVEL_MIDDLE,    // 中
    SELOG_AUDITLOG_LEVEL_LOW,       // 低
    SELOG_AUDITLOG_LEVEL_PROMPT,    // 提示
} Selog_AuditLogLevelType;

typedef enum
{
    SELOG_AUDITLOG_TYPE_SYSTEM = 0, // 系统安全类
    SELOG_AUDITLOG_TYPE_APP,        // 应用安全类
    SELOG_AUDITLOG_TYPE_COMM,       // 通信安全类
    SELOG_AUDITLOG_TYPE_DATA,       // 数据安全类
    SELOG_AUDITLOG_TYPE_BUSINESS,   // 业务安全类
    SELOG_AUDITLOG_TYPE_HARDWARE,   // 硬件安全类
    SELOG_AUDITLOG_TYPE_DEBUG,      // 调试类
} Selog_AuditLogType;

typedef struct
{
    SELOG_S64 timestamp;                        // 时间戳
    SELOG_U16 eventid;                          // 事件ID（大类）
    SELOG_U16 user_eventid;                     // 事件ID（小类）
    Selog_LogType log_type;                     // 表示日志类型
    Selog_LogLevelType level;                   // 表示日志级别
    SELOG_bool urgent_flag;                     // 标识紧急事件
    SELOG_U32 aggregation_count;                // 表示聚合计数，有效范围为1-65535，0会转化成1，超过65535会转化成65535
    SELOG_S8 app_tags[SELOG_APP_TAGS_SIZE + 1]; // 表示app标识
} Selog_WriteStructType;

typedef struct
{
    SELOG_S32 logNum;                       // 表示审计日志读取个数
    SELOG_S8 **dataBuff;                    // 表示审计日志缓冲区
    SELOG_S8 **auditlogPath;                // 表示审计日志文件绝对路径
    SELOG_U16 *dataLen;                     // 表示审计日志长度
    Selog_AuditLogType *auditlogType;       // 表示审计日志类型
    Selog_AuditLogLevelType *auditlogLevel; // 表示审计日志级别
} Selog_AuditlogReadStructType;

typedef struct
{
    SELOG_S32 logNum;                // 表示日志读取条数
    Selog_WriteStructType *addInfor; // 表示附加信息
    SELOG_U16 *dataLen;              // 表示日志信息长度
    SELOG_S8 **dataBuff;             // 表示日志信息
} Selog_ReadStructType;

#ifdef __cplusplus
extern "C"
{
#endif
    /**************************************************************************************************/
    /* Brief: Create a selog handle.
     * Sync/Async: Synchronous
     * Reentrancy: Reentrant
     * Param-Name[in]: runMode: create module type.
     * Param-Name[in]: pAppName: create app name.
     * Param-Name[out]: None
     * Param-Name[in/out]: lhs: security log module handle.
     * Return: 	0:success.
     * 			!0:error code.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_CreateHandle(selog_handle *lhs, Selog_ModeType runMode, SELOG_S8 *pAppName);

    /**************************************************************************************************/
    /* Brief: Initializes the selog handle.
     * Sync/Async: Synchronous
     * Reentrancy: Non Reentrant
     * Param-Name[in]: lhs: security log module handle.
     * Param-Name[out]: None
     * Param-Name[in/out]: None
     * Return: 	0:success.
     * 			!0:error code.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_Init(selog_handle lhs);

    /**************************************************************************************************/
    /* Brief: stops the selog.
     * Sync/Async: Synchronous
     * Reentrancy: Non Reentrant
     * Param-Name[in]: lhs: security log module handle.
     * Param-Name[out]: None
     * Param-Name[in/out]: None
     * Return: 	0:success.
     * 			!0:error code.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_Deinit(selog_handle lhs);

    /**************************************************************************************************/
    /* Brief: write security log info.
     * Sync/Async: Synchronous
     * Reentrancy: Non Reentrant
     * Param-Name[in]: lhs: security log module handle.
     * Param-Name[in]: logInfo: write log parameter.
     * Param-Name[in]: logs: security log info.
     * Param-Name[in]: logLen: security log info length.
     * Param-Name[out]: None
     * Param-Name[in/out]: None
     * Return: 	0:success.
     * 			!0:error code.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_Write(selog_handle lhs, Selog_WriteStructType logInfo, SELOG_S8 *logs, SELOG_U32 logLen);

    /**************************************************************************************************/
    /* Brief: read security log info.
     * Sync/Async: Synchronous
     * Reentrancy: Non Reentrant
     * Param-Name[in]: lhs: security log module handle.
     * Param-Name[in/out]: logNum: read parameter.
     * Param-Name[in/out]: logPtr: security log info list.
     * Return: 	0:success.
     * 			< 0:error code.
     * 			> 0:read log num.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_Read(selog_handle lhs, SELOG_S32 logNum, Selog_ReadStructType *logPtr);

    /**************************************************************************************************/
    /* Brief: read audit log info.
     * Sync/Async: Synchronous
     * Reentrancy: Non Reentrant
     * Param-Name[in]: lhs: security log module handle.
     * Param-Name[in]: logLen: read max len.
     * Param-Name[in/out]: logPtr: audit log info list.
     * 			< 0:error code.
     * 			> 0:read audit log num.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_AuditlogRead(selog_handle lhs, SELOG_S32 logLen, Selog_AuditlogReadStructType *logPtr);

    /**************************************************************************************************/
    /* Brief: printf version info.
     * Sync/Async: Synchronous
     * Reentrancy: Reentrant
     * Param-Name[in]: None.
     * Param-Name[out]: None.
     * Param-Name[in/out]: None.
     * Return: 	version info.
     */
    /**************************************************************************************************/
    const SELOG_S8 *Selog_VerPrint(void);

    /**************************************************************************************************/
    /* Brief: set debug level. The default debug level is SELOG_DEBUG_LEVEL_ERROR.
     * Sync/Async: Synchronous
     * Reentrancy: Reentrant
     * Param-Name[in]: Level：debug level.
     * Param-Name[out]: None.
     * Param-Name[in/out]: None.
     * Return: 	None.
     */
    /**************************************************************************************************/
    SELOG_S32 Selog_SetDebugLevel(Selog_DebugLevelType level);

#ifdef __cplusplus
}
#endif
#endif /*!_LOG_H_*/
