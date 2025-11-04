#include <pcre2.h>
#include <stdio.h>
#include <string.h>
#define MATCH_IPV4 "((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}"
#include "ip_resolver.h"


// 正则表达式匹配结构体
typedef struct {
    pcre2_code *re;
    pcre2_match_data *match_data;
} RegexMatcher;

RegexMatcher matcher = {0};
static unsigned char initialized = 0;

// 
/**
 * @brief 初始化正则表达式匹配器
 * 
 * @param matcher 
 * @param pattern 
 * @return int 
 */
int regex_init(RegexMatcher *matcher, const char *pattern) {
    int error_number;
    PCRE2_SIZE error_offset;

    // 编译正则表达式
    matcher->re = pcre2_compile(
        (PCRE2_SPTR)pattern,
        PCRE2_ZERO_TERMINATED,
        0,
        &error_number,
        &error_offset,
        NULL
    );

    if (matcher->re == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(error_number, buffer, sizeof(buffer));
        fprintf(stderr, "PCRE2 compilation failed at offset %d: %s\n", 
                (int)error_offset, buffer);
        return 0;
    }

    // 准备匹配数据
    matcher->match_data = pcre2_match_data_create_from_pattern(matcher->re, NULL);
    if (matcher->match_data == NULL) {
        fprintf(stderr, "Failed to create match data\n");
        pcre2_code_free(matcher->re);
        return 0;
    }
    initialized = 1;
    return 1;
}

/**
 * @brief 释放正则表达式匹配器资源
 * 
 * @param matcher 
 * @return * void 
 */
void regex_free(RegexMatcher *matcher) {
    if (matcher->re) {
        pcre2_code_free(matcher->re);
        matcher->re = NULL;
    }
    if (matcher->match_data) {
        pcre2_match_data_free(matcher->match_data);
        matcher->match_data = NULL;
    }
}

/**
 * @brief 初始化正则表达式匹配器
 * 
 */
void InitializeRegex()
{
    if (!initialized) {
        if (!regex_init(&matcher, MATCH_IPV4)) {
            fprintf(stderr, "Failed to initialize regex matcher\n");
            exit(EXIT_FAILURE);
        }
    }
}

/**
 * @brief 销毁正则表达式匹配器资源
 * 
 */
void destroy_regex()
{
    regex_free(&matcher);
}

/**
 * @brief  使用正则表达式查找所有匹配的IP地址
 * 
 * @param matcher 
 * @param subject 
 * @param match_count 
 * @param match_results 
 */
void regex_find_all(RegexMatcher *matcher, const char *subject,int* match_count,char* match_results[]) {
    size_t subject_len = strlen(subject);
    unsigned int offset = 0;
    int rc;
    PCRE2_SIZE *ovector;

    printf("Searching in: %s\n", subject);

    while (offset < subject_len) {
        rc = pcre2_match(
            matcher->re,
            (PCRE2_SPTR)subject,
            subject_len,
            offset,
            0,
            matcher->match_data,
            NULL
        );

        if (rc < 0) {
            if (rc == PCRE2_ERROR_NOMATCH) {
                break;
            }
            fprintf(stderr, "Matching error %d\n", rc);
            break;
        }

        ovector = pcre2_get_ovector_pointer(matcher->match_data);
        printf("Found match: %.*s at position %d-%d\n",
               (int)(ovector[1] - ovector[0]),
               subject + ovector[0],
               (int)ovector[0],
               (int)ovector[1]);
        match_results[*match_count] = strndup(subject + ovector[0], ovector[1] - ovector[0]);
        (*match_count)++;
        offset = ovector[1]; // 移动到下一个匹配位置
    }
}

/**
 * @brief 查找IP地址
 * 
 * @param subject 输入字符串
 * @param match_count 匹配数量
 * @param match_results 匹配结果数组
 */
void found_ip_addresses(const char *subject, int *match_count, char *match_results[]) {
    if (initialized) {
        regex_find_all(&matcher, subject, match_count, match_results);
    } else {
        fprintf(stderr, "Failed to initialize regex matcher\n");
    }
}