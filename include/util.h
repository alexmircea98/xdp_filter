#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>      /* fprintf */
#include <stdlib.h>     /* exit    */
#include <errno.h>      /* errno   */

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CLR     "\033[0m"

/* quality of life - conditional killer */
#define DIE(assertion, msg...)                                  \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, RED "%s:%d ", __FILE__, __LINE__);  \
            fprintf(stderr, msg);                               \
            fprintf(stderr, CLR "\n");                          \
            exit(-1);                                           \
        }                                                       \
    } while(0)

/* quality of life - conditional warning */
#define WAR(assertion, msg...)                                      \
    do {                                                            \
        if (assertion) {                                            \
            fprintf(stderr, YELLOW "%s:%d ", __FILE__, __LINE__);   \
            fprintf(stderr, msg);                                   \
            fprintf(stderr, CLR "\n");                              \
        }                                                           \
    } while (0)

/* quality of life - jump to cleanup label */
#define ABORT(assertion, label, msg...)                         \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, RED "%s:%d ", __FILE__, __LINE__);  \
            fprintf(stderr, msg);                               \
            fprintf(stderr, CLR "\n");                          \
            goto label;                                         \
        }                                                       \
    } while (0)

/* quality of life - conditional immediate return */
#define RET(assertion, code, msg...)                            \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, RED "%s:%d ", __FILE__, __LINE__);  \
            fprintf(stderr, msg);                               \
            fprintf(stderr, CLR "\n");                          \
            return code;                                        \
        }                                                       \
    } while (0)

#endif


