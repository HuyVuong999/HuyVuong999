#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

// Set in makefile
// #define DEBUG 1

// Always enable message
#define DEBUG_MESSAGE_EN 1

#ifdef DEBUG
#define debug_print(fmt, ...) \
        do { if (DEBUG_MESSAGE_EN) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)
#else
#define debug_print(fmt, ...) \
        do { if (DEBUG_MESSAGE_EN) fprintf(stderr, fmt, __VA_ARGS__); } while (0)
#endif

#endif
