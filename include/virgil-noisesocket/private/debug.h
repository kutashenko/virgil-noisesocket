//
// Created by Roman Kutashenko on 2/12/18.
//

#ifndef NOISESOCKET_DEBUG_H
#define NOISESOCKET_DEBUG_H

#include <stdio.h>
#include <assert.h>
#include "virgil-noisesocket/results.h"

#if !defined(ASSERT)
#define ASSERT assert
#endif

#define CHECK(X) do { \
    vn_result_t res; \
    res = (X); \
    if (VN_OK != res) return res; \
} while(0);

#define CHECK_MES(X, MES) do { \
    vn_result_t res; \
    res = (X); \
    if (VN_OK != res) { \
        (MES); \
        return res; \
    } \
} while(0);

#define LOG printf

#endif //NOISESOCKET_DEBUG_H
