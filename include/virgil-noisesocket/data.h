//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_DATA_H
#define VIRGIL_NOISESOCKET_DATA_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <virgil-noisesocket/results.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *bytes;
    size_t sz;
    bool need_free;
} vn_data_t;

vn_result_t
vn_data_init_copy(vn_data_t *data, const uint8_t *bytes, size_t sz);

vn_result_t
vn_data_init_alloc(vn_data_t *data, size_t sz);

vn_result_t
vn_data_init_set(vn_data_t *data, const uint8_t *bytes, size_t sz);

vn_result_t
vn_data_free(vn_data_t *data);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_DATA_H
