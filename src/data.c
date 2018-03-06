//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/data.h>
#include "debug.h"
#include "string.h"

static vn_result_t
_init_alloc_copy(vn_data_t *data, const uint8_t *bytes, size_t sz) {
    ASSERT(data);
    ASSERT(sz);

    if (!data || !sz) {
        return VN_WRONG_PARAM;
    }

    data->sz = sz;
    data->bytes = calloc(1, sz);
    ASSERT(data->bytes);
    if (!data->bytes) {
        return VN_ALLOC_ERROR;
    }

    if (bytes) {
        memcpy(data->bytes, bytes, sz);
    }

    data->need_free = true;

    return VN_OK;
}

vn_result_t
vn_data_init_copy(vn_data_t *data, const uint8_t *bytes, size_t sz) {
    ASSERT(bytes);

    if (!bytes) {
        return VN_WRONG_PARAM;
    }

    return _init_alloc_copy(data, bytes, sz);
}

vn_result_t
vn_data_init_set(vn_data_t *data, const uint8_t *bytes, size_t sz) {
    ASSERT(data);
    ASSERT(bytes);
    ASSERT(sz);

    if (!data || !bytes || !sz) {
        return VN_WRONG_PARAM;
    }

    data->sz = sz;
    data->bytes = (uint8_t*)bytes;
    data->need_free = false;

    return VN_OK;
}

vn_result_t
vn_data_init_alloc(vn_data_t *data, size_t sz) {
    return _init_alloc_copy(data, NULL, sz);
}

vn_result_t
vn_data_free(vn_data_t *data) {
    ASSERT(data);

    if (!data) {
        return VN_WRONG_PARAM;
    }

    if (data->need_free && data->bytes) {
        free(data->bytes);
    }

    memset(data, 0, sizeof(vn_data_t));

    return VN_OK;
}