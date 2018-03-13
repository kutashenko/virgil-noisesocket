//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_STORAGE_H
#define VIRGIL_NOISESOCKET_STORAGE_H

#include <virgil-noisesocket/data.h>
#include <virgil-noisesocket/general.h>

#ifdef __cplusplus
extern "C" {
#endif


vn_result_t
vn_storage_load(const char *name, vn_data_t *data);

vn_result_t
vn_storage_save(const char *name, const vn_data_t *data);

vn_result_t
vn_storage_load_keys(const uint8_t id[ID_MAX_SZ],
                     vn_data_t *private_key,
                     vn_data_t *public_key);

vn_result_t
vn_storage_save_keys(const uint8_t id[ID_MAX_SZ],
                     const vn_data_t *private_key,
                     const vn_data_t *public_key);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_STORAGE_H
