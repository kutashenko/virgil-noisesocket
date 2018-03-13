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
vn_storage_save(const char *name, const vn_data_t data);

vn_result_t
vn_storage_load_keys(const uint8_t id[ID_MAX_SZ],
                     uint8_t private_key[PRIVATE_KEY_SZ],
                     uint8_t public_key[PUBLIC_KEY_SZ]);

extern const char *PRIVATE_KEY_FILE;
extern const char *CARD_ID_FILE;

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_STORAGE_H
