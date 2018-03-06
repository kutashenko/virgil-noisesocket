//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_STORAGE_H
#define VIRGIL_NOISESOCKET_STORAGE_H

#include <virgil-noisesocket/data.h>

vn_result_t
vn_storage_load(const char *name, const vn_data_t data);

vn_result_t
vn_storage_save(const char *name, vn_data_t data);

extern const char *PRIVATE_KEY_FILE;
extern const char *CARD_ID_FILE;

#endif //VIRGIL_NOISESOCKET_STORAGE_H
