//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/storage.h>

const char *PRIVATE_KEY_FILE = "private-key.dat";
const char *CARD_ID_FILE = "card-id.dat";

vn_result_t
vn_storage_load(const char *name, const vn_data_t data) {
    return VN_GENERAL_ERROR;
}

vn_result_t
vn_storage_save(const char *name, vn_data_t data) {
    return VN_GENERAL_ERROR;
}