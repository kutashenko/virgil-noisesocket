//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/storage.h>

const char *PRIVATE_KEY_FILE = "private-key-%s.dat";
const char *CARD_ID_FILE = "card-id.dat";

vn_result_t
vn_storage_load(const char *name, vn_data_t *data) {
    return VN_GENERAL_ERROR;
}

vn_result_t
vn_storage_save(const char *name, const vn_data_t data) {
    return VN_GENERAL_ERROR;
}

vn_result_t
vn_storage_load_keys(const uint8_t id[ID_MAX_SZ],
                     uint8_t private_key[PRIVATE_KEY_SZ],
                     uint8_t public_key[PUBLIC_KEY_SZ]) {
    return VN_GENERAL_ERROR;
}