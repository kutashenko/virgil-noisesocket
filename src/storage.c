//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/storage.h>
#include <virgil-noisesocket/private/debug.h>
#include <virgil-noisesocket/private/common.h>
#include <limits.h>
#include <string.h>
#include <virgil-noisesocket/data.h>

static const char *PRIVATE_KEY_FILE_SUFFIX = "-private-key.dat";
static const char *PUBLIC_KEY_FILE_SUFFIX = "-public-key.dat";
static const char *CARD_ID_FILE = "card-id.dat";

vn_result_t
vn_storage_load(const char *name, vn_data_t *data) {
    ASSERT(name);
    ASSERT(data);

    if (!name || !data) {
        return VN_WRONG_PARAM;
    }

    bool res = false;
    FILE *f = fopen(name, "rb");
    if (f > 0) {
        fseek(f, 0, SEEK_END);

        fpos_t flesize;
        fgetpos(f, &flesize);

        fseek(f, 0, SEEK_SET);

        if (flesize > 0 && flesize < 2048) {
            vn_data_init_alloc(data, flesize);
            data->sz = fread(data->bytes, flesize, 1, f);
            res = true;
        }

        fclose(f);
    }

    return res ? VN_OK : VN_SAVE_ERROR;
}

vn_result_t
vn_storage_save(const char *name, const vn_data_t *data) {
    ASSERT(name);
    ASSERT(data);
    ASSERT(data->sz);

    if (!name || !data || !data->sz) {
        return VN_WRONG_PARAM;
    }

    bool res = false;
    FILE *f = fopen(name, "wb");
    if (f > 0) {
        res = data->sz == fwrite(data->bytes, 1, data->sz, f);
        fclose(f);
    }

    return res ? VN_OK : VN_SAVE_ERROR;
}

static vn_result_t
_prepare_names(const uint8_t id[ID_MAX_SZ],
               char private_key_path[PATH_MAX],
               char public_key_path[PATH_MAX]) {

    if (VN_OK != vn_name_by_id(id, private_key_path)) {
        return VN_GENERAL_ERROR;
    }

    if (VN_OK != vn_name_by_id(id, public_key_path)) {
        return VN_GENERAL_ERROR;
    }

    strcat(private_key_path, PRIVATE_KEY_FILE_SUFFIX);
    strcat(public_key_path, PUBLIC_KEY_FILE_SUFFIX);

    return VN_OK;
}

vn_result_t
vn_storage_load_keys(const uint8_t id[ID_MAX_SZ],
                     uint8_t private_key[PRIVATE_KEY_SZ],
                     uint8_t public_key[PUBLIC_KEY_SZ]) {
    char private_key_path[PATH_MAX];
    char public_key_path[PATH_MAX];

    if (VN_OK != _prepare_names(id, private_key_path, public_key_path)) {
        return VN_SAVE_ERROR;
    }

    bool res = false;
    vn_data_t private_key_data;
    vn_data_t public_key_data;

    memset(&private_key_data, 0, sizeof(private_key_data));
    memset(&public_key_data, 0, sizeof(public_key_data));

    if (VN_OK == vn_storage_load(private_key_path, &private_key_data)
        && VN_OK == vn_storage_load(public_key_path, &public_key_data)) {

        memcpy(private_key, private_key_data.bytes, PRIVATE_KEY_SZ);
        memcpy(public_key, public_key_data.bytes, PUBLIC_KEY_SZ);
        res = true;
    }

    vn_data_free(&private_key_data);
    vn_data_free(&public_key_data);

    return res ? VN_OK : VN_LOAD_ERROR;
}

vn_result_t
vn_storage_save_keys(const uint8_t id[ID_MAX_SZ],
                     const uint8_t private_key[PRIVATE_KEY_SZ],
                     const uint8_t public_key[PUBLIC_KEY_SZ]) {
    char private_key_path[PATH_MAX];
    char public_key_path[PATH_MAX];

    if (VN_OK != _prepare_names(id, private_key_path, public_key_path)) {
        return VN_SAVE_ERROR;
    }

    bool res = false;
    vn_data_t private_key_data;
    vn_data_t public_key_data;

    vn_data_init_set(&private_key_data, private_key, PRIVATE_KEY_SZ);
    vn_data_init_set(&public_key_data, public_key, PUBLIC_KEY_SZ);

    if (VN_OK == vn_storage_save(private_key_path, &private_key_data)
        && VN_OK == vn_storage_save(public_key_path, &public_key_data)) {
        return VN_OK;
    }

    return VN_SAVE_ERROR;
}