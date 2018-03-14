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
static const char *CARD_ID_FILE_SUFFIX = "-card-id.dat";

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

        fpos_t filesize;
        fgetpos(f, &filesize);

        fseek(f, 0, SEEK_SET);

        int f_sz = filesize.__pos;

        if (f_sz > 0 && f_sz < 2048) {
            vn_data_init_alloc(data, f_sz);
            data->sz = fread(data->bytes, 1, f_sz, f);
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
    FILE *f = fopen(name, "w+");
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
                     vn_data_t *private_key,
                     vn_data_t *public_key) {

    ASSERT(id);
    ASSERT(private_key);
    ASSERT(public_key);

    if (!id || !private_key || !public_key) {
        return VN_WRONG_PARAM;
    }

    char private_key_path[PATH_MAX];
    char public_key_path[PATH_MAX];

    if (VN_OK != _prepare_names(id, private_key_path, public_key_path)) {
        return VN_SAVE_ERROR;
    }

    if (VN_OK == vn_storage_load(private_key_path, private_key)
        && VN_OK == vn_storage_load(public_key_path, public_key)) {
        return VN_OK;
    }

    return VN_LOAD_ERROR;
}

vn_result_t
vn_storage_save_keys(const uint8_t id[ID_MAX_SZ],
                     const vn_data_t *private_key,
                     const vn_data_t *public_key) {

    ASSERT(id);
    ASSERT(private_key && private_key->bytes);
    ASSERT(public_key && public_key->bytes);

    if (!id || !private_key || !private_key->bytes
            || !public_key || !public_key->bytes) {
        return VN_WRONG_PARAM;
    }

    char private_key_path[PATH_MAX];
    char public_key_path[PATH_MAX];

    if (VN_OK != _prepare_names(id, private_key_path, public_key_path)) {
        return VN_SAVE_ERROR;
    }

    if (VN_OK == vn_storage_save(private_key_path, private_key)
        && VN_OK == vn_storage_save(public_key_path, public_key)) {
        return VN_OK;
    }

    return VN_SAVE_ERROR;
}

vn_result_t
vn_storage_load_card_id(const uint8_t id[ID_MAX_SZ],
                        vn_data_t *card_id) {
    char id_path[PATH_MAX];
    if (VN_OK != vn_name_by_id(id, id_path)) {
        return VN_GENERAL_ERROR;
    }
    strcat(id_path, CARD_ID_FILE_SUFFIX);

    if (VN_OK == vn_storage_load(id_path, card_id)) {
        return VN_OK;
    }

    return VN_LOAD_ERROR;
}

vn_result_t
vn_storage_save_card_id(const uint8_t id[ID_MAX_SZ],
                        const vn_data_t *card_id) {
    char id_path[PATH_MAX];
    if (VN_OK != vn_name_by_id(id, id_path)) {
        return VN_GENERAL_ERROR;
    }
    strcat(id_path, CARD_ID_FILE_SUFFIX);

    if (VN_OK == vn_storage_save(id_path, card_id)) {
        return VN_OK;
    }

    return VN_SAVE_ERROR;
}