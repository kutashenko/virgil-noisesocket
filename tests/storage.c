//
// Created by Roman Kutashenko on 3/13/18.
//

#define TEST_NO_MAIN
#include "acutest.h"

#include <stdbool.h>
#include <uv.h>
#include <virgil-noisesocket/storage.h>
#include <virgil-noisesocket/data.h>

static bool
test_simple_save_load() {
    const char *name = "virgil-noisesocket-test.dat";
    const char *test_data = "Test data !!!";
    vn_data_t data_save;
    vn_data_t data_load;
    bool res = false;

    memset(&data_save, 0, sizeof(vn_data_t));
    memset(&data_load, 0, sizeof(vn_data_t));

    vn_data_init_copy(&data_save, (const uint8_t *)test_data, strlen(test_data) + 1);

    if (VN_OK != vn_storage_save(name, &data_save)) {
        goto exit;
    }

    if (VN_OK != vn_storage_load(name, &data_load)) {
        goto exit;
    }

    res = 0 == memcmp(data_save.bytes, data_load.bytes, data_save.sz);

exit:
    vn_data_free(&data_save);
    vn_data_free(&data_load);

    return res;
}

static bool
test_simple_resave_load() {
    const char *name = "virgil-noisesocket-test.dat";
    const char *test_data = "Test data !!!";
    const char *test_data_2 = "Test data new !!!";

    vn_data_t data_save;
    vn_data_t data_load;
    bool res = false;

    memset(&data_save, 0, sizeof(vn_data_t));
    memset(&data_load, 0, sizeof(vn_data_t));

    vn_data_init_copy(&data_save, (const uint8_t *)test_data, strlen(test_data) + 1);

    if (VN_OK != vn_storage_save(name, &data_save)) {
        goto exit;
    }

    vn_data_free(&data_save);
    vn_data_init_copy(&data_save, (const uint8_t *)test_data_2, strlen(test_data_2) + 1);

    if (VN_OK != vn_storage_save(name, &data_save)) {
        goto exit;
    }

    if (VN_OK != vn_storage_load(name, &data_load)) {
        goto exit;
    }

    res = 0 == memcmp(data_save.bytes, data_load.bytes, data_save.sz);

    exit:
    vn_data_free(&data_save);
    vn_data_free(&data_load);

    return res;
}

static bool
test_simple_save_keypair() {
    uint8_t id[ID_MAX_SZ];

    uint8_t private_key_in[PRIVATE_KEY_SZ];
    uint8_t public_key_in[PUBLIC_KEY_SZ];

    uint8_t private_key_out[PRIVATE_KEY_SZ];
    uint8_t public_key_out[PUBLIC_KEY_SZ];

    memset(id, 0xAA, ID_MAX_SZ);
    memset(private_key_in, 0xAB, PRIVATE_KEY_SZ);
    memset(public_key_in, 0xCD, PUBLIC_KEY_SZ);
    memset(private_key_out, 0, PRIVATE_KEY_SZ);
    memset(public_key_out, 0, PUBLIC_KEY_SZ);

    if (VN_OK == vn_storage_save_keys(id,
                                      private_key_in,
                                      public_key_in)
            && VN_OK == vn_storage_load_keys(id,
                                             private_key_out,
                                             public_key_out)) {
        return 0 == memcmp(private_key_in, private_key_out, PRIVATE_KEY_SZ)
                && 0 == memcmp(public_key_in, public_key_out, PUBLIC_KEY_SZ);
    }

    return false;
}

void test_storage() {
    TEST_CHECK_(test_simple_save_load(), "Simple Save/Load error!\n");
    TEST_CHECK_(test_simple_resave_load(), "Simple ReSave/Load error!\n");
    TEST_CHECK_(test_simple_save_keypair(), "Key pair Save/Load error!\n");
}

