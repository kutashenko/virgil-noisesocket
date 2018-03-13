//
// Created by Roman Kutashenko on 3/7/18.
//

#include <virgil-noisesocket/results.h>
#include <virgil-noisesocket/private/debug.h>
#include <virgil-noisesocket/private/common.h>
#include <stdint.h>
#include <sodium.h>

vn_result_t
vn_gen_static_keys(uint8_t private_key[STATIC_KEY_SZ],
                   uint8_t public_key[STATIC_KEY_SZ]) {
    ASSERT(private_key);
    ASSERT(public_key);

    if (!private_key || !public_key) {
        return VN_WRONG_PARAM;
    }

    randombytes_buf(private_key, STATIC_KEY_SZ);
    private_key[0] &= 0xF8;
    private_key[31] = (private_key[31] & 0x7F) | 0x40;
    crypto_scalarmult_curve25519_base(public_key, private_key);

    return VN_OK;
}

vn_result_t
vn_name_by_id(uint8_t id[ID_MAX_SZ],
              char name[NAME_MAX_SZ]) {
    ASSERT(id);
    ASSERT(name);

    int i;
    char *p = name;

    for (i = 0; i < ID_MAX_SZ; ++i, p += 2) {
        sprintf(p, "%02X", id[i]);
    }

    return VN_OK;
}

vn_result_t
vn_sign_static_key(const uint8_t private_key[PRIVATE_KEY_SZ],
                   const uint8_t static_public_key[STATIC_KEY_SZ],
                   uint8_t signature[SIGNATURE_SZ]) {
    return VN_CANNOT_SIGN_OWN_KEY;
}