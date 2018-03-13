//
// Created by Roman Kutashenko on 3/7/18.
//

#include <virgil-noisesocket/results.h>
#include <virgil-noisesocket/private/debug.h>
#include <virgil-noisesocket/private/common.h>
#include <sodium.h>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil-noisesocket/data.h>

using virgil::sdk::crypto::CryptoInterface;

namespace vsdk = virgil::sdk;

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
vn_name_by_id(const uint8_t id[ID_MAX_SZ],
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
vn_sign_static_key(const vn_data_t *private_key,
                   const char *password,
                   const uint8_t static_public_key[STATIC_KEY_SZ],
                   vn_data_t *signature) {

    ASSERT(private_key && private_key->bytes);
    ASSERT(password);
    ASSERT(static_public_key);
    ASSERT(signature);

    if (!private_key || !private_key->bytes
            || !password || !static_public_key || !signature) {
        return VN_WRONG_PARAM;
    }

    try {
        auto crypto = vsdk::crypto::Crypto();

        auto privateKey = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(private_key->bytes, private_key->sz);
        auto key = crypto.importPrivateKey(privateKey, password);
        auto data = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(static_public_key, STATIC_KEY_SZ);

        auto sign = crypto.generateSignature(data, key);

        vn_data_init_copy(signature, sign.data(), sign.size());

        return VN_OK;

    } catch(...) {}

    return VN_CANNOT_SIGN_OWN_KEY;
}