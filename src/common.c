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