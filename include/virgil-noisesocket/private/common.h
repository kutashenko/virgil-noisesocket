//
// Created by Roman Kutashenko on 3/7/18.
//

#ifndef VIRGIL_NOISESOCKET_COMMON_H
#define VIRGIL_NOISESOCKET_COMMON_H

#include <stdint.h>
#include <virgil-noisesocket/general.h>

#define NAME_MAX_SZ     (2 * ID_MAX_SZ)

#ifdef __cplusplus
extern "C" {
#endif

vn_result_t
vn_gen_static_keys(uint8_t private_key[STATIC_KEY_SZ],
                   uint8_t public_key[STATIC_KEY_SZ]);

vn_result_t
vn_name_by_id(uint8_t private_key[ID_MAX_SZ],
              char name[NAME_MAX_SZ]);

vn_result_t
vn_sign_static_key(const uint8_t private_key[PRIVATE_KEY_SZ],
                   const uint8_t static_public_key[STATIC_KEY_SZ],
                   uint8_t signature[SIGNATURE_SZ]);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_COMMON_H
