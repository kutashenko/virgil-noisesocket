//
// Created by Roman Kutashenko on 3/7/18.
//

#ifndef VIRGIL_NOISESOCKET_COMMON_H
#define VIRGIL_NOISESOCKET_COMMON_H

#include <stdint.h>

#define STATIC_KEY_SZ   (32)
#define SIGNATURE_SZ    (64)
#define ID_MAX_SZ       (64)

#ifdef __cplusplus
extern "C" {
#endif

vn_result_t
vn_gen_static_keys(uint8_t private_key[STATIC_KEY_SZ],
                   uint8_t public_key[STATIC_KEY_SZ]);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_COMMON_H
