//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_CLIENT_H
#define VIRGIL_NOISESOCKET_CLIENT_H

#include "results.h"
#include "data.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vn_client_s vn_client_t;

vn_client_t *
vn_client_new(const char *identity,
              const char *password);

vn_result_t
vn_client_free(vn_client_t *ctx);

vn_result_t
vn_client_register(vn_client_t *ctx);

vn_result_t
vn_client_load(vn_client_t *ctx);

vn_result_t
vn_client_save(vn_client_t *ctx);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_CLIENT_H
