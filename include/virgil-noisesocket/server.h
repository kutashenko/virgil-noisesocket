//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_SERVER_H
#define VIRGIL_NOISESOCKET_SERVER_H

#include <virgil-noisesocket/results.h>

#include <stdint.h>
#include <stdlib.h>

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vn_server_s vn_server_t;

vn_server_t *
vn_server_new(const char *addr,
              uint16_t port,
              const char *identity,
              uv_loop_t *uv_loop);

vn_result_t
vn_server_free(vn_server_t *server);

vn_result_t
vn_server_start(vn_server_t *server);

vn_result_t
vn_server_stop(vn_server_t *server);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_SERVER_H
