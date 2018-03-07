//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_CLIENT_H
#define VIRGIL_NOISESOCKET_CLIENT_H

#include "results.h"
#include "data.h"
#include "ticket.h"

#include <uv.h>
#include <noisesocket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vn_client_s vn_client_t;

typedef void (*vn_client_reg_result_cb_t)(vn_client_t *ctx, vn_result_t result);

vn_client_t *
vn_client_new(const char *identity,
              const char *password,
              uv_loop_t *uv_loop);

vn_result_t
vn_client_free(vn_client_t *ctx);

vn_result_t
vn_client_register(vn_client_t *ctx,
                   const char *server_addr,
                   uint16_t server_port,
                   vn_ticket_t *ticket,
                   vn_client_reg_result_cb_t done_cb);

vn_result_t
vn_client_connect(vn_client_t *ctx,
                  const char *server_addr,
                  uint16_t server_port,
                  ns_session_ready_cb_t session_ready_cb,
                  uv_read_cb read_cb);

#ifdef __cplusplus
}
#endif

#endif //VIRGIL_NOISESOCKET_CLIENT_H
