#include <stdlib.h>
#include <uv.h>

#include <virgil-noisesocket.h>

uv_loop_t *uv_loop = NULL;

void
client_reg_result_cb(vn_client_t *ctx, vn_result_t result) {

}

int
main() {

    const char *addr = "0.0.0.0";
    uint16_t port = 31000;

    const char *test_identity = "5edfb645-b32d-486d-af22-719a717f2062";
    const char *test_password = "qweASD123";

    vn_ticket_t ticket;

    vn_client_t *client = NULL;
    vn_server_t *server = NULL;

    // Create UV loops
    uv_loop = uv_default_loop();

    client = vn_client_new(test_identity, test_password, uv_loop);
    vn_client_register(client,
                       addr, port,
                       &ticket,
                       client_reg_result_cb);

    uv_run(uv_loop, UV_RUN_DEFAULT);

    vn_client_free(client);

    return 0;
}