//
// Created by Roman Kutashenko on 2/23/18.
//

#define TEST_NO_MAIN
#include "acutest.h"

#include <stdbool.h>
#include <uv.h>
#include <virgil-noisesocket.h>

uv_loop_t *uv_loop = NULL;

void
client_reg_result_cb(vn_client_t *ctx, vn_result_t result) {

}

void
test_registration() {

    const char *addr = "0.0.0.0";
    uint16_t port = 31000;

    const char *test_identity = "5edfb645-b32d-486d-af22-719a717f2062";
    const char *test_password = "qweASD123";

    vn_ticket_t ticket;

    vn_client_t *client = NULL;
    vn_server_t *server = NULL;

    // Create UV loops
    uv_loop = uv_default_loop();

    // Start server
    server = vn_server_new(addr, port,
                           "TEST_SERVER",
                           uv_loop);
    TEST_CHECK_(vn_server_start(server), "Cannot start server");

    // Start client
    client = vn_client_new(test_identity, test_password, uv_loop);
    TEST_CHECK_(!!client,
                "Cannot create client");

    TEST_CHECK_(VN_OK == vn_client_register(client,
                                            addr, port,
                                            &ticket,
                                            client_reg_result_cb),
                "Cannot register client");

    uv_run(uv_loop, UV_RUN_DEFAULT);

    vn_client_free(client);
    vn_server_free(server);

    TEST_CHECK_(false, "Registration error!\n");

}