//
// Created by Roman Kutashenko on 2/23/18.
//

#define TEST_NO_MAIN
#include "acutest.h"

#include <stdbool.h>
#include <uv.h>
#include <virgil-noisesocket.h>
#include <virgil-noisesocket/credentials.h>

uv_loop_t *uv_loop = NULL;

vn_client_t *client = NULL;
vn_server_t *server = NULL;

vn_result_t register_result;

void
client_reg_result_cb(vn_client_t *ctx, vn_result_t result) {
    register_result = result;

    printf("Registration result: %s\n", VN_OK == result ? "OK" : "ERROR");

    vn_server_stop(server);
}

void
test_registration() {

    const char *addr = "0.0.0.0";
    uint16_t port = 31000;

    const char *test_identity = "5edfb645-b32d-486d-af22-719a717f2062";
    const char *test_password = "qweASD123";

    vn_ticket_t ticket;

    // Create UV loops
    uv_loop = uv_default_loop();

    vn_virgil_credentials_t virgil_credentials;
    virgil_credentials.token = "AT.1e4554197853556d3f66fb71afb15629524eae58ba4fd59ba4f94959b8d18677";
    virgil_credentials.app_id = "8348cc9c0cff04328404b8b1122b18caa1cbb1e9b30e9386a0dc543c9a803a2d";
    virgil_credentials.private_key = "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBAtpTHSss+sKcW0Z5RvVwgKAgIfeDAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEJm+qFYlntvXKZQymeuTXD8EQPVyCvP521iWDJJfeBo2lwOf/FvfFsD3Dzayytw81V9TdxddCemntdHM2F8GgpQ+hDLZtKUyaXgzUBjSqCu0K+w=";
    virgil_credentials.private_key_password = "qweASD123";

    // Start server
    server = vn_server_new(addr, port,
                           "TEST_SERVER",
                           virgil_credentials,
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

    TEST_CHECK_(VN_OK == register_result, "Registration error!\n");
}
