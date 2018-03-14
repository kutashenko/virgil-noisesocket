//
// Created by Roman Kutashenko on 3/13/18.
//

#define TEST_NO_MAIN
#include "acutest.h"

#include <stdbool.h>
#include <uv.h>
#include <virgil-noisesocket.h>
#include <virgil-noisesocket/credentials.h>

static uv_loop_t *uv_loop = NULL;

static vn_client_t *client = NULL;
static vn_server_t *server = NULL;

static vn_result_t connection_result = VN_CONNECT_ERROR;

static void
on_session_ready(uv_tcp_t *handle, ns_result_t result) {
    printf("Session ready \n");

    connection_result = NS_OK == result ? VN_OK : VN_CONNECT_ERROR;

    vn_client_disconnect(client, 0);
    vn_server_stop(server);
}

static void
on_read(uv_stream_t *stream,
        ssize_t nread,
        const uv_buf_t* buf) {
    printf("Ready to read\n");
}

void
test_verified_connection() {
    const char *addr = "0.0.0.0";
    uint16_t port = 30005;

    const char *test_identity = "5edfb645-b32d-486d-af22-719a717f2062";
    const char *test_password = "qweASD123";

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

    TEST_CHECK_(VN_OK == vn_client_connect(client,
                                           addr, port,
                                           on_session_ready,
                                           on_read),
                "Cannot connect client");

    uv_run(uv_loop, UV_RUN_DEFAULT);

    vn_client_free(client);
    vn_server_free(server);

    TEST_CHECK_(VN_OK == connection_result, "Connection error!\n");
}
