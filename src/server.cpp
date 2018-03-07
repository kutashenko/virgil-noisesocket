//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/server.h>
#include <virgil-noisesocket/private/common.h>
#include <virgil-noisesocket/private/debug.h>

#include <noisesocket.h>
#include <noisesocket/types.h>

#define SERVER_CTX(X) ((vn_server_t*)(X->data))

struct vn_server_s {
    uint8_t id[ID_MAX_SZ];

    uint8_t static_public_key[STATIC_KEY_SZ];
    uint8_t static_private_key[STATIC_KEY_SZ];

    uint8_t static_signature[SIGNATURE_SZ];

    uint8_t root_public_key[STATIC_KEY_SZ];

    char *addr;
    uint16_t port;
    uv_tcp_t uv_server;
    uv_loop_t *uv_loop;

    char *identity;
};

extern "C" vn_server_t *
vn_server_new(const char *addr,
              uint16_t port,
              const char *identity,
              uv_loop_t *uv_loop) {
    ASSERT(uv_loop);
    ASSERT(identity);

    if (!uv_loop || !identity) {
        return NULL;
    }

    vn_server_t *server = NULL;

    server = (vn_server_t *) calloc(1, sizeof(vn_server_t));

    if (VN_OK != vn_gen_static_keys(server->static_private_key,
                                    server->static_public_key)) {
        vn_server_free(server);
        return NULL;
    }

    server->port = port;
    server->addr = strdup(addr);
    server->identity = strdup(identity);
    server->uv_loop = uv_loop;

    return server;
}

extern "C" vn_result_t
vn_server_free(vn_server_t *server) {
    ASSERT(server);

    if (!server) {
        return VN_WRONG_PARAM;
    }

    if (server->addr) {
        free(server->addr);
    }
    free(server->identity);
    free(server);

    return VN_OK;
}

static vn_result_t
_fill_crypto_ctx(vn_server_t *server, ns_crypto_t *crypto_ctx) {
    crypto_ctx->public_key = server->static_public_key;
    crypto_ctx->public_key_sz = STATIC_KEY_SZ;
    crypto_ctx->private_key = server->static_private_key;
    crypto_ctx->private_key_sz = STATIC_KEY_SZ;
    strcpy((char*)crypto_ctx->meta_data, "Server meta data");
    return VN_OK;
}

static void
on_session_ready(uv_tcp_t *client, ns_result_t result) {

    if (NS_OK != result) {
        printf("Session error %d.\n", (int)result);
        ns_close((uv_handle_t*)client, NULL);
        return;
    }

    printf("Connected.\n");
}

static void
alloc_buffer(uv_handle_t * handle, size_t size, uv_buf_t *buf) {
    buf->base = (char*)malloc(size);
    buf->len = size;
}

static int
on_verify_client(void * empty,
                 const uint8_t *public_key, size_t public_key_len,
                 const uint8_t *meta_data, size_t meta_data_len) {
    printf("Verify client\n");
    printf("    Meta data: %s.\n", (const char*)meta_data);
//    print_buf("    Public key:", public_key, public_key_len);
    return 0;
}


static void
on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread  <= 0) {
        fprintf(stderr, "Read error!\n");
        ns_close((uv_handle_t *)client, NULL);
        return;
    }

    if (nread > 0) {
        char str_buf[nread + 1];
        memcpy(str_buf, buf->base, nread);
        str_buf[nread] = 0;
        printf("\n\n%s\n\n", str_buf);
    }

//    uv_write_t *write_req = (uv_write_t *) malloc(sizeof(uv_write_t));
//    uv_buf_t send_buf;
//    send_buf.base = malloc(1024);
//    http_str(send_buf.base);
//    write_req->data = (void *)send_buf.base;
//    if (NS_OK != ns_prepare_write(client,
//                                  (uint8_t*)send_buf.base, strlen(send_buf.base) + 1,
//                                  1024, &send_buf.len)) {
//        printf("ERROR: Cannot prepare data to send.");
//    }
//
//    uv_write(write_req, client, &send_buf, 1, echo_write);
}

static void
on_new_connection(uv_stream_t *server, int status) {
    if (status == -1) {
        return;
    }

    uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(SERVER_CTX(server)->uv_loop, client);

    if (uv_accept(server, (uv_stream_t *) client) == 0) {

        ns_crypto_t crypto_ctx;
        _fill_crypto_ctx(SERVER_CTX(server), &crypto_ctx);

        ns_tcp_connect_client(client,
                              &crypto_ctx,
                              ns_negotiation_default_params(),
                              on_session_ready,
                              alloc_buffer,
                              on_read,
                              on_verify_client);
    } else {
        ns_close((uv_handle_t*) client, NULL);
    }
}

extern "C" vn_result_t
vn_server_start(vn_server_t *server) {
    ASSERT(server);
    ASSERT(server->uv_loop);
    ASSERT(server->addr);

    if (!server || !server->uv_loop || !server->addr) {
        return VN_WRONG_PARAM;
    }

    uv_tcp_init(server->uv_loop, &server->uv_server);

    struct sockaddr_in bind_addr;
    uv_ip4_addr(server->addr, server->port, &bind_addr);
    uv_tcp_bind(&server->uv_server, (const struct sockaddr *) &bind_addr, 0);
    server->uv_server.data = server;
    int r = uv_listen((uv_stream_t *) &server->uv_server, 128, on_new_connection);
    if (r) {
        LOG("Listen error!\n");
        return VN_LISTEN_ERROR;
    }

    return VN_GENERAL_ERROR;
}

extern "C" vn_result_t
vn_server_stop(vn_server_t *server) {
    return VN_GENERAL_ERROR;
}