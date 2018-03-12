//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/client.h>
#include <virgil-noisesocket/general.h>
#include "virgil-noisesocket/private/debug.h"
#include "virgil-noisesocket/private/common.h"

#include <iostream>

#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/crypto/Crypto.h>

using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::crypto::CryptoInterface;

//namespace vcrypto = virgil::sdk::crypto::Crypto;
namespace vsdk = virgil::sdk;

typedef enum {
    VN_STATE_UNKNOWN = 0,
    VN_STATE_REGISTRATION
} vn_client_state_t;

struct vn_client_s {
    uint8_t id[ID_MAX_SZ];

    uint8_t static_public_key[STATIC_KEY_SZ];
    uint8_t static_private_key[STATIC_KEY_SZ];

    uint8_t static_signature[SIGNATURE_SZ];

    uint8_t root_public_key[STATIC_KEY_SZ];

    char *password;

    vn_data_t card;
    vn_data_t private_key;

    vn_client_reg_result_cb_t registration_done_cb;

    uv_loop_t *uv_loop;

    vn_client_state_t state;
    vn_data_t registration_request;

    uv_connect_t connect;
    uv_tcp_t socket;
};

extern "C" vn_client_t *
vn_client_new(const char *identity,
              const char *password,
              uv_loop_t *uv_loop) {
    ASSERT(identity);
    ASSERT(password);
    ASSERT(uv_loop);

    vn_client_t *client = NULL;

    if (!identity || !*identity
        || !password || !*password
        || !uv_loop) {
        return NULL;
    }

    if (strnlen(identity, ID_MAX_SZ + 1) >= ID_MAX_SZ) {
        return NULL;
    }

    client = (vn_client_t *) calloc(1, sizeof(vn_client_t));

    strcpy((char*)client->id, identity);
    client->password = strdup(password);
    client->uv_loop = uv_loop;

    if (VN_OK != vn_gen_static_keys(client->static_private_key,
                                    client->static_public_key)) {
        vn_client_free(client);
        return NULL;
    }

    return client;
}

extern "C" vn_result_t
vn_client_free(vn_client_t *ctx) {
    ASSERT(ctx);

    if (!ctx) {
        return VN_WRONG_PARAM;
    }

    free(ctx->password);

    vn_data_free(&ctx->card);
    vn_data_free(&ctx->private_key);

    free(ctx);

    return VN_OK;
}

static vn_result_t
_fill_crypto_ctx(vn_client_t *client, ns_crypto_t *crypto_ctx) {
    crypto_ctx->public_key = client->static_public_key;
    crypto_ctx->public_key_sz = STATIC_KEY_SZ;
    crypto_ctx->private_key = client->static_private_key;
    crypto_ctx->private_key_sz = STATIC_KEY_SZ;
    strcpy((char*)crypto_ctx->meta_data, "Client meta data");
    return VN_OK;
}

static void
on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "uv_write error: \n");
        return;
    }
    printf("Client wrote data to server.\n");
}

static void
on_registration_session_ready(uv_tcp_t *handle, ns_result_t result) {

    if (NS_OK != result) {
        printf("Session error %d.\n", (int)result);
        ns_close((uv_handle_t*)handle, NULL);
        return;
    }

    printf("Connection to server is done.\n");

    vn_client_t *client = 0;
    ns_get_ctx(handle->data, USER_CTX_0, (void**)&client);

    if (VN_STATE_REGISTRATION != client->state) {
        LOG("Incorrect registration state.\n");
        return;
    }

    uv_buf_t buf;
    size_t sz = client->registration_request.sz;
    buf.base = (char*)malloc(ns_write_buf_sz(sz));
    memcpy(buf.base, client->registration_request.bytes, sz);
    ns_prepare_write((uv_stream_t*)handle,
                     (uint8_t*)buf.base, sz,
                     ns_write_buf_sz(sz),
                     &buf.len);

    uv_write_t *request = (uv_write_t*)calloc(1, sizeof(uv_write_t));
    uv_write(request, (uv_stream_t*)handle, &buf, 1, on_write);
}

static void
alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = (char*)malloc(size);
    buf->len = size;
}

static int
on_verify_server(void *user_data,
                 const uint8_t *public_key, size_t public_key_len,
                 const uint8_t *meta_data, size_t meta_data_len) {

    uv_tcp_t *socket = (uv_tcp_t*)user_data;
    vn_client_t *client = 0;
    ns_get_ctx(socket->data, USER_CTX_0, (void**)&client);

    printf("Verify server\n");
    printf("    Meta data: %s.\n", (const char*)meta_data);
    print_buf("    Public key:", public_key, public_key_len);
    return 0;
}

static void
on_close(uv_handle_t *handle) {
    printf("closed.\n");
}

static void
on_registration_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf) {
    printf("Registration read\n");

    if (nread >= 0) {
        printf("read: %d\n", (int) buf->len);
    } else {
        //we got an EOF
        ns_close((uv_handle_t *) tcp, on_close);
    }

//    free(buf->base);
}

vn_result_t
vn_client_connect(vn_client_t *ctx,
                  const char *server_addr,
                  uint16_t server_port,
                  ns_session_ready_cb_t session_ready_cb,
                  uv_read_cb read_cb) {

    ASSERT(ctx);
    ASSERT(server_addr && *server_addr);
    ASSERT(ctx->uv_loop);

    if (!ctx || !server_addr || !*server_addr) {
        return VN_WRONG_PARAM;
    }

    struct sockaddr_in dest;
    uv_ip4_addr(server_addr, server_port, &dest);

    uv_tcp_init(ctx->uv_loop, &ctx->socket);

    uv_tcp_keepalive(&ctx->socket, 1, 60);

    ns_crypto_t crypto_ctx;
    _fill_crypto_ctx(ctx, &crypto_ctx);

    if (NS_OK != ns_tcp_connect_server(&ctx->connect,
                                       &ctx->socket,
                                       (const struct sockaddr *) &dest,
                                       &crypto_ctx,
                                       ns_negotiation_default_params(),
                                       session_ready_cb,
                                       alloc_cb,
                                       read_cb,
                                       on_verify_server)) {
        return VN_CONNECT_ERROR;
    }

    ns_set_ctx(ctx->socket.data, USER_CTX_0, ctx);

    return VN_OK;
}

extern "C" vn_result_t
vn_client_register(vn_client_t *ctx,
                   const char *server_addr,
                   uint16_t server_port,
                   vn_ticket_t *ticket,
                   vn_client_reg_result_cb_t done_cb) {
    ASSERT(ctx);
    ASSERT(ticket);

    if (!ctx || !ticket) {
        return VN_WRONG_PARAM;
    }

    // Create key pair
    auto crypto = vsdk::crypto::Crypto();
    auto keyPair = crypto.generateKeyPair();

    // Create card request
    std::unordered_map<std::string, std::string> payload;
    // TODO: Process Ticket
    //---------------------

    auto request = CreateCardRequest::createRequest(std::string((char*)ctx->id),
                                                    std::string(IDENTITY_TYPE),
                                                    crypto.exportPublicKey(keyPair.publicKey()),
                                                    payload,
                                                    "",
                                                    "");
    auto fingerprint = crypto.calculateFingerprint(request.snapshot());
    auto signature = crypto.generateSignature(fingerprint.value(), keyPair.privateKey());
    request.addSignature(signature, fingerprint.hexValue());

    // Send Card request to server
    ctx->registration_done_cb = done_cb;

    auto cardRequest = request.exportAsString();

    vn_data_free(&ctx->registration_request);
    vn_data_init_copy(&ctx->registration_request,
                      (const uint8_t*)cardRequest.c_str(),
                      cardRequest.size() + 1);
    ctx->state = VN_STATE_REGISTRATION;

    return vn_client_connect(ctx,
                             server_addr, server_port,
                             on_registration_session_ready,
                             on_registration_read);
}
