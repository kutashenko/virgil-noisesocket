//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/client.h>
#include <virgil-noisesocket/general.h>
#include "virgil-noisesocket/private/debug.h"
#include "virgil-noisesocket/private/common.h"
#include "virgil-noisesocket/storage.h"

#include <iostream>

#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/crypto/Crypto.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include <meta.pb.h>
#include <registration.pb.h>
#include <virgil-noisesocket/data.h>

using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::crypto::CryptoInterface;

namespace vsdk = virgil::sdk;

typedef enum {
    VN_STATE_UNKNOWN = 0,
    VN_STATE_REGISTRATION
} vn_client_state_t;

struct vn_client_s {
    uint8_t id[ID_MAX_SZ];

    uint8_t static_public_key[STATIC_KEY_SZ];
    uint8_t static_private_key[STATIC_KEY_SZ];

    vn_data_t static_signature;

    uint8_t root_public_key[STATIC_KEY_SZ];

    char *password;

    vn_data_t card_id;
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

    vn_data_t private_key;
    vn_data_t public_key;

    memset(&private_key, 0, sizeof(private_key));
    memset(&public_key, 0, sizeof(public_key));

    bool is_signed = false;
    if (VN_OK == vn_storage_load_keys(client->id, &private_key, &public_key)
            && VN_OK == vn_storage_load_card_id(client->id, &client->card_id)) {

        if (VN_OK == vn_sign_static_key(&private_key,
                                        client->password,
                                        client->static_public_key,
                                        &client->static_signature)) {
            LOG("Static key has been signed successfuly.");
            is_signed = true;
        }
    }

    vn_data_free(&private_key);
    vn_data_free(&public_key);

    if (!is_signed) {
        LOG("Cannot sign static key. Looks like client should be regestered at first.");
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

    vn_data_free(&ctx->card_id);
    vn_data_free(&ctx->private_key);
    vn_data_free(&ctx->static_signature);
    vn_data_free(&ctx->registration_request);

    free(ctx);

    return VN_OK;
}

static vn_result_t
_fill_crypto_ctx(vn_client_t *client, ns_crypto_t *crypto_ctx) {
    crypto_ctx->public_key = client->static_public_key;
    crypto_ctx->public_key_sz = STATIC_KEY_SZ;
    crypto_ctx->private_key = client->static_private_key;
    crypto_ctx->private_key_sz = STATIC_KEY_SZ;

    meta_info_request message = meta_info_request_init_zero;

    // Create a stream that will write to our buffer.
    pb_ostream_t stream = pb_ostream_from_buffer(crypto_ctx->meta_data, META_DATA_LEN);

    message.is_registration = VN_STATE_REGISTRATION == client->state;
    memcpy(message.card_id, client->card_id.bytes, client->card_id.sz);

    message.signature.size = client->static_signature.sz;
    memcpy(message.signature.bytes, client->static_signature.bytes, client->static_signature.sz);

    if (!pb_encode(&stream, meta_info_request_fields, &message)) {
        LOG("Cannot encode meta request %s\n.", PB_GET_ERROR(&stream));
        return VN_CANNOT_REGISTER_CLIENT;
    }

    return VN_OK;
}

static void
on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "uv_write error: \n");
        return;
    }
    printf("Client wrote data to server.\n");

    free(req->bufsml[0].base);
    free(req);
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

    meta_info_request message = meta_info_request_init_zero;

    pb_istream_t stream = pb_istream_from_buffer((pb_byte_t *)meta_data, meta_data_len);

    if (!pb_decode(&stream, meta_info_request_fields, &message)) {
        LOG("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        return VN_CANNOT_REGISTER_CLIENT;
    }

    printf("Verify server\n");
    printf("    Card ID: %s.\n", message.card_id);
    print_buf("    Public key:", public_key, public_key_len);
    if (message.signature.size) {
        print_buf("    Signature:", message.signature.bytes, message.signature.size);
    } else {
        printf("    Signature NOT PRESENT\n");
    }

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
        return;
    }

    // Get protobuf data

    registration_response message = registration_response_init_zero;

    pb_istream_t stream = pb_istream_from_buffer((pb_byte_t *)buf->base, nread);

    if (!pb_decode(&stream, registration_response_fields, &message)) {
        LOG("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        return;
    }

    vn_client_t *client = 0;
    ns_get_ctx(tcp->data, USER_CTX_0, (void**)&client);

    vn_result_t res;

    res = (vn_result_t)message.result;

    if (VN_OK == res) {
        vn_data_t card_id;
        vn_data_init_set(&card_id, (uint8_t *)message.card_id, strlen(message.card_id) + 1);
        res = vn_storage_save_card_id(client->id, &card_id);
    }

    if (client->registration_done_cb) {
        client->registration_done_cb(client, res);
    }

    ns_close((uv_handle_t *) tcp, on_close);

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
vn_client_disconnect(vn_client_t *ctx,
                     uv_close_cb close_cb) {
    ASSERT(ctx);

    if (!ctx) {
        return VN_WRONG_PARAM;
    }

    ns_close((uv_handle_t *) &ctx->socket, close_cb);

    return VN_OK;
}

extern "C" vn_result_t
vn_client_register(vn_client_t *ctx,
                   const char *server_addr,
                   uint16_t server_port,
                   vn_ticket_t *ticket,
                   vn_client_reg_result_cb_t done_cb) {
    ASSERT(ctx);
    ASSERT(ctx->password);
    ASSERT(ticket);

    if (!ctx || !ticket) {
        return VN_WRONG_PARAM;
    }

    // Create key pair
    auto crypto = vsdk::crypto::Crypto();
    auto keyPair = crypto.generateKeyPair();

    // Save key pair

    auto publicKey = crypto.exportPublicKey(keyPair.publicKey());
    auto privateKey = crypto.exportPrivateKey(keyPair.privateKey(), ctx->password);

    vn_data_t private_key_data;
    vn_data_t public_key_data;

    vn_data_init_set(&private_key_data, privateKey.data(), privateKey.size());
    vn_data_init_set(&public_key_data, publicKey.data(), publicKey.size());

    vn_result_t res;
    res = vn_storage_save_keys(ctx->id,
                               &private_key_data,
                               &public_key_data);
    if (VN_OK != res) {
        LOG("Cannot save own key pair to file.");
        return res;
    }

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

    ctx->registration_done_cb = done_cb;

    auto cardRequest = request.exportAsString();


    // Create protobuf data
    vn_data_free(&ctx->registration_request);
    vn_data_init_alloc(&ctx->registration_request, REGISTATION_DATA_MAX_SZ);

    registration_request message = registration_request_init_zero;

    // Create a stream that will write to our buffer.
    pb_ostream_t stream = pb_ostream_from_buffer(ctx->registration_request.bytes,
                                                 ctx->registration_request.sz);

    if (cardRequest.size() + 1 > sizeof(message.card_creation_request)) {
        LOG("Card request too long.");
        return VN_CANNOT_REGISTER_CLIENT;
    }

    strcpy(message.card_creation_request, cardRequest.c_str());

    if (!pb_encode(&stream, registration_request_fields, &message)) {
        LOG("Cannot encode registration request %s\n.", PB_GET_ERROR(&stream));
        return VN_CANNOT_REGISTER_CLIENT;
    }

    ctx->registration_request.sz = stream.bytes_written;

    // Send Card request to server
    ctx->state = VN_STATE_REGISTRATION;

    return vn_client_connect(ctx,
                             server_addr, server_port,
                             on_registration_session_ready,
                             on_registration_read);
}
