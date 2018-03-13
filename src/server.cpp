//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/server.h>
#include <virgil-noisesocket/private/common.h>
#include <virgil-noisesocket/private/debug.h>

#include <string.h>
#include <noisesocket.h>
#include <virgil-noisesocket.h>

#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/CardValidator.h>
#include <virgil/sdk/client/ServiceConfig.h>
#include <virgil/sdk/client/RequestSigner.h>
#include <virgil/sdk/client/models/SearchCardsCriteria.h>
#include <iostream>
#include <virgil-noisesocket/credentials.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::CardValidator;
using virgil::crypto::VirgilByteArray;

#include <pb_encode.h>
#include <pb_decode.h>
#include <meta.pb.h>
#include <registration.pb.h>
#include <virgil-noisesocket/data.h>

#define SERVER_CTX(X) ((vn_server_t*)(X->data))

struct vn_server_s {
    uint8_t id[ID_MAX_SZ];

    uint8_t static_public_key[STATIC_KEY_SZ];
    uint8_t static_private_key[STATIC_KEY_SZ];

    uint8_t static_signature[SIGNATURE_SZ];

    uint8_t root_public_key[STATIC_KEY_SZ];

    vn_virgil_credentials_t virgil_cretentials;

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
              vn_virgil_credentials_t cretentials,
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
    server->virgil_cretentials = cretentials;

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

    meta_info_request message = meta_info_request_init_zero;

    // Create a stream that will write to our buffer.
    pb_ostream_t stream = pb_ostream_from_buffer(crypto_ctx->meta_data, META_DATA_LEN);

    message.is_registration = false;
    memcpy(message.client_id, server->id, ID_MAX_SZ);

    if (!pb_encode(&stream, meta_info_request_fields, &message)) {
        LOG("Cannot encode meta request %s\n.", PB_GET_ERROR(&stream));
        return VN_CANNOT_REGISTER_CLIENT;
    }

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
on_verify_client(void *user_data,
                 const uint8_t *public_key, size_t public_key_len,
                 const uint8_t *meta_data, size_t meta_data_len) {

    uv_tcp_t *socket = (uv_tcp_t*)user_data;

    vn_server_t *server = 0;
    vn_serverside_client_t *client = 0;
    ns_get_ctx(socket->data, USER_CTX_0, (void**)&server);
    ns_get_ctx(socket->data, USER_CTX_1, (void**)&client);

    meta_info_request message = meta_info_request_init_zero;

    pb_istream_t stream = pb_istream_from_buffer((pb_byte_t *)meta_data, meta_data_len);

    if (!pb_decode(&stream, meta_info_request_fields, &message)) {
        LOG("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        return VN_CANNOT_REGISTER_CLIENT;
    }

    client->register_only = message.is_registration;

    printf("Verify client\n");
    printf("    Registration: %s.\n", message.is_registration ? "TRUE" : "FALSE");
    printf("    ID: %s.\n", message.client_id);
    print_buf("    Public key:", public_key, public_key_len);
    return 0;
}

static void
on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "uv_write error: \n");
        return;
    }
    printf("Client wrote data to client.\n");
}

static vn_result_t
_send_register_response(vn_server_t *server,
                        vn_serverside_client_t *client,
                        vn_result_t result) {

    // Create protobuf data
    uv_buf_t *buf = (uv_buf_t*)calloc(1, sizeof(uv_buf_t));
    size_t sz = registration_response_size;
    buf->base = (char*)malloc(ns_write_buf_sz(sz));

    registration_response message = registration_response_init_zero;

    // Create a stream that will write to our buffer.
    pb_ostream_t stream = pb_ostream_from_buffer((pb_byte_t*)buf->base, sz);

    message.result = result;

    if (!pb_encode(&stream, registration_response_fields, &message)) {
        LOG("Cannot encode registration request %s\n.", PB_GET_ERROR(&stream));
        return VN_CANNOT_REGISTER_CLIENT;
    }

    ns_prepare_write((uv_stream_t*)client->socket,
                     (uint8_t*)buf->base, stream.bytes_written,
                     ns_write_buf_sz(sz),
                     &buf->len);

    uv_write_t *request = (uv_write_t*)calloc(1, sizeof(uv_write_t));
    uv_write(request, (uv_stream_t*)client->socket, buf, 1, on_write);
    LOG("Send register response: %s\n", VN_OK == result ? "OK" : "ERROR");

    return VN_OK;
}

static vn_result_t
_register_client(vn_server_t *server,
                 vn_serverside_client_t *client,
                 const uint8_t *card_request) {

            ASSERT(server);
            ASSERT(server->virgil_cretentials.private_key_password);
            ASSERT(server->virgil_cretentials.private_key);
            ASSERT(server->virgil_cretentials.app_id);
            ASSERT(server->virgil_cretentials.token);

    const std::string _card_request = (const char *)card_request;
    const std::string _token = server->virgil_cretentials.token;
    const std::string _appid = server->virgil_cretentials.app_id;
    const std::string _private_key_pass = server->virgil_cretentials.private_key_password;
    const std::string _private_key_str = server->virgil_cretentials.private_key;
    const VirgilByteArray _private_key = virgil::sdk::VirgilBase64::decode(_private_key_str);

    free((void *) card_request);

    auto crypto = std::make_shared<Crypto>();

    auto serviceConfig = ServiceConfig::createConfig(_token);

    serviceConfig
            .cardsServiceURL("https://cards.virgilsecurity.com/v4")
            .cardsServiceROURL("https://cards-ro.virgilsecurity.com/v4");

    auto publicKey = virgil::crypto::VirgilKeyPair::extractPublicKey(_private_key,
                                                                     virgil::crypto::str2bytes(_private_key_pass));

    auto validator = std::make_unique<CardValidator>(crypto);
    validator->addVerifier(_appid, publicKey);
    serviceConfig.cardValidator(std::move(validator));

    Client virgilClient(std::move(serviceConfig));

    RequestSigner signer(crypto);

    auto appPrivateKey = crypto->importPrivateKey(_private_key, _private_key_pass);

    auto request = CreateCardRequest::importFromString(_card_request);

    signer.authoritySign(request, _appid, appPrivateKey);

    auto future = virgilClient.createCard(request);
    try {
        auto card = future.get();
        std::cout << "Output: " << card.identity() << " " << card.createdAt() << " " << card.cardVersion() << std::endl;
        _send_register_response(server, client, VN_OK);
    } catch (...) {
        _send_register_response(server, client, VN_CANNOT_REGISTER_CLIENT);
    }

    return VN_OK;
}

static void
on_read(uv_stream_t *socket, ssize_t nread, const uv_buf_t *buf) {
    if (nread  <= 0) {
        fprintf(stderr, "Read error!\n");
        ns_close((uv_handle_t *)socket, NULL);
        return;
    }

    vn_server_t *server = 0;
    vn_serverside_client_t *client = 0;
    ns_get_ctx(socket->data, USER_CTX_0, (void**)&server);
    ns_get_ctx(socket->data, USER_CTX_1, (void**)&client);

    if (client->register_only) {
        LOG("Register new client.\n");

        // Get protobuf data

        registration_request message = registration_request_init_zero;

        pb_istream_t stream = pb_istream_from_buffer((pb_byte_t *)buf->base, nread);

        if (!pb_decode(&stream, registration_request_fields, &message)) {
            LOG("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            _send_register_response(server, client, VN_CANNOT_REGISTER_CLIENT);
            return;
        }

        uint8_t *data = (uint8_t*)malloc(nread);
        strcpy((char*)data, message.card_creation_request);

        // TODO: Be careful here ! Think about socket close and response after it.
        std::thread{_register_client, server, client, data}.detach();
        LOG("Wait registration...\n");
    } else {
        LOG("Wrong registration state.\n");
        _send_register_response(server, client, VN_CANNOT_REGISTER_CLIENT);
    }
}

static void
on_new_connection(uv_stream_t *server, int status) {
    if (status == -1) {
        return;
    }

    LOG("On new connection ...");

    uv_tcp_t *socket = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(SERVER_CTX(server)->uv_loop, socket);

    if (uv_accept(server, (uv_stream_t *) socket) == 0) {

        ns_crypto_t crypto_ctx;
        _fill_crypto_ctx(SERVER_CTX(server), &crypto_ctx);

        vn_serverside_client_t *client = (vn_serverside_client_t *)calloc(1, sizeof(vn_serverside_client_t));
        client->socket = socket;

        ns_tcp_connect_client(socket,
                              &crypto_ctx,
                              ns_negotiation_default_params(),
                              on_session_ready,
                              alloc_buffer,
                              on_read,
                              on_verify_client);

        vn_server_t *vn_server = (vn_server_t*)server->data;
        ns_set_ctx(socket->data, USER_CTX_0, vn_server);
        ns_set_ctx(socket->data, USER_CTX_1, client);
    } else {
        ns_close((uv_handle_t*) socket, NULL);
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
    ASSERT(server);
    uv_close((uv_handle_t*)&server->uv_server, NULL);
    return VN_GENERAL_ERROR;
}