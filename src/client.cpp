//
// Created by Roman Kutashenko on 3/6/18.
//

#include <virgil-noisesocket/client.h>
#include <virgil-noisesocket/general.h>
#include "private/debug.h"
#include <sodium.h>

#include <iostream>

#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/crypto/Crypto.h>

using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::crypto::CryptoInterface;

//namespace vcrypto = virgil::sdk::crypto::Crypto;
namespace vsdk = virgil::sdk;

#define STATIC_KEY_SZ (32)

struct vn_client_s {
    char *identity;
    char *password;

    vn_data_t card;
    vn_data_t private_key;

    uint8_t static_public_key[STATIC_KEY_SZ];
    uint8_t static_private_key[STATIC_KEY_SZ];
};

static vn_result_t
_gen_static_keys(vn_client_t *ctx) {
    ASSERT(ctx);

    if (!ctx) {
        return VN_WRONG_PARAM;
    }

    randombytes_buf(ctx->static_private_key, STATIC_KEY_SZ);
    ctx->static_private_key[0] &= 0xF8;
    ctx->static_private_key[31] = (ctx->static_private_key[31] & 0x7F) | 0x40;
    crypto_scalarmult_curve25519_base(ctx->static_public_key, ctx->static_private_key);

    return VN_OK;
}

extern "C" vn_client_t *
vn_client_new(const char *identity,
              const char *password) {
    ASSERT(identity);
    ASSERT(password);

    vn_client_t *client = NULL;

    if (!identity || !*identity
        || !password || !*password) {
        return NULL;
    }

    client = (vn_client_t *) calloc(1, sizeof(vn_client_t));

    client->identity = strdup(identity);
    client->password = strdup(password);

    if (VN_OK != _gen_static_keys(client)) {
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

    free(ctx->identity);
    free(ctx->password);

    vn_data_free(&ctx->card);
    vn_data_free(&ctx->private_key);

    free(ctx);

    return VN_OK;
}

vn_result_t
vn_client_load(vn_client_t *ctx) {
            ASSERT(ctx);

    if (!ctx) {
        return VN_WRONG_PARAM;
    }

    //TODO: Load own private key
    //TODO: Load own card

    return VN_OK;
}

vn_result_t
vn_client_save(vn_client_t *ctx) {
    ASSERT(ctx);

    if (!ctx) {
        return VN_WRONG_PARAM;
    }

    //TODO: Save own private key
    //TODO: Save own card

    return VN_OK;
}

extern "C" vn_result_t
vn_client_register(vn_client_t *ctx) {
    ASSERT(ctx);
    ASSERT(ctx->identity);

    if (!ctx) {
        return VN_WRONG_PARAM;
    }

    // Create key pair
    auto crypto = vsdk::crypto::Crypto();
    auto keyPair = crypto.generateKeyPair();

    // Create card request
    std::unordered_map<std::string, std::string> payload;

    // TODO: Payload should be received from Admin
    payload["test"] = "test";

    auto request = CreateCardRequest::createRequest(std::string(ctx->identity),
                                                    std::string(IDENTITY_TYPE),
                                                    crypto.exportPublicKey(keyPair.publicKey()),
                                                    payload,
                                                    "",
                                                    "");
    auto fingerprint = crypto.calculateFingerprint(request.snapshot());
    auto signature = crypto.generateSignature(fingerprint.value(), keyPair.privateKey());
    request.addSignature(signature, fingerprint.hexValue());

    auto cardRequest = request.exportAsString();

    std::cout << cardRequest << std::endl;

    // Send Card request to server

    // Wait for response ???

    // Callback on registration result

    return VN_GENERAL_ERROR;
}
