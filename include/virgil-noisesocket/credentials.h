//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_CREDENTIALS_H
#define VIRGIL_NOISESOCKET_CREDENTIALS_H

typedef struct {
    const char *private_key;
    const char *private_key_password;
    const char *app_id;
    const char *token;
} vn_virgil_credentials_t;

#endif //VIRGIL_NOISESOCKET_CREDENTIALS_H
