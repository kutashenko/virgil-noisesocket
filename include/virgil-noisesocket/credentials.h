//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_CREDENTIALS_H
#define VIRGIL_NOISESOCKET_CREDENTIALS_H

typedef struct {
    vn_data_t static_public_key;
    vn_data_t static_private_key;

    vn_data_t static_key_signature; // Signatire of Static public key (signed by card_private_key)

    vn_data_t root_public_key;

    vn_data_t card_private_key;

    vn_data_t own_card;

} vn_credentials_t;

#endif //VIRGIL_NOISESOCKET_CREDENTIALS_H
