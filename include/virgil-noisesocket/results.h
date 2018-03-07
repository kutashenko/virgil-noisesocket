//
// Created by Roman Kutashenko on 3/6/18.
//

#ifndef VIRGIL_NOISESOCKET_RESULTS_H
#define VIRGIL_NOISESOCKET_RESULTS_H

typedef enum {
    VN_OK,
    VN_WRONG_PARAM,
    VN_ALLOC_ERROR,
    VN_LISTEN_ERROR,
    VN_CONNECT_ERROR,
    VN_GENERAL_ERROR
} vn_result_t;

#endif //VIRGIL_NOISESOCKET_RESULTS_H
