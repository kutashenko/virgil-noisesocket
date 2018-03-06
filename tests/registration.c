//
// Created by Roman Kutashenko on 2/23/18.
//

#define TEST_NO_MAIN
#include "acutest.h"

#include <stdbool.h>
#include <virgil-noisesocket.h>

void
test_registration() {

    const char *test_identity = "5edfb645-b32d-486d-af22-719a717f2062";
    const char *test_password = "qweASD123";

    vn_client_t *client;

    client = vn_client_new(test_identity, test_password);

    TEST_CHECK_(client, "Cannot create client");
    TEST_CHECK_(VN_OK == vn_client_register(client), "Cannot register client");

    vn_client_free(client);

    TEST_CHECK_(false, "Registration error!\n");
}