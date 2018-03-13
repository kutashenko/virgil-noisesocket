
#include "acutest.h"

void test_registration();
void test_verified_connection();

TEST_LIST = {
        { "Client registration", test_registration },
        { "Verified conection", test_verified_connection },
        { NULL, NULL }
};