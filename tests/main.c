
#include "acutest.h"

void test_registration();
void test_verified_connection();
void test_storage();

TEST_LIST = {
        { "Storage", test_storage },
        { "Client registration", test_registration },
        { "Verified conection", test_verified_connection },
        { NULL, NULL }
};