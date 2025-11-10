#include <string.h>

void mbedtls_platform_zeroize(void *buf, size_t len);

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    if (len >0) {
        memset(buf, 0, len);
    }
}
