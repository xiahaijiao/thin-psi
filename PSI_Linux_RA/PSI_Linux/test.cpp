#include "RAPSIUtil.hpp"
#include "RAPSIUtilOpenSSL.hpp"

static RAPSIUtil* m_util;

int main() {

    if (m_util == NULL)
    {
        m_util = new RAPSIUtilOpenSSL();
    }

    char* data = "hello";
     
    printf("data:%s\n", data);
    char point[256] = { 0 };

    m_util->data2Point(data, point);

    printf("point:%s\n", point);

	return 0;
}