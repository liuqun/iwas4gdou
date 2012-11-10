/* 打印iwas4gdou版本号和libpcap动态库版本号 */
#include <stdio.h>
#include <pcap/pcap.h>
#include "version.h"

int main()
{
	printf("Iwas4gdou version %s\n", iwas4g_package_version());
	printf("Based on %s\n", pcap_lib_version());
	return(0);
}

