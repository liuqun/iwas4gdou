#include "config.h"
#include <stdio.h>
#include "helloworld.h"

void ShowPackageVersion(void)
{
	printf("%s-%s\n", PACKAGE_NAME, PACKAGE_VERSION);
}


