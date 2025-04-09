#include "elfpatcher.h"

#include <stdio.h>

int main() {
	int res = patch_auto("libcustom.so", "/data/data/com.test/files/lib/armeavi-v7a/");

	if (res) {
		printf("%s\n", "Succeed!");
		return 0;
	}
	
	printf("%s\n", "Fail!");
	return 1;
}
