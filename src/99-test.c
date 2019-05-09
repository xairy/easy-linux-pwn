#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
	execve("/bin/sh", NULL, NULL);
	return 0;
}
