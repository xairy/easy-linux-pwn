#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void not_called() {
	printf("launching shell...\n");
	system("/bin/sh");
}

int vulnerable() {
	printf("> ");
	fflush(stdout);

	char buffer[128];
	read(STDIN_FILENO, &buffer[0], 256);
}

int main(int argc, char** argv) {
	vulnerable();

	return EXIT_SUCCESS;
}
