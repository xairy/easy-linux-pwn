#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int vulnerable() {
	printf("> ");
	fflush(stdout);

	char buffer[128];
	read(STDIN_FILENO, &buffer[0], 512);

	// Dealing with cache coherency.
	usleep(1000);
}

int main(int argc, char** argv) {
	vulnerable();

	return EXIT_SUCCESS;
}
