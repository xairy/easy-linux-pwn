#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct frame {
	char buffer[128];
	unsigned long x;
};

int main(int argc, char** argv) {
	struct frame f;
	memset(&f, 0, sizeof(f));

	printf("> ");
	fflush(stdout);

	read(STDIN_FILENO, &f.buffer[0], 256);

	printf("x = %lx\n", f.x);
	if (f.x == (unsigned long)0xdeadbabebeefc0deUL) {
		printf("launching shell...\n");
		system("/bin/sh");
	}

	return EXIT_SUCCESS;
}
