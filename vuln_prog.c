#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFSZ 512

void do_echo(const char *str)
{
	char echo[128] = "echo: ";
	int i;

	for (i = 6; *str != '\n'; i++) {
		echo[i] = *str++;
	}
	echo[i] = '\0';

	puts(echo);
}

int main(int argc, char **argv)
{
	char buf[BUFSZ];
	int r;

	while (1) {
		r = read(STDIN_FILENO, buf, BUFSZ);
		if (r <= 0)
			break;
		do_echo(buf);
	}

	return 0;
}
