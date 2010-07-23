#include <stdlib.h>
#include <rstdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char** argv)
{
	int status;
	pid_t pid = 0;
	pid = fork();
	if (pid) {
		printf("Hello world from parent!!\n");
		waitpid(pid, &status, 0);
	} else {
		printf("Hello world from child!!\n");
	}
	return 0;
}
