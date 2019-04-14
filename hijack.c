#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * Executes a `file` with `arguments`, with a `PTRACE_TRACEME` request.
 */
int run(char* file, char** arguments) {
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
		perror("ptrace");
		return EX_OSERR;
	}
	if (execvp(file, arguments)) {
		perror(file);
		return EX_NOINPUT;
	}
	return 0;
}

/**
 * Traces a given `pid`, logging all system calls.
 */
int trace(pid_t pid) {
	if (waitpid(pid, 0, 0) == -1) {
		perror("waitpid");
		return EX_OSERR;
	}
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL) == -1) {
		perror("ptrace");
		return EX_OSERR;
	}
	while (true) {
		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) {
			fprintf(stderr, "%d: ", pid);
			perror("ptrace");
			return EX_OSERR;
		}
		if (waitpid(pid, 0, 0) == -1) {
			perror("waitpid");
			return EX_OSERR;
		}
	}
}

int main(int argc, char** argv) {
	if (argc <= 1) {
		fprintf(stderr, "Usage: %s program-name ...arguments\n", argv[0]);
		return EX_USAGE;
	}
	pid_t pid = fork();
	if (pid == -1) {
		perror("fatal");
		return EX_OSERR;
	} else if (pid) {
		// Trace the child process in the parent.
		exit(trace(pid));
	} else {
		// Run the given program in the child process.
		exit(run(argv[1], argv + 1));
	}
}

