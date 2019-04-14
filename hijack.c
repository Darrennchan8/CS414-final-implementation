#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#define ASSERT(expr) \
	if (expr == -1) { \
		perror(#expr); \
		return EX_OSERR; \
	}

/**
 * Executes a `file` with `arguments`, with a `PTRACE_TRACEME` request.
 */
int run(char* file, char** arguments) {
	ASSERT(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
	if (execvp(file, arguments)) {
		perror(file);
		return EX_NOINPUT;
	}
	return 0;
}

void print_syscall(struct user_regs_struct regs) {
	printf("Syscall: %llu\n", regs.orig_rax);
}

/**
 * Traces a given `pid`, logging all system calls.
 */
int trace(pid_t pid) {
	fprintf(stderr, "Tracing PID %d.\n", pid);
	ASSERT(waitpid(pid, 0, 0));
	ASSERT(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL));
	while (true) {
		ASSERT(ptrace(PTRACE_SYSCALL, pid, NULL, 0));
		ASSERT(waitpid(pid, 0, 0));
		// Registers mapped here: https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/user_64.h#L69
		struct user_regs_struct child_regs = {0};
		ASSERT(ptrace(PTRACE_GETREGS, pid, NULL, &child_regs));
		print_syscall(child_regs);
		ASSERT(ptrace(PTRACE_SYSCALL, pid, NULL, 0));
		ASSERT(waitpid(pid, 0, 0));
		if (ptrace(PTRACE_GETREGS, pid, NULL, &child_regs) == -1) {
			// The program probably exited.
			return (int) child_regs.rdi;
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

