#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#define DEBUG true

#define ASSERT(expr) \
	if (expr == -1) { \
		perror(#expr); \
		return EX_OSERR; \
	}

typedef struct user_regs_struct regset;
typedef unsigned long long regval;

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

void print_syscall(regset *before, regset *after) {
	// http://6.035.scripts.mit.edu/sp17/x86-64-architecture-guide.html
	regval syscall = before->orig_rax;
	regval arg1 = before->rdi;
	regval arg2 = before->rsi;
	regval arg3 = before->rdx;
	regval arg4 = before->rcx;
	regval arg5 = before->r8;
	regval arg6 = before->r9;
	regval ret = after ? after->rax : -1;
	char* lhs_format = NULL;
	char* rhs_format = NULL;
	// http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
	switch (syscall) {
		case SYS_open:
			// lhs_format = arg3 ? "open(\"%s\", %d, %o)" : "open(\"%s\", %d)";
			lhs_format = arg3 ? "open(%p, %d, %o)" : "open(%p, %d)";
			rhs_format = "%d";
			break;
		case SYS_openat:
			// lhs_format = arg4 ? "openat(%d, \"%s\", %d, %o)" : "open(%d, \"%s\", %d)";
			lhs_format = arg4 ? "openat(%d, %p, %d, %o)" : "open(%d, %p, %d)";
			rhs_format = "%d";
			break;
		case SYS_read:
			lhs_format = "read(%d, %p, %llu)";
			rhs_format = "%llu";
			break;
		case SYS_write:
			lhs_format = "write(%d, %p, %llu)";
			rhs_format = "%llu";
			break;
		case SYS_close:
			lhs_format = "close(%d)";
			rhs_format = "%d";
			break;
		case SYS_chdir:
			// lhs_format = "chdir(\"%s\")";
			lhs_format = "chdir(%p)";
			rhs_format = "%d";
			break;
		case SYS_fchdir:
			lhs_format = "fchdir(%d)";
			rhs_format = "%d";
			break;
		case SYS_stat:
			// lhs_format = "stat(\"%s\", %p)";
			lhs_format = "stat(%p, %p)";
			rhs_format = "%d";
			break;
		case SYS_fstat:
			lhs_format = "fstat(%d, %p)";
			rhs_format = "%d";
			break;
		case SYS_lstat:
			// lhs_format = "lstat(\"%s\", %p)";
			lhs_format = "lstat(%p, %p)";
			rhs_format = "%d";
			break;
	}
	if (lhs_format) {
		fprintf(stderr, lhs_format, arg1, arg2, arg3, arg4, arg5, arg6);
		if (after && rhs_format) {
			fprintf(stderr, " = ");
			fprintf(stderr, rhs_format, ret);
		}
		fprintf(stderr, ";\n");
	} else {
		fprintf(stderr, "Unknown syscall: %llu\n", syscall);
	}
}

/**
 * Traces a given `pid`, logging all system calls.
 */
int trace(pid_t pid) {
	fprintf(stderr, "Tracing PID %d.\n", pid);
	ASSERT(waitpid(pid, 0, 0));
	ASSERT(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL));
	while (true) {
		regset regs_before;
		regset regs_after;
		ASSERT(ptrace(PTRACE_SYSCALL, pid, NULL, 0));
		ASSERT(waitpid(pid, 0, 0));
		ASSERT(ptrace(PTRACE_GETREGS, pid, NULL, &regs_before));
		ASSERT(ptrace(PTRACE_SYSCALL, pid, NULL, 0));
		ASSERT(waitpid(pid, 0, 0));
		bool programExit = ptrace(PTRACE_GETREGS, pid, NULL, &regs_after) == -1;
		print_syscall(&regs_before, programExit ? NULL : &regs_after);
		if (programExit) {
			// The program probably exited.
			return (int) regs_before.rdi;
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

