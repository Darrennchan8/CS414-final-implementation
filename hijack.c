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

union value {
	unsigned long long as_regvalue;
	int as_int;
	unsigned int as_uint;
	unsigned long long as_ullong;
	void* as_ptr;
	char* as_string;
};

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
	unsigned long long syscall = regs.orig_rax;
	union value arg1;
	union value arg2;
	union value arg3;
	union value arg4;
	union value arg5;
	union value arg6;
	arg1.as_regvalue = regs.rdi;
	arg2.as_regvalue = regs.rsi;
	arg3.as_regvalue = regs.rdx;
	arg4.as_regvalue = regs.rcx;
	arg5.as_regvalue = regs.r8;
	arg6.as_regvalue = regs.r9;
	switch (syscall) {
		case SYS_open:
			if (arg3.as_uint) {
				// printf("open(\"%s\", %d, %o)\n", arg1.as_string, arg2.as_int, arg3.as_uint);
				printf("open(%p, %d, %o)\n", arg1.as_ptr, arg2.as_int, arg3.as_uint);
			} else {
				// printf("open(\"%s\", %d)\n", arg1.as_string, arg2.as_int);
				printf("open(%p, %d)\n", arg1.as_ptr, arg2.as_int);
			}
			break;
		case SYS_openat:
			if (arg4.as_uint) {
				// printf("open(%d, \"%s\", %d, %o)\n", arg1.as_int, arg2.as_string, arg3.as_int, arg4.as_uint);
				printf("open(%d, %p, %d, %o)\n", arg1.as_int, arg2.as_ptr, arg3.as_int, arg4.as_uint);
			} else {
				// printf("open(%d, \"%s\", %d)\n", arg1.as_int, arg2.as_string, arg3.as_int);
				printf("open(%d, %p, %d)\n", arg1.as_int, arg2.as_ptr, arg3.as_int);
			}
			break;
		case SYS_read:
			printf("read(%d, %p, %llu)\n", arg1.as_int, arg2.as_ptr, arg3.as_ullong);
			break;
		case SYS_close:
			printf("close(%d)\n", arg1.as_int);
			break;
		case SYS_chdir:
			// printf("chdir(\"%s\")\n", arg1.as_string);
			printf("chdir(%p)\n", arg1.as_ptr);
			break;
		case SYS_fchdir:
			printf("fchdir(%d)\n", arg1.as_int);
			break;
		case SYS_stat:
			// printf("stat(\"%s\", %p)\n", arg1.as_string, arg2.as_ptr);
			printf("stat(%p, %p)\n", arg1.as_ptr, arg2.as_ptr);
			break;
		case SYS_fstat:
			printf("fstat(%d, %p)\n", arg1.as_int, arg2.as_ptr);
			break;
		case SYS_lstat:
			// printf("lstat(\"%s\", %p)\n", arg1.as_string, arg2.as_ptr);
			printf("lstat(%p, %p)\n", arg1.as_ptr, arg2.as_ptr);
			break;
		default:
			printf("%d|", SYS_open);
			printf("Syscall: %llu\n", syscall);
			break;
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
		ASSERT(ptrace(PTRACE_SYSCALL, pid, NULL, 0));
		ASSERT(waitpid(pid, 0, 0));
		// Registers mapped here: http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
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

