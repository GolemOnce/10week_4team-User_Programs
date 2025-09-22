#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address (void *);
void sys_halt (void);
void sys_exit (int);
bool sys_create (const char *, unsigned initial_size);
bool sys_remove (const char *file);
int sys_write (int, const void *, unsigned);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

/* 헬퍼 함수들 */

/* 유효한 주소인지 체크 */
void check_address (void *addr) {
	struct thread *cur = thread_current();
	/* --- Project 2: User memory access --- */
	// if (!is_user_vaddr(addr)||addr == NULL) 
	//-> 이 경우는 유저 주소 영역 내에서도 할당되지 않는 공간 가리키는 것을 체크하지 않음. 그래서 
	// pml4_get_page를 추가해줘야!
	if (!is_user_vaddr(addr) || addr == NULL || 
	pml4_get_page(cur->pml4, addr)== NULL) { sys_exit(-1); }
}

 /* 파일을 현재 프로세스의 fdt에 추가 */
int add_file_to_fd_table(struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->fd_table;
	int fd = t->fd_idx; //fd값은 2부터 출발
	
	while (t->fd_table[fd] != NULL && fd < FDCOUNT_LIMIT) {
		fd++;
	}

	if (fd >= FDCOUNT_LIMIT) {
		return -1;
	}
	t->fd_idx = fd;
	fdt[fd] = file;
	return fd;
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// thread_exit ();
	int sys_input = f->R.rax;
	uint64_t arg0 = f->R.rdi;
	uint64_t arg1 = f->R.rsi;
	uint64_t arg2 = f->R.rdx;
	uint64_t arg3 = f->R.r10;
	uint64_t arg4 = f->R.r8;
	uint64_t arg5 = f->R.r9;

	switch (sys_input) {
		case SYS_HALT: {
			sys_halt ();
			__builtin_unreachable;
		}
		case SYS_EXIT: {
			sys_exit (arg0);
			__builtin_unreachable;
		}
		
		case SYS_OPEN: {
			int ret = sys_open (arg0);
			f->R.rax = ret;
			break;
		}

		case SYS_WRITE: {
			int ret = sys_write (arg0, arg1, arg2);
			f->R.rax = ret;
			break;
		}

		default: {

		}
	}
}

/* pintos 종료시키는 함수 */
void sys_halt(void) {
	power_off();
}

/* 현재 프로세스를 종료시키는 시스템 콜 */
void sys_exit(int status) {
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit(%d)\n", t->name, status);
	/* 정상적으로 종료됐다면 status는 0 */
	/* status: 프로그램이 정상적으로 종료됐는지 확인 */
	thread_exit();
}

/* 파일 생성하는 시스템 콜 */
bool sys_create (const char *file, unsigned initial_size) {
	/* 성공이면 true, 실패면 false */
	check_address(file);
	if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
}

bool sys_remove (const char *file) {
	check_address(file);
	if (filesys_remove(file)) {
		return true;
	} else {
		return false;
	}
}

int sys_open (const char *file) {
	check_address(file); // 주소 유효 체크
	struct file *file_obj = filesys_open(file); // 파일 객체 정보 받기

	//
	if (file_obj == NULL) {
		return -1;
	}
	int fd = add_file_to_fd_table(file_obj); // 만들어진 파일 fd테이블에 추가

	// 파일을 열 수 없다면 -1
	if (fd == -1) {
		file_close(file_obj);
	}

	return fd;
}

int sys_write (int fd, const void *buffer, unsigned size) {
	if (fd == STDOUT_FILENO) putbuf(buffer, size);
	return size;
}