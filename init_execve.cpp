#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/user.h>
#include <stdio.h>
#include <string.h>

#include "process_utils.h"

#define INIT_PID 1

unsigned char execve_code[] =
{
	0x07, 0xC0, 0xA0, 0xE1,
	0x0B, 0x70, 0xA0, 0xE3,
	0x00, 0x00, 0x00, 0xEF,
	0x0C, 0x70, 0xA0, 0xE1
};

unsigned long memfindpos(void * buf, unsigned long size, void * what_buf, unsigned long what_size)
{
	for (unsigned long i = 0; i < size - what_size; ++i)
	{
		if (memcmp(&((unsigned char *) buf)[i], what_buf, what_size) == 0)
			return i;
	}
	
	return 0xFFFFFFFF;
}

void pushRegistersToStack(struct pt_regs * regs)
{
	unsigned long StackPointer = regs->ARM_sp;
	StackPointer -= 16 * sizeof(unsigned long); //We don't need CPSR and ORIG_R0, so we need only 16 registers
	
	ProcessWrite(INIT_PID, (void *) StackPointer, regs->uregs, 16 * sizeof(unsigned long));
	
	regs->ARM_sp = StackPointer;
}

int main(int argc, char ** argv)
{
	if(argc < 2)
	{
		printf("Usage: init_execve <filename> [args]\n");
		return 1;
	}
	
	if (ptrace(PTRACE_ATTACH, INIT_PID, NULL, NULL))
	{
		printf("ERROR: Couldn't attach to /init.\n");
		return 1;
	}
	
	wait(NULL); //Why do i need this?

	void * initBase;
	unsigned long initSize;
	ProcessGetCodeSectionInfo(INIT_PID, &initBase, &initSize);

	if (!initBase || initSize == 0)
	{
		printf("ERROR: Couldn't get the image base of /init.\n");
		printf("Detaching...\n");
		ptrace(PTRACE_DETACH, INIT_PID, NULL, NULL);
		return 1;
	}

	printf("initBase: %X.\n", initBase);
	printf("initSize: %X.\n", initSize);

	unsigned char* initCodeSection = new unsigned char[initSize];
	ProcessRead(INIT_PID, initBase, initCodeSection, initSize);
	
	void * execvePtr = (void *) memfindpos(initCodeSection, initSize, execve_code, sizeof(execve_code));
	
	delete [] initCodeSection;

	if (((unsigned long) execvePtr) == 0xFFFFFFFF)
	{
		printf("ERROR: Failed locating execve.\n");
		printf("Detaching...\n");
		ptrace(PTRACE_DETACH, INIT_PID, NULL, NULL);
		return 5;
	}
	
	execvePtr = (void *) (((unsigned long) execvePtr) + ((unsigned long) initBase));
	
	printf("execvePtr: %X\n", execvePtr);
	
	struct pt_regs regs;
	memset(&regs, 0, sizeof(regs));
	ptrace(PTRACE_GETREGS, INIT_PID, NULL, &regs);
		
	printf("R0: %X\n", regs.ARM_r0);
	printf("R1: %X\n", regs.ARM_r1);
	printf("R2: %X\n", regs.ARM_r2);
	printf("R3: %X\n", regs.ARM_r3);
	printf("R4: %X\n", regs.ARM_r4);
	printf("R5: %X\n", regs.ARM_r5);
	printf("R6: %X\n", regs.ARM_r6);
	printf("R7: %X\n", regs.ARM_r7);
	printf("R8: %X\n", regs.ARM_r8);
	printf("R9: %X\n", regs.ARM_r9);
	printf("R10: %X\n", regs.ARM_r10);
	printf("FP: %X\n", regs.ARM_fp); // R11
	printf("IP: %X\n", regs.ARM_ip); // R12
	printf("SP: %X\n", regs.ARM_sp); // R13
	printf("LR: %X\n", regs.ARM_lr); // R14
	printf("PC: %X\n", regs.ARM_pc); // R15
	printf("CPSR: %X\n", regs.ARM_cpsr); // R16
	printf("ORIG_R0: %X\n", regs.ARM_ORIG_r0); // R17
	
	pushRegistersToStack(&regs);
	
	// START - This part is wrong, awful and crap!
	
	execvePtr = (void *) (((unsigned long) execvePtr) + sizeof(execve_code));
	
	unsigned long POP_R0_PC = 0xE8DBFFFF; //POP {R0 - PC} - LDMFD SP!, {R0-PC}
	ProcessWrite(INIT_PID, execvePtr, &POP_R0_PC, 4); //Then execve gets called in /init, it will crash, and kenel will panic.
	
	regs.ARM_pc = ((unsigned long) execvePtr);
	
	// END - This part is wrong, awful and crap!
	
	printf("new PC: %X.\n", regs.ARM_pc);
	ptrace(PTRACE_SETREGS, INIT_PID, NULL, &regs);

	printf("Detaching...\n");
	ptrace(PTRACE_DETACH, INIT_PID, NULL, NULL);
	return 0;
}
