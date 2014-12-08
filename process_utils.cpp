#include <stdio.h>
#include <string.h>
#include <cstdlib>
#include <sys/ptrace.h>

#include "process_utils.h"

void ProcessGetCodeSectionInfo(pid_t pid, void** ptr, unsigned long* size)
{
	if (!ptr || !size)
		return;
	
	*ptr = 0;
	*size = 0;
	
	char filename[30];
	sprintf(filename, "/proc/%d/maps", pid);
	FILE *f = fopen(filename, "r");

	if (!f)
		return;
	
	char line[85];
	if (fgets(line, 85, f) != nullptr)
	{
		// begin-end perms offset dev inode pathname
		// ex:
		// 00008000-0002e000 r-xp 00000000 00:01 4140       /init
		sscanf(line, "%lx-%lx %*s %*lx %*s %*d %*s", ptr, size);
		*size -= *((unsigned long*)ptr);
	}

	fclose(f);
}

void * ProcessGetNonFileSection(pid_t pid, unsigned long size)
{
	char filename[30];
	sprintf(filename, "/proc/%d/maps", pid);
	FILE *f = fopen(filename, "r");

	if (!f)
		return 0;

	void* addr = nullptr;
	
	char line[85];
	while (fgets(line, 85, f) != nullptr)
	{
		// begin-end perms offset dev inode pathname
		// ex:
		// 00008000-0002e000 r-xp 00000000 00:01 4140       /init
		unsigned long begin_addr;
		unsigned long end_addr;
		char dev[20];
		sscanf(line, "%lx-%lx %*s %*lx %s %*d %*s", &begin_addr, &end_addr, dev);

		if (
			begin_addr + size < end_addr && // Check size.
			strcmp(dev, "00:00") == 0 // We dont want to overwrite any device.
		)
		{
			addr = (void *) begin_addr;
			break;
		}
	}

	fclose(f);
	return addr;
}

char* ProcessGetEnviron(pid_t pid, int * size)
{
	if(!size)
		return nullptr;
	
	char filename[30];
	sprintf(filename, "/proc/%d/environ", pid);
	FILE* f = fopen(filename, "r");

	if (!f)
		return nullptr;
	
	char* ret = new char[512];
	memset(ret, 0, 512);
	*size = fread(ret, sizeof(char), 512, f);
	
	fclose(f);
	
	return ret;
}

void ProcessRead(pid_t pid, void * remove_buf, void * buf, int len)
{
	unsigned long * remote = (unsigned long *) remove_buf;
	unsigned long * local = (unsigned long *) buf;
	
	for(int i = 0; i < len / sizeof(unsigned long); ++i)
		local[i] = ptrace(PTRACE_PEEKDATA, pid, &remote[i], nullptr);
	
	if (len % sizeof(unsigned long) != 0)
	{
		unsigned long tmp = ptrace(PTRACE_PEEKDATA, pid, &remote[len / sizeof(unsigned long) - 1], nullptr);
		memcpy(&local[len / sizeof(unsigned long) - 1], &tmp, len % sizeof(unsigned long));
	}
}

void ProcessWrite(pid_t pid, void * remove_buf, void * buf, int len)
{
	unsigned long * remote = (unsigned long *) remove_buf;
	unsigned long * local = (unsigned long *) buf;
	
	for(int i = 0; i < len / sizeof(unsigned long); ++i)
		ptrace(PTRACE_POKEDATA, pid, &remote[i], (void *) local[i]);

	if (len % sizeof(unsigned long) != 0)
	{
		unsigned long tmp = 0;
		memcpy(&tmp, &local[len / sizeof(unsigned long) - 1], len % sizeof(unsigned long));
		ptrace(PTRACE_POKEDATA, pid, &remote[len / sizeof(unsigned long) - 1], (void *) tmp);
	}
}