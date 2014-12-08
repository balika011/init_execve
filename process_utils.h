#ifndef __PROCESS_UTILS_H__
#define __PROCESS_UTILS_H__

#include <sys/types.h>

void ProcessGetCodeSectionInfo(pid_t pid, void** ptr, unsigned long* size);
void * ProcessGetNonFileSection(pid_t pid, unsigned long size);
char* ProcessGetEnviron(pid_t pid, int * size);
void ProcessRead(pid_t pid, void * remove_buf, void * buf, int len);
void ProcessWrite(pid_t pid, void * remove_buf, void * buf, int len);

#endif