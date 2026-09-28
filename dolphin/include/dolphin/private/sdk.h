#ifndef __DOLPHIN_PRIVATE_SDK_H__
#define __DOLPHIN_PRIVATE_SDK_H__

// Declarations used by this library that the dolsdk2004 headers
// (dolphin/include, not tracked here) don't provide.

#include <dolphin/types.h>
#include <dolphin/os/OSRtc.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ARRAY_COUNT
#define ARRAY_COUNT(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef ASSERTMSG2LINE
#ifdef DEBUG
#define ASSERTMSG2LINE(line, cond, msg, arg1, arg2) ((cond) || (OSPanic(__FILE__, line, msg, arg1, arg2), 0))
#else
#define ASSERTMSG2LINE(line, cond, msg, arg1, arg2) (void)0
#endif
#endif

// OSRtc.c
OSSram* __OSLockSram(void);
OSSramEx* __OSLockSramEx(void);
BOOL __OSUnlockSram(BOOL commit);
BOOL __OSUnlockSramEx(BOOL commit);

// MSL C
int toupper(int c);
int isdigit(int c);
int isxdigit(int c);
int islower(int c);
int isprint(int c);
int atoi(const char* str);
int snprintf(char* s, unsigned long n, const char* format, ...);

#ifdef __cplusplus
}
#endif

#endif
