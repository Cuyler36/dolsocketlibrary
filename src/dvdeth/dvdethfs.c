#include <dolphin/dvdeth.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

typedef struct FSTEntry {
    u32 isDirAndStringOff; // offset 0x0, size 0x4
    u32 parent; // offset 0x4, size 0x4
    u32 next; // offset 0x8, size 0x4
    u32 childOrLength; // offset 0xC, size 0x4
} FSTEntry;

enum {
    LOOKUP_NONE = 0,
    LOOKUP_CREATE = 1,
    LOOKUP_REMOVE = 2,
};

static FSTEntry* FstStart; // size: 0x4, address: 0x0
static char* FstStringStart; // size: 0x4, address: 0x4
static u32 MaxEntryNum; // size: 0x4, address: 0x8
static u32 MaxStringSize; // size: 0x4, address: 0xC
static u32 currentDirectory; // size: 0x4, address: 0x10
static OSBootInfo* BootInfo; // size: 0x4, address: 0x14
u32 __DVDLongFileNameFlag; // size: 0x4, address: 0x18
OSThreadQueue __DVDThreadQueue; // size: 0x8, address: 0x1C

#define entryIsDir(i) (((FstStart[i].isDirAndStringOff & 0xF0000000) == 0) ? FALSE : TRUE)
#define entryIsUsed(i) (((FstStart[i].isDirAndStringOff & 0x0F000000) == 0) ? FALSE : TRUE)
#define stringOff(i) (FstStart[i].isDirAndStringOff & 0x00FFFFFF)
#define parentDir(i) (FstStart[i].parent)
#define nextEntry(i) (FstStart[i].next)
#define childOrLength(i) (FstStart[i].childOrLength)

static void cbForReadFstEntry(s32 result, DVDCommandBlock* block);
static void cbForReadFstString(s32 result, DVDCommandBlock* block);
static void cbForRemoveSync();
static void cbForCreateSync();
static void cbForWriteAsync(s32 result, DVDCommandBlock* block);
static void cbForWriteSync(s32 result, DVDCommandBlock* block);
static void cbForReadAsync(s32 result, DVDCommandBlock* block);
static void cbForReadSync(s32 result, DVDCommandBlock* block);
static void cbForSeekAsync(s32 result, DVDCommandBlock* block);
static void cbForSeekSync();
static void cbForPrepareStreamAsync(s32 result, DVDCommandBlock* block);

// Range: 0x0 -> 0xB0
static s32 DVDFstEntry(void* addr /* r1+0x8 */, u32 length /* r1+0xC */) {
    // Local variables
    BOOL result; // r29
    DVDCommandBlock block; // r1+0x10
    s32 state; // r31
    BOOL enabled; // r28
    s32 retVal; // r30

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDNetReadFstEntryAsyncPrio(&block, addr, length, cbForReadFstEntry, 2);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)&block)->state;
        if (state == DVD_STATE_END) {
            retVal = (s32)block.transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0xB0 -> 0xEC
static void cbForReadFstEntry(s32 result, DVDCommandBlock* block /* r31 */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    DCFlushRange(block->addr, block->length);
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0xEC -> 0x198
static s32 DVDFstString(void* addr /* r1+0x8 */) {
    // Local variables
    s32 result; // r29
    DVDCommandBlock block; // r1+0xC
    s32 state; // r31
    BOOL enabled; // r28
    s32 retVal; // r30

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static unsigned long MaxStringSize;
    result = DVDNetReadFstStringAsyncPrio(&block, addr, MaxStringSize, cbForReadFstEntry, 2);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)&block)->state;
        if (state == DVD_STATE_END) {
            retVal = (s32)block.transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x198 -> 0x1D4
static void cbForReadFstString(s32 result, DVDCommandBlock* block /* r31 */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    DCFlushRange(block->addr, block->length);
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x1D4 -> 0x23C
static s32 LoadFst(u32 entryLen /* r1+0x8 */) {
    // Local variables
    s32 resultFstEnt; // r31
    s32 resultFstStr; // r30

    // References
    // -> static char * FstStringStart;
    // -> static struct FSTEntry * FstStart;
    resultFstEnt = DVDFstEntry(FstStart, entryLen);
    if (resultFstEnt < 0) {
        return resultFstEnt;
    }

    resultFstStr = DVDFstString(FstStringStart);
    if (resultFstStr < 0) {
        return resultFstStr;
    }

    return resultFstEnt + resultFstStr;
}

// Range: 0x23C -> 0x2F4
BOOL DVDFstInit(void* fstAddr /* r29 */, u32 fstLen /* r30 */) {
    // Local variables
    u32 len; // r28
    u32 entryLen; // r31
    s32 result; // r27

    // References
    // -> static unsigned long MaxStringSize;
    // -> static char * FstStringStart;
    // -> static struct FSTEntry * FstStart;
    // -> static unsigned long MaxEntryNum;
    ASSERTMSGLINE(361, fstAddr, "DVDFstInit(): null pointer is specified to addr  ");

    if (fstLen < 32) {
        return FALSE;
    }

    memset(fstAddr, 0, fstLen);
    len = fstLen >> 1;
    entryLen = (len + 15) & ~15;
    MaxEntryNum = entryLen >> 4;
    FstStart = (FSTEntry*)fstAddr;
    FstStringStart = (char*)fstAddr + entryLen;
    MaxStringSize = fstLen - entryLen;

    result = LoadFst(entryLen);
    if (result < 0) {
        return FALSE;
    }

    return TRUE;
}

// Range: 0x2F4 -> 0x360
BOOL DVDFstRefresh(void) {
    // Local variables
    u32 fstLen; // r31
    u32 entryLen; // r30
    s32 result; // r29

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static unsigned long MaxEntryNum;
    // -> static unsigned long MaxStringSize;
    entryLen = MaxEntryNum << 4;
    fstLen = MaxStringSize + (MaxEntryNum << 4);
    memset(FstStart, 0, fstLen);

    result = LoadFst(entryLen);
    if (result < 0) {
        return FALSE;
    }

    return TRUE;
}

// Range: 0x360 -> 0x388
void __DVDFSInit(void) {
    // References
    // -> static struct OSBootInfo_s * BootInfo;
    BootInfo = (OSBootInfo*)OSPhysicalToCached(0);
}

// Range: 0x388 -> 0x41C
static BOOL isSame2(const char* path /* r31 */, const char* string /* r30 */) {
    while (*string != '\0') {
        if (tolower(*path++) != tolower(*string++)) {
            return FALSE;
        }
    }

    if (*path == '/' || *path == '\0') {
        return TRUE;
    }

    return FALSE;
}

// Range: 0x41C -> 0x4BC
static BOOL isSame(const char* path /* r30 */, const char* string /* r31 */) {
    while (*string != '\0' && *path != '\0') {
        if (tolower(*path++) != tolower(*string++)) {
            return FALSE;
        }
    }

    if (*string == '\0' && *path == '\0') {
        return TRUE;
    }

    return FALSE;
}

// Range: 0x4BC -> 0x76C
s32 DVDConvertPathToEntrynum(const char* pathPtr /* r31 */) {
    // Local variables
    const char* ptr; // r30
    char* stringPtr; // r23
    BOOL isDir; // r24
    u32 length; // r22
    u32 dirLookAt; // r29
    u32 i; // r28
    const char* origPathPtr; // r21
    const char* extentionStart; // r20
    BOOL illegal; // r26
    BOOL extention; // r25

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static char * FstStringStart;
    // -> unsigned long __DVDLongFileNameFlag;
    // -> static unsigned long currentDirectory;
    origPathPtr = pathPtr;
    ASSERTMSGLINE(522, pathPtr, "DVDConvertPathToEntrynum(): null pointer is specified  ");

    dirLookAt = currentDirectory;

    while (TRUE) {
        if (*pathPtr == '\0') {
            return (s32)dirLookAt;
        } else if (*pathPtr == '/') {
            dirLookAt = 0;
            pathPtr++;
            continue;
        } else if (*pathPtr == '.') {
            if (*(pathPtr + 1) == '.') {
                if (*(pathPtr + 2) == '/') {
                    dirLookAt = parentDir(dirLookAt);
                    pathPtr += 3;
                    continue;
                } else if (*(pathPtr + 2) == '\0') {
                    return (s32)parentDir(dirLookAt);
                }
            } else if (*(pathPtr + 1) == '/') {
                pathPtr += 2;
                continue;
            } else if (*(pathPtr + 1) == '\0') {
                return (s32)dirLookAt;
            }
        }

        if (__DVDLongFileNameFlag == 0) {
            extention = FALSE;
            illegal = FALSE;

            for (ptr = pathPtr; (*ptr != '\0') && (*ptr != '/'); ptr++) {
                if (*ptr == '.') {
                    if ((ptr - pathPtr > 8) || (extention == TRUE)) {
                        illegal = TRUE;
                        break;
                    }

                    extention = TRUE;
                    extentionStart = ptr + 1;
                } else if (*ptr == ' ') {
                    illegal = TRUE;
                }
            }

            if ((extention == TRUE) && (ptr - extentionStart > 3)) {
                illegal = TRUE;
            }

            if (illegal) {
                OSPanic(__FILE__, 592,
                        "DVDConvertEntrynumToPath(possibly DVDOpen or DVDChangeDir or DVDOpenDir): specified directory or file (%s) doesn't match standard 8.3 format. This is a temporary restriction and will be removed soon\n",
                        origPathPtr);
            }
        } else {
            for (ptr = pathPtr; (*ptr != '\0') && (*ptr != '/'); ptr++) {
                ;
            }
        }

        isDir = (*ptr == '\0') ? FALSE : TRUE;
        length = (u32)(ptr - pathPtr);

        ptr = pathPtr;

        for (i = childOrLength(dirLookAt); i != 0; i = nextEntry(i)) {
            if ((entryIsDir(i) == FALSE) && (isDir == TRUE)) {
                continue;
            }

            stringPtr = FstStringStart + stringOff(i);

            if (isSame2(ptr, stringPtr) == TRUE) {
                goto next_hier;
            }
        }

        return -1;

    next_hier:
        if (!isDir) {
            return (s32)i;
        }

        dirLookAt = i;
        pathPtr += length + 1;
    }
}

// Range: 0x76C -> 0x7B4
static u32 myStrncpy(char* dest /* r3 */, char* src /* r4 */, u32 maxlen /* r5 */) {
    // Local variables
    u32 i; // r31

    i = maxlen;
    while ((i > 0) && (*src != '\0')) {
        *dest++ = *src++;
        i--;
    }

    return (maxlen - i);
}

// Range: 0x7B4 -> 0x860
static u32 entryToPath(u32 entry /* r28 */, char* path /* r29 */, u32 maxlen /* r30 */) {
    // Local variables
    char* name; // r27
    u32 loc; // r31

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static char * FstStringStart;
    if (entry == 0) {
        return 0;
    }

    name = FstStringStart + stringOff(entry);
    loc = entryToPath(parentDir(entry), path, maxlen);
    if (loc == maxlen) {
        return loc;
    }

    *(path + loc++) = '/';
    loc += myStrncpy(path + loc, name, maxlen - loc);
    return loc;
}

// Range: 0x860 -> 0x970
BOOL DVDConvertEntrynumToPath(s32 entrynum /* r28 */, char* path /* r29 */, u32 maxlen /* r30 */) {
    // Local variables
    u32 loc; // r31

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static unsigned long MaxEntryNum;
    ASSERTMSG1LINE(726, (0 <= entrynum) && (entrynum < MaxEntryNum), "DVDConvertEntrynumToPath: specified entrynum(%d) is out of range  ", entrynum);
    ASSERTMSG1LINE(728, 1 < maxlen, "DVDConvertEntrynumToPath: maxlen should be more than 1 (%d is specified)", maxlen);

    loc = entryToPath((u32)entrynum, path, maxlen);
    if (loc == maxlen) {
        path[maxlen - 1] = '\0';
        return FALSE;
    }

    if (entryIsDir(entrynum)) {
        if (loc == maxlen - 1) {
            path[loc] = '\0';
            return FALSE;
        }

        path[loc++] = '/';
    }

    path[loc] = '\0';
    return TRUE;
}

// Range: 0x970 -> 0xA9C
BOOL DVDFastOpen(s32 entrynum /* r31 */, DVDFileInfo* fileInfo /* r29 */) {
    // References
    // -> static struct FSTEntry * FstStart;
    // -> static unsigned long MaxEntryNum;
    ASSERTMSGLINE(775, fileInfo, "DVDFastOpen(): null pointer is specified to file info address  ");
    ASSERTMSG1LINE(778, (0 <= entrynum) && (entrynum < MaxEntryNum), "DVDFastOpen(): specified entry number '%d' is out of range  ", entrynum);
    ASSERTMSG1LINE(781, !entryIsDir(entrynum), "DVDFastOpen(): entry number '%d' is assigned to a directory  ", entrynum);

    if ((entrynum < 0) || (entrynum >= MaxEntryNum) || entryIsDir(entrynum)) {
        return FALSE;
    }

    fileInfo->startAddr = (u32)entrynum;
    fileInfo->length = childOrLength(entrynum);
    fileInfo->callback = NULL;
    fileInfo->cb.state = DVD_STATE_END;
    return TRUE;
}

// Range: 0xA9C -> 0xBE0
BOOL DVDOpen(const char* fileName /* r28 */, DVDFileInfo* fileInfo /* r29 */) {
    // Local variables
    s32 entry; // r30
    char currentDir[128]; // r1+0x10

    // References
    // -> static struct FSTEntry * FstStart;
    ASSERTMSGLINE(811, fileName, "DVDOpen(): null pointer is specified to file name  ");
    ASSERTMSGLINE(812, fileInfo, "DVDOpen(): null pointer is specified to file info address  ");

    entry = DVDConvertPathToEntrynum(fileName);

    if (entry < 0) {
        DVDGetCurrentDir(currentDir, 128);
        OSReport("Warning: DVDOpen(): file '%s' was not found under %s.\n", fileName, currentDir);
        return FALSE;
    }

    if (entryIsDir(entry)) {
        ASSERTMSG1LINE(827, !entryIsDir(entry), "DVDOpen(): directory '%s' is specified as a filename  ", fileName);
        return FALSE;
    }

    fileInfo->startAddr = (u32)entry;
    fileInfo->length = childOrLength(entry);
    fileInfo->callback = NULL;
    fileInfo->cb.state = DVD_STATE_END;
    return TRUE;
}

// Range: 0xBE0 -> 0xC38
BOOL DVDClose(DVDFileInfo* fileInfo /* r31 */) {
    ASSERTMSGLINE(855, fileInfo, "DVDClose(): null pointer is specified to file info address  ");
    DVDCancel(&fileInfo->cb);
    return TRUE;
}

// Range: 0xC38 -> 0xC98
static s32 FSTEntryAlloc() {
    // Local variables
    u32 i; // r31

    // References
    // -> static unsigned long MaxEntryNum;
    // -> static struct FSTEntry * FstStart;
    for (i = 0; i < MaxEntryNum; i++) {
        if (entryIsUsed(i) == FALSE) {
            return (s32)i;
        }
    }

    return -1;
}

// Range: 0xC98 -> 0xCD4
static void FSTEntryFree(u32 entry /* r1+0x8 */) {
    // References
    // -> static struct FSTEntry * FstStart;
    memset(&FstStart[entry], 0, sizeof(FSTEntry));
}

// Range: 0xCD4 -> 0xD1C
static u32 IsEmpty(u32 offset /* r3 */, u32 len /* r4 */) {
    // Local variables
    u32 i; // r31
    u32 end; // r30

    // References
    // -> static char * FstStringStart;
    end = len + offset;
    for (i = offset; i < end; i++) {
        if (FstStringStart[i] != '\0') {
            return i;
        }
    }

    return 0;
}

// Range: 0xD1C -> 0xDC8
static s32 FSTStringAlloc(const char* string /* r28 */) {
    // Local variables
    u32 len; // r30
    u32 i; // r31
    u32 next; // r29

    // References
    // -> static unsigned long MaxStringSize;
    // -> static char * FstStringStart;
    len = strlen(string) + 1;
    for (i = 0; i < MaxStringSize;) {
        if (FstStringStart[i] == '\0') {
            next = IsEmpty(i, len);
            if (next == 0) {
                memcpy(FstStringStart + i, string, len);
                return (s32)i;
            }

            i = next;
        } else {
            i += strlen(FstStringStart + i);
            i++;
        }
    }

    return -1;
}

// Range: 0xDC8 -> 0xE28
static void FSTStringFree(u32 entry /* r1+0x8 */) {
    // Local variables
    char* name; // r31
    u32 len; // r30

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static char * FstStringStart;
    name = FstStringStart + stringOff(entry);
    len = strlen(name);
    memset(name, 0, len);
}

// Range: 0xE28 -> 0xED0
static s32 FSTAlloc(const char* string /* r29 */) {
    // Local variables
    s32 entry; // r31
    s32 offset; // r30

    // References
    // -> static struct FSTEntry * FstStart;
    entry = FSTEntryAlloc();
    if (entry < 0) {
        OSReport("Warning: DVDCreate(): Not enough FST buffer to create new enetry, %s.\n", string);
        return -1;
    }

    offset = FSTStringAlloc(string);
    if (offset < 0) {
        OSReport("Warning: DVDCreate(): Not enough FST buffer to create new enetry, %s.\n", string);
        FSTEntryFree(entry);
        return -1;
    }

    FstStart[entry].isDirAndStringOff |= (offset & 0x00FFFFFF);
    return entry;
}

// Range: 0xED0 -> 0xF08
static void FSTFree(u32 entry /* r31 */) {
    FSTStringFree(entry);
    FSTEntryFree(entry);
}

// Range: 0xF08 -> 0xFE0
#pragma dont_inline on // @HACK - this stops an inline from LookUpFileList from being performed
static s32 mystrcmp(const char* path1 /* r28 */, const char* path2 /* r31 */) {
    // Local variables
    u8 tmp1; // r30
    u8 tmp2; // r29

    while (*path1 != '\0' && *path2 != '\0') {
        tmp1 = toupper(*path1++);
        tmp2 = toupper(*path2++);
        if (tmp1 > tmp2) {
            return 1;
        }

        if (tmp2 > tmp1) {
            return -1;
        }
    }

    if (*path2 == '\0' && *path1 == '\0') {
        return 0;
    }

    if (*path2 == '\0') {
        return 1;
    }

    return -1;
}
#pragma dont_inline off

// Range: 0xFE0 -> 0x10F4
static u32 DeleteFileList(u32 parentEntry /* r30 */) {
    // Local variables
    u32 childEntry; // r31
    u32 nextEntry; // r28
    u32 entry; // r29

    // References
    // -> static struct FSTEntry * FstStart;
    if (entryIsDir(parentEntry)) {
        childEntry = FstStart[parentEntry].childOrLength;
    } else {
        childEntry = 0;
    }

    while (childEntry != 0) {
        if (entryIsDir(childEntry)) {
            entry = DeleteFileList(childEntry);
            FstStart[parentEntry].childOrLength = entry;
            childEntry = entry;
        } else {
            entry = FstStart[childEntry].next;
            FstStart[parentEntry].childOrLength = entry;
            FSTFree(childEntry);
            childEntry = FstStart[parentEntry].childOrLength;
        }
    }

    nextEntry = FstStart[parentEntry].next;
    FSTFree(parentEntry);
    return nextEntry;
}

// Range: 0x10F4 -> 0x13B4
static s32 LookUpFileList(const char* pSearchPath /* r31 */, u32 parentEntry /* r28 */, int lookupType /* r22 */, s32 option /* r20 */) {
    // Local variables
    s32 newEntry; // r30
    u32 entry; // r29
    s32 retEntry; // r25
    u32* pNextEntry = NULL; // r27
    const char* pChildPath; // r24
    BOOL bChild; // r26
    s32 result; // r21
    char filename[128]; // r1+0x18
    char* pFilename; // r23

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static char * FstStringStart;
    pChildPath = NULL;

    while (TRUE) {
        if (*pSearchPath == '\0') {
            return (s32)parentEntry;
        } else if (*pSearchPath == '/') {
            pSearchPath++;
            continue;
        } else if (*pSearchPath == '.') {
            if (*(pSearchPath + 1) == '.') {
                if (*(pSearchPath + 2) == '/') {
                    parentEntry = parentDir(parentEntry);
                    pSearchPath += 3;
                    continue;
                } else if (*(pSearchPath + 2) == '\0') {
                    return (s32)parentDir(parentEntry);
                }
            } else if (*(pSearchPath + 1) == '/') {
                pSearchPath += 2;
                continue;
            } else if (*(pSearchPath + 1) == '\0') {
                return (s32)parentEntry;
            }
        }

        break;
    }

    entry = FstStart[parentEntry].childOrLength;
    pNextEntry = &FstStart[parentEntry].childOrLength;
    pFilename = filename;

    while (TRUE) {
        if (*pSearchPath == '/') {
            *pFilename = '\0';
            pChildPath = pSearchPath + 1;
            bChild = TRUE;
            break;
        }

        if (*pSearchPath == '\0') {
            *pFilename = '\0';
            bChild = FALSE;
            break;
        }

        *pFilename++ = *pSearchPath++;
    }

    while (TRUE) {
        if (entry == 0) {
            break;
        }

        result = mystrcmp(filename, FstStringStart + stringOff(entry));
        if (result == 0) {
            if (bChild) {
                retEntry = LookUpFileList(pChildPath, entry, lookupType, option);
                return retEntry;
            }

            if (lookupType == LOOKUP_REMOVE) {
                retEntry = DeleteFileList(entry);
                *pNextEntry = retEntry;
                return 0;
            }

            return (s32)entry;
        }

        if (result <= 0) {
            break;
        }

        pNextEntry = &FstStart[entry].next;
        entry = FstStart[entry].next;
    }

    if (lookupType == LOOKUP_CREATE) {
        newEntry = FSTAlloc(filename);
        if (newEntry < 0) {
            return -1;
        }

        if (bChild) {
            FstStart[newEntry].isDirAndStringOff |= 0xFF000000;
        } else {
            FstStart[newEntry].isDirAndStringOff |= 0x0F000000;
        }

        FstStart[newEntry].next = entry;
        FstStart[newEntry].parent = parentEntry;
        FstStart[newEntry].childOrLength = option;
        *pNextEntry = newEntry;

        if (bChild) {
            return LookUpFileList(pChildPath, newEntry, lookupType, option);
        }

        return newEntry;
    }

    return -1;
}

// Range: 0x13B4 -> 0x1408
static s32 LookUpAllFileList(const char* pSearchPath /* r31 */, int lookupType /* r1+0xC */, s32 option /* r1+0x10 */) {
    if (*pSearchPath == '/') {
        pSearchPath++;
    }

    return LookUpFileList(pSearchPath, 0, lookupType, option);
}

// Range: 0x1408 -> 0x1490
static BOOL GetAbsPath(char* pAbsPath /* r29 */, const char* pRelPath /* r31 */) {
    // Local variables
    BOOL result; // r30
    char rootPath[256]; // r1+0x10

    // References
    // -> static unsigned long currentDirectory;
    if (*pRelPath == '/') {
        strcpy(pAbsPath, pRelPath);
    } else {
        result = DVDConvertEntrynumToPath(currentDirectory, rootPath, 256);
        if (result == FALSE) {
            return FALSE;
        }

        sprintf(pAbsPath, "%s%s", rootPath, pRelPath);
    }

    return TRUE;
}

// Range: 0x1490 -> 0x14DC
static void DeleteLastSlash(char* fileName /* r3 */) {
    // Local variables
    char* pStart; // r31

    pStart = fileName;
    if (*pStart == '\0') {
        return;
    }

    while (*pStart != '\0') {
        pStart++;
    }

    if (*(pStart - 1) == '/') {
        *(pStart - 1) = '\0';
    }
}

// Range: 0x14DC -> 0x1758
BOOL DVDRemove(const char* fileName /* r24 */, DVDFileInfo* fileInfo /* r31 */) {
    // Local variables
    BOOL result; // r27
    DVDCommandBlock* pBlock; // r29
    DVDFileInfo tmpFileInfo = {0}; // r1+0x110
    s32 state; // r26
    BOOL enabled; // r23
    s32 retVal; // r28
    s32 entry; // r30
    char path[256]; // r1+0x10

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static struct FSTEntry * FstStart;
    ASSERTMSGLINE(1376, fileName || fileInfo, "DVDRemove(): null pointer is specified to both file name and file info address  ");

    (void)fileName;

    if (fileInfo) {
        pBlock = &fileInfo->cb;
        fileInfo->length = 0;
        fileInfo->callback = NULL;
        fileInfo->cb.state = DVD_STATE_END;
        entry = (s32)fileInfo->startAddr;
        if (entryIsUsed(entry) == FALSE) {
            return FALSE;
        }

        result = DVDConvertEntrynumToPath((s32)fileInfo->startAddr, path, 256);
        if (result == FALSE) {
            return FALSE;
        }
    } else {
        fileInfo = &tmpFileInfo;
        pBlock = &tmpFileInfo.cb;
        GetAbsPath(path, fileName);
        entry = DVDConvertPathToEntrynum(path);
        if (entry < 0) {
            return FALSE;
        }
    }

    DeleteLastSlash(path);
    if (entryIsDir(entry)) {
        return FALSE;
    }

    result = DVDRemoveAsyncPrio(pBlock, &fileInfo->startAddr, 4, cbForRemoveSync, path, 2);
    if (result == FALSE) {
        return FALSE;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)pBlock)->state;
        if (state == DVD_STATE_END) {
            retVal = (s32)pBlock->transferredSize;
            if (retVal == 0) {
                return FALSE;
            }

            if (fileInfo->startAddr < 0) {
                return FALSE;
            }

            if (pBlock->transferredSize == 0xFFFFFFFF) {
                return FALSE;
            }

            if (LookUpAllFileList(path, LOOKUP_REMOVE, 0) < 0) {
                return FALSE;
            }

            if (fileInfo->startAddr != entry) {
                OSReport("DVDRemove: Entry number of %s\n           is %d on DVDServer, but %d on GC.\n", path, fileInfo->startAddr, entry);
            }
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    if (retVal > 0) {
        return TRUE;
    }

    return FALSE;
}

// Range: 0x1758 -> 0x177C
static void cbForRemoveSync() {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x177C -> 0x1944
BOOL DVDCreate(const char* fileName /* r24 */, DVDFileInfo* fileInfo /* r31 */) {
    // Local variables
    BOOL result; // r26
    DVDCommandBlock* pBlock; // r28
    s32 state; // r27
    BOOL enabled; // r25
    s32 retVal; // r30
    char path[256]; // r1+0x10

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static struct FSTEntry * FstStart;
    ASSERTMSGLINE(1538, fileName, "DVDCreate(): null pointer is specified to file name  ");
    ASSERTMSGLINE(1539, fileInfo, "DVDCreate(): null pointer is specified to file info address  ");

    GetAbsPath(path, fileName);
    DeleteLastSlash(path);

    fileInfo->startAddr = 0;
    fileInfo->length = 0;
    fileInfo->callback = NULL;
    fileInfo->cb.state = DVD_STATE_END;
    pBlock = &fileInfo->cb;

    result = DVDCreateAsyncPrio(pBlock, &fileInfo->startAddr, 4, cbForCreateSync, path, 2);
    if (result == FALSE) {
        return FALSE;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)pBlock)->state;
        if (state == DVD_STATE_END) {
            if (fileInfo->startAddr < 0) {
                return FALSE;
            }

            if (pBlock->transferredSize == -1) {
                return FALSE;
            }

            retVal = LookUpAllFileList(path, LOOKUP_CREATE, 0);
            if (retVal < 0) {
                return FALSE;
            }

            if (fileInfo->startAddr != retVal) {
                OSReport("DVDCreate: Entry number of %s\n            is %d on DVDServer, but %d on GC.\n", path, fileInfo->startAddr, retVal);
            }

            fileInfo->startAddr = (u32)retVal;
            fileInfo->length = childOrLength(retVal);
            fileInfo->callback = NULL;
            fileInfo->cb.state = DVD_STATE_END;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    if (retVal > 0) {
        return TRUE;
    }

    return FALSE;
}

// Range: 0x1944 -> 0x1968
static void cbForCreateSync() {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x1968 -> 0x19D4
BOOL DVDGetCurrentDir(char* path /* r1+0x8 */, u32 maxlen /* r31 */) {
    // Local variables
    BOOL result; // r30

    // References
    // -> static unsigned long currentDirectory;
    ASSERTMSG1LINE(1660, (maxlen > 1), "DVDGetCurrentDir: maxlen should be more than 1 (%d is specified)", maxlen);

    result = DVDConvertEntrynumToPath((s32)currentDirectory, path, maxlen);
    return result;
}

// Range: 0x19D4 -> 0x1ADC
BOOL DVDChangeDir(const char* dirName /* r29 */) {
    // Local variables
    s32 entry; // r30
    char currentDir[128]; // r1+0xC

    // References
    // -> static unsigned long currentDirectory;
    // -> static struct FSTEntry * FstStart;
    ASSERTMSGLINE(1685, dirName, "DVDChangeDir(): null pointer is specified to directory name  ");

    entry = DVDConvertPathToEntrynum(dirName);
#ifdef DEBUG
    if (entry < 0) {
        DVDGetCurrentDir(currentDir, 128);
        OSPanic(__FILE__, 1693, "DVDChangeDir(): directory '%s' is not found under %s  ", dirName, currentDir);
    }
#endif
    ASSERTMSG1LINE(1697, entryIsDir(entry), "DVDChangeDir(): file '%s' is specified as a directory name  ", dirName);

    if ((entry < 0) || (entryIsDir(entry) == FALSE)) {
        return FALSE;
    }

    currentDirectory = (u32)entry;
    return TRUE;
}

// Range: 0x1ADC -> 0x1BBC
BOOL DVDWriteAsyncPrio(DVDFileInfo* fileInfo /* r30 */, void* addr /* r27 */, s32 length /* r28 */, s32 offset /* r29 */, DVDCallback callback /* r1+0x18 */, s32 prio /* r1+0x1C */) {
    ASSERTMSGLINE(1728, fileInfo, "DVDWriteAsync(): null pointer is specified to file info address  ");
    ASSERTMSGLINE(1729, addr, "DVDWriteAsync(): null pointer is specified to addr  ");

    if (!(0 <= length)) {
        OSPanic(__FILE__, 1734, "DVDWriteAsync(): specified area is out of the file  ");
    }

    if (!(0 <= offset)) {
        OSPanic(__FILE__, 1739, "DVDWriteAsync(): specified area is out of the file  ");
    }

    fileInfo->callback = callback;
    DVDWriteAbsAsyncPrio(&fileInfo->cb, addr, length, offset, cbForWriteAsync, prio);
    return TRUE;
}

// Range: 0x1BBC -> 0x1C9C
static void cbForWriteAsync(s32 result /* r29 */, DVDCommandBlock* block /* r30 */) {
    // Local variables
    DVDFileInfo* fileInfo; // r31

    // References
    // -> static struct FSTEntry * FstStart;
    fileInfo = (DVDFileInfo*)((u8*)block - (u32)&((DVDFileInfo*)0)->cb);
    ASSERTLINE(1757, (void*) &fileInfo->cb == (void*) block);

    if (result != -1 && fileInfo->length < result + block->offset) {
        fileInfo->length = result + block->offset;
        if (!entryIsDir(fileInfo->startAddr)) {
            FstStart[fileInfo->startAddr].childOrLength = fileInfo->length;
        }
    }

    if (fileInfo->callback) {
        (*fileInfo->callback)(result, fileInfo);
    }
}

// Range: 0x1C9C -> 0x1DD8
s32 DVDWritePrio(DVDFileInfo* fileInfo /* r22 */, void* addr /* r23 */, s32 length /* r24 */, s32 offset /* r25 */, s32 prio /* r1+0x18 */) {
    // Local variables
    BOOL result; // r27
    DVDCommandBlock* block; // r30
    s32 state; // r29
    BOOL enabled; // r26
    s32 retVal; // r28

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    ASSERTMSGLINE(1804, fileInfo, "DVDWrite(): null pointer is specified to file info address  ");
    ASSERTMSGLINE(1805, addr, "DVDWrite(): null pointer is specified to addr  ");

    if (!(0 <= offset)) {
        OSPanic(__FILE__, 1810, "DVDWrite(): specified area is out of the file  ");
    }

    if (!(0 <= length)) {
        OSPanic(__FILE__, 1815, "DVDWrite(): specified area is out of the file  ");
    }

    block = &fileInfo->cb;
    result = DVDWriteAbsAsyncPrio(block, addr, length, offset, cbForWriteSync, prio);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END) {
            retVal = (s32)block->transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x1DD8 -> 0x1EA4
static void cbForWriteSync(s32 result /* r29 */, DVDCommandBlock* block /* r30 */) {
    // Local variables
    DVDFileInfo* fileInfo; // r31

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static struct FSTEntry * FstStart;
    fileInfo = (DVDFileInfo*)((u8*)block - (u32)&((DVDFileInfo*)0)->cb);
    ASSERTLINE(1870, (void*) &fileInfo->cb == (void*) block);

    if (result != -1) {
        if (fileInfo->length < result + block->offset) {
            fileInfo->length = result + block->offset;
            if (!entryIsDir(fileInfo->startAddr)) {
                FstStart[fileInfo->startAddr].childOrLength = fileInfo->length;
            }
        }

        block->transferredSize = (u32)result;
    }

    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x1EA4 -> 0x1FF8
BOOL DVDReadAsyncPrio(DVDFileInfo* fileInfo /* r29 */, void* addr /* r27 */, s32 length /* r28 */, s32 offset /* r30 */, DVDCallback callback /* r1+0x18 */, s32 prio /* r1+0x1C */) {
    ASSERTMSGLINE(1912, fileInfo, "DVDReadAsync(): null pointer is specified to file info address  ");
    ASSERTMSGLINE(1913, addr, "DVDReadAsync(): null pointer is specified to addr  ");
    ASSERTMSGLINE(1917, !((u32)addr & 31), "DVDReadAsync(): address must be aligned with 32 byte boundaries  ");
    ASSERTMSGLINE(1919, !(length & 31), "DVDReadAsync(): length must be  multiple of 32 byte  ");
    ASSERTMSGLINE(1921, !(offset & 3), "DVDReadAsync(): offset must be multiple of 4 byte  ");

    if (!((0 <= offset) && (offset <= fileInfo->length))) {
        OSPanic(__FILE__, 1926, "DVDReadAsync(): specified area is out of the file  ");
    }

    if (!((0 <= offset + length) && (offset + length < fileInfo->length + DVD_MIN_TRANSFER_SIZE))) {
        OSPanic(__FILE__, 1932, "DVDReadAsync(): specified area is out of the file  ");
    }

    fileInfo->callback = callback;
    DVDNetReadAbsAsyncPrio(&fileInfo->cb, addr, length, offset, cbForReadAsync, prio);
    return TRUE;
}

// Range: 0x1FF8 -> 0x2078
static void cbForReadAsync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r30 */) {
    // Local variables
    DVDFileInfo* fileInfo; // r31

    fileInfo = (DVDFileInfo*)((u8*)block - (u32)&((DVDFileInfo*)0)->cb);
    ASSERTLINE(1950, (void*) &fileInfo->cb == (void*) block);

    DCFlushRange(block->addr, block->length);
    if (fileInfo->callback) {
        (*fileInfo->callback)(result, fileInfo);
    }
}

// Range: 0x2078 -> 0x2228
s32 DVDReadPrio(DVDFileInfo* fileInfo /* r25 */, void* addr /* r24 */, s32 length /* r26 */, s32 offset /* r30 */, s32 prio /* r1+0x18 */) {
    // Local variables
    BOOL result; // r23
    DVDCommandBlock* block; // r29
    s32 state; // r28
    BOOL enabled; // r22
    s32 retVal; // r27

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    ASSERTMSGLINE(1984, fileInfo, "DVDRead(): null pointer is specified to file info address  ");
    ASSERTMSGLINE(1985, addr, "DVDRead(): null pointer is specified to addr  ");
    ASSERTMSGLINE(1989, !((u32)addr & 31), "DVDRead(): address must be aligned with 32 byte boundaries  ");
    ASSERTMSGLINE(1991, !(length & 31), "DVDRead(): length must be  multiple of 32 byte  ");
    ASSERTMSGLINE(1993, !(offset & 3), "DVDRead(): offset must be multiple of 4 byte  ");

    if (!((0 <= offset) && (offset <= fileInfo->length))) {
        OSPanic(__FILE__, 1998, "DVDRead(): specified area is out of the file  ");
    }

    if (!((0 <= offset + length) && (offset + length < fileInfo->length + DVD_MIN_TRANSFER_SIZE))) {
        OSPanic(__FILE__, 2004, "DVDRead(): specified area is out of the file  ");
    }

    block = &fileInfo->cb;
    result = DVDNetReadAbsAsyncPrio(block, addr, length, offset, cbForReadSync, prio);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END) {
            retVal = (s32)block->transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x2228 -> 0x2264
static void cbForReadSync(s32 result, DVDCommandBlock* block /* r31 */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    DCFlushRange(block->addr, block->length);
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x2264 -> 0x2324
BOOL DVDSeekAsyncPrio(DVDFileInfo* fileInfo /* r29 */, s32 offset /* r30 */, DVDCallback callback /* r1+0x10 */, s32 prio /* r1+0x14 */) {
    ASSERTMSGLINE(2083, fileInfo, "DVDSeek(): null pointer is specified to file info address  ");
    ASSERTMSGLINE(2087, !(offset & 3), "DVDSeek(): offset must be multiple of 4 byte  ");

    if (!((0 <= offset) && (offset <= fileInfo->length))) {
        OSPanic(__FILE__, 2092, "DVDSeek(): offset is out of the file  ");
    }

    fileInfo->callback = callback;
    DVDSeekAbsAsyncPrio(&fileInfo->cb, offset, cbForSeekAsync, prio);
    return TRUE;
}

// Range: 0x2324 -> 0x2398
static void cbForSeekAsync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r30 */) {
    // Local variables
    DVDFileInfo* fileInfo; // r31

    fileInfo = (DVDFileInfo*)((u8*)block - (u32)&((DVDFileInfo*)0)->cb);
    ASSERTLINE(2113, (void*) &fileInfo->cb == (void*) block);

    if (fileInfo->callback) {
        (*fileInfo->callback)(result, fileInfo);
    }
}

// Range: 0x2398 -> 0x24B4
s32 DVDSeekPrio(DVDFileInfo* fileInfo /* r26 */, s32 offset /* r28 */, s32 prio /* r1+0x10 */) {
    // Local variables
    BOOL result; // r25
    DVDCommandBlock* block; // r27
    s32 state; // r30
    BOOL enabled; // r24
    s32 retVal; // r29

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    ASSERTMSGLINE(2143, fileInfo, "DVDSeek(): null pointer is specified to file info address  ");
    ASSERTMSGLINE(2147, !(offset & 3), "DVDSeek(): offset must be multiple of 4 byte  ");

    ASSERTMSGLINE(2151, (0 <= offset) && (offset <= fileInfo->length), "DVDSeek(): offset is out of the file  ");

    block = &fileInfo->cb;
    result = DVDSeekAbsAsyncPrio(block, offset, cbForSeekSync, prio);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END) {
            retVal = 0;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = -1;
            break;
        }

        if (state == DVD_STATE_CANCELED) {
            retVal = -3;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x24B4 -> 0x24D8
static void cbForSeekSync() {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x24D8 -> 0x2500
s32 DVDGetFileInfoStatus(const DVDFileInfo* fileInfo /* r1+0x8 */) {
    return DVDGetCommandBlockStatus(&fileInfo->cb);
}

// Range: 0x2500 -> 0x2624
BOOL DVDFastOpenDir(s32 entrynum /* r31 */, DVDDir* dir /* r29 */) {
    // References
    // -> static struct FSTEntry * FstStart;
    // -> static unsigned long MaxEntryNum;
    ASSERTMSGLINE(2236, dir, "DVDFastOpenDir(): null pointer is specified to dir structure address  ");
    ASSERTMSG1LINE(2239, (0 <= entrynum) && (entrynum < MaxEntryNum), "DVDFastOpenDir(): specified entry number '%d' is out of range  ", entrynum);
    ASSERTMSG1LINE(2242, entryIsDir(entrynum), "DVDFastOpenDir(): entry number '%d' is assigned to a file  ", entrynum);

    if ((entrynum < 0) || (entrynum >= MaxEntryNum) || !entryIsDir(entrynum)) {
        return FALSE;
    }

    dir->entryNum = (u32)entrynum;
    dir->next = childOrLength(entrynum);
    dir->location = dir->next;
    return TRUE;
}

// Range: 0x2624 -> 0x2760
BOOL DVDOpenDir(const char* dirName /* r28 */, DVDDir* dir /* r29 */) {
    // Local variables
    s32 entry; // r30
    char currentDir[128]; // r1+0x10

    // References
    // -> static struct FSTEntry * FstStart;
    ASSERTMSGLINE(2272, dirName, "DVDOpendir(): null pointer is specified to directory name  ");
    ASSERTMSGLINE(2273, dir, "DVDOpenDir(): null pointer is specified to dir structure address  ");

    entry = DVDConvertPathToEntrynum(dirName);

    if (entry < 0) {
        DVDGetCurrentDir(currentDir, 128);
        OSReport("Warning: DVDOpenDir(): file '%s' was not found under %s.\n", dirName, currentDir);
        return FALSE;
    }

    if (!entryIsDir(entry)) {
        ASSERTMSG1LINE(2287, entryIsDir(entry), "DVDOpendir(): file '%s' is specified as a directory name  ", dirName);
        return FALSE;
    }

    dir->entryNum = (u32)entry;
    dir->next = childOrLength(entry);
    dir->location = dir->next;
    return TRUE;
}

// Range: 0x2760 -> 0x27E4
BOOL DVDReadDir(DVDDir* dir /* r3 */, DVDDirEntry* dirent /* r4 */) {
    // Local variables
    u32 loc; // r31

    // References
    // -> static struct FSTEntry * FstStart;
    // -> static char * FstStringStart;
    loc = dir->location;
    if (loc == 0) {
        return FALSE;
    }

    dirent->entryNum = loc;
    dirent->isDir = entryIsDir(loc);
    dirent->name = FstStringStart + stringOff(loc);
    dir->location = nextEntry(loc);
    return TRUE;
}

// Range: 0x27E4 -> 0x27EC
BOOL DVDCloseDir(DVDDir* dir) {
    return TRUE;
}

// Range: 0x27EC -> 0x27F8
void DVDRewindDir(DVDDir* dir /* r3 */) {
    dir->location = dir->next;
}

// Range: 0x27F8 -> 0x2804
void* DVDGetFSTLocation(void) {
    // References
    // -> static struct OSBootInfo_s * BootInfo;
    return BootInfo->FSTLocation;
}

// Range: 0x2804 -> 0x2908
BOOL DVDPrepareStreamAsync(DVDFileInfo* fileInfo /* r28 */, u32 length /* r29 */, u32 offset /* r30 */, DVDCallback callback /* r1+0x14 */) {
    // Local variables
    u32 start; // r27

    ASSERTMSGLINE(2398, fileInfo, "DVDPrepareStreamAsync(): NULL file info was specified");

    start = offset;
    if (start & 0x7FFF) {
        OSPanic(__FILE__, 2405, "DVDPrepareStreamAsync(): Specified start address (offset(0x%x)) is not 32KB aligned", offset);
    }

    if (length == 0) {
        length = fileInfo->length - offset;
    }

    if (length & 0x7FFF) {
        OSPanic(__FILE__, 2415, "DVDPrepareStreamAsync(): Specified length (0x%x) is not a multiple of 32768(32*1024)", length);
    }

    if (!((offset <= fileInfo->length) && (offset + length <= fileInfo->length))) {
        OSPanic(__FILE__, 2423, "DVDPrepareStreamAsync(): The area specified (offset(0x%x), length(0x%x)) is out of the file", offset, length);
    }

    fileInfo->callback = callback;
    return DVDPrepareStreamAbsAsync(&fileInfo->cb, length, offset, cbForPrepareStreamAsync);
}

// Range: 0x2908 -> 0x297C
static void cbForPrepareStreamAsync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r30 */) {
    // Local variables
    DVDFileInfo* fileInfo; // r31

    fileInfo = (DVDFileInfo*)((u8*)block - (u32)&((DVDFileInfo*)0)->cb);
    ASSERTLINE(2442, (void*) &fileInfo->cb == (void*) block);

    if (fileInfo->callback) {
        (*fileInfo->callback)(result, fileInfo);
    }
}

// Range: 0x297C -> 0x2A70
s32 DVDPrepareStream(DVDFileInfo* fileInfo /* r28 */, u32 length /* r29 */, u32 offset /* r30 */) {
    // Local variables
    DVDCommandBlock* block; // r27
    s32 retVal; // r26
    u32 start; // r25

    ASSERTMSGLINE(2473, fileInfo, "DVDPrepareStream(): NULL file info was specified");

    start = offset;
    if (start & 0x7FFF) {
        OSPanic(__FILE__, 2480, "DVDPrepareStream(): Specified start address (offset(0x%x)) is not 32KB aligned", offset);
    }

    if (length == 0) {
        length = fileInfo->length - offset;
    }

    if (length & 0x7FFF) {
        OSPanic(__FILE__, 2490, "DVDPrepareStream(): Specified length (0x%x) is not a multiple of 32768(32*1024)", length);
    }

    if (!((offset <= fileInfo->length) && (offset + length <= fileInfo->length))) {
        OSPanic(__FILE__, 2498, "DVDPrepareStream(): The area specified (offset(0x%x), length(0x%x)) is out of the file", offset, length);
    }

    block = &fileInfo->cb;
    block->state = DVD_STATE_END;
    retVal = 0;
    return retVal;
}

// Range: 0x2A70 -> 0x2B18
s32 DVDGetTransferredSize(DVDFileInfo* fileinfo /* r1+0x8 */) {
    // Local variables
    s32 bytes; // r30
    DVDCommandBlock* cb; // r31

    cb = &fileinfo->cb;

    switch (cb->state) {
        case DVD_STATE_END:
        case DVD_STATE_COVER_CLOSED:
        case DVD_STATE_NO_DISK:
        case DVD_STATE_COVER_OPEN:
        case DVD_STATE_WRONG_DISK:
        case DVD_STATE_FATAL_ERROR:
        case DVD_STATE_MOTOR_STOPPED:
        case DVD_STATE_CANCELED:
        case DVD_STATE_RETRY:
            bytes = (s32)cb->transferredSize;
            break;
        case DVD_STATE_WAITING:
            bytes = 0;
            break;
        case DVD_STATE_BUSY:
            bytes = (s32)cb->transferredSize;
            break;
        default:
            ASSERTMSG1LINE(2541, FALSE, "DVDGetTransferredSize(): Illegal state (%d)", cb->state);
            break;
    }

    return bytes;
}
