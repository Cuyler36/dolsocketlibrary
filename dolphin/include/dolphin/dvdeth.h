#ifndef _DOLPHIN_DVDETH_H_
#define _DOLPHIN_DVDETH_H_

#include <dolphin/types.h>
#include <dolphin/os.h>
#include <dolphin/dvd.h>
#include <dolphin/private/sdk.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*DVDLowCallback)(u32 intType);

// ASSERTMSGLINE/ASSERTMSG1LINE come from os.h; ASSERTMSG2LINE from private/sdk.h

// external (dvd library)
void __DVDInterruptHandler(__OSInterrupt interrupt, OSContext* context);

// dvdeth.c
extern const char* __DVDETHVersion;
extern OSThreadQueue __DVDThreadQueue;

void DVDInit(void);
int DVDRemoveAsyncPrio(DVDCommandBlock* block, void* addr, u32 length, DVDCBCallback callback, const char* fileName, s32 prio);
int DVDCreateAsyncPrio(DVDCommandBlock* block, void* addr, u32 length, DVDCBCallback callback, const char* fileName, s32 prio);
int DVDWriteAbsAsyncPrio(DVDCommandBlock* block, void* addr, s32 length, s32 offset, DVDCBCallback callback, s32 prio);
int DVDNetReadAbsAsyncPrio(DVDCommandBlock* block, void* addr, s32 length, s32 offset, DVDCBCallback callback, s32 prio);
int DVDNetReadFstEntryAsyncPrio(DVDCommandBlock* block, void* addr, u32 length, DVDCBCallback callback, s32 prio);
int DVDNetReadFstStringAsyncPrio(DVDCommandBlock* block, void* addr, u32 length, DVDCBCallback callback, s32 prio);
int DVDSeekAbsAsyncPrio(DVDCommandBlock* block, s32 offset, DVDCBCallback callback, s32 prio);
int DVDPrepareStreamAbsAsync(DVDCommandBlock* block, u32 length, u32 offset, DVDCBCallback callback);
int DVDCancelStreamAsync(DVDCommandBlock* block, DVDCBCallback callback);
s32 DVDCancelStream(DVDCommandBlock* block);
int DVDStopStreamAtEndAsync(DVDCommandBlock* block, DVDCBCallback callback);
s32 DVDStopStreamAtEnd(DVDCommandBlock* block);
int DVDGetStreamErrorStatusAsync(DVDCommandBlock* block, DVDCBCallback callback);
s32 DVDGetStreamErrorStatus(DVDCommandBlock* block);
int DVDGetStreamPlayAddrAsync(DVDCommandBlock* block, DVDCBCallback callback);
s32 DVDGetStreamPlayAddr(DVDCommandBlock* block);
int DVDChangeDiskAsync(DVDCommandBlock* block, DVDDiskID* id, DVDCBCallback callback);
s32 DVDChangeDisk(DVDCommandBlock* block, DVDDiskID* id);
s32 DVDGetCommandBlockStatus(const DVDCommandBlock* block);
s32 DVDGetDriveStatus(void);
int DVDSetAutoInvalidation(int autoInval);
void DVDPause(void);
void DVDResume(void);
int DVDCancelAsync(DVDCommandBlock* block, DVDCBCallback callback);
s32 DVDCancel(volatile DVDCommandBlock* block);
int DVDCancelAllAsync(DVDCBCallback callback);
s32 DVDCancelAll(void);
DVDDiskID* DVDGetCurrentDiskID(void);
int DVDCheckDisk(void);
void __DVDPrepareResetAsync(DVDCBCallback callback);
void __DVDInitWA(void);

// dvdethfs.c
extern u32 __DVDLongFileNameFlag;

int DVDFstInit(void* fstAddr, u32 fstLen);
int DVDFstRefresh(void);
void __DVDFSInit(void);
s32 DVDConvertPathToEntrynum(const char* pathPtr);
int DVDConvertEntrynumToPath(s32 entrynum, char* path, u32 maxlen);
int DVDFastOpen(s32 entrynum, DVDFileInfo* fileInfo);
int DVDOpen(const char* fileName, DVDFileInfo* fileInfo);
int DVDClose(DVDFileInfo* fileInfo);
int DVDRemove(const char* fileName, DVDFileInfo* fileInfo);
int DVDCreate(const char* fileName, DVDFileInfo* fileInfo);
int DVDGetCurrentDir(char* path, u32 maxlen);
int DVDChangeDir(const char* dirName);
int DVDWriteAsyncPrio(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset, DVDCallback callback, s32 prio);
s32 DVDWritePrio(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset, s32 prio);
int DVDReadAsyncPrio(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset, DVDCallback callback, s32 prio);
s32 DVDReadPrio(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset, s32 prio);
int DVDSeekAsyncPrio(DVDFileInfo* fileInfo, s32 offset, DVDCallback callback, s32 prio);
s32 DVDSeekPrio(DVDFileInfo* fileInfo, s32 offset, s32 prio);
s32 DVDGetFileInfoStatus(const DVDFileInfo* fileInfo);
int DVDFastOpenDir(s32 entrynum, DVDDir* dir);
int DVDOpenDir(const char* dirName, DVDDir* dir);
int DVDReadDir(DVDDir* dir, DVDDirEntry* dirent);
int DVDCloseDir(DVDDir* dir);
void DVDRewindDir(DVDDir* dir);
void* DVDGetFSTLocation(void);
int DVDPrepareStreamAsync(DVDFileInfo* fileInfo, u32 length, u32 offset, DVDCallback callback);
s32 DVDPrepareStream(DVDFileInfo* fileInfo, u32 length, u32 offset);
s32 DVDGetTransferredSize(DVDFileInfo* fileinfo);

// dvdetherror.c
void __DVDStoreErrorCode(u32 error);

// dvdethFatal.c
int DVDSetAutoFatalMessaging(int enable);
void __DVDPrintFatalMessage(void);

// dvdethidutils.c
int DVDCompareDiskID(const DVDDiskID* id1, const DVDDiskID* id2);
DVDDiskID* DVDGenerateDiskID(DVDDiskID* id, const char* game, const char* company, u8 diskNum, u8 version);

// dvdethqueue.c
void __DVDClearWaitingQueue(void);
int __DVDPushWaitingQueue(s32 prio, DVDCommandBlock* block);
DVDCommandBlock* __DVDPopWaitingQueue(void);
int __DVDCheckWaitingQueue(void);
int __DVDDequeueWaitingQueue(DVDCommandBlock* block);
int __DVDIsBlockInWaitingQueue(DVDCommandBlock* block);
void DVDDumpWaitingQueue(void);

// dvdethlow.c
extern int bNetConfigured;

u32 ErrorMsg(s32 error_no);
int DVDLowNetRead(void* addr, u32 length, u32 offset, DVDLowCallback callback, u32 startAddr);
int DVDLowWrite(void* addr, u32 length, u32 offset, DVDLowCallback callback, u32 startAddr);
int DVDLowCommand(void* pRecv, u32 command, u32 recvlen, u32 offset, DVDLowCallback callback, const char* pFileName);
int DVDLowCancel(DVDLowCallback callback);
int DVDLowInit(const u8* pServerAddr, u16 ServerPort);
int DVDEthInit(const u8* addr, const u8* netmask, const u8* gateway);
void DVDEthShutdown(void);

#ifdef __cplusplus
}
#endif

#endif // _DOLPHIN_DVDETH_H_
