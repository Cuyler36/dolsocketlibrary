#include <dolphin/dvdeth.h>
#include <dolphin/hw_regs.h>

#ifdef DEBUG
const char* __DVDETHVersion = "<< Dolphin SDK - DVDETH\tdebug build: Mar 12 2004 16:48:08 (0x2301) >>"; // size: 0x4, address: 0x0
#else
const char* __DVDETHVersion = "<< Dolphin SDK - DVDETH\trelease build: Mar 12 2004 17:06:41 (0x2301) >>"; // size: 0x4, address: 0x0
#endif

static DVDCommandBlock* executing; // size: 0x4, address: 0x0
static DVDDiskID* IDShouldBe; // size: 0x4, address: 0x4
static OSBootInfo* bootInfo; // size: 0x4, address: 0x8
static BOOL autoInvalidation = TRUE; // size: 0x4, address: 0x4
static volatile BOOL PauseFlag; // size: 0x4, address: 0xC
static volatile BOOL PausingFlag; // size: 0x4, address: 0x10
static volatile BOOL AutoFinishing; // size: 0x4, address: 0x14
static volatile BOOL FatalErrorFlag; // size: 0x4, address: 0x18
static volatile u32 CurrCommand; // size: 0x4, address: 0x1C
static volatile u32 Canceling; // size: 0x4, address: 0x20
static DVDCBCallback CancelCallback; // size: 0x4, address: 0x24
static volatile u32 ResumeFromHere; // size: 0x4, address: 0x28
static volatile BOOL CancelAllSyncComplete; // size: 0x4, address: 0x2C
static BOOL FirstTimeInBootrom; // size: 0x4, address: 0x30
static DVDCommandBlock DummyCommandBlock; // size: 0x30, address: 0x0
static BOOL DVDInitialized; // size: 0x4, address: 0x34
OSThreadQueue __DVDThreadQueue; // size: 0x8, address: 0x0

static void stateReady(void);
static void stateBusy(DVDCommandBlock* block);
static void cbForStateBusy(u32 intType);
static void cbForCancelStreamSync(s32 result, DVDCommandBlock* block);
static void cbForStopStreamAtEndSync(s32 result, DVDCommandBlock* block);
static void cbForGetStreamErrorStatusSync(s32 result, DVDCommandBlock* block);
static void cbForGetStreamPlayAddrSync(s32 result, DVDCommandBlock* block);
static void cbForChangeDiskSync();
static void cbForCancelSync();
static void cbForCancelAllSync();

// Range: 0x0 -> 0xC0
void DVDInit(void) {
    // References
    // -> static int FirstTimeInBootrom;
    // -> static struct OSBootInfo_s * bootInfo;
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static struct DVDDiskID * IDShouldBe;
    // -> static int DVDInitialized;
    // -> const char * __DVDETHVersion;
    if (DVDInitialized) {
        return;
    }

    OSRegisterVersion(__DVDETHVersion);
    DVDInitialized = TRUE;
    __DVDFSInit();
    __DVDClearWaitingQueue();
    __DVDInitWA();
    bootInfo = (OSBootInfo*)OSPhysicalToCached(0);
    IDShouldBe = &bootInfo->DVDDiskID;
    __OSSetInterruptHandler(__OS_INTERRUPT_PI_DI, __DVDInterruptHandler);
    __OSUnmaskInterrupts(OS_INTERRUPTMASK_PI_DI);
    OSInitThreadQueue(&__DVDThreadQueue);
    __DIRegs[0] = 0x2A;
    __DIRegs[1] = 0;

    if (bootInfo->magic != 0xE5207C22 && bootInfo->magic != 0x0D15EA5E) {
        FirstTimeInBootrom = TRUE;
    }
}

// Range: 0xC0 -> 0x16C
static BOOL CheckCancel(u32 resume /* r1+0x8 */) {
    // Local variables
    DVDCommandBlock* finished; // r31

    // References
    // -> static void (* CancelCallback)(long, struct DVDCommandBlock *);
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static struct DVDCommandBlock * executing;
    // -> static unsigned long Canceling;
    // -> static unsigned long ResumeFromHere;
    if (Canceling) {
        ResumeFromHere = resume;
        Canceling = FALSE;
        finished = executing;
        executing = &DummyCommandBlock;
        finished->state = DVD_STATE_CANCELED;
        if (finished->callback) {
            (*finished->callback)(-3, finished);
        }

        if (CancelCallback) {
            (*CancelCallback)(0, finished);
        }

        stateReady();
        return TRUE;
    }

    return FALSE;
}

// Range: 0x16C -> 0x2E0
static void stateReady(void) {
    // Local variables
    DVDCommandBlock* finished; // r31

    // References
    // -> static struct DVDCommandBlock * executing;
    // -> static unsigned long ResumeFromHere;
    // -> static unsigned long CurrCommand;
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static int FatalErrorFlag;
    // -> static int PausingFlag;
    // -> static int PauseFlag;
    if (!__DVDCheckWaitingQueue()) {
        executing = NULL;
        return;
    }

    if (PauseFlag) {
        PausingFlag = TRUE;
        executing = NULL;
        return;
    }

    executing = __DVDPopWaitingQueue();

    if (FatalErrorFlag) {
        executing->state = DVD_STATE_FATAL_ERROR;
        finished = executing;
        executing = &DummyCommandBlock;
        if (finished->callback) {
            (*finished->callback)(-1, finished);
        }

        stateReady();
        return;
    }

    CurrCommand = executing->command;

    if (ResumeFromHere) {
        switch (ResumeFromHere) {
            case 2:
                executing->state = DVD_STATE_RETRY;
                break;
            case 3:
                executing->state = DVD_STATE_NO_DISK;
                break;
            case 4:
                executing->state = DVD_STATE_COVER_OPEN;
                break;
            case 1:
            case 6:
            case 7:
                executing->state = DVD_STATE_COVER_CLOSED;
                break;
            case 5:
                executing->state = DVD_STATE_FATAL_ERROR;
                break;
        }

        ResumeFromHere = 0;
    } else {
        executing->state = DVD_STATE_BUSY;
        stateBusy(executing);
    }
}

// Range: 0x2E0 -> 0x458
static void stateBusy(DVDCommandBlock* block /* r31 */) {
    // Local variables
    DVDCommandBlock* finished; // r30
    DVDFileInfo* fileInfo; // r29
    u32 currTransferSize; // r28

    // References
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static struct DVDCommandBlock * executing;
    if (block->command == 1) {
        if (block->length == 0) {
            finished = executing;
            executing = &DummyCommandBlock;
            finished->state = DVD_STATE_END;
            if (finished->callback) {
                (*finished->callback)(0, finished);
            }

            stateReady();
        } else {
            currTransferSize = block->length - block->transferredSize;
            fileInfo = (DVDFileInfo*)block;
            DVDLowNetRead((u8*)block->addr + block->transferredSize, currTransferSize, block->offset + block->transferredSize, cbForStateBusy, fileInfo->startAddr);
        }
    } else if (block->command == 0x21) {
        if (block->length == 0) {
            finished = executing;
            executing = &DummyCommandBlock;
            finished->state = DVD_STATE_END;
            if (finished->callback) {
                (*finished->callback)(0, finished);
            }

            stateReady();
        } else {
            currTransferSize = block->length - block->transferredSize;
            fileInfo = (DVDFileInfo*)block;
            DVDLowWrite((u8*)block->addr + block->transferredSize, currTransferSize, block->offset + block->transferredSize, cbForStateBusy, fileInfo->startAddr);
        }
    } else {
        DVDLowCommand(block->addr, block->command, block->length, block->offset, cbForStateBusy, (const char*)block->currTransferSize);
    }
}

// Range: 0x458 -> 0x61C
static void cbForStateBusy(u32 intType /* r1+0x8 */) {
    // Local variables
    DVDCommandBlock* finished; // r31
    s32 result; // r29

    // References
    // -> static void (* CancelCallback)(long, struct DVDCommandBlock *);
    // -> static unsigned long Canceling;
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static struct DVDCommandBlock * executing;
    // -> static int FatalErrorFlag;
    // -> static unsigned long CurrCommand;
    result = (s32)intType;
    if (result >= 0) {
        executing->transferredSize += result;
        if (CurrCommand == 1 && result != 0) {
            if (Canceling) {
                DVDLowCancel(cbForStateBusy);
                return;
            }

            stateBusy(executing);
            return;
        }

        if (CheckCancel(0)) {
            return;
        }

        finished = executing;
        executing = &DummyCommandBlock;
        finished->state = DVD_STATE_END;
        if (result == 0 && CurrCommand != 1) {
            finished->transferredSize = 0;
        }

        if (finished->callback) {
            (*finished->callback)((s32)finished->transferredSize, finished);
        }

        stateReady();
    } else if (executing->transferredSize == executing->length) {
        if (CheckCancel(0)) {
            return;
        }

        finished = executing;
        executing = &DummyCommandBlock;
        finished->state = DVD_STATE_END;
        if (finished->callback) {
            (*finished->callback)((s32)finished->transferredSize, finished);
        }

        stateReady();
    } else {
        executing->state = DVD_STATE_FATAL_ERROR;
        __DVDPrintFatalMessage();
        FatalErrorFlag = TRUE;
        finished = executing;
        executing = &DummyCommandBlock;
        if (finished->callback) {
            (*finished->callback)(-1, finished);
        }

        if (Canceling) {
            Canceling = FALSE;
            if (CancelCallback) {
                (*CancelCallback)(0, finished);
            }
        }

        stateReady();
    }
}

// Range: 0x61C -> 0x694
static BOOL issueCommand(s32 prio /* r1+0x8 */, DVDCommandBlock* block /* r29 */) {
    // Local variables
    BOOL level; // r31
    BOOL result; // r30

    // References
    // -> static int PauseFlag;
    // -> static struct DVDCommandBlock * executing;
    level = OSDisableInterrupts();
    block->state = DVD_STATE_WAITING;
    result = __DVDPushWaitingQueue(prio, block);
    if (executing == NULL && PauseFlag == FALSE) {
        stateReady();
    }

    OSRestoreInterrupts(level);
    return result;
}

// Range: 0x694 -> 0x78C
BOOL DVDRemoveAsyncPrio(DVDCommandBlock* block /* r30 */, void* addr /* r27 */, u32 length /* r28 */, DVDCBCallback callback /* r1+0x14 */, const char* fileName /* r1+0x18 */, s32 prio /* r1+0x1C */) {
    // Local variables
    BOOL idle; // r29

    ASSERTMSGLINE(690, block, "DVDRemoveAsyncPrio(): null pointer is specified to command block address.");
    ASSERTMSGLINE(691, addr, "DVDRemoveAsyncPrio(): null pointer is specified to recieve address.");
    ASSERTMSGLINE(692, length, "DVDRemoveAsyncPrio(): null is specified to length.");

    block->command = 0x23;
    block->addr = addr;
    block->length = length;
    block->offset = 0;
    block->transferredSize = 0;
    block->callback = callback;
    block->currTransferSize = (u32)fileName;

    idle = issueCommand(prio, block);
    ASSERTMSGLINE(704, idle, "DVDRemoveAsyncPrio(): command block is used for processing previous request.");
    return idle;
}

// Range: 0x78C -> 0x89C
BOOL DVDCreateAsyncPrio(DVDCommandBlock* block /* r30 */, void* addr /* r26 */, u32 length /* r27 */, DVDCBCallback callback /* r1+0x14 */, const char* fileName /* r28 */, s32 prio /* r1+0x1C */) {
    // Local variables
    BOOL idle; // r29

    ASSERTMSGLINE(726, block, "DVDCreateAsyncPrio(): null pointer is specified to command block address.");
    ASSERTMSGLINE(727, addr, "DVDCreateAsyncPrio(): null pointer is specified to recieve address.");
    ASSERTMSGLINE(728, length, "DVDCreateAsyncPrio(): null is specified to length.");
    ASSERTMSGLINE(729, fileName, "DVDCreateAsyncPrio(): null pointer is specified to file name.");

    block->command = 0x22;
    block->addr = addr;
    block->length = length;
    block->offset = 0;
    block->transferredSize = 0;
    block->callback = callback;
    block->currTransferSize = (u32)fileName;

    idle = issueCommand(prio, block);
    ASSERTMSGLINE(741, idle, "DVDCreateAsyncPrio(): command block is used for processing previous request.");
    return idle;
}

// Range: 0x89C -> 0x9A4
BOOL DVDWriteAbsAsyncPrio(DVDCommandBlock* block /* r30 */, void* addr /* r26 */, s32 length /* r27 */, s32 offset /* r28 */, DVDCBCallback callback /* r1+0x18 */, s32 prio /* r1+0x1C */) {
    // Local variables
    BOOL idle; // r29

    ASSERTMSGLINE(767, block, "DVDWriteAbsAsync(): null pointer is specified to command block address.");
    ASSERTMSGLINE(768, addr, "DVDWriteAbsAsync(): null pointer is specified to addr.");
    ASSERTMSGLINE(771, length >= 0, "DVD write: negative value was specified to length of the write\n");
    ASSERTMSGLINE(773, offset >= 0, "DVD write: negative value was specified to offset of the write\n");

    block->command = 0x21;
    block->addr = addr;
    block->length = length;
    block->offset = offset;
    block->transferredSize = 0;
    block->callback = callback;

    idle = issueCommand(prio, block);
    ASSERTMSGLINE(783, idle, "DVDWriteAbsAsync(): command block is used for processing previous request.");
    return idle;
}

// Range: 0x9A4 -> 0xAE4
BOOL DVDNetReadAbsAsyncPrio(DVDCommandBlock* block /* r30 */, void* addr /* r27 */, s32 length /* r28 */, s32 offset /* r26 */, DVDCBCallback callback /* r1+0x18 */, s32 prio /* r1+0x1C */) {
    // Local variables
    BOOL idle; // r29

    ASSERTMSGLINE(809, block, "DVDReadAbsAsync(): null pointer is specified to command block address.");
    ASSERTMSGLINE(810, addr, "DVDReadAbsAsync(): null pointer is specified to addr.");
    ASSERTMSGLINE(812, !((u32)addr & 31), "DVDReadAbsAsync(): address must be aligned with 32 byte boundary.");
    ASSERTMSGLINE(814, !(length & 31), "DVDReadAbsAsync(): length must be a multiple of 32.");
    ASSERTMSGLINE(816, !(offset & 3), "DVDReadAbsAsync(): offset must be a multiple of 4.");
    ASSERTMSGLINE(818, length >= 0, "DVD read: negative value was specified to length of the read\n");

    block->command = 1;
    block->addr = addr;
    block->length = length;
    block->offset = offset;
    block->transferredSize = 0;
    block->callback = callback;

    idle = issueCommand(prio, block);
    ASSERTMSGLINE(828, idle, "DVDReadAbsAsync(): command block is used for processing previous request.");
    return idle;
}

// Range: 0xAE4 -> 0xB8C
BOOL DVDNetReadFstEntryAsyncPrio(DVDCommandBlock* block /* r31 */, void* addr /* r1+0xC */, u32 length /* r1+0x10 */, DVDCBCallback callback /* r1+0x14 */, s32 prio /* r1+0x18 */) {
    // Local variables
    BOOL idle; // r30

    block->command = 0x24;
    block->addr = addr;
    block->length = length;
    block->offset = 0;
    block->transferredSize = 0;
    block->currTransferSize = 0;
    block->callback = callback;

    idle = issueCommand(prio, block);
    ASSERTMSGLINE(860, idle, "DVDReadAbsAsync(): command block is used for processing previous request.");
    return idle;
}

// Range: 0xB8C -> 0xC34
BOOL DVDNetReadFstStringAsyncPrio(DVDCommandBlock* block /* r31 */, void* addr /* r1+0xC */, u32 length /* r1+0x10 */, DVDCBCallback callback /* r1+0x14 */, s32 prio /* r1+0x18 */) {
    // Local variables
    BOOL idle; // r30

    block->command = 0x25;
    block->addr = addr;
    block->length = length;
    block->offset = 0;
    block->transferredSize = 0;
    block->currTransferSize = 0;
    block->callback = callback;

    idle = issueCommand(prio, block);
    ASSERTMSGLINE(893, idle, "DVDReadAbsAsync(): command block is used for processing previous request.");
    return idle;
}

// Range: 0xC34 -> 0xCF4
BOOL DVDSeekAbsAsyncPrio(DVDCommandBlock* block /* r31 */, s32 offset /* r28 */, DVDCBCallback callback /* r1+0x10 */, s32 prio) {
    // Local variables
    BOOL enabled; // r29

    ASSERTMSGLINE(918, block, "DVDSeekAbs(): null pointer is specified to command block address.");
    ASSERTMSGLINE(920, !(offset & 3), "DVDSeekAbs(): offset must be a multiple of 4.");

    block->command = 2;
    block->offset = offset;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0xCF4 -> 0xD84
BOOL DVDPrepareStreamAbsAsync(DVDCommandBlock* block /* r31 */, u32 length /* r1+0xC */, u32 offset /* r1+0x10 */, DVDCBCallback callback /* r1+0x14 */) {
    // Local variables
    BOOL enabled; // r30

    block->command = 6;
    block->length = length;
    block->offset = offset;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0xD84 -> 0xDFC
BOOL DVDCancelStreamAsync(DVDCommandBlock* block /* r31 */, DVDCBCallback callback /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30

    block->command = 7;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0xDFC -> 0xE94
s32 DVDCancelStream(DVDCommandBlock* block /* r30 */) {
    // Local variables
    BOOL result; // r28
    s32 state; // r31
    BOOL enabled; // r27
    s32 retVal; // r29

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDCancelStreamAsync(block, cbForCancelStreamSync);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END || state == DVD_STATE_CANCELED) {
            retVal = (s32)block->transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = (s32)block->transferredSize;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0xE94 -> 0xECC
static void cbForCancelStreamSync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r1+0xC */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    block->transferredSize = (u32)result;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0xECC -> 0xF44
BOOL DVDStopStreamAtEndAsync(DVDCommandBlock* block /* r31 */, DVDCBCallback callback /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30

    block->command = 8;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0xF44 -> 0xFDC
s32 DVDStopStreamAtEnd(DVDCommandBlock* block /* r30 */) {
    // Local variables
    BOOL result; // r28
    s32 state; // r31
    BOOL enabled; // r27
    s32 retVal; // r29

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDStopStreamAtEndAsync(block, cbForStopStreamAtEndSync);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END || state == DVD_STATE_CANCELED) {
            retVal = (s32)block->transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = (s32)block->transferredSize;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0xFDC -> 0x1014
static void cbForStopStreamAtEndSync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r1+0xC */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    block->transferredSize = (u32)result;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x1014 -> 0x108C
BOOL DVDGetStreamErrorStatusAsync(DVDCommandBlock* block /* r31 */, DVDCBCallback callback /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30

    block->command = 9;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0x108C -> 0x1124
s32 DVDGetStreamErrorStatus(DVDCommandBlock* block /* r30 */) {
    // Local variables
    BOOL result; // r28
    s32 state; // r31
    BOOL enabled; // r27
    s32 retVal; // r29

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDGetStreamErrorStatusAsync(block, cbForGetStreamErrorStatusSync);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END || state == DVD_STATE_CANCELED) {
            retVal = (s32)block->transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = (s32)block->transferredSize;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x1124 -> 0x115C
static void cbForGetStreamErrorStatusSync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r1+0xC */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    block->transferredSize = (u32)result;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x115C -> 0x11D4
BOOL DVDGetStreamPlayAddrAsync(DVDCommandBlock* block /* r31 */, DVDCBCallback callback /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30

    block->command = 10;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0x11D4 -> 0x126C
s32 DVDGetStreamPlayAddr(DVDCommandBlock* block /* r30 */) {
    // Local variables
    BOOL result; // r28
    s32 state; // r31
    BOOL enabled; // r27
    s32 retVal; // r29

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDGetStreamPlayAddrAsync(block, cbForGetStreamPlayAddrSync);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END || state == DVD_STATE_CANCELED) {
            retVal = (s32)block->transferredSize;
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            retVal = (s32)block->transferredSize;
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x126C -> 0x12A4
static void cbForGetStreamPlayAddrSync(s32 result /* r1+0x8 */, DVDCommandBlock* block /* r1+0xC */) {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    block->transferredSize = (u32)result;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x12A4 -> 0x1390
BOOL DVDChangeDiskAsync(DVDCommandBlock* block /* r31 */, DVDDiskID* id /* r29 */, DVDCBCallback callback /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r28

    ASSERTMSGLINE(1353, block, "DVDChangeDisk(): null pointer is specified to command block address.");
    ASSERTMSGLINE(1354, id, "DVDChangeDisk(): null pointer is specified to id address.");

    if (id->company[0] == '\0') {
        OSReport("DVDChangeDiskAsync(): You can't specify NULL to company name.  \n");
        OSPanic(__FILE__, 1359, "");
    }

    block->command = 3;
    block->id = id;
    block->callback = callback;
    block->state = DVD_STATE_END;
    if (block->callback) {
        enabled = OSDisableInterrupts();
        (*block->callback)(0, block);
        OSRestoreInterrupts(enabled);
    }

    return TRUE;
}

// Range: 0x1390 -> 0x1438
s32 DVDChangeDisk(DVDCommandBlock* block /* r27 */, DVDDiskID* id /* r1+0xC */) {
    // Local variables
    BOOL result; // r29
    s32 state; // r31
    BOOL enabled; // r28
    s32 retVal; // r30

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDChangeDiskAsync(block, id, cbForChangeDiskSync);
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

// Range: 0x1438 -> 0x145C
static void cbForChangeDiskSync() {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x145C -> 0x14D4
s32 DVDGetCommandBlockStatus(const DVDCommandBlock* block /* r30 */) {
    // Local variables
    BOOL enabled; // r29
    s32 retVal; // r31

    ASSERTMSGLINE(1451, block, "DVDGetCommandBlockStatus(): null pointer is specified to command block address.");

    enabled = OSDisableInterrupts();
    if (block->state == DVD_STATE_COVER_CLOSED) {
        retVal = DVD_STATE_BUSY;
    } else {
        retVal = block->state;
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x14D4 -> 0x1574
s32 DVDGetDriveStatus(void) {
    // Local variables
    BOOL enabled; // r30
    s32 retVal; // r31

    // References
    // -> static struct DVDCommandBlock * executing;
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static int PausingFlag;
    // -> static int FatalErrorFlag;
    enabled = OSDisableInterrupts();

    if (FatalErrorFlag) {
        retVal = DVD_STATE_FATAL_ERROR;
    } else if (PausingFlag) {
        retVal = DVD_STATE_PAUSING;
    } else if (executing == NULL) {
        retVal = DVD_STATE_END;
    } else if (executing == &DummyCommandBlock) {
        retVal = DVD_STATE_END;
    } else {
        retVal = DVDGetCommandBlockStatus(executing);
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x1574 -> 0x1594
BOOL DVDSetAutoInvalidation(BOOL autoInval /* r3 */) {
    // Local variables
    BOOL prev; // r31

    // References
    // -> static int autoInvalidation;
    prev = autoInvalidation;
    autoInvalidation = autoInval;
    return prev;
}

// Range: 0x1594 -> 0x15E8
void DVDPause(void) {
    // Local variables
    BOOL level; // r31

    // References
    // -> static int PausingFlag;
    // -> static struct DVDCommandBlock * executing;
    // -> static int PauseFlag;
    level = OSDisableInterrupts();
    PauseFlag = TRUE;
    if (executing == NULL) {
        PausingFlag = TRUE;
    }

    OSRestoreInterrupts(level);
}

// Range: 0x15E8 -> 0x163C
void DVDResume(void) {
    // Local variables
    BOOL level; // r31

    // References
    // -> static int PausingFlag;
    // -> static int PauseFlag;
    level = OSDisableInterrupts();
    PauseFlag = FALSE;
    if (PausingFlag) {
        PausingFlag = FALSE;
        stateReady();
    }

    OSRestoreInterrupts(level);
}

// Range: 0x163C -> 0x187C
BOOL DVDCancelAsync(DVDCommandBlock* block /* r31 */, DVDCBCallback callback /* r30 */) {
    // Local variables
    BOOL enabled; // r29
    DVDCommandBlock* finished; // r1+0x10

    // References
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static struct DVDCommandBlock * executing;
    // -> static unsigned long ResumeFromHere;
    // -> static void (* CancelCallback)(long, struct DVDCommandBlock *);
    // -> static unsigned long Canceling;
    enabled = OSDisableInterrupts();

    switch (block->state) {
        case DVD_STATE_FATAL_ERROR:
        case DVD_STATE_END:
        case DVD_STATE_CANCELED:
            if (callback) {
                (*callback)(0, block);
            }
            break;
        case DVD_STATE_BUSY:
            if (Canceling) {
                OSRestoreInterrupts(enabled);
                return FALSE;
            }

            Canceling = TRUE;
            CancelCallback = callback;
            break;
        case DVD_STATE_WAITING:
            __DVDDequeueWaitingQueue(block);
            block->state = DVD_STATE_CANCELED;
            if (block->callback) {
                (*block->callback)(-3, block);
            }

            if (callback) {
                (*callback)(0, block);
            }
            break;
        case DVD_STATE_COVER_CLOSED:
            switch (block->command) {
                case 5:
                case 4:
                case 13:
                case 15:
                    if (callback) {
                        (*callback)(0, block);
                    }
                    break;
                default:
                    if (Canceling) {
                        OSRestoreInterrupts(enabled);
                        return FALSE;
                    }

                    Canceling = TRUE;
                    CancelCallback = callback;
                    break;
            }
            break;
        case DVD_STATE_NO_DISK:
        case DVD_STATE_COVER_OPEN:
        case DVD_STATE_WRONG_DISK:
        case DVD_STATE_MOTOR_STOPPED:
        case DVD_STATE_RETRY:
            if (block->state == DVD_STATE_NO_DISK) {
                ResumeFromHere = 3;
            }

            if (block->state == DVD_STATE_COVER_OPEN) {
                ResumeFromHere = 4;
            }

            if (block->state == DVD_STATE_WRONG_DISK) {
                ResumeFromHere = 1;
            }

            if (block->state == DVD_STATE_RETRY) {
                ResumeFromHere = 2;
            }

            if (block->state == DVD_STATE_MOTOR_STOPPED) {
                ResumeFromHere = 7;
            }

            finished = executing;
            executing = &DummyCommandBlock;
            block->state = DVD_STATE_CANCELED;
            if (block->callback) {
                (*block->callback)(-3, block);
            }

            if (callback) {
                (*callback)(0, block);
            }

            stateReady();
            break;
    }

    OSRestoreInterrupts(enabled);
    return TRUE;
}

// Range: 0x187C -> 0x1930
s32 DVDCancel(volatile DVDCommandBlock* block /* r29 */) {
    // Local variables
    BOOL result; // r28
    s32 state; // r31
    u32 command; // r30
    BOOL enabled; // r27

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    result = DVDCancelAsync((DVDCommandBlock*)block, cbForCancelSync);
    if (result == FALSE) {
        return -1;
    }

    enabled = OSDisableInterrupts();
    while (TRUE) {
        state = ((volatile DVDCommandBlock*)block)->state;
        if (state == DVD_STATE_END || state == DVD_STATE_CANCELED) {
            break;
        }

        if (state == DVD_STATE_FATAL_ERROR) {
            break;
        }

        if (state == DVD_STATE_COVER_CLOSED) {
            command = ((volatile DVDCommandBlock*)block)->command;
            if (command == 4 || command == 5 || command == 13 || command == 15) {
                break;
            }
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return 0;
}

// Range: 0x1930 -> 0x1954
static void cbForCancelSync() {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x1954 -> 0x19F4
BOOL DVDCancelAllAsync(DVDCBCallback callback /* r30 */) {
    // Local variables
    BOOL enabled; // r29
    DVDCommandBlock* p; // r28
    BOOL retVal; // r31

    // References
    // -> static struct DVDCommandBlock * executing;
    enabled = OSDisableInterrupts();
    DVDPause();

    while ((p = __DVDPopWaitingQueue()) != 0) {
        DVDCancelAsync(p, NULL);
    }

    if (executing) {
        retVal = DVDCancelAsync(executing, callback);
    } else {
        retVal = TRUE;
        if (callback) {
            (*callback)(0, NULL);
        }
    }

    DVDResume();
    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x19F4 -> 0x1A74
s32 DVDCancelAll(void) {
    // Local variables
    BOOL result; // r30
    BOOL enabled; // r31

    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static int CancelAllSyncComplete;
    enabled = OSDisableInterrupts();
    CancelAllSyncComplete = FALSE;

    result = DVDCancelAllAsync(cbForCancelAllSync);
    if (result == FALSE) {
        OSRestoreInterrupts(enabled);
        return -1;
    }

    while (TRUE) {
        if (CancelAllSyncComplete) {
            break;
        }

        OSSleepThread(&__DVDThreadQueue);
    }

    OSRestoreInterrupts(enabled);
    return 0;
}

// Range: 0x1A74 -> 0x1AA0
static void cbForCancelAllSync() {
    // References
    // -> struct OSThreadQueue __DVDThreadQueue;
    // -> static int CancelAllSyncComplete;
    CancelAllSyncComplete = TRUE;
    OSWakeupThread(&__DVDThreadQueue);
}

// Range: 0x1AA0 -> 0x1AC4
DVDDiskID* DVDGetCurrentDiskID(void) {
    return (DVDDiskID*)OSPhysicalToCached(0);
}

// Range: 0x1AC4 -> 0x1BAC
BOOL DVDCheckDisk(void) {
    // Local variables
    BOOL enabled; // r29
    s32 retVal; // r30
    s32 state; // r31

    // References
    // -> static unsigned long ResumeFromHere;
    // -> static struct DVDCommandBlock * executing;
    // -> static struct DVDCommandBlock DummyCommandBlock;
    // -> static int PausingFlag;
    // -> static int FatalErrorFlag;
    enabled = OSDisableInterrupts();

    if (FatalErrorFlag) {
        state = DVD_STATE_FATAL_ERROR;
    } else if (PausingFlag) {
        state = DVD_STATE_PAUSING;
    } else if (executing == NULL) {
        state = DVD_STATE_END;
    } else if (executing == &DummyCommandBlock) {
        state = DVD_STATE_END;
    } else {
        state = executing->state;
    }

    switch (state) {
        case DVD_STATE_BUSY:
        case DVD_STATE_IGNORED:
        case DVD_STATE_CANCELED:
        case DVD_STATE_WAITING:
            retVal = TRUE;
            break;
        case DVD_STATE_FATAL_ERROR:
        case DVD_STATE_RETRY:
        case DVD_STATE_MOTOR_STOPPED:
        case DVD_STATE_COVER_CLOSED:
        case DVD_STATE_NO_DISK:
        case DVD_STATE_COVER_OPEN:
        case DVD_STATE_WRONG_DISK:
            retVal = FALSE;
            break;
        case DVD_STATE_END:
        case DVD_STATE_PAUSING:
            if (ResumeFromHere) {
                retVal = FALSE;
            } else {
                retVal = TRUE;
            }
            break;
    }

    OSRestoreInterrupts(enabled);
    return retVal;
}

// Range: 0x1BAC -> 0x1C1C
void __DVDPrepareResetAsync(DVDCBCallback callback /* r30 */) {
    // Local variables
    BOOL enabled; // r31

    // References
    // -> static struct DVDCommandBlock * executing;
    // -> static void (* CancelCallback)(long, struct DVDCommandBlock *);
    // -> static unsigned long Canceling;
    enabled = OSDisableInterrupts();
    __DVDClearWaitingQueue();

    if (Canceling) {
        CancelCallback = callback;
    } else {
        if (executing) {
            executing->callback = NULL;
        }

        DVDCancelAllAsync(callback);
    }

    OSRestoreInterrupts(enabled);
}
