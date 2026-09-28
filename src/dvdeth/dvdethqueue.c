#include <dolphin/os.h>
#include <dolphin/dvdeth.h>

#ifdef NULL
#undef NULL
#endif
#define NULL ((void*)0)

static struct {
    DVDCommandBlock* next; // offset 0x0, size 0x4
    DVDCommandBlock* prev; // offset 0x4, size 0x4
} WaitingQueue[4]; // size: 0x20, address: 0x0

// Range: 0x0 -> 0x40
void __DVDClearWaitingQueue(void) {
    // Local variables
    u32 i; // r30
    DVDCommandBlock* q; // r31

    // References
    // -> static struct [anonymous] WaitingQueue[4];

    for (i = 0; i < 4; i++) {
        q = (DVDCommandBlock*)&WaitingQueue[i];
        q->next = q;
        q->prev = q;
    }
}

// Range: 0x40 -> 0xAC
int __DVDPushWaitingQueue(s32 prio /* r1+0x8 */, DVDCommandBlock* block /* r30 */) {
    // Local variables
    BOOL enabled; // r29
    DVDCommandBlock* q; // r31

    // References
    // -> static struct [anonymous] WaitingQueue[4];

    enabled = OSDisableInterrupts();
    q = (DVDCommandBlock*)&WaitingQueue[prio];
    q->prev->next = block;
    block->prev = q->prev;
    block->next = q;
    q->prev = block;
    OSRestoreInterrupts(enabled);
    return TRUE;
}

// Range: 0xAC -> 0x148
static DVDCommandBlock* PopWaitingQueuePrio(s32 prio /* r1+0x8 */) {
    // Local variables
    DVDCommandBlock* tmp; // r31
    BOOL enabled; // r29
    DVDCommandBlock* q; // r30

    // References
    // -> static struct [anonymous] WaitingQueue[4];

    enabled = OSDisableInterrupts();
    q = (DVDCommandBlock*)&WaitingQueue[prio];
    ASSERTLINE(82, q->next != q);
    tmp = q->next;
    q->next = tmp->next;
    tmp->next->prev = q;
    OSRestoreInterrupts(enabled);
    tmp->next = NULL;
    tmp->prev = NULL;
    return tmp;
}

// Range: 0x148 -> 0x1C4
DVDCommandBlock* __DVDPopWaitingQueue(void) {
    // Local variables
    u32 i; // r31
    BOOL enabled; // r30
    DVDCommandBlock* q; // r29

    // References
    // -> static struct [anonymous] WaitingQueue[4];

    enabled = OSDisableInterrupts();
    for (i = 0; i < 4; i++) {
        q = (DVDCommandBlock*)&WaitingQueue[i];
        if (q->next != q) {
            OSRestoreInterrupts(enabled);
            return PopWaitingQueuePrio(i);
        }
    }
    OSRestoreInterrupts(enabled);
    return NULL;
}

// Range: 0x1C4 -> 0x23C
int __DVDCheckWaitingQueue(void) {
    // Local variables
    u32 i; // r31
    BOOL enabled; // r30
    DVDCommandBlock* q; // r29

    // References
    // -> static struct [anonymous] WaitingQueue[4];

    enabled = OSDisableInterrupts();
    for (i = 0; i < 4; i++) {
        q = (DVDCommandBlock*)&WaitingQueue[i];
        if (q->next != q) {
            OSRestoreInterrupts(enabled);
            return TRUE;
        }
    }
    OSRestoreInterrupts(enabled);
    return FALSE;
}

// Range: 0x23C -> 0x2B0
int __DVDDequeueWaitingQueue(DVDCommandBlock* block /* r28 */) {
    // Local variables
    BOOL enabled; // r29
    DVDCommandBlock* prev; // r31
    DVDCommandBlock* next; // r30

    enabled = OSDisableInterrupts();
    prev = block->prev;
    next = block->next;
    if (prev == NULL || next == NULL) {
        OSRestoreInterrupts(enabled);
        return FALSE;
    }
    prev->next = next;
    next->prev = prev;
    OSRestoreInterrupts(enabled);
    return TRUE;
}

// Range: 0x2B0 -> 0x31C
int __DVDIsBlockInWaitingQueue(DVDCommandBlock* block /* r3 */) {
    // Local variables
    u32 i; // r29
    DVDCommandBlock* start; // r31
    DVDCommandBlock* q; // r30

    // References
    // -> static struct [anonymous] WaitingQueue[4];

    for (i = 0; i < 4; i++) {
        start = (DVDCommandBlock*)&WaitingQueue[i];
        if (start->next != start) {
            for (q = start->next; q != start; q = q->next) {
                if (q == block) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static char* CommandNames[43] = { // size: 0xAC, address: 0x100
    "",
    "READ",
    "SEEK",
    "CHANGE_DISK",
    "BSREAD",
    "READID",
    "INITSTREAM",
    "CANCELSTREAM",
    "STOP_STREAM_AT_END",
    "REQUEST_AUDIO_ERROR",
    "REQUEST_PLAY_ADDR",
    "REQUEST_START_ADDR",
    "REQUEST_LENGTH",
    "AUDIO_BUFFER_CONFIG",
    "INQUIRY",
    "BS_CHANGE_DISK",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "NETREAD",
    "OPEN",
    "FASTOPEN",
    "WRITE",
    "CREATE",
    "REMOVE",
    "CONVERT",
    "FASTOPENDIR",
    "OPENDIR",
    "READDIR",
    "CHANGEDIR",
};

// Range: 0x31C -> 0x424
void DVDDumpWaitingQueue(void) {
    // Local variables
    u32 i; // r29
    DVDCommandBlock* start; // r28
    DVDCommandBlock* q; // r31

    // References
    // -> static char * CommandNames[43];
    // -> static struct [anonymous] WaitingQueue[4];

    OSReport("==== DVD Waiting Queue Status ====\n");
    for (i = 0; i < 4; i++) {
        OSReport("< Queue #%d > ", i);
        start = (DVDCommandBlock*)&WaitingQueue[i];
        if (start->next == start) {
            OSReport("None\n");
        } else {
            OSReport("\n");
            for (q = start->next; q != start; q = q->next) {
                OSReport("0x%08x: Command: %s ", q, CommandNames[q->command]);
                if (q->command == 1 || q->command == 33) {
                    OSReport("Disk offset: %d, Length: %d, Addr: 0x%08x\n", q->offset, q->length, q->addr);
                } else {
                    OSReport("\n");
                }
            }
        }
    }
}
