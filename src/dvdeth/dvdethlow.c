#include <dolphin/os.h>
#include <dolphin/db.h>
#include <dolphin/ip.h>
#include <dolphin/dvdeth.h>
#include <string.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

u32 __OSGetDIConfig(void);

enum __INIT_STATE {
    INIT_NOT_ALLOWED = 0,
    INIT_NEEDED = 1,
    INIT_NOT_NEEDED = 2,
};

int bNetConfigured = TRUE; // size: 0x4, address: 0x0

static struct {
    u32 Command; // offset 0x0, size 0x4
    void* AddressR; // offset 0x4, size 0x4
    void* AddressW; // offset 0x8, size 0x4
    u32 LengthR; // offset 0xC, size 0x4
    u32 LengthW; // offset 0x10, size 0x4
    u32 Offset; // offset 0x14, size 0x4
    DVDLowCallback Callback; // offset 0x18, size 0x4
    s32 Result; // offset 0x1C, size 0x4
    u32 TotalSize; // offset 0x20, size 0x4
    char pFileName[256]; // offset 0x24, size 0x100
} CommandList; // size: 0x124, address: 0x0

static struct {
    u32 Command; // offset 0x0, size 0x4
    u32 Length; // offset 0x4, size 0x4
    u32 Offset; // offset 0x8, size 0x4
    char FileName[256]; // offset 0xC, size 0x100
} sendBD = { 0 }; // size: 0x10C, address: 0x0

static s32 SendLength; // size: 0x4, address: 0x0
static s32 WriteResult; // size: 0x4, address: 0x4

char* pIpErrMsg[21] = { // size: 0x54, address: 0x3F0
    "Succeeded.",
    "Specified socket is busy.",
    "Specified socket is unreachable from this machine.",
    "Connection reset",
    "Connection does not exist",
    "Specified socket is already in use.",
    "socket unspecified.",
    "Used up ephemeral local ports.",
    "Connection closing.",
    "No error message for error number -9\n",
    "Connection timeout",
    "Connection refused. The connection is reset in the middle of three-way hand shake.",
    "Info is not a valid TCPInfo. Specified Socket is invalid.",
    "Specified socket address is not valid for the local machine",
    "Specified option is not supported.",
    "COLLISION Error\n",
    "INV_OPTION Error\n",
    "The data size exceeds the transfer limit.",
    "ICMP source quench error.",
    "Local network interface is down.",
    "Returned Error Number has no error message.",
};

static TCPInfo Listen; // size: 0x360, address: 0x128
static TCPInfo Info; // size: 0x360, address: 0x488
static u8 RecvBuf[4096]; // size: 0x1000, address: 0x7E8
static u8 SendBuf[1460]; // size: 0x5B4, address: 0x17E8
static u8 TDEVServerAddr[4]; // size: 0x4, address: 0x8
static u16 TDEVServerPort; // size: 0x2, address: 0xC
static BOOL bConnected; // size: 0x4, address: 0x10

static void TCPConnectCallback(TCPInfo* info, s32 result);
static void TCPSendCallback(TCPInfo* info, s32 result);
static void TCPRecvCallback(TCPInfo* info, s32 result);
static void TCPCloseCallback(TCPInfo* info, s32 result);

// Range: 0x0 -> 0x38
u32 ErrorMsg(s32 error_no /* r3 */) {
    // Local variables
    u32 result; // r31

    if (error_no >= 0) {
        result = 0;
    } else {
        result = -error_no;
        if (result >= 21) {
            result = 20;
        }
    }
    return result;
}

// Range: 0x38 -> 0xD4
static void ErrorProc() {
    // Local variables
    s32 rc; // r30

    // References
    // -> static struct [anonymous] CommandList;
    // -> char * pIpErrMsg[21];
    // -> static struct TCPInfo Info;

    CommandList.Result = -1;
    rc = TCPCloseAsync(&Info, TCPCloseCallback, NULL);
    if (rc != 0) {
        OSReport("Warning: Close failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        if (CommandList.Callback) {
            CommandList.Callback(-1);
        }
    }
}

// Range: 0xD4 -> 0x224
static BOOL DVDLowConnect() {
    // Local variables
    IPSocket socket; // r1+0x8
    s32 rc; // r29
    BOOL enabled; // r28

    // References
    // -> static struct [anonymous] CommandList;
    // -> char * pIpErrMsg[21];
    // -> static struct TCPInfo Info;
    // -> static unsigned short TDEVServerPort;
    // -> static unsigned char TDEVServerAddr[4];
    // -> static unsigned char RecvBuf[4096];
    // -> static unsigned char SendBuf[1460];

    rc = TCPOpen(&Info, SendBuf, sizeof(SendBuf), RecvBuf, sizeof(RecvBuf));
    if (rc != 0) {
        OSReport("Warning: DVDLowConnect(): Open failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        if (CommandList.Callback) {
            enabled = OSDisableInterrupts();
            CommandList.Callback(-1);
            OSRestoreInterrupts(enabled);
        }
        return FALSE;
    }

    memmove(socket.addr, TDEVServerAddr, 4);
    socket.len = 8;
    socket.family = 2;
    socket.port = TDEVServerPort;
    rc = TCPConnectAsync(&Info, &socket, TCPConnectCallback, NULL);
    if (rc != 0) {
        OSReport("Warning: DVDLowConnect(): Connect failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        if (CommandList.Callback) {
            enabled = OSDisableInterrupts();
            CommandList.Callback(-1);
            OSRestoreInterrupts(enabled);
        }
        return FALSE;
    }

    return TRUE;
}

// Range: 0x224 -> 0x368
static void TCPConnectCallback(TCPInfo* info, s32 result /* r28 */) {
    // Local variables
    s32 rc; // r29

    // References
    // -> char * pIpErrMsg[21];
    // -> static long SendLength;
    // -> static struct [anonymous] sendBD;
    // -> static struct TCPInfo Info;
    // -> static struct [anonymous] CommandList;
    // -> static int bConnected;

    if (result != 0) {
        OSReport("Warning: TCPConnectCallback(): Connect failed. %s\n", pIpErrMsg[ErrorMsg(result)]);
        ErrorProc();
        return;
    }

    bConnected = TRUE;
    ASSERTMSGLINE(496, CommandList.Command < 0x26, "TCPConnectCallback(): specified command is not defined. ");
    sendBD.Command = CommandList.Command - 0x20;
    sendBD.Offset = CommandList.Offset;
    if (CommandList.Command == 0x21) {
        sendBD.Length = CommandList.LengthW;
    } else {
        sendBD.Length = CommandList.LengthR;
    }

    if (CommandList.pFileName[0] != '\0') {
        strcpy(sendBD.FileName, CommandList.pFileName);
        SendLength = strlen(sendBD.FileName) + 13;
    } else {
        SendLength = 12;
    }

    rc = TCPSendAsync(&Info, &sendBD, SendLength, TCPSendCallback, NULL);
    if (rc < 0) {
        OSReport("Warning: TCPConnectCallback(): Send failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        ErrorProc();
    }
}

// Range: 0x368 -> 0x4EC
static void TCPSendCallback(TCPInfo* info, s32 result /* r28 */) {
    // Local variables
    s32 rc; // r29

    // References
    // -> char * pIpErrMsg[21];
    // -> static struct [anonymous] CommandList;
    // -> static struct TCPInfo Info;
    // -> static long SendLength;

    if (result < 0) {
        OSReport("Warning: TCPSendCallback(): Send failed. %s\n", pIpErrMsg[ErrorMsg(result)]);
        ErrorProc();
        return;
    }

    if (SendLength != result) {
        OSReport("TCPSendCallback(): transfered length is not equal to sent length.");
    }

    if (CommandList.Command == 0x21 && CommandList.LengthW != 0) {
        SendLength = CommandList.LengthW;
        CommandList.LengthW = 0;
        rc = TCPSendAsync(&Info, CommandList.AddressW, SendLength, TCPSendCallback, NULL);
        if (rc < 0) {
            OSReport("Warning: TCPSendCallback(): Send failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
            ErrorProc();
        }
        return;
    }

    rc = TCPShutdown(&Info, 1);
    if (rc != 0) {
        OSReport("Warning: TCPSendCallback(): Shutdown failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        ErrorProc();
        return;
    }

    rc = TCPReceiveAsync(&Info, CommandList.AddressR, CommandList.LengthR, TCPRecvCallback, NULL);
    if (rc < 0) {
        OSReport("Warning: TCPSendCallback(): Receive failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        ErrorProc();
    }
}

// Range: 0x4EC -> 0x698
static void TCPRecvCallback(TCPInfo* info, s32 result /* r28 */) {
    // Local variables
    s32 rc; // r29

    // References
    // -> char * pIpErrMsg[21];
    // -> static struct [anonymous] CommandList;
    // -> static struct TCPInfo Info;

    if (result < 0) {
        OSReport("Warning: TCPRecvCallback(): Receive failed. %s\n", pIpErrMsg[ErrorMsg(result)]);
        ErrorProc();
        return;
    }

    if (result == 0) {
        rc = TCPCloseAsync(&Info, TCPCloseCallback, NULL);
        if (rc != 0) {
            OSReport("Warning: TCPRecvCallback(): Close failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
            if (CommandList.Callback) {
                CommandList.Callback(-1);
            }
        }
        return;
    }

    CommandList.TotalSize += result;
    if (CommandList.Command == 0x20) {
        if (CommandList.Callback) {
            CommandList.Callback(result);
        }
        return;
    }

    if (CommandList.TotalSize > CommandList.LengthR) {
        OSReport("TCPRecvCallback(): Read buffer is overflowed. %s\n");
        ErrorProc();
        return;
    }

    if (CommandList.Command == 0x21) {
        CommandList.Result = *(s32*)CommandList.AddressR;
    } else {
        CommandList.Result = CommandList.TotalSize;
    }

    rc = TCPReceiveAsync(&Info, (u8*)CommandList.AddressR + CommandList.TotalSize, CommandList.LengthR - CommandList.TotalSize, TCPRecvCallback, NULL);
    if (rc < 0) {
        OSReport("Warning: TCPRecvCallback(): Receive failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        ErrorProc();
    }
}

// Range: 0x698 -> 0x740
static void TCPCloseCallback(TCPInfo* info, s32 result /* r30 */) {
    // References
    // -> static struct [anonymous] CommandList;
    // -> char * pIpErrMsg[21];
    // -> static int bConnected;

    bConnected = FALSE;
    if (result != 0) {
        OSReport("Warning: TCPCloseCallback(): Close failed. %s\n", pIpErrMsg[ErrorMsg(result)]);
        if (CommandList.Callback) {
            CommandList.Callback(-1);
        }
    } else if (CommandList.Callback) {
        CommandList.Callback(CommandList.Result);
    }
}

// Range: 0x740 -> 0x874
int DVDLowNetRead(void* addr /* r26 */, u32 length /* r27 */, u32 offset /* r1+0x10 */, DVDLowCallback callback /* r1+0x14 */, u32 startAddr /* r28 */) {
    // Local variables
    s32 rc; // r29

    // References
    // -> char * pIpErrMsg[21];
    // -> static struct TCPInfo Info;
    // -> static struct [anonymous] CommandList;
    // -> static int bConnected;

    ASSERTMSGLINE(761, startAddr, "DVDLowNetRead(): null pointer is specified to file name");

    CommandList.Command = 0x20;
    CommandList.AddressR = addr;
    CommandList.AddressW = NULL;
    CommandList.LengthR = length;
    CommandList.LengthW = 0;
    CommandList.Offset = offset;
    CommandList.Callback = callback;
    CommandList.Result = 0;
    CommandList.TotalSize = 0;

    if (!bConnected) {
        if (!DVDConvertEntrynumToPath(startAddr, CommandList.pFileName, 256)) {
            return FALSE;
        }
        DVDLowConnect();
        return TRUE;
    }

    rc = TCPReceiveAsync(&Info, addr, length, TCPRecvCallback, NULL);
    if (rc < 0) {
        OSReport("Warning: DVDLowNetRead(): Receive failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
        ErrorProc();
        return FALSE;
    }

    return TRUE;
}

// Range: 0x874 -> 0x94C
int DVDLowWrite(void* addr /* r1+0x8 */, u32 length /* r1+0xC */, u32 offset /* r1+0x10 */, DVDLowCallback callback /* r1+0x14 */, u32 startAddr /* r29 */) {
    // Local variables
    int result; // r30

    // References
    // -> static struct [anonymous] CommandList;
    // -> static long WriteResult;

    ASSERTMSGLINE(821, startAddr, "DVDLowWrite(): null pointer is specified to file name");

    result = DVDConvertEntrynumToPath(startAddr, CommandList.pFileName, 256);
    if (!result) {
        return FALSE;
    }

    CommandList.Command = 0x21;
    CommandList.AddressR = &WriteResult;
    CommandList.AddressW = addr;
    CommandList.LengthR = 4;
    CommandList.LengthW = length;
    CommandList.Offset = offset;
    CommandList.Callback = callback;
    CommandList.Result = 0;
    CommandList.TotalSize = 0;
    DVDLowConnect();
    return TRUE;
}

// Range: 0x94C -> 0xA00
int DVDLowCommand(void* pRecv /* r1+0x8 */, u32 command /* r1+0xC */, u32 recvlen /* r1+0x10 */, u32 offset /* r1+0x14 */, DVDLowCallback callback /* r1+0x18 */, const char* pFileName /* r30 */) {
    // References
    // -> static struct [anonymous] CommandList;

    CommandList.Command = command;
    CommandList.AddressR = pRecv;
    CommandList.AddressW = NULL;
    CommandList.LengthR = recvlen;
    CommandList.LengthW = 0;
    CommandList.Offset = offset;
    CommandList.Callback = callback;
    if (pFileName) {
        strcpy(CommandList.pFileName, pFileName);
    } else {
        CommandList.pFileName[0] = '\0';
    }
    CommandList.Result = 0;
    CommandList.TotalSize = 0;
    DVDLowConnect();
    return TRUE;
}

// Range: 0xA00 -> 0xAC8
int DVDLowCancel(DVDLowCallback callback /* r29 */) {
    // Local variables
    s32 rc; // r30
    BOOL enabled; // r28

    // References
    // -> char * pIpErrMsg[21];
    // -> static struct TCPInfo Info;
    // -> static struct [anonymous] CommandList;
    // -> static int bConnected;

    if (!bConnected) {
        if (callback) {
            enabled = OSDisableInterrupts();
            callback(0);
            OSRestoreInterrupts(enabled);
        }
        return TRUE;
    }

    CommandList.Callback = callback;
    CommandList.Result = 0;
    rc = TCPCloseAsync(&Info, TCPCloseCallback, NULL);
    if (rc != 0) {
        OSReport("Warning: DVDLowCancel(): Close failed. %s\n", pIpErrMsg[ErrorMsg(rc)]);
    }
    return TRUE;
}

static u8 TimeWaitBuf[4096]; // size: 0x1000, address: 0x1D9C
static BOOL DHCP_configured; // size: 0x4, address: 0x14

// Range: 0xAC8 -> 0xB78
int DVDLowInit(const u8* pServerAddr /* r31 */, u16 ServerPort /* r1+0xC */) {
    // References
    // -> static unsigned short TDEVServerPort;
    // -> static unsigned char TDEVServerAddr[4];
    // -> int bNetConfigured;

    ASSERTMSGLINE(948, bNetConfigured, "DVDLowInit():DVDEthInit() is not called or failed");
    if (!bNetConfigured) {
        return FALSE;
    }

    TDEVServerAddr[0] = pServerAddr[0];
    TDEVServerAddr[1] = pServerAddr[1];
    TDEVServerAddr[2] = pServerAddr[2];
    TDEVServerAddr[3] = pServerAddr[3];
    TDEVServerPort = ServerPort;
    DVDSetAutoFatalMessaging(TRUE);
    DVDSetAutoFatalMessaging(FALSE);
    return TRUE;
}

// Range: 0xE3C -> 0xEDC
static inline enum __INIT_STATE CheckConsoleType() {
    if (__OSGetDIConfig() == 0xFF) {
        switch (*(u16*)0x800030E6) {
        case 0x8200:
            return INIT_NEEDED;
        case 0x8001:
            if (OSGetPhysicalMemSize() == 0x3000000) {
                if (DBIsDebuggerPresent()) {
                    return INIT_NOT_NEEDED;
                }
                return INIT_NEEDED;
            }
            return INIT_NOT_ALLOWED;
        default:
            return INIT_NOT_ALLOWED;
        }
    }
    return INIT_NEEDED;
}

// Range: 0xB78 -> 0xE3C
int DVDEthInit(const u8* addr /* r28 */, const u8* netmask /* r29 */, const u8* gateway /* r27 */) {
    // Local variables
    int state; // r1+0x240

    // References
    // -> int bNetConfigured;
    // -> static int DHCP_configured;
    // -> static unsigned char TimeWaitBuf[4096];

    switch (CheckConsoleType()) {
    case INIT_NOT_ALLOWED:
        return FALSE;
    case INIT_NOT_NEEDED:
        TCPSetTimeWaitBuffer(TimeWaitBuf, sizeof(TimeWaitBuf));
        bNetConfigured = TRUE;
        return TRUE;
    case INIT_NEEDED:
    default:
        break;
    }

    IFInit(4);
    TCPSetTimeWaitBuffer(TimeWaitBuf, sizeof(TimeWaitBuf));

    state = 0;
    while (state == 0) {
        IPGetLinkState(NULL, &state);
    }

    if (addr && netmask) {
        bNetConfigured = IPInitRoute(addr, netmask, gateway);
        if (!bNetConfigured) {
            ASSERTMSGLINE(1082, FALSE, "DVDEthInit():failed to initialize IP routing table ");
            return FALSE;
        }
    } else {
        DHCPInfo dhcp; // r1+0x14
        s32 state; // r30

        DHCPStartup(NULL);
        ASSERTMSGLINE(1092, !addr, "DVDEthInit():null pointer is specified to netmask ");
        ASSERTMSGLINE(1093, !netmask, "DVDEthInit():null pointer is specified to addr");
        ASSERTMSGLINE(1094, !gateway, "DVDEthInit():null pointer is not specified to gateway");
        OSReport("Host configuration in progress...\n");
        while (TRUE) {
            state = DHCPGetStatus(&dhcp);
            if (state == 0) {
                OSReport("Host configuration failed\n");
            } else if (state == 3 || state == 4 || state == 5) {
                break;
            }
        }

        DHCP_configured = TRUE;
        bNetConfigured = TRUE;
        OSReport("Host configured:\n");
        OSReport("ipaddr:    %d.%d.%d.%d\n", dhcp.ipaddr[0], dhcp.ipaddr[1], dhcp.ipaddr[2], dhcp.ipaddr[3]);
        OSReport("broadcast: %d.%d.%d.%d\n", dhcp.broadcast[0], dhcp.broadcast[1], dhcp.broadcast[2], dhcp.broadcast[3]);
        OSReport("server:    %d.%d.%d.%d\n", dhcp.server[0], dhcp.server[1], dhcp.server[2], dhcp.server[3]);
        OSReport("router:    %d.%d.%d.%d\n", dhcp.router[0], dhcp.router[1], dhcp.router[2], dhcp.router[3]);
        OSReport("dns1:      %d.%d.%d.%d\n", dhcp.dns1[0], dhcp.dns1[1], dhcp.dns1[2], dhcp.dns1[3]);
        OSReport("dns2:      %d.%d.%d.%d\n", dhcp.dns2[0], dhcp.dns2[1], dhcp.dns2[2], dhcp.dns2[3]);
        OSReport("domain:    %s\n", dhcp.domain);
        OSReport("renewal:   %u\n", dhcp.renewal);
        OSReport("rebinding: %u\n", dhcp.rebinding);
        OSReport("lease:     %u\n", dhcp.lease);
        return FALSE;
    }

    return TRUE;
}

// Range: 0xEDC -> 0xF10
void DVDEthShutdown(void) {
    // References
    // -> int bNetConfigured;
    // -> static int DHCP_configured;

    if (DHCP_configured) {
        DHCPCleanup();
    }
    bNetConfigured = FALSE;
}
