#include <dolphin/ip.h>
#include <dolphin/private/ip.h>
#include <ctype.h>
#include <stdlib.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

static char* TypeStrings[43] = {
    "",
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT",
    "RP",
    "AFSDB",
    "X25",
    "ISDN",
    "RT",
    "NSAP",
    "NSAP_PTR",
    "SIG",
    "KEY",
    "PX",
    "GPOS",
    "AAAA",
    "LOC",
    "NXT",
    "EID",
    "NIMLOC",
    "SRV",
    "ATMA",
    "NAPTR",
    "KX",
    "CERT",
    "A6",
    "DNAME",
    "SINK",
    "OPT",
    "APL",
}; // size: 0xAC, address: 0xC

static char* ClassStrings[5] = {
    "",
    "IN",
    "CS",
    "CH",
    "HS",
}; // size: 0x14, address: 0xB8

static void RecvCallback(UDPInfo* udp, s32 result);
static void TimeoutCallback(OSAlarm* alarm, OSContext*);
static void SOMakeHostent(SOResolver* res, DNSHeader* dns, s32 result);

// Range: 0x0 -> 0xC8
static void NullCallback(DNSCommand* cmd /* r31 */, s32 result /* r1+0xC */) {
    // Local variables
    DNSCallback callback; // r30

    ASSERTLINE(175, cmd);
    switch (cmd->func) {
        case 1:
            callback = cmd->data.ga.callback;
            break;
        case 2:
            callback = cmd->data.gn.callback;
            break;
        case 3:
            callback = cmd->data.lu.callback;
            break;
    }

    if (callback) {
        ASSERTLINE(192, cmd->info);
        callback(cmd->info, result);
    }
}

// Range: 0xC8 -> 0xF4
static void SyncCallback(DNSInfo* info /* r1+0x8 */, s32) {
    OSWakeupThread(&info->queueThread);
}

// Range: 0xF4 -> 0x1B0
static u8* DumpName(DNSHeader* dns /* r1+0x8 */, u8* ptr /* r31 */) {
    // Local variables
    int count; // r29
    u8* ret; // r30

    ret = NULL;
    while (*ptr != 0) {
        count = *ptr;
        if (count & 0xC0) {
            if (ret == NULL) {
                ret = ptr + 2;
            }
            ptr = (u8*)dns + (*(u16*)ptr & ~0xC000);
        } else {
            OSReport("%.*s", count, ++ptr);
            ptr += count;
            if (*ptr != 0) {
                OSReport(".");
            }
        }
    }
    OSReport(".");
    if (ret == NULL) {
        ret = ptr + 1;
    }
    return ret;
}

// Range: 0x1B0 -> 0x210
static u8* DumpString(u8* ptr /* r30 */) {
    // Local variables
    int count; // r29
    u8 i; // r31

    count = *ptr++;
    for (i = 0; i < count; i++) {
        OSReport("%c", *ptr++);
    }
    return ptr;
}

// Range: 0x210 -> 0x294
static u8* DumpQuestion(DNSHeader* dns /* r1+0x8 */, u8* ptr /* r31 */) {
    // Local variables
    u16 type; // r30

    // References
    // -> static char * TypeStrings[43];

    ptr = DumpName(dns, ptr);
    type = *(u16*)ptr;
    if (type < 43) {
        OSReport("\t%s\t", TypeStrings[type]);
    }
    ptr += 2;
    ptr += 2;
    OSReport("\n");
    return ptr;
}

// Range: 0x294 -> 0x5D0
static u8* DumpResource(DNSHeader* dns /* r29 */, u8* ptr /* r31 */) {
    // Local variables
    int count; // r28
    u16 type; // r27

    // References
    // -> static char * TypeStrings[43];

    ptr = DumpName(dns, ptr);
    type = *(u16*)ptr;
    if (type < 43) {
        OSReport("\t%s\t", TypeStrings[type]);
    }
    ptr += 2;
    ptr += 2;
    ptr += 4;
    count = *(u16*)ptr;
    ptr += 2;

    switch (type) {
        case 2:
        case 3:
        case 4:
        case 5:
        case 7:
        case 8:
        case 9:
        case 12:
            ptr = DumpName(dns, ptr);
            break;
        case 13:
        case 16:
            OSReport("%*.s", count, ptr);
            ptr += count;
            break;
        case 14:
            ptr = DumpName(dns, ptr);
            OSReport(" ");
            ptr = DumpName(dns, ptr);
            break;
        case 15:
            OSReport("%u ", *(u16*)ptr);
            ptr += 2;
            ptr = DumpName(dns, ptr);
            break;
        case 6:
            ptr = DumpName(dns, ptr);
            OSReport(" ");
            ptr = DumpName(dns, ptr);
            OSReport(" (\n\t\t\t");
            OSReport("%u ;serial\n\t\t\t", *(u32*)ptr);
            ptr += 4;
            OSReport("%u ;refresh\n\t\t\t", *(u32*)ptr);
            ptr += 4;
            OSReport("%u ;retry\n\t\t\t", *(u32*)ptr);
            ptr += 4;
            OSReport("%u ;expire\n\t\t\t", *(u32*)ptr);
            ptr += 4;
            OSReport("%u ;minimum\n\t\t\t)", *(u32*)ptr);
            ptr += 4;
            break;
        case 1:
            OSReport("%d.%d.%d.%d", ptr[0], ptr[1], ptr[2], ptr[3]);
            ptr += 4;
            break;
        case 11:
            OSReport("%d.%d.%d.%d", ptr[0], ptr[1], ptr[2], ptr[3]);
            ptr += 4;
            OSReport(":%d", *(u16*)ptr);
            ptr += 2;
            count -= 6;
            IFDump(ptr, count);
            ptr += count;
            break;
        case 35:
            OSReport("%d", *(u16*)ptr);
            ptr += 2;
            OSReport(" %d ", *(u16*)ptr);
            ptr += 2;
            OSReport(" \"");
            ptr = DumpString(ptr);
            OSReport("\" \"");
            ptr = DumpString(ptr);
            OSReport("\" \"");
            ptr = DumpString(ptr);
            OSReport("\" ");
            ptr = DumpName(dns, ptr);
            break;
        case 33:
            OSReport("%d", *(u16*)ptr);
            ptr += 2;
            OSReport(" %d", *(u16*)ptr);
            ptr += 2;
            OSReport(" %d ", *(u16*)ptr);
            ptr += 2;
            ptr = DumpName(dns, ptr);
            break;
        default:
            IFDump(ptr, count);
            ptr += count;
            break;
    }
    OSReport("\n");
    return ptr;
}

// Range: 0x5D0 -> 0x6E4
void DNSDumpPacket(DNSHeader* dns /* r31 */) {
    // Local variables
    u8* opt; // r29
    int i; // r30

    opt = (u8*)(dns + 1);
    OSReport("qdcount: %d\n", dns->qdcount);
    for (i = 0; i < dns->qdcount; i++) {
        opt = DumpQuestion(dns, opt);
    }
    OSReport("ancount: %d\n", dns->ancount);
    for (i = 0; i < dns->ancount; i++) {
        opt = DumpResource(dns, opt);
    }
    OSReport("nscount: %d\n", dns->nscount);
    for (i = 0; i < dns->nscount; i++) {
        opt = DumpResource(dns, opt);
    }
    OSReport("arcount: %d\n", dns->arcount);
    for (i = 0; i < dns->arcount; i++) {
        opt = DumpResource(dns, opt);
    }
}

// Range: 0x6E4 -> 0x770
static u8* SkipName(u8* ptr /* r3 */, u8* end /* r4 */) {
    // Local variables
    int count; // r31

    for (;;) {
        if (end <= ptr) {
            return NULL;
        }
        if (*ptr == 0) {
            ptr++;
            return (ptr <= end) ? ptr : NULL;
        }
        count = *ptr;
        if (count & 0xC0) {
            if ((count & 0xC0) != 0xC0) {
                return NULL;
            }
            ptr += 2;
            return (ptr <= end) ? ptr : NULL;
        }
        ptr += count + 1;
    }
}

// Range: 0x770 -> 0x86C
static char* CopyName(DNSHeader* dns /* r26 */, u8* end /* r27 */, u8* ptr /* r30 */, char* name /* r29 */, s32 namelen /* r28 */) {
    // Local variables
    s32 count; // r31

    while (*ptr != 0 && 1 < namelen) {
        count = *ptr;
        if (count & 0xC0) {
            if ((count & 0xC0) != 0xC0) {
                return NULL;
            }
            ptr = (u8*)dns + (*(u16*)ptr & ~0xC000);
            if (ptr < (u8*)dns || end <= ptr) {
                return NULL;
            }
        } else {
            if (end < ptr + count + 1) {
                return NULL;
            }
            if (namelen <= count) {
                count = namelen - 1;
            }
            namelen -= count;
            memmove(name, ++ptr, count);
            ptr += count;
            name += count;
            if (*ptr != 0) {
                *name++ = '.';
            }
        }
    }
    *name = '\0';
    return name;
}

// Range: 0x86C -> 0x908
static u8* DupName(u8* opt /* r29 */, DNSHeader* dns /* r1+0xC */, u8* ptr /* r30 */) {
    // Local variables
    u8 count; // r31

    while (*ptr != 0) {
        count = *ptr;
        if (count & 0xC0) {
            ptr = (u8*)dns + (*(u16*)ptr & ~0xC000);
        } else {
            *opt++ = count;
            memmove(opt, ++ptr, count);
            ptr += count;
            opt += count;
        }
    }
    *opt++ = 0;
    return opt;
}

// Range: 0x908 -> 0xA84
static u8* CheckResource(DNSHeader* dns, u8* end /* r30 */, u8* ptr /* r31 */) {
    // Local variables
    u16 type; // r28
    u16 class; // r27
    int count; // r29

    ptr = SkipName(ptr, end);
    if (ptr == NULL || end < ptr + 10) {
        return NULL;
    }
    type = *(u16*)ptr;
    ptr += 2;
    class = *(u16*)ptr;
    ptr += 2;
    ptr += 4;
    count = *(u16*)ptr;
    ptr += 2;
    if (class != 1 || type < 1) {
        return NULL;
    }

    end = ptr + count;
    switch (type) {
        case 2:
        case 3:
        case 4:
        case 5:
        case 7:
        case 8:
        case 9:
        case 12:
            ptr = SkipName(ptr, end);
            break;
        case 13:
        case 16:
            ptr += count;
            break;
        case 14:
            ptr = SkipName(ptr, end);
            if (ptr) {
                ptr = SkipName(ptr, end);
            }
            break;
        case 15:
            ptr += 2;
            ptr = SkipName(ptr, end);
            break;
        case 6:
            ptr = SkipName(ptr, end);
            if (ptr) {
                ptr = SkipName(ptr, end);
                if (ptr) {
                    ptr += 20;
                }
            }
            break;
        case 1:
            ptr += 4;
            break;
        case 11:
            ptr += count;
            break;
        default:
            ptr += count;
            break;
    }
    return (ptr == end) ? ptr : NULL;
}

// Range: 0xA84 -> 0xB50
static s32 Connect(DNSInfo* info /* r31 */) {
    // Local variables
    s32 result; // r30
    IPInterface* interface; // r29

    result = UDPConnect(&info->udp, &info->socket);
    if (result < 0) {
        UDPClose(&info->udp);
    } else {
        interface = IPGetRoute(info->socket.addr, NULL);
        ASSERTLINE(637, interface);
        info->flag &= ~3;
        if (IPIsBroadcastAddr(interface, info->socket.addr)) {
            info->flag |= 1;
        } else if (IP_CLASSD(info->socket.addr)) {
            info->flag |= 2;
        }
    }
    return result;
}

// Range: 0xB50 -> 0xC34
static s32 DNSSwitch(DNSInfo* info /* r31 */) {
    // Local variables
    DNSHeader* dns; // r29
    u8* next; // r30

    // References
    // -> unsigned char IPAddrAny[4];

    if (2 <= ++info->retry) {
        return -4;
    }
    next = IPEQ(info->socket.addr, info->dns2) ? info->dns1 : info->dns2;
    if (IPNEQ(next, IPAddrAny)) {
        dns = (DNSHeader*)info->query;
        dns->id = ++info->id;
        info->rxmit = OSMillisecondsToTicks(1000LL);
        memmove(info->socket.addr, next, IP_ALEN);
        return Connect(info);
    }
    return -4;
}

// Range: 0xC34 -> 0xD40
static s32 CancelAll(DNSInfo* info /* r29 */, s32 rc /* r28 */) {
    // Local variables
    DNSCommand* cmd; // r31

    ASSERTLINE(690, rc != IP_ERR_BUSY);
    info->flag |= 8;
    cmd = info->current;
    info->current = NULL;
    if (cmd) {
        if (cmd->result) {
            *cmd->result = rc;
        }
        cmd->callback(cmd, rc);
    }
    while (!IFIsEmptyQueue(&info->queue)) {
        IFQueueDequeueHead(DNSCommand*, &info->queue, cmd);
        if (cmd->result) {
            *cmd->result = rc;
        }
        cmd->callback(cmd, rc);
    }
    UDPCancel(&info->udp);
    info->flag &= ~8;
    return rc;
}

// Range: 0xD40 -> 0x11EC
static void RecvCallback(UDPInfo* udp /* r1+0x8 */, s32 result /* r29 */) {
    // Local variables
    DNSInfo* info; // r31
    DNSHeader* dns; // r28
    u16 type; // r21
    u8* opt; // r30
    u8* ans; // r20
    u8* end; // r25
    int i; // r27
    u16 len; // r24
    DNSCommand* current; // r26
    char* name; // r23
    s32 rc; // r22

    info = (DNSInfo*)udp;
    if (info->current == NULL) {
        return;
    }
    current = info->current;

    if (0 <= result) {
        dns = (DNSHeader*)info->response;
        if (result < 12 || dns->id != info->id || (dns->flags & 0x8000) != 0x8000) {
            goto Receive;
        }

        opt = info->response + sizeof(DNSHeader);
        end = &info->response[result];
        for (i = 0; i < dns->qdcount; i++) {
            opt = SkipName(opt, end);
            if (opt == NULL || end < opt + 4) {
                goto Receive;
            }
            opt += 4;
        }
        if (info->queryLen != opt - info->response || memcmp(info->query + 12, info->response + 12, info->queryLen - 12) != 0) {
            goto Receive;
        }

        ans = opt;
        for (i = 0; i < dns->ancount; i++) {
            opt = CheckResource(dns, end, opt);
            if (opt == NULL) {
                goto Receive;
            }
        }
        for (i = 0; i < dns->nscount; i++) {
            opt = CheckResource(dns, end, opt);
            if (opt == NULL) {
                goto Receive;
            }
        }
        for (i = 0; i < dns->arcount; i++) {
            opt = CheckResource(dns, end, opt);
            if (opt == NULL) {
                goto Receive;
            }
        }

        if ((dns->flags & 0xF) == 0) {
            opt = ans;
            switch (current->func) {
                case 3:
                    result = (info->datalen < result) ? info->datalen : result;
                    memmove(info->data, info->response, result);
                    break;
                case 1:
                case 2:
                    result = 0;
                    for (i = 0; i < dns->ancount; i++) {
                        opt = SkipName(opt, end);
                        len = *(u16*)(opt + 8);
                        type = *(u16*)opt;
                        switch (type) {
                            case 1:
                                if (current->func == 1 && info->data && len == 4) {
                                    memmove(info->data, opt + 10, 4);
                                    info->datalen -= 4;
                                    if (0 < info->datalen) {
                                        info->data += 4;
                                    } else {
                                        info->data = NULL;
                                    }
                                    result = result + 4;
                                }
                                break;
                            case 12:
                                if (current->func == 2 && info->data) {
                                    name = CopyName(dns, opt + 10 + len, opt + 10, (char*)info->data, info->datalen);
                                    if (name) {
                                        result = name - (char*)info->data;
                                    }
                                    info->data = NULL;
                                }
                                break;
                        }
                        opt += len + 10;
                    }
                    if (info->flag & 4) {
                        SOMakeHostent((SOResolver*)info, dns, end - info->response);
                    }
                    break;
            }
        } else {
            result = -200 - (dns->flags & 0xF);
        }

        OSCancelAlarm(&info->alarm);
        if (current->result) {
            *current->result = result;
        }
        current->callback(current, result);
        DNSGo(info, NULL);
        return;

    Receive:
        UDPReceiveAsync(&info->udp, info->response, 512, NULL, &info->socket, RecvCallback, NULL);
    } else {
        ASSERTLINE(894, result < 0);
        switch (result) {
            case -8:
                return;
            case -19:
            case -16:
                ASSERTLINE(902, current->result == NULL || *current->result != IP_ERR_BUSY);
                return;
            case -2:
            default:
                OSCancelAlarm(&info->alarm);
                if (0 <= DNSSwitch(info)) {
                    rc = UDPSendAsync(&info->udp, info->query, info->queryLen, NULL, NULL, NULL);
                    if (0 <= rc || rc == IP_ERR_BUSY) {
                        OSSetAlarm(&info->alarm, info->rxmit, TimeoutCallback);
                        UDPReceiveAsync(&info->udp, info->response, 512, NULL, &info->socket, RecvCallback, NULL);
                    }
                } else {
                    CancelAll(info, result);
                }
                break;
        }
    }
}

// Range: 0x11EC -> 0x1348
static void TimeoutCallback(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    DNSInfo* info; // r31
    DNSCommand* current; // r1+0x10
    s32 rc; // r30

    info = (DNSInfo*)((u8*)alarm - 0x100);
    ASSERTLINE(943, info->current);
    current = info->current;
    info->rxmit <<= 1;
    if (info->rxmit < OSMillisecondsToTicks(20000LL) || 0 <= DNSSwitch(info)) {
        rc = UDPSendAsync(&info->udp, info->query, info->queryLen, NULL, NULL, NULL);
        if (0 <= rc || rc == IP_ERR_BUSY) {
            OSSetAlarm(&info->alarm, info->rxmit, TimeoutCallback);
            UDPReceiveAsync(&info->udp, info->response, 512, NULL, &info->socket, RecvCallback, NULL);
            return;
        }
    }
    CancelAll(info, -10);
}

// Range: 0x1348 -> 0x137C
s32 DNSOpen(DNSInfo* info /* r1+0x8 */, const u8* addr /* r1+0xC */) {
    return DNSOpen2(info, addr, NULL);
}

// Range: 0x137C -> 0x1500
s32 DNSOpen2(DNSInfo* info /* r31 */, const u8* dns1 /* r27 */, const u8* dns2 /* r28 */) {
    // Local variables
    s32 result; // r30
    BOOL enabled; // r29

    // References
    // -> unsigned char IPAddrAny[4];

    enabled = OSDisableInterrupts();
    memset(info, 0, sizeof(DNSInfo));
    memmove(info->dns1, dns1 ? dns1 : IPAddrAny, IP_ALEN);
    memmove(info->dns2, dns2 ? dns2 : IPAddrAny, IP_ALEN);
    if (IPEQ(info->dns1, IPAddrAny)) {
        memmove(info->dns1, dns2, IP_ALEN);
    }
    if (IPEQ(info->dns1, IPAddrAny)) {
        OSRestoreInterrupts(enabled);
        return -4;
    }
    if (IPEQ(info->dns1, info->dns2)) {
        memmove(info->dns2, IPAddrAny, IP_ALEN);
    }

    result = UDPOpen(&info->udp, NULL, 0);
    if (0 <= result) {
        info->id = (u16)(OSGetTime() / (OS_TIMER_CLOCK / 250000));
        OSCreateAlarm(&info->alarm);
        info->socket.len = IP_SOCKLEN;
        info->socket.family = IP_INET;
        memmove(info->socket.addr, info->dns1, IP_ALEN);
        info->socket.port = 53;
        OSInitThreadQueue(&info->queueThread);
        result = Connect(info);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x1500 -> 0x1800
void DNSGo(DNSInfo* info /* r31 */, DNSCommand* cmd /* r30 */) {
    // Local variables
    BOOL enabled; // r26
    s32 rc; // r27
    DNSHeader* dns; // r25

    enabled = OSDisableInterrupts();
    for (;;) {
        if (cmd == NULL) {
            if (IFIsEmptyQueue(&info->queue)) {
                ASSERTLINE(1028, info->current == NULL || info->current->result == NULL || *info->current->result != IP_ERR_BUSY);
                info->current = NULL;
                UDPCancel(&info->udp);
                OSRestoreInterrupts(enabled);
                return;
            }
            IFQueueDequeueHead(DNSCommand*, &info->queue, cmd);
        } else {
            if (info->flag & 8) {
                if (cmd->result) {
                    *cmd->result = -19;
                }
                if (cmd->callback) {
                    cmd->callback(cmd, -19);
                }
                OSRestoreInterrupts(enabled);
                return;
            }
            cmd->info = info;
            if (cmd->result) {
                *cmd->result = IP_ERR_BUSY;
            }
            if (info->current) {
                IFQueueEnqueueTail(DNSCommand*, &info->queue, cmd);
                OSRestoreInterrupts(enabled);
                return;
            }
        }

        info->current = cmd;
        if (cmd->precallback) {
            rc = cmd->precallback(info, cmd);
            if (rc < 0) {
                if (cmd->result) {
                    *cmd->result = rc;
                }
                if (cmd->callback) {
                    cmd->callback(cmd, rc);
                }
                cmd = NULL;
                continue;
            }
        }

        dns = (DNSHeader*)info->query;
        dns->id = ++info->id;
        if (cmd->result) {
            *cmd->result = IP_ERR_BUSY;
        }
        info->retry = 0;
        do {
            info->rxmit = OSMillisecondsToTicks(1000LL);
            rc = UDPSendAsync(&info->udp, info->query, info->queryLen, NULL, NULL, NULL);
            if (0 <= rc || rc == IP_ERR_BUSY) {
                OSSetAlarm(&info->alarm, info->rxmit, TimeoutCallback);
                UDPReceiveAsync(&info->udp, info->response, 512, NULL, &info->socket, RecvCallback, NULL);
                OSRestoreInterrupts(enabled);
                return;
            }
        } while (0 <= DNSSwitch(info));
        CancelAll(info, rc);
        OSRestoreInterrupts(enabled);
        return;
    }
}

// Range: 0x1800 -> 0x1968
static s32 PreGetAddr(DNSInfo* info /* r30 */, DNSCommand* cmd /* r25 */) {
    // Local variables
    const char* name; // r29
    u8* addr; // r24
    s32 addrLen; // r26
    DNSHeader* dns; // r28
    u8* opt; // r31
    u8* count; // r23
    int i; // r27

    name = cmd->data.ga.name;
    addr = cmd->data.ga.addr;
    addrLen = cmd->data.ga.addrLen;

    dns = (DNSHeader*)info->query;
    dns->flags = 0;
    if (!(info->flag & 3)) {
        dns->flags |= 0x100;
    }
    dns->qdcount = 1;
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    opt = info->query + sizeof(DNSHeader);
    while (*name != '\0') {
        if (254 <= opt - info->query) {
            return -12;
        }
        count = opt++;
        for (i = 0; *name != '\0' && *name != '.'; i++) {
            if (63 <= i || 254 <= opt - info->query) {
                return -12;
            }
            *opt++ = *name++;
        }
        *count = i;
        if (*name == '.') {
            name++;
        }
    }
    *opt++ = 0;
    *(u16*)opt = 1;
    opt += 2;
    *(u16*)opt = 1;
    opt += 2;
    info->queryLen = opt - info->query;

    info->data = addr;
    memset(info->data, 0, addrLen);
    info->datalen = addrLen & ~3;
    return 0;
}

// Range: 0x1968 -> 0x1A64
s32 DNSGetAddrAsync(DNSInfo* info /* r1+0x8 */, const char* name /* r26 */, u8* addr /* r27 */, s32 addrLen /* r28 */, DNSCallback callback /* r1+0x18 */, s32* result /* r29 */) {
    // Local variables
    s32 rc; // r30
    static DNSCommand cmd;

    // References
    // -> static struct DNSCommand cmd$445;

    ASSERTLINE(1190, addr == NULL || IP_ALEN <= addrLen);
    if (name == NULL || addr != NULL && addrLen < IP_ALEN) {
        rc = -12;
    } else if (cmd.callback) {
        rc = IP_ERR_BUSY;
    } else {
        cmd.func = 1;
        cmd.precallback = PreGetAddr;
        cmd.callback = NullCallback;
        cmd.result = result;
        cmd.data.ga.name = name;
        cmd.data.ga.addr = addr;
        cmd.data.ga.addrLen = addrLen;
        cmd.data.ga.callback = callback;
        DNSGo(info, &cmd);
        return 0;
    }
    if (result) {
        *result = rc;
    }
    return rc;
}

// Range: 0x1A64 -> 0x1AF8
s32 DNSGetAddr(DNSInfo* info /* r29 */, const char* name /* r1+0xC */, u8* addr /* r1+0x10 */, s32 addrLen /* r1+0x14 */) {
    // Local variables
    s32 result; // r1+0x18
    s32 rc; // r31
    BOOL enabled; // r30

    rc = DNSGetAddrAsync(info, name, addr, addrLen, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x1AF8 -> 0x1C4C
static s32 PreGetName(DNSInfo* info /* r30 */, DNSCommand* cmd /* r24 */) {
    // Local variables
    const u8* addr; // r25
    char* name; // r28
    DNSHeader* dns; // r29
    u8* opt; // r31
    u8* count; // r26
    int i; // r27

    addr = cmd->data.gn.addr;
    name = cmd->data.gn.name;

    dns = (DNSHeader*)info->query;
    dns->flags = 0;
    if (!(info->flag & 3)) {
        dns->flags |= 0x100;
    }
    dns->qdcount = 1;
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    opt = info->query + sizeof(DNSHeader);
    for (i = 3; 0 <= i; i--) {
        count = opt++;
        *count = sprintf((char*)opt, "%d", addr[i]);
        opt += *count;
    }
    *opt++ = 7;
    memmove(opt, "in-addr", 7);
    opt += 7;
    *opt++ = 4;
    memmove(opt, "arpa", 4);
    opt += 4;
    *opt++ = 0;
    *(u16*)opt = 12;
    opt += 2;
    *(u16*)opt = 1;
    opt += 2;
    info->queryLen = opt - info->query;

    info->data = (u8*)name;
    if (name) {
        *name = '\0';
        info->datalen = 255;
    } else {
        info->datalen = 0;
    }
    return 0;
}

// Range: 0x1C4C -> 0x1D2C
s32 DNSGetNameAsync(DNSInfo* info /* r1+0x8 */, const u8* addr /* r28 */, char* name /* r1+0x10 */, DNSCallback callback /* r1+0x14 */, s32* result /* r29 */) {
    // Local variables
    s32 rc; // r30
    static DNSCommand cmd;

    // References
    // -> static struct DNSCommand cmd$477;

    ASSERTLINE(1312, addr != NULL);
    if (addr == NULL) {
        rc = -12;
    } else if (cmd.callback) {
        rc = IP_ERR_BUSY;
    } else {
        cmd.func = 2;
        cmd.precallback = PreGetName;
        cmd.callback = NullCallback;
        cmd.result = result;
        cmd.data.gn.addr = addr;
        cmd.data.gn.name = name;
        cmd.data.gn.callback = callback;
        DNSGo(info, &cmd);
        return 0;
    }
    if (result) {
        *result = rc;
    }
    return rc;
}

// Range: 0x1D2C -> 0x1DB8
s32 DNSGetName(DNSInfo* info /* r29 */, const u8* addr /* r1+0xC */, char* name /* r1+0x10 */) {
    // Local variables
    s32 result; // r1+0x14
    s32 rc; // r31
    BOOL enabled; // r30

    rc = DNSGetNameAsync(info, addr, name, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x1DB8 -> 0x1E14
static s32 PreLookup(DNSInfo* info /* r30 */, DNSCommand* cmd /* r31 */) {
    // Local variables
    const u8* query; // r28
    s32 queryLen; // r29
    u8* response; // r27
    s32 responseLen; // r26

    query = cmd->data.lu.query;
    queryLen = cmd->data.lu.queryLen;
    response = cmd->data.lu.response;
    responseLen = cmd->data.lu.responseLen;
    memmove(info->query, query, queryLen);
    info->queryLen = queryLen;
    info->data = response;
    info->datalen = responseLen;
    return 0;
}

// Range: 0x1E14 -> 0x1EF8
s32 DNSLookupAsync(DNSInfo* info /* r1+0x8 */, const u8* query /* r25 */, s32 queryLen /* r26 */, u8* response /* r27 */, s32 responseLen /* r28 */, DNSCallback callback /* r1+0x1C */, s32* result /* r29 */) {
    // Local variables
    s32 rc; // r30
    static DNSCommand cmd;

    // References
    // -> static struct DNSCommand cmd$495;

    if (query == NULL || 512 < queryLen || response != NULL && responseLen < 0) {
        rc = -12;
    } else if (cmd.callback) {
        rc = IP_ERR_BUSY;
    } else {
        cmd.func = 3;
        cmd.precallback = PreLookup;
        cmd.callback = NullCallback;
        cmd.result = result;
        cmd.data.lu.query = query;
        cmd.data.lu.queryLen = queryLen;
        cmd.data.lu.response = response;
        cmd.data.lu.responseLen = responseLen;
        cmd.data.lu.callback = callback;
        DNSGo(info, &cmd);
        return 0;
    }
    if (result) {
        *result = rc;
    }
    return rc;
}

// Range: 0x1EF8 -> 0x1F94
s32 DNSLookup(DNSInfo* info /* r29 */, const u8* query /* r1+0xC */, s32 queryLen /* r1+0x10 */, u8* response /* r1+0x14 */, s32 responseLen /* r1+0x18 */) {
    // Local variables
    s32 result; // r1+0x1C
    s32 rc; // r31
    BOOL enabled; // r30

    rc = DNSLookupAsync(info, query, queryLen, response, responseLen, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x1F94 -> 0x1FEC
s32 DNSClose(DNSInfo* info /* r31 */) {
    // Local variables
    BOOL enabled; // r30

    enabled = OSDisableInterrupts();
    CancelAll(info, -19);
    UDPClose(&info->udp);
    OSCancelAlarm(&info->alarm);
    OSRestoreInterrupts(enabled);
    return 0;
}

// Range: 0x1FEC -> 0x21AC
static void SOMakeHostent(SOResolver* res /* r26 */, DNSHeader* dns /* r23 */, s32 result /* r28 */) {
    // Local variables
    DNSInfo* info; // r30
    DNSCommand* current; // r27
    u8* opt; // r31
    u8* end; // r22
    u16 len; // r25
    u16 type; // r20
    int i; // r29
    u8** ptr; // r24
    u8* addr; // r21

    info = &res->info;
    current = info->current;
    opt = (u8*)(dns + 1);
    end = &info->response[result];
    for (i = 0; i < dns->qdcount; i++) {
        opt = SkipName(opt, end);
        opt += 4;
    }

    if (current->func == 2) {
        info->data = res->addrList;
        info->datalen = sizeof(res->addrList);
    }

    result = 0;
    for (i = 0; i < dns->ancount; i++) {
        opt = SkipName(opt, end);
        len = *(u16*)(opt + 8);
        type = *(u16*)opt;
        switch (type) {
            case 1:
                if (current->func == 2 && info->data && len == 4) {
                    memmove(info->data, opt + 10, 4);
                    info->datalen -= 4;
                    if (0 < info->datalen) {
                        info->data += 4;
                    } else {
                        info->data = NULL;
                    }
                    result += 4;
                }
                break;
            case 5:
                if (current->func == 1) {
                    CopyName(dns, opt + 10 + len, opt + 10, res->name, 256);
                }
                break;
        }
        opt += len + 10;
    }

    if (current->func == 2 && 0 < result) {
        for (ptr = res->ptrList, addr = res->addrList; 0 < result; result -= 4, ptr++, addr += 4) {
            *ptr = addr;
        }
        *ptr = NULL;
    }
}

// Range: 0x21AC -> 0x238C
static s32 PreGetAddrInfo(DNSInfo* info /* r30 */, DNSCommand* cmd /* r27 */) {
    // Local variables
    const char* nodeName; // r29
    const char* servName; // r24
    u16 type; // r23
    DNSHeader* dns; // r28
    u8* opt; // r31
    u8* count; // r22
    int i; // r26
    u8 len; // r25

    nodeName = cmd->data.ai.nodeName;
    servName = cmd->data.ai.servName;
    type = cmd->data.ai.type;

    dns = (DNSHeader*)info->query;
    dns->flags = 0;
    if (!(info->flag & 3)) {
        dns->flags |= 0x100;
    }
    dns->qdcount = 1;
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    opt = info->query + sizeof(DNSHeader);
    if (type == 33) {
        len = strlen(servName);
        *opt++ = len + 1;
        *opt++ = '_';
        memmove(opt, servName, len);
        opt += len;
        *opt++ = 4;
        *opt++ = '_';
        memmove(opt, (cmd->data.ai.sockType == 2) ? "udp" : "tcp", 3);
        opt += 3;
    }
    while (*nodeName != '\0') {
        if (254 <= opt - info->query) {
            return -12;
        }
        count = opt++;
        for (i = 0; *nodeName != '\0' && *nodeName != '.'; i++) {
            if (63 <= i || 254 <= opt - info->query) {
                return -12;
            }
            *opt++ = *nodeName++;
        }
        *count = i;
        if (*nodeName == '.') {
            nodeName++;
        }
    }
    *opt++ = 0;
    *(u16*)opt = type;
    opt += 2;
    *(u16*)opt = 1;
    opt += 2;
    info->queryLen = opt - info->query;

    info->data = cmd->data.ai.addrList;
    info->datalen = 0;
    return 0;
}

// Range: 0x238C -> 0x2730
static void GetAddrInfoCallback(DNSCommand* cmd /* r31 */, s32 result /* r21 */) {
    // Local variables
    DNSInfo* info; // r30
    u16 type; // r22
    DNSHeader* dns; // r28
    u8* res; // r29
    u8* end; // r19
    u8* ans; // r24
    u8* req; // r23
    int i; // r27
    u16 len; // r20

    ASSERTLINE(1634, cmd);
    info = cmd->info;
    type = cmd->data.ai.type;
    if (cmd->result) {
        *cmd->result = IP_ERR_BUSY;
    }

    if (0 <= result) {
        ASSERTLINE(1647, info);

        dns = (DNSHeader*)info->query;
        dns->flags = 0;
        if (!(info->flag & 3)) {
            dns->flags |= 0x100;
        }
        dns->qdcount = 1;
        dns->ancount = 0;
        dns->nscount = 0;
        dns->arcount = 0;
        req = info->query + sizeof(DNSHeader);

        dns = (DNSHeader*)info->response;
        end = &info->response[result];
        ans = info->response + sizeof(DNSHeader);
        for (i = 0; i < dns->qdcount; i++) {
            ans = SkipName(ans, end);
            ans = ans + 4;
        }

        switch (type) {
            case 33:
                result = 0;
                res = ans;
                for (i = 0; i < dns->ancount; i++) {
                    res = SkipName(res, end);
                    len = *(u16*)(res + 8);
                    type = *(u16*)res;
                    switch (type) {
                        case 33:
                            cmd->data.ai.port = *(u16*)(res + 14);
                            req = DupName(req, dns, res + 16);
                            *(u16*)req = 1;
                            req += 2;
                            *(u16*)req = 1;
                            req += 2;
                            info->queryLen = req - info->query;
                            cmd->precallback = NULL;
                            cmd->data.ai.type = 1;
                            IFQueueEnqueueHead(DNSCommand*, &info->queue, cmd);
                            return;
                    }
                    res += len + 10;
                }
                break;
            case 1:
                result = 0;
                res = ans;
                for (i = 0; i < dns->ancount; i++) {
                    res = SkipName(res, end);
                    len = *(u16*)(res + 8);
                    type = *(u16*)res;
                    switch (type) {
                        case 1:
                            if (info->datalen < 140) {
                                memmove(info->data, res + 10, 4);
                                info->data += 4;
                                info->datalen += 4;
                                result += 4;
                            }
                            break;
                        case 5:
                            if (cmd->data.ai.cname) {
                                CopyName(dns, res + 10 + len, res + 10, cmd->data.ai.cname, 256);
                            }
                            break;
                    }
                    res += len + 10;
                }
                break;
            case 35:
                break;
        }
    }

    if (type == 33) {
        cmd->data.ai.type = 1;
        if (cmd->data.ai.port == 0 && cmd->data.ai.servName) {
            if (stricmp(cmd->data.ai.servName, "sip") == 0) {
                cmd->data.ai.port = 5060;
            } else if (stricmp(cmd->data.ai.servName, "sips") == 0) {
                cmd->data.ai.port = 5061;
            }
        }
        IFQueueEnqueueHead(DNSCommand*, &info->queue, cmd);
        return;
    }

    if (cmd->result) {
        *cmd->result = result;
    }
    if (cmd->data.ai.callback) {
        cmd->data.ai.callback(cmd->info, result);
    }
}

// Range: 0x2730 -> 0x2B2C
int SOGetAddrInfoAsync(const char* nodeName /* r25 */, const char* servName /* r28 */, const SOAddrInfo* hints /* r30 */, DNSCommand* cmd /* r31 */, u8* addrList /* r20 */, DNSCallback callback /* r1+0x1C */, int* result /* r22 */) {
    // Local variables
    int rc; // r29
    int doNode; // r23
    int doServ; // r21
    int numeric; // r24
    u16 type; // r27
    int sockType; // r26

    // References
    // -> struct SOResolver __SOResolver;

    type = 0;
    sockType = 0;
    cmd->data.ai.cname = NULL;

    if (hints) {
        switch (hints->family) {
            case 0:
            case 2:
                break;
            default:
                rc = -303;
                goto Exit;
        }
        switch (hints->sockType) {
            case 0:
                break;
            case 1:
            case 2:
                sockType = hints->sockType;
                break;
            default:
                rc = -307;
                goto Exit;
        }
        switch (hints->protocol) {
            case 0:
                break;
            case 6:
                sockType = 1;
                break;
            case 17:
                sockType = 2;
                break;
            default:
                rc = -307;
                goto Exit;
        }
    }

    doNode = (nodeName && *nodeName != '\0');
    doServ = (servName && *servName != '\0');

    if (!doNode) {
        if (hints && (hints->flags & 4)) {
            rc = -305;
            goto Exit;
        }
        if (hints && (hints->flags & 1)) {
            nodeName = "0.0.0.0";
        } else {
            nodeName = "127.0.0.1";
        }
    } else if (256 <= strlen(nodeName)) {
        rc = -305;
        goto Exit;
    }

    if (SOInetPtoN(2, nodeName, addrList) == 1) {
        numeric = TRUE;
        rc = 4;
    } else {
        numeric = FALSE;
        if (hints && (hints->flags & 4)) {
            rc = -305;
            goto Exit;
        }
    }

    if (!doServ) {
        if (hints && (hints->flags & 8)) {
            rc = -305;
            goto Exit;
        }
        if (!numeric) {
            type = 1;
        }
        cmd->data.ai.port = 0;
    } else {
        if (isdigit(*servName)) {
            cmd->data.ai.port = atoi(servName);
        } else {
            cmd->data.ai.port = 0;
            if (hints && (hints->flags & 8)) {
                rc = -305;
                goto Exit;
            }
        }
        if (sockType == 0) {
            if (!numeric && cmd->data.ai.port == 0) {
                type = 35;
            } else if (stricmp(servName, "sip") == 0) {
                sockType = 2;
            } else if (stricmp(servName, "sips") == 0) {
                sockType = 1;
            } else {
                rc = -306;
                goto Exit;
            }
        }
        if (numeric) {
            if (cmd->data.ai.port == 0) {
                if (stricmp(servName, "sip") == 0) {
                    cmd->data.ai.port = 5060;
                } else if (stricmp(servName, "sips") == 0) {
                    cmd->data.ai.port = 5061;
                } else {
                    rc = -306;
                    goto Exit;
                }
            }
        } else if (cmd->data.ai.port != 0) {
            type = 1;
        } else if (type == 0) {
            type = 33;
        }
    }

    if (type == 0) {
        goto Exit;
    }

    cmd->func = 4;
    cmd->precallback = PreGetAddrInfo;
    cmd->callback = GetAddrInfoCallback;
    cmd->result = (s32*)result;
    cmd->data.ai.nodeName = nodeName;
    cmd->data.ai.servName = servName;
    cmd->data.ai.type = type;
    cmd->data.ai.sockType = sockType;
    cmd->data.ai.addrList = addrList;
    cmd->data.ai.callback = callback;
    if (doNode && hints && (hints->flags & 2)) {
        cmd->data.ai.cname = SOAlloc(9, 256);
        if (cmd->data.ai.cname == NULL) {
            rc = -304;
            goto Exit;
        }
        strcpy(cmd->data.ai.cname, nodeName);
    } else {
        cmd->data.ai.cname = NULL;
    }
    DNSGo(&__SOResolver.info, cmd);
    return 0;

Exit:
    if (result) {
        *result = rc;
    }
    return rc;
}

// Range: 0x2B2C -> 0x2D74
int SOGetAddrInfo(const char* nodeName /* r1+0x8 */, const char* servName /* r1+0xC */, const SOAddrInfo* hints /* r1+0x10 */, SOAddrInfo** res /* r27 */) {
    // Local variables
    int result; // r1+0xE0
    DNSCommand cmd; // r1+0xA4
    u8 addrList[140]; // r1+0x18
    BOOL enabled; // r26
    int offset; // r30
    SOAddrInfo* ai; // r31
    SOAddrInfo* next; // r28
    SOSockAddrIn* sockAddr; // r29

    // References
    // -> struct SOResolver __SOResolver;

    if (res) {
        *res = NULL;
    }
    SOGetAddrInfoAsync(nodeName, servName, hints, &cmd, addrList, SyncCallback, &result);
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&__SOResolver.info.queueThread);
    }
    OSRestoreInterrupts(enabled);

    if (result <= 0) {
        if (cmd.data.ai.cname) {
            SOFree(9, cmd.data.ai.cname, 256);
        }
        switch (result) {
            case -203:
            case 0:
                return -305;
            case -204:
            case -202:
            case -201:
            default:
                return -302;
        }
    }

    offset = result - 4;
    result = 0;
    for (next = NULL; 0 <= offset; next = ai, offset -= 4) {
        ai = SOAlloc(10, sizeof(SOAddrInfo));
        if (ai) {
            ai->flags = 0;
            ai->family = 2;
            ai->sockType = cmd.data.ai.sockType;
            ai->protocol = 0;
            ai->addrLen = 8;
            if (offset == 0) {
                ai->canonName = cmd.data.ai.cname;
                cmd.data.ai.cname = NULL;
            } else {
                ai->canonName = NULL;
            }
            ai->next = next;
            ai->addr = SOAlloc(8, 8);
            if (ai->addr) {
                sockAddr = ai->addr;
                sockAddr->len = 8;
                sockAddr->family = 2;
                sockAddr->port = cmd.data.ai.port;
                memmove(&sockAddr->addr, addrList + offset, 4);
            } else {
                result = -304;
                SOFreeAddrInfo(ai);
                ai = NULL;
                if (cmd.data.ai.cname) {
                    SOFree(9, cmd.data.ai.cname, 256);
                }
                break;
            }
        } else {
            result = -304;
            SOFreeAddrInfo(next);
            ai = NULL;
            if (cmd.data.ai.cname) {
                SOFree(9, cmd.data.ai.cname, 256);
            }
            break;
        }
    }
    *res = ai;
    return result;
}

// Range: 0x2D74 -> 0x2E08
void SOFreeAddrInfo(SOAddrInfo* head /* r29 */) {
    // Local variables
    SOAddrInfo* ai; // r31
    SOAddrInfo* next; // r30

    if (head) {
        for (ai = head; ai; ai = next) {
            if (ai->addr) {
                SOFree(8, ai->addr, ((SOSockAddrIn*)ai->addr)->len);
            }
            if (ai->canonName) {
                SOFree(9, ai->canonName, 256);
            }
            next = ai->next;
            SOFree(10, ai, sizeof(SOAddrInfo));
        }
    }
}

// Range: 0x2E08 -> 0x2F48
static s32 PreGetNameInfo(DNSInfo* info /* r29 */, DNSCommand* cmd /* r1+0xC */) {
    // Local variables
    const SOSockAddrIn* sockAddr; // r26
    const u8* addr; // r25
    DNSHeader* dns; // r30
    u8* opt; // r31
    u8* count; // r27
    int i; // r28

    sockAddr = cmd->data.ni.sa;
    addr = (const u8*)&sockAddr->addr;

    dns = (DNSHeader*)info->query;
    dns->flags = 0;
    if (!(info->flag & 3)) {
        dns->flags |= 0x100;
    }
    dns->qdcount = 1;
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    opt = info->query + sizeof(DNSHeader);
    for (i = 3; 0 <= i; i--) {
        count = opt++;
        *count = sprintf((char*)opt, "%d", addr[i]);
        opt += *count;
    }
    *opt++ = 7;
    memmove(opt, "in-addr", 7);
    opt += 7;
    *opt++ = 4;
    memmove(opt, "arpa", 4);
    opt += 4;
    *opt++ = 0;
    *(u16*)opt = 12;
    opt += 2;
    *(u16*)opt = 1;
    opt += 2;
    info->queryLen = opt - info->query;

    info->data = NULL;
    info->datalen = 0;
    return 0;
}

// Range: 0x2F48 -> 0x30A0
static void GetNameInfoCallback(DNSCommand* cmd /* r30 */, s32 result /* r26 */) {
    // Local variables
    DNSInfo* info; // r29
    DNSHeader* dns; // r25
    u8* res; // r31
    u8* end; // r24
    u8* ans; // r28
    int i; // r27
    u16 len; // r23
    u16 type; // r21
    char* name; // r22

    ASSERTLINE(2236, cmd);
    info = cmd->info;
    if (0 <= result) {
        ASSERTLINE(2245, info);
        dns = (DNSHeader*)info->response;
        end = &info->response[result];
        ans = info->response + sizeof(DNSHeader);
        for (i = 0; i < dns->qdcount; i++) {
            ans = SkipName(ans, end);
            ans = ans + 4;
        }

        result = 0;
        res = ans;
        for (i = 0; i < dns->ancount; i++) {
            res = SkipName(res, end);
            len = *(u16*)(res + 8);
            type = *(u16*)res;
            switch (type) {
                case 12:
                    name = CopyName(dns, res + 10 + len, res + 10, cmd->data.ni.node, cmd->data.ni.nodeLen);
                    if (name) {
                        result = name - cmd->data.ni.node;
                    }
                    break;
            }
            res += len + 10;
        }
    }
    if (cmd->result) {
        *cmd->result = result;
    }
    OSWakeupThread(&info->queueThread);
}

// Range: 0x30A0 -> 0x32D0
int SOGetNameInfo(void* sa /* r20 */, char* node /* r30 */, unsigned int nodeLen /* r25 */, char* service /* r26 */, unsigned int serviceLen /* r27 */, int flags /* r28 */) {
    // Local variables
    DNSCommand cmd; // r1+0x24
    s32 result; // r1+0x20
    int doService; // r24
    int doNode; // r23
    BOOL enabled; // r22
    const SOSockAddrIn* sockAddr; // r31
    u16 port; // r29
    char* dot; // r21

    // References
    // -> struct SOResolver __SOResolver;

    sockAddr = sa;
    if (sockAddr->family != 2) {
        return -303;
    }

    doService = (serviceLen && service);
    doNode = (nodeLen && node);
    if (!doService && !doNode) {
        return -305;
    }

    if (doService) {
        port = sockAddr->port;
        if (flags & 8) {
            snprintf(service, serviceLen, "%d", port);
        } else if (port == 5060) {
            snprintf(service, serviceLen, "sip");
        } else {
            snprintf(service, serviceLen, "%d", port);
        }
    }

    if (!doNode) {
        return 0;
    }

    if (flags & 2) {
        if (SOInetNtoP(sockAddr->family, (void*)&sockAddr->addr, node, nodeLen) == NULL) {
            return -303;
        }
        return 0;
    }

    cmd.func = 5;
    cmd.precallback = PreGetNameInfo;
    cmd.callback = GetNameInfoCallback;
    cmd.result = &result;
    cmd.data.ni.sa = sa;
    cmd.data.ni.node = node;
    cmd.data.ni.nodeLen = nodeLen;
    DNSGo(&__SOResolver.info, &cmd);

    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&__SOResolver.info.queueThread);
    }
    OSRestoreInterrupts(enabled);

    if (0 < result) {
        if ((flags & 1) && (dot = strchr(node, '.'))) {
            *dot = '\0';
        }
        return 0;
    }

    if (flags & 4) {
        return -305;
    }
    if (SOInetNtoP(sockAddr->family, (void*)&sockAddr->addr, node, nodeLen) == NULL) {
        return -303;
    }
    return 0;
}
