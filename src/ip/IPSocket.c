#include <dolphin/private/ip.h>
#include <dolphin/ip/IPArp.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

static SOAllocFunc Alloc = NULL;
static SOFreeFunc Free = NULL;
static u32 Allocated = 0;

#define SO_TABLE_NUM 256
static SONode SocketTable[SO_TABLE_NUM];
static IFQueue LingerQueue;
static SOSockAddrIn SockAnyIn = { 8, 2, 0, { 0 } };
static u8* TimeWaitBuf = NULL;
static s32 TimeWaitBufSize = 0;
static u8* ReassemblyBuffer = NULL;
static s32 ReassemblyBufferSize = 0;
static s32 State = 0;
static u32 Flag = 0;
static s32 Mtu = 0;
static s32 Rwin = 0;
static OSTime R2 = 0;
static s32 UdpSendBuff = 0;
static s32 UdpRecvBuff = 0;

static OSThreadQueue CleaningQueue;
static OSThreadQueue PollingQueue;
static BOOL LowInitialized;
static BOOL Initialized;

static BOOL OnReset(BOOL);
static OSResetFunctionInfo ResetFunctionInfo = { &OnReset, 110, NULL, NULL };

static void LingerCallback(TCPInfo* info, s32);
static int __SOClose(int s);
static int __SOSetSockOpt(int s, int level, int optname, void* optval, int optlen);

void* SOAlloc(u32 name, s32 size) {
    void* ptr;
    BOOL enabled;

    ASSERTLINE(303, Alloc);
    
    ptr = (*Alloc)(name, size);
    if (ptr != NULL) {
        enabled = OSDisableInterrupts();
        Allocated += size;
        OSRestoreInterrupts(enabled);
    }

    return ptr;
}

void SOFree(u32 name, void* ptr, s32 size) {
    BOOL enabled;

    ASSERTLINE(321, Free);

    if (ptr != NULL) {
        (*Free)(name, ptr, size);
        enabled = OSDisableInterrupts();
        Allocated -= size;

        if (Allocated == 0 && State == 2) {
            OSWakeupThread(&CleaningQueue);
        }

        OSRestoreInterrupts(enabled);
    }
}

u32 SONtoHl(u32 netlong) {
    return netlong;
}

u16 SONtoHs(u16 netshort) {
    return netshort;
}

u32 SOHtoNl(u32 hostlong) {
    return hostlong;
}

u16 SOHtoNs(u16 hostshort) {
    return hostshort;
}

int SOInetAtoN(const char* cp, SOInAddr* inp) {
    u8 addr[4];

    if (IPAtoN(cp, inp ? (u8*)&inp->addr : addr) != NULL) {
        return TRUE;
    }

    return FALSE;
}

char* SOInetNtoA(SOInAddr in) {
    return IPNtoA((u8*)&in);
}

int SOInetPtoN(int af, const char* src, void* dst) {
    if (af == 2) {
        if (IPAtoN(src, (u8*)dst)) {
            return TRUE;
        }

        return FALSE;
    }

    return -5;
}

char* SOInetNtoP(int af, void* src, char* dst, u32 len) {
    const u8* addr;

    addr = (const u8*)src;
    if (af == 2 && dst != NULL && len >= 16) {
        sprintf(dst, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
        return dst;
    }

    return NULL;
}

static struct SONode* GetNode(int s, IPInfo** pinfo) {
    SONode* node;
    IPInfo* info;
    IPInfo* next;
    TCPInfo* tcp;
    BOOL enabled;
    IFQueue queue;

    queue.next = queue.prev = NULL;
    enabled = OSDisableInterrupts();
    
    /* Find any TCP packets which are unused */
    IFQueueIterator(IPInfo*, &LingerQueue, info, next) {
        tcp = (TCPInfo*)info;
        if (tcp->node == NULL || ((SONode*)tcp->node)->ref == 0) {
            IFQueueDequeueEntry(IPInfo*, &LingerQueue, info);
            IFQueueEnqueueTail(IPInfo*, &queue, info);
        }
    }

    OSRestoreInterrupts(enabled);

    /* Free all unused TCP packets */
    while (queue.next != NULL) {
        IFQueueDequeueHead(IPInfo*, &queue, info);

        tcp = (TCPInfo*)info;
        SOFree(2, tcp->recvData, tcp->recvBuff);
        SOFree(1, tcp->sendData, tcp->sendBuff);
        SOFree(0, tcp, sizeof(TCPInfo));
    }

    node = NULL;
    enabled = OSDisableInterrupts();
    if (s >= 0 && s < SO_TABLE_NUM) {
        node = &SocketTable[s];
        if (node->ref <= 0 || node->info == NULL) {
            node = NULL;
        } else {
            node->ref++;
            if (pinfo != NULL) {
                *pinfo = node->info;
            }
        }
    }
    OSRestoreInterrupts(enabled);
    return node;
}

static void PutNode(SONode* node) {
    BOOL enabled;
    IPInfo* info;
    TCPInfo* tcp;
    UDPInfo* udp;
    u8 proto;

    ASSERTLINE(538, node);

    proto = 0;
    info = NULL;
    enabled = OSDisableInterrupts();
    ASSERTLINE(542, 0 < node->ref);
    if (--node->ref == 0 && node->info != NULL) {
        info = node->info;
        node->info = NULL;
        proto = node->proto;
        node->proto = 0;
    }
    OSRestoreInterrupts(enabled);

    if (info != NULL) {
        switch (proto) {
            case IP_PROTO_UDP:
                udp = (UDPInfo*)info;
                SOFree(5, udp->recvRing, udp->recvBuff);
                SOFree(4, udp->sendData, udp->sendBuff);
                SOFree(3, udp, sizeof(UDPInfo));
                break;
            case IP_PROTO_TCP:
                tcp = (TCPInfo*)info;
                SOFree(2, tcp->recvData, tcp->recvBuff);
                SOFree(1, tcp->sendData, tcp->sendBuff);
                SOFree(0, tcp, sizeof(TCPInfo));
                break;
            default:
                OSPanic(__FILE__, 569, "PutNode: unknown proto");
                break;
        }
    }
}

SOResolver __SOResolver;

int SOSetResolver(const SOInAddr* dns1, const SOInAddr* dns2) {
    if (State != 1) {
        return -39;
    }

    DNSClose(&__SOResolver.info);
    DNSOpen2(&__SOResolver.info, (const u8*)dns1, (const u8*)dns2);
    __SOResolver.info.flag |= 0x4;
    return 0;
}

int SOGetResolver(SOInAddr* dns1, SOInAddr* dns2) {
    BOOL enabled;
    int rc;

    enabled = OSDisableInterrupts();
    if (State != 1) {
        rc = -39;
    } else {
        if (dns1 != NULL) {
            memcpy(dns1, __SOResolver.info.dns1, sizeof(__SOResolver.info.dns1));
        }

        if (dns2 != NULL) {
            memcpy(dns2, __SOResolver.info.dns2, sizeof(__SOResolver.info.dns2));
        }

        rc = 0;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

static void LcpHandler(PPPConf* conf) {
    if (conf->state == 0 && State == 2) {
        OSWakeupThread(&CleaningQueue);
    }
}

static void DhcpHandler(int state) {
    u8 prev1[4];
    u8 prev2[4];
    u8 dns[8];

    switch (state) {
        case 3:
            if (SOGetResolver((SOInAddr*)prev1, (SOInAddr*)prev2) == 0) {
                if (IPEQ(prev1, IPAddrAny) && IPEQ(prev2, IPAddrAny)) {
                    DHCPGetOpt(DHCP_OPT_DNS, dns, sizeof(dns));
                    SOSetResolver((SOInAddr*)dns, (SOInAddr*)&dns[4]);
                } else {
                    SOSetResolver((SOInAddr*)prev1, (SOInAddr*)prev2);
                }
            }
            break;
        case 0:
            IPSetMtu(0, Mtu);
            if (State == 2) {
                OSWakeupThread(&CleaningQueue);
            }
            break;
    }
}

void SOInit(void) {
    if (!Initialized) {
        Initialized = TRUE;
        OSRegisterResetFunction(&ResetFunctionInfo);
    }

    IFInit(4);
    if (State == 0) {
        if (SOGetHostID() != SO_INADDR_ANY || DHCPGetStatus(0) != 0) {
            LowInitialized = TRUE;
        } else {
            IFMute(TRUE);
        }
    }
}

int SOStartup(const SOConfig* config) {
    SOHostEnt* ent = &__SOResolver.ent;
    s32 mtu;

    if (config->vendor != 0 || config->version != 0x0100) {
        return -28;
    }

    if (!IFInit(4)) {
        return -28;
    }

    if (State  != 0) {
        return -28;
    }

    if (0 < config->mtu) {
        mtu = (SO_GET_CONFIG_MTU(config) < 68) ? 68 : SO_GET_CONFIG_MTU(config);
    } else {
        mtu = SO_MTU_MAX;
    }

    Mtu = mtu;
    IPSetMtu(0, mtu);

    if (config->rwin > 0) {
        Rwin = config->rwin < 28 ? 28 : config->rwin;
    } else {
        Rwin = 0;
    }

    if (0 < config->r2) {
        R2 = config->r2;
    } else {
        R2 = OSSecondsToTicks((OSTime)100); // default timeout is 100 seconds
    }

    UdpSendBuff = config->udpSendBuff;
    if (UdpSendBuff <= 0) {
        UdpSendBuff = 1472;
    }

    if (UdpSendBuff < 556) {
        UdpSendBuff = 556;
    }
    

    UdpRecvBuff = config->udpRecvBuff;
    if (UdpRecvBuff <= 0) {
        UdpRecvBuff = UdpSendBuff * 3;
    }
    if (UdpRecvBuff < 556) {
        UdpRecvBuff = 556;
    }

    OSInitThreadQueue(&CleaningQueue);
    OSInitThreadQueue(&PollingQueue);

    Alloc = config->alloc;
    Free = config->free;
    Flag = config->flag;

    if (!LowInitialized) {
        if (config->timeWaitBuffer) {
            TimeWaitBufSize = config->timeWaitBuffer;
            TimeWaitBuf = SOAlloc(6, TimeWaitBufSize);
            TCPSetTimeWaitBuffer(TimeWaitBuf, TimeWaitBufSize);
        }

        if (config->reassemblyBuffer) {
            ReassemblyBufferSize = config->reassemblyBuffer;
            ReassemblyBuffer = SOAlloc(7, ReassemblyBufferSize);
            IPSetReassemblyBuffer(ReassemblyBuffer, ReassemblyBufferSize, UdpSendBuff + 20);
        }

        IPClearConfigError(0);
    }

    if (!LowInitialized) {
        if ((Flag & 2) != 0) {
            Flag &= ~0x8001;
            PPPoEInit(&__IFDefault, config->serviceName);
            if (PPPInit(&__IFDefault, &PPPLcpConf, &PPPIpcpConf, config->peerid, config->passwd) == 0) {
                goto fail;
            }
            PPPLcpConf.callback = &LcpHandler;
        } else if ((Flag & 1) != 0) {
            if (DHCPStartupEx(&DhcpHandler, config->rdhcp, config->hostName) == 0) {
                LowInitialized = TRUE;
            }

            DHCPAuto(0);
        } else {
            if (config->addr.addr != 0) {
                if (SOGetHostID() == SO_INADDR_ANY) {
                    IPInitRoute((const u8*)&config->addr, (const u8*)&config->netmask, (const u8*)&config->router);
                } else {
                    LowInitialized = TRUE;
                }
            }
        }
    }

    if (!LowInitialized) {
        ARPRefresh();
    }

    if ((Flag & 0x8000) != 0) {
        IPAutoConfig();
    }

    LingerQueue.next = LingerQueue.prev = NULL;
    memset(&__SOResolver, 0, sizeof(__SOResolver));
    __SOResolver.zero = NULL;
    ent->name = __SOResolver.name;
    ent->aliases = &__SOResolver.zero;
    ent->addrType = 2;
    ent->length = 4;
    ent->addrList = __SOResolver.ptrList;
    State = 1;
    SOSetResolver(&config->dns1, &config->dns2);
    return 0;

fail:
    if (TimeWaitBuf != NULL) {
        SOFree(6, TimeWaitBuf, TimeWaitBufSize);
    }

    if (ReassemblyBuffer != NULL) {
        SOFree(7, ReassemblyBuffer, ReassemblyBufferSize);
    }

    return -28;
}

int SOCleanup(void) {
    int s;
    SONode* node;
    IPInfo* info;
    IPInfo* next;
    SOLinger linger;
    int optlen;
    BOOL enabled;
    TCPInfo* tcp;

    if (State != 1) {
        return -39;
    }

    State = 2;
    __IPWakeupPollingThreads();

    for (s = 0; s < SO_TABLE_NUM; s++) {
        node = &SocketTable[s];

        if (node->ref != 0) {
            switch (node->proto) {
                case IP_PROTO_UDP:
                    __SOClose(s);
                    break;
                case IP_PROTO_TCP:
                    optlen = 8;
                    linger.onoff = 1;
                    linger.linger = 0;
                    __SOSetSockOpt(s, 0xFFFF, 0x80, &linger, optlen);
                    __SOClose(s);
                    break;
            }
        }
    }

    IFQueueIterator(IPInfo*, &TCPInfoQueue, info, next) {
        tcp = (TCPInfo*)info;

        if (tcp->closeCallback == &LingerCallback) {
            TCPCancel(tcp);
        }
    }

    GetNode(-1, NULL);

    if ((Flag & 0x8000) != 0) {
        IPAutoStop();
    }

    DNSClose(&__SOResolver.info);

    if (!LowInitialized) {
        if ((Flag & 2) != 0) {
            PPPClose(&PPPIpcpConf);
            enabled = OSDisableInterrupts();
            while (PPPGetState(&PPPLcpConf) != 0) {
                OSSleepThread(&CleaningQueue);
            }
            OSRestoreInterrupts(enabled);
        } else if ((Flag & 1) != 0) {
            enabled = OSDisableInterrupts();
            DHCPCleanup();
            while (DHCPGetStatus(0) != 0) {
                OSSleepThread(&CleaningQueue);
            }
            OSRestoreInterrupts(enabled);
        } else {
            IPInitRoute(0, 0, 0);
            IPSetBroadcastAddr(&__IFDefault, IPLimited);
        }
    }

    if (TimeWaitBuf != NULL) {
        SOFree(6, TimeWaitBuf, TimeWaitBufSize);
    }

    if (ReassemblyBuffer != NULL) {
        IPSetReassemblyBuffer(NULL, 0, UdpSendBuff + 20);
        SOFree(7, ReassemblyBuffer, ReassemblyBufferSize);
    }

    enabled = OSDisableInterrupts();
    while (Allocated != 0) {
        OSSleepThread(&CleaningQueue);
    }
    OSRestoreInterrupts(enabled);
    ASSERTLINE(996, Allocated == 0);

    if (!LowInitialized) {
        IFMute(TRUE);
        ARPRefresh();
    }

    State = 0;
    return 0;
}

static s32 GetRwin(void) {
    s32 mtu;

    if (Rwin != 0) {
        return Rwin;
    }

    IPGetMtu(0, &mtu);
    return (mtu - 40) * 2;
}

int SOSocket(int af, int type, int protocol) {
    BOOL enabled;
    int socket;
    SONode* node;
    s32 rc;
    TCPInfo* tcp;
    UDPInfo* udp;
    void* sendbuf;
    void* recvbuf;
    s32 rwin;

    tcp = NULL;
    udp = NULL;
    sendbuf = NULL;
    recvbuf = NULL;
    rc = 0;

    if (State != 1) {
        return -39;
    }

    if (af != 2) {
        return -5;
    }

    if (protocol != 0) {
        return -68;
    }

    GetNode(-1, NULL);
    node = NULL;
    enabled = OSDisableInterrupts();
    for (socket = 0; socket < SO_TABLE_NUM; socket++) {
        node = &SocketTable[socket];
        if (node->ref == 0) {
            ASSERTLINE(1087, node->info == NULL);
            node->ref = 2;
            break;
        }
    }
    OSRestoreInterrupts(enabled);

    if (node == NULL) {
        return -33;
    }

    rwin = GetRwin();
    switch (type) {
        case 1:
            tcp = (TCPInfo*)SOAlloc(0, sizeof(TCPInfo));
            sendbuf = SOAlloc(1, rwin);
            recvbuf = SOAlloc(2, rwin);
            rc = TCPOpen(tcp, sendbuf, rwin, recvbuf, rwin);
            if (rc >= 0) {
                TCPSetTimeout(tcp, R2);
            }
            break;
        case 2:
            udp = (UDPInfo*)SOAlloc(3, sizeof(UDPInfo));
            sendbuf = SOAlloc(4, UdpSendBuff);
            recvbuf = SOAlloc(5, UdpRecvBuff);
            rc = (0, UDPOpen(udp, recvbuf, UdpRecvBuff)); // permuter: comma expression fixes release regalloc (type/sendbuf swap)
            if (rc >= 0) {
                rc = UDPSetSendBuff(udp, sendbuf, UdpSendBuff);
            }
            break;
        default:
            PutNode(node);
            PutNode(node);
            return -69;
    }

    if (rc < 0) {
        switch (type) {
            case 1:
                SOFree(0, tcp, sizeof(TCPInfo));
                SOFree(1, sendbuf, rwin);
                SOFree(2, recvbuf, rwin);
                break;
            case 2:
                SOFree(3, udp, sizeof(UDPInfo));
                SOFree(4, sendbuf, UdpSendBuff);
                SOFree(5, recvbuf, UdpRecvBuff);
                break;
        }

        PutNode(node);
        PutNode(node);
        return -49;
    }

    node->flag = 0;
    OSInitMutex(&node->mutexRead);
    OSInitMutex(&node->mutexWrite);

    switch (type) {
        case 1:
            tcp->node = node;
            node->proto = IP_PROTO_TCP;
            node->info = &tcp->pair;
            break;
        case 2:
            node->proto = IP_PROTO_UDP;
            node->info = &udp->pair;
            break;
    }

    PutNode(node);
    return socket;
}

static void LingerCallback(TCPInfo* info, s32) {
    SONode* node;

    node = (SONode*)info->node;
    if (node != NULL) {
        ASSERTLINE(1178, 0 < node->ref);
        node->ref--;
    }

    IFQueueEnqueueTail(IPInfo*, &LingerQueue, &info->pair);
}

static void LingerTimeout(OSAlarm* alarm, OSContext*) {
    TCPInfo* tcp;

    tcp = (TCPInfo*)(((u8*)alarm) - offsetof(TCPInfo, lingerAlarm));
    TCPCancel(tcp);
}

static int __SOClose(int s) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    TCPInfo* log;
    UDPInfo* udp;
    SOLinger linger;
    int optlen;
    BOOL enabled;
    s32 rc;
    IFQueue queue;

    rc = 0;
    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    ASSERTLINE(1211, 0 < node->ref);
    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            rc = UDPClose(udp);
            ASSERTLINE(1218, 0 <= rc);
            node->ref--;
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            optlen = 8;
            rc = TCPGetSockOpt(tcp, 0xFFFF, 0x80, &linger, &optlen);
            ASSERTLINE(1226, 0 <= rc);

            queue.next = queue.prev = NULL;
            enabled = OSDisableInterrupts();
            
            while (tcp->queueBacklog.next != NULL) {
                IFQueueDequeueHeadLINK(TCPInfo*, &tcp->queueBacklog, linkLog, log);
                log->logging = NULL;
                TCPCancel(log);
                IFQueueEnqueueTailLINK(TCPInfo*, &queue, linkLog, log);
            }

            while (tcp->queueCompleted.next != NULL) {
                IFQueueDequeueHeadLINK(TCPInfo*, &tcp->queueCompleted, linkLog, log);
                log->logging = NULL;
                TCPCancel(log);
                IFQueueEnqueueTailLINK(TCPInfo*, &queue, linkLog, log);
            }

            if (TCPGetStatus(tcp) == TCP_STATE_LISTEN) {
                rc = TCPCancel(tcp);
                ASSERTLINE(1252, TCPGetStatus(tcp) != TCP_STATE_LISTEN);
                if (tcp->accepting > 0) {
                    OSWakeupThread(&tcp->queueThread);
                }
                node->ref--;
            } else if ((node->flag & 0x4) != 0) {
                rc = TCPCancel(tcp);
                node->ref--;
            } else if (linger.onoff) {
                if (linger.linger <= 0) {
                    rc = TCPCancel(tcp);
                } else {
                    OSSetAlarm(&tcp->lingerAlarm, OSSecondsToTicks((OSTime)linger.linger), &LingerTimeout);
                    rc = TCPClose(tcp);
                }

                node->ref--;
            } else {
                OSSetAlarm(&tcp->lingerAlarm, OSSecondsToTicks((OSTime)15), &LingerTimeout);
                rc = TCPCloseAsync(tcp, &LingerCallback, 0);
                if (node->ref == 2) {
                    tcp->node = NULL;
                    node->ref--;
                }
                node->info = NULL;
            }

            OSRestoreInterrupts(enabled);

            while (queue.next != NULL) {
                IFQueueDequeueHeadLINK(TCPInfo*, &queue, linkLog, log);
                SOFree(2, log->recvData, log->recvBuff);
                SOFree(1, log->sendData, log->sendBuff);
                SOFree(0, log, sizeof(TCPInfo));

            }
            
            ASSERTLINE(1318, 0 <= rc);
            break;
        default:
            rc = -8;
            break;
    }

    PutNode(node);

    if (rc < 0) {
        return -8;
    }

    return 0;
}

int SOClose(int s) {
    if (State != 1) {
        return -39;
    }

    return __SOClose(s);
}

static void AcceptCallback(TCPInfo* tcp, s32 result) {
    TCPInfo* logging;

    logging = tcp->logging;
    if (logging != NULL) {
        if (result >= 0) {
            IFQueueDequeueEntryLINK(TCPInfo*, &logging->queueBacklog, linkLog, tcp);
            IFQueueEnqueueTailLINK(TCPInfo*, &logging->queueCompleted, linkLog, tcp);
            OSWakeupThread(&logging->queueThread);
            if (logging->pair.poll > 0) {
                __IPWakeupPollingThreads();
            }
        } else {
            IFQueueDequeueEntryLINK(TCPInfo*, &logging->queueBacklog, linkLog, tcp);
            TCPCancel(tcp);
            TCPOpen(tcp, tcp->sendData, tcp->sendBuff, tcp->recvData, tcp->recvBuff);
            TCPSetTimeout(tcp, R2);
            tcp->logging = logging;
            IFQueueEnqueueTailLINK(TCPInfo*, &logging->queueBacklog, linkLog, tcp);
            TCPAcceptAsync(tcp, logging, &AcceptCallback, 0);
        }
    }
}

static TCPInfo* AddBackLog(TCPInfo* listening) {
    TCPInfo* tcp;
    void* sendbuf;
    s32 sendbufLen;
    void* recvbuf;
    s32 recvbufLen;
    s32 rc;
    BOOL enabled;
    
    ASSERTLINE(1423, listening);
    tcp = SOAlloc(0, sizeof(TCPInfo));
    sendbufLen = listening->sendBuff;
    recvbufLen = listening->recvBuff;
    sendbuf = SOAlloc(1, sendbufLen);
    recvbuf = SOAlloc(2, recvbufLen);
    rc = TCPOpen(tcp, sendbuf, sendbufLen, recvbuf, recvbufLen);
    if (rc >= 0) {
        TCPSetTimeout(tcp, R2);
        enabled = OSDisableInterrupts();

        if (TCPGetStatus(listening) == TCP_STATE_LISTEN) {
            tcp->logging = listening;
            IFQueueEnqueueTailLINK(TCPInfo*, &listening->queueBacklog, linkLog, tcp);
            OSRestoreInterrupts(enabled);
            TCPAcceptAsync(tcp, listening, &AcceptCallback, 0);
            OSRestoreInterrupts(enabled);
            return tcp;
        }

        OSRestoreInterrupts(enabled);
    }

    SOFree(2, recvbuf, recvbufLen);
    SOFree(1, sendbuf, sendbufLen);
    SOFree(0, tcp, sizeof(TCPInfo));
    return NULL;
}

int SOListen(int s, int backlog) {
    SONode* node;
    IPInfo* info;
    TCPInfo* listening;
    s32 rc;
    
    if (State != 1) {
        return -39;
    }

    if (backlog < 1) {
        backlog = 1;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            rc = -63;
            break;
        case IP_PROTO_TCP:
            listening = (TCPInfo*)info;
            rc = TCPListen(listening, NULL, NULL, NULL, 0);
            switch (rc) {
                case 0:
                    while (0 < backlog--) {
                        if (AddBackLog(listening) == NULL) {
                            break;
                        }
                    }
                    break;
                case -7:
                    rc = -42;
                    break;
                case -5:
                default:
                    rc = -28;
                    break;
            }
            break;
        default:
            rc = -8;
            break;
    }

    PutNode(node);
    return rc;
}

int SOAccept(int s, void* sockAddr) {
    BOOL enabled;
    SONode* node;
    IPInfo* info;
    TCPInfo* listening;
    TCPInfo* tcp;
    int socket;
    s32 rc;
    s32 state;
    SONode* connected;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(1586, sockAddr == NULL || sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockAddr)->len);
    if (sockAddr != NULL && ((SOSockAddr*) sockAddr)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    enabled = OSDisableInterrupts();
    switch (info->proto) {
        case IP_PROTO_UDP:
            rc = -63;
            break;
        case IP_PROTO_TCP:
            listening = (TCPInfo*)info;

        tcp_accept_loop:
            if (TCPGetStatus(listening) != TCP_STATE_LISTEN) {
                rc = -28;
                break;
            }

            listening->accepting++;
            while (TCPGetStatus(listening) == TCP_STATE_LISTEN && listening->queueCompleted.next == NULL) {
                if ((node->flag & 0x4) != 0) {
                    listening->accepting--;
                    rc = -6;
                    goto tcp_accept_end;
                }

                OSSleepThread(&listening->queueThread);
            }

            listening->accepting--;
            if (TCPGetStatus(listening) != TCP_STATE_LISTEN) {
                rc = -13;
                break;
            }

            for (socket = 0; socket < SO_TABLE_NUM; socket++) {
                connected = &SocketTable[socket];
                if (connected->ref == 0) {
                    IFQueueDequeueHeadLINK(TCPInfo*, &listening->queueCompleted, linkLog, tcp);
                    ASSERTLINE(1641, tcp);
                    rc = 0;
                    if (sockAddr != NULL) {
                        rc = TCPGetRemoteSocket(tcp, (IPSocket*)sockAddr);
                    }

                    state = TCPGetStatus(tcp);
                    if ((state != 4 && state != 7) || rc < 0) {
                        TCPCancel(tcp);
                        TCPOpen(tcp, tcp->sendData, tcp->sendBuff, tcp->recvData, tcp->recvBuff);
                        TCPSetTimeout(tcp, R2);
                        tcp->logging = listening;
                        IFQueueEnqueueTailLINK(TCPInfo*, &listening->queueBacklog, linkLog, tcp);
                        TCPAcceptAsync(tcp, listening, &AcceptCallback, 0);
                        goto tcp_accept_loop;
                    } else {
                        connected->flag = node->flag;
                        connected->ref = 1;
                        OSInitMutex(&connected->mutexRead);
                        OSInitMutex(&connected->mutexWrite);
                        connected->proto = IP_PROTO_TCP;
                        connected->info = (IPInfo*)tcp;
                        rc = socket;
                        OSRestoreInterrupts(enabled);
                        AddBackLog(listening);
                        break;
                    }
                }
            }

            if (socket >= SO_TABLE_NUM) {
                rc = -33;
            }
            break;
        default:
            rc = -8;
            break;
    }

tcp_accept_end:
    OSRestoreInterrupts(enabled);
    PutNode(node);
    return rc;
}

int SOBind(int s, void* sockAddr) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    UDPInfo* udp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(1730, sockAddr != NULL && sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockAddr)->len);
    if (sockAddr == NULL || ((SOSockAddr*) sockAddr)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            rc = UDPBind(udp, (IPSocket*)sockAddr);
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            rc = TCPBind(tcp, (IPSocket*)sockAddr);
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    switch (rc) {
        case 0:
            return 0;
        case -13:
            return -5;
        case -5:
            return -3;
        case -12:
        default:
            return -28;
    }
}

int SOConnect(int s, void* sockAddr) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    UDPInfo* udp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(1825, sockAddr != NULL && sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockAddr)->len);
    if (sockAddr == NULL || ((SOSockAddr*) sockAddr)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            if (((SOSockAddr*) sockAddr)->family == 0) {
                sockAddr = &SockAnyIn;
            }
            rc = UDPConnect(udp, (IPSocket*)sockAddr);
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            if ((node->flag & 0x4) == 0) {
                rc = TCPConnect(tcp, (IPSocket*)sockAddr);
            } else {
                rc = TCPConnectAsync(tcp, (IPSocket*)sockAddr, NULL, 0);
                if (rc == 0 && tcp->openCallback != NULL) {
                    rc = -1;
                }
            }
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    switch (rc) {
        case 0:
            return 0;
        case -1:
            return -26;
        case -13:
            return -5;
        case -5:
            return -30;
        case -3:
            return -15;
        case -11:
            return -14;
        case -10:
            return -76;
        case -12:
            return -28;
        case -7:
            return -42;
        case -19:
            return -38;
        default:
            return -40;
    }
}

int SOGetPeerName(int s, void* sockAddr) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    UDPInfo* udp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(1930, sockAddr);
    ASSERTLINE(1931, sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockAddr)->len);
    if (sockAddr == NULL || ((SOSockAddr*) sockAddr)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            rc = UDPGetRemoteSocket(udp, (IPSocket*)sockAddr);
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            rc = TCPGetRemoteSocket(tcp, (IPSocket*)sockAddr);
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    if (rc < 0) {
        return -8;
    }

    if (((SOSockAddrIn*) sockAddr)->port == 0) {
        return -56;
    }

    return 0;
}

int SOGetSockName(int s, void* sockAddr) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    UDPInfo* udp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(2011, sockAddr);
    ASSERTLINE(2012, sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockAddr)->len);
    if (sockAddr == NULL || ((SOSockAddr*) sockAddr)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            rc = UDPGetLocalSocket(udp, (IPSocket*)sockAddr);
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            rc = TCPGetLocalSocket(tcp, (IPSocket*)sockAddr);
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    if (rc < 0) {
        return -8;
    }

    return 0;
}

int SOShutdown(int s, int how) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    switch (how) {
        case 0:
        case 1:
        case 2:
            break;
        default:
            return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            rc = 0;
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            rc = TCPShutdown(tcp, how);
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    switch (rc) {
        case 0:
        case -8:
            return 0;
        case -4:
            return -56;
        case -12:
        default:
            return -28;
    }
}

int SORead(int s, void* buf, int len) {
    return SORecvFrom(s, buf, len, 0, NULL);
}

int SORecv(int s, void* buf, int len, int flags) {
    return SORecvFrom(s, buf, len, flags, NULL);
}

int SORecvFrom(int s, void* buf, int len, int flags, void* sockFrom) {
    SONode* node;
    IPInfo* info;
    UDPInfo* udp;
    TCPInfo* tcp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(2198, sockFrom == NULL || sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockFrom)->len);
    if (sockFrom != NULL && ((SOSockAddr*) sockFrom)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            if (flags & ~(0x2 | 0x4)) {
                PutNode(node);
                return -63;
            }

            OSLockMutex(&node->mutexRead);
            if (node->info == NULL) {
                rc = -8;
            } else {
                if (node->flag & 0x4) {
                    flags |= 0x4;
                }

                udp = (UDPInfo*)info;
                rc = UDPReceiveEx(udp, buf, len, NULL, (IPSocket*)sockFrom, flags);
            }
            OSUnlockMutex(&node->mutexRead);
            break;
        case IP_PROTO_TCP:
            if (flags & ~(0x1 | 0x2 | 0x4)) {
                PutNode(node);
                return -63;
            }

            tcp = (TCPInfo*)info;
            if (sockFrom != NULL) {
                rc = TCPGetRemoteSocket(tcp, (IPSocket*)sockFrom);
                if (rc < 0) {
                    PutNode(node);
                    return -8;
                }
            }

            OSLockMutex(&node->mutexRead);
            if (node->info == NULL) {
                rc = -8;
            } else {
                if (node->flag & 0x4) {
                    flags |= 0x4;
                }

                tcp = (TCPInfo*)info;
                if (!(flags & 0x1)) {
                    rc = TCPReceiveEx(tcp, buf, len, flags);
                } else {
                    rc = TCPReceiveUrgEx(tcp, buf, len, flags);
                }
            }
            OSUnlockMutex(&node->mutexRead);
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    if (rc < 0) {
        switch (rc) {
            case -1:
            case -9:
                rc = -6;
                break;
            case -4:
            case -8:
                rc = -56;
                break;
            case -16:
                rc = -27;
                break;
            case -10:
            case -19:
                rc = -76;
                break;
            case -3:
            case -11:
            case -18:
                rc = -15;
                break;
            default:
                rc = -28;
                break;
        }
    }

    return rc;
}

int SOWrite(int s, void* buf, int len) {
    return SOSendTo(s, buf, len, 0, NULL);
}

int SOSend(int s, void* buf, int len, int flags) {
    return SOSendTo(s, buf, len, flags, NULL);
}

int SOSendTo(int s, void* buf, int len, int flags, void* sockTo) {
    SONode* node;
    IPInfo* info;
    UDPInfo* udp;
    TCPInfo* tcp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    ASSERTLINE(2404, sockTo == NULL || sizeof(SOSockAddrIn) <= ((SOSockAddr*) sockTo)->len);
    if (sockTo != NULL && ((SOSockAddr*) sockTo)->len < sizeof(SOSockAddrIn)) {
        return -28;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            if (flags != 0) {
                PutNode(node);
                return -63;
            }

            OSLockMutex(&node->mutexWrite);
            if (node->info == NULL) {
                rc = -8;
            } else {
                udp = (UDPInfo*)info;
                switch (flags) {
                    case 0:
                        rc = UDPSend(udp, buf, len, (IPSocket*)sockTo);
                        break;
                }
            }
            OSUnlockMutex(&node->mutexWrite);
            break;
        case IP_PROTO_TCP:
            if (flags & ~(0x1 | 0x4)) {
                PutNode(node);
                return -63;
            }

            OSLockMutex(&node->mutexWrite);
            if (node->info == NULL) {
                rc = -8;
            } else {
                tcp = (TCPInfo*)info;
                if (node->flag & 0x4) {
                    flags |= 0x4;
                }

                switch (flags) {
                    case 0:
                        rc = TCPSend(tcp, buf, len);
                        break;
                    case 1:
                        rc = TCPSendUrg(tcp, buf, len);
                        break;
                    case 4:
                        rc = TCPSendNonblock(tcp, buf, len);
                        break;
                    case 5:
                        rc = TCPSendUrgNonblock(tcp, buf, len);
                        break;
                }
            }
            OSUnlockMutex(&node->mutexWrite);
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    if (rc < 0) {
        switch (rc) {
            case -13:
                rc = -5;
                break;
            case -6:
                rc = -17;
                break;
            case -17:
                rc = -35;
                break;
            case -2:
                rc = -40;
                break;
            case -7:
                rc = -42;
                break;
            case -1:
            case -9:
                rc = -6;
                break;
            case -4:
            case -8:
                rc = -56;
                break;
            case -16:
                rc = -27;
                break;
            case -10:
                rc = -76;
                break;
            case -3:
            case -11:
            case -18:
                rc = -15;
                break;
            case -12:
                rc = -28;
                break;
            case -19:
                rc = -38;
                break;
            default:
                rc = -8;
                break;
        }
    }

    return rc;
}

int SOSockAtMark(int s) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    s32 rc;

    if (State != 1) {
        return -39;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            PutNode(node);
            return 0;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            rc = TCPGetUrgOffset(tcp);
            PutNode(node);
            if (rc < 0) {
                return -8;
            }

            if (rc == 1) {
                return 1;
            }

            return 0;
        default:
            PutNode(node);
            return -8;
    }
}

int SOGetSockOpt(int s, int level, int optname, void* optval, int* optlen) {
    SONode* node;
    IPInfo* info;
    UDPInfo* udp;
    TCPInfo* tcp;
    s32 rc;
    s32 buff;

    if (State != 1) {
        return -39;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            if (level == 0xFFFF) {
                switch (optname) {
                    case 0x1001:
                        if (optlen != NULL && sizeof(s32) <= *optlen && optval != NULL) {
                            rc = UDPGetSendBuff(udp, NULL, &buff);
                            if (rc == 0) {
                                *(s32*)optval = buff;
                                *optlen = sizeof(s32);
                            }
                        }
                        goto udp_done;
                    case 0x1002:
                        rc = -12;
                        if (optlen != NULL && sizeof(s32) <= *optlen && optval != NULL) {
                            rc = UDPGetRecvBuff(udp, NULL, &buff);
                            if (rc == 0) {
                                *(s32*)optval = buff;
                                *optlen = sizeof(s32);
                            }
                        }
                        goto udp_done;
                }
            }
            rc = UDPGetSockOpt((UDPInfo*)info, level, optname, optval, optlen);
        udp_done:
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            if (level == 0xFFFF) {
                switch (optname) {
                    case 0x1001:
                        if (optlen != NULL && sizeof(s32) <= *optlen && optval != NULL) {
                            rc = TCPGetSendBuff(tcp, NULL, &buff);
                            if (rc == 0) {
                                *(s32*)optval = buff;
                                *optlen = sizeof(s32);
                            }
                        }
                        goto tcp_done;
                    case 0x1002:
                        rc = -12;
                        if (optlen != NULL && sizeof(s32) <= *optlen && optval != NULL) {
                            rc = TCPGetRecvBuff(tcp, NULL, &buff);
                            if (rc == 0) {
                                *(s32*)optval = buff;
                                *optlen = sizeof(s32);
                            }
                        }
                        goto tcp_done;
                }
            }
            rc = TCPGetSockOpt((TCPInfo*)info, level, optname, optval, optlen);
        tcp_done:
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    switch (rc) {
        case 0:
            return 0;
        case -14:
            return -51;
        default:
            return -28;
    }
}

static int __SOSetSockOpt(int s, int level, int optname, void* optval, int optlen) {
    SONode* node;
    IPInfo* info;
    TCPInfo* tcp;
    UDPInfo* udp;
    s32 rc;

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
            udp = (UDPInfo*)info;
            if (level == 0xFFFF) {
                switch (optname) {
                    case 0x1001: {
                        void* sendData;
                        s32 sendBuff;
                        void* prevData;
                        s32 prevBuff;

                        rc = -12;
                        if (sizeof(s32) <= optlen && optval != NULL) {
                            sendBuff = *(s32*)optval;
                            if (sendBuff < 536) {
                                sendBuff = 536;
                            }
                            sendBuff += 88;

                            sendData = SOAlloc(4, sendBuff);
                            if (sendData != NULL) {
                                rc = UDPGetSendBuff(udp, &prevData, &prevBuff);
                                ASSERTLINE(2798, rc == IP_ERR_NONE);
                                rc = UDPSetSendBuff(udp, sendData, sendBuff);
                                if (rc == 0) {
                                    SOFree(4, prevData, prevBuff);
                                } else {
                                    SOFree(4, sendData, sendBuff);
                                }
                            } else {
                                rc = -7;
                            }
                        }
                        goto udp_done;
                    }
                    case 0x1002: {
                        void* recvData;
                        s32 recvBuff;
                        void* prevData;
                        s32 prevBuff;

                        rc = -12;
                        if (sizeof(s32) <= optlen && optval != NULL) {
                            recvBuff = *(s32*)optval;
                            if (recvBuff < 536) {
                                recvBuff = 536;
                            }

                            recvData = SOAlloc(5, recvBuff);
                            if (recvData != NULL) {
                                rc = UDPGetRecvBuff(udp, &prevData, &prevBuff);
                                ASSERTLINE(2835, rc == IP_ERR_NONE);
                                rc = UDPSetRecvBuff(udp, recvData, recvBuff);
                                if (rc == 0) {
                                    SOFree(5, prevData, prevBuff);
                                } else {
                                    SOFree(5, recvData, recvBuff);
                                }
                            } else {
                                rc = -7;
                            }
                        }
                        goto udp_done;
                    }
                }
            }
            rc = UDPSetSockOpt((UDPInfo*)info, level, optname, optval, optlen);
        udp_done:
            break;
        case IP_PROTO_TCP:
            tcp = (TCPInfo*)info;
            if (level == 0xFFFF) {
                switch (optname) {
                    case 0x1001: {
                        void* sendData;
                        s32 sendBuff;
                        void* prevData;
                        s32 prevBuff;

                        rc = -12;
                        if (sizeof(s32) <= optlen && optval != NULL) {
                            sendBuff = *(s32*)optval;
                            if (sendBuff < 536) {
                                sendBuff = 536;
                            }

                            sendData = SOAlloc(1, sendBuff);
                            if (sendData != NULL) {
                                rc = TCPGetSendBuff(tcp, &prevData, &prevBuff);
                                ASSERTLINE(2884, rc == IP_ERR_NONE);
                                rc = TCPSetSendBuff(tcp, sendData, sendBuff);
                                if (rc == 0) {
                                    SOFree(1, prevData, prevBuff);
                                } else {
                                    SOFree(1, sendData, sendBuff);
                                }
                            } else {
                                rc = -7;
                            }
                        }
                        goto tcp_done;
                    }
                    case 0x1002: {
                        void* recvData;
                        s32 recvBuff;
                        void* prevData;
                        s32 prevBuff;

                        rc = -12;
                        if (sizeof(s32) <= optlen && optval != NULL) {
                            recvBuff = *(s32*)optval;
                            if (recvBuff < 536) {
                                recvBuff = 536;
                            }

                            recvData = SOAlloc(2, recvBuff);
                            if (recvData != NULL) {
                                rc = TCPGetRecvBuff(tcp, &prevData, &prevBuff);
                                ASSERTLINE(2921, rc == IP_ERR_NONE);
                                rc = TCPSetRecvBuff(tcp, recvData, recvBuff);
                                if (rc == 0) {
                                    SOFree(2, prevData, prevBuff);
                                } else {
                                    SOFree(2, recvData, recvBuff);
                                }
                            } else {
                                rc = -7;
                            }
                        }
                        goto tcp_done;
                    }
                }
            }
            rc = TCPSetSockOpt(tcp, level, optname, optval, optlen);
        tcp_done:
            break;
        default:
            PutNode(node);
            return -8;
    }

    PutNode(node);
    switch (rc) {
        case 0:
            return 0;
        case -14:
            return -51;
        case -7:
            return -49;
        default:
            return -28;
    }
}

int SOSetSockOpt(int s, int level, int optname, void* optval, int optlen) {
    if (State != 1) {
        return -39;
    }

    return __SOSetSockOpt(s, level, optname, optval, optlen);
}

int SOFcntl(int s, int cmd, ...) {
    SONode* node;
    IPInfo* info;
    s32 rc;
    va_list marker;
    int arg;

    if (State != 1) {
        return -39;
    }

    node = GetNode(s, &info);
    if (node == NULL || info == NULL) {
        return -8;
    }

    switch (info->proto) {
        case IP_PROTO_UDP:
        case IP_PROTO_TCP:
            switch (cmd) {
                case 3:
                    rc = node->flag;
                    break;
                case 4:
                    va_start(marker, cmd);
                    arg = va_arg(marker, int);
                    va_end(marker);
                    node->flag = arg;
                    rc = 0;
                    break;
                default:
                    rc = -12;
                    break;
            }
            break;
        default:
            rc = -12;
            break;
    }

    PutNode(node);
    if (0 <= rc) {
        return rc;
    }

    return -28;
}

SOHostEnt* SOGetHostByName(const char* name) {
    u8** ptr;
    u8* addr;
    s32 rc;
    SOInAddr inaddr;

    if (SOInetAtoN(name, &inaddr)) {
        return SOGetHostByAddr(&inaddr, 4, 2);
    }

    strncpy(__SOResolver.name, name, 256);
    rc = DNSGetAddr(&__SOResolver.info, name, __SOResolver.addrList, sizeof(__SOResolver.addrList));
    if (0 <= rc) {
        for (ptr = __SOResolver.ptrList, addr = __SOResolver.addrList; 0 < rc; rc -= 4, ptr++, addr += 4) {
            *ptr = addr;
        }
        *ptr = NULL;
        return &__SOResolver.ent;
    }

    return NULL;
}

SOHostEnt* SOGetHostByAddr(void* addr, int len, int type) {
    u8** ptr;
    s32 rc;

    if (len != 4 || type != 2) {
        return NULL;
    }

    memcpy(__SOResolver.addrList, addr, 4);
    ptr = __SOResolver.ptrList;
    *ptr = __SOResolver.addrList;
    ptr++;
    *ptr = NULL;
    rc = DNSGetName(&__SOResolver.info, (const u8*)addr, __SOResolver.name);
    if (0 <= rc) {
        return &__SOResolver.ent;
    }

    return NULL;
}

s32 SOGetHostID(void) {
    s32 addr;

    IPGetAddr(NULL, (u8*)&addr);
    return addr;
}

static void PollTimeout(OSAlarm*, OSContext*) {
    OSWakeupThread(&PollingQueue);
}

void __IPWakeupPollingThreads(void) {
    OSWakeupThread(&PollingQueue);
}

int SOPoll(SOPollFD* fds, u32 nfds, OSTime timeout) {
    u32 i;
    SONode* node;
    int selected;
    SOPollFD* pollfd;
    BOOL enabled;
    OSAlarm alarm;
    s16 revents;
    IPInfo* info;

    if (State != 1) {
        return -39;
    }

    if (nfds > SO_TABLE_NUM) {
        return -28;
    }

    enabled = OSDisableInterrupts();
    for (i = 0; i < nfds; i++) {
        pollfd = &fds[i];
        pollfd->revents = 0;
        node = NULL;
        if (0 <= pollfd->fd && pollfd->fd < SO_TABLE_NUM) {
            node = &SocketTable[pollfd->fd];
            if (node->ref <= 0 || node->info == NULL) {
                node = NULL;
            } else {
                node->ref++;
            }
        }

        if (node != NULL) {
            info = node->info;
            info->poll++;
        }
    }
    OSRestoreInterrupts(enabled);

    if (0 < timeout) {
        OSCreateAlarm(&alarm);
        OSSetAlarm(&alarm, timeout, &PollTimeout);
    }

    enabled = OSDisableInterrupts();
    selected = 0;
    while (State == 1) {
        for (i = 0; i < nfds; i++) {
            pollfd = &fds[i];
            pollfd->revents = 0;
            node = NULL;
            if (0 <= pollfd->fd && pollfd->fd < SO_TABLE_NUM) {
                node = &SocketTable[pollfd->fd];
                if (node->ref <= 0 || node->info == NULL) {
                    node = NULL;
                }
            }

            if (node != NULL) {
                info = node->info;
                revents = pollfd->events | 0x20 | 0x40 | 0x80;
                switch (info->proto) {
                    case IP_PROTO_UDP:
                        revents &= __UDPPoll((UDPInfo*)node->info);
                        break;
                    case IP_PROTO_TCP:
                        revents &= __TCPPoll((TCPInfo*)node->info);
                        break;
                    default:
                        revents = 0;
                        break;
                }

                if (revents) {
                    selected++;
                    pollfd->revents = revents;
                }
            }
        }

        if (0 < selected || timeout == 0 || (0 < timeout && alarm.handler == NULL)) {
            break;
        }

        OSSleepThread(&PollingQueue);
    }
    OSRestoreInterrupts(enabled);

    if (0 < timeout) {
        OSCancelAlarm(&alarm);
    }

    for (i = 0; i < nfds; i++) {
        pollfd = &fds[i];
        if (0 <= pollfd->fd && pollfd->fd < SO_TABLE_NUM) {
            node = &SocketTable[pollfd->fd];
            if (0 < node->ref && node->info != NULL) {
                enabled = OSDisableInterrupts();
                node->info->poll--;
                OSRestoreInterrupts(enabled);
                PutNode(node);
            }
        }
    }

    return selected;
}

static BOOL OnReset(BOOL) {
    State = 3;
    return TRUE;
}
