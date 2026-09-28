#ifndef __DOLPHIN_OS_IP_PPP_H__
#define __DOLPHIN_OS_IP_PPP_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LCPHeader {
    // total size: 0x4
    u8 code; // offset 0x0, size 0x1
    u8 id; // offset 0x1, size 0x1
    u16 len; // offset 0x2, size 0x2
} LCPHeader;

typedef struct CHAPHeader {
    // total size: 0x4
    u8 code; // offset 0x0, size 0x1
    u8 id; // offset 0x1, size 0x1
    u16 len; // offset 0x2, size 0x2
} CHAPHeader;

typedef struct PPPConf PPPConf;
typedef void (*PPPConfCallback)(PPPConf*);
typedef int (*PPPConfRecvCallback)(PPPConf*, LCPHeader*);
typedef int (*PPPConfTransCallback)(PPPConf*);

struct PPPConf {
    // total size: 0xA0
    u16 protocol; // offset 0x0, size 0x2
    int state; // offset 0x4, size 0x4
    u8 id; // offset 0x8, size 0x1
    u8 idTerminate; // offset 0x9, size 0x1
    u8 idReject; // offset 0xA, size 0x1
    u8 idEcho; // offset 0xB, size 0x1
    int rxmit; // offset 0xC, size 0x4
    int configure; // offset 0x10, size 0x4
    int terminate; // offset 0x14, size 0x4
    int failure; // offset 0x18, size 0x4
    u8 data[20]; // offset 0x1C, size 0x14
    u16 len; // offset 0x30, size 0x2
    OSAlarm alarm; // offset 0x38, size 0x28
    IPInterface* interface; // offset 0x60, size 0x4
    PPPConfRecvCallback receiveConfigureRequest; // offset 0x64, size 0x4
    PPPConfRecvCallback receiveConfigureAck; // offset 0x68, size 0x4
    PPPConfRecvCallback receiveConfigureNak; // offset 0x6C, size 0x4
    PPPConfRecvCallback receiveConfigureReject; // offset 0x70, size 0x4
    PPPConfTransCallback up; // offset 0x74, size 0x4
    PPPConfTransCallback down; // offset 0x78, size 0x4
    PPPConfTransCallback started; // offset 0x7C, size 0x4
    PPPConfTransCallback finished; // offset 0x80, size 0x4
    PPPConfCallback callback; // offset 0x84, size 0x4
    IFLink link; // offset 0x88, size 0x8
    u16 mru; // offset 0x90, size 0x2
    u16 auth; // offset 0x92, size 0x2
    u32 magic; // offset 0x94, size 0x4
    u32 remote; // offset 0x98, size 0x4
};

typedef struct PPPAuth {
    // total size: 0x303
    u8 peerIdLen; // offset 0x0, size 0x1
    u8 passwordLen; // offset 0x1, size 0x1
    u8 messageLen; // offset 0x2, size 0x1
    char peerId[256]; // offset 0x3, size 0x100
    char password[256]; // offset 0x103, size 0x100
    char message[256]; // offset 0x203, size 0x100
} PPPAuth;

#define PPP_STATE_INITIAL 0
#define PPP_STATE_STARTING 1
#define PPP_STATE_CLOSED 2
#define PPP_STATE_STOPPED 3
#define PPP_STATE_CLOSING 4
#define PPP_STATE_STOPPING 5
#define PPP_STATE_REQ_SENT 6
#define PPP_STATE_ACK_RCVD 7
#define PPP_STATE_ACK_SENT 8
#define PPP_STATE_OPENED 9

#define PPP_IP 0x0021
#define PPP_IPCP 0x8021
#define PPP_LCP 0xC021
#define PPP_PAP 0xC023
#define PPP_CHAP 0xC223

typedef struct LCPOpt {
    // total size: 0x2
    u8 type; // offset 0x0, size 0x1
    u8 len; // offset 0x1, size 0x1
} LCPOpt;

typedef struct LCPOptPAP {
    // total size: 0x4
    u8 type; // offset 0x0, size 0x1
    u8 len; // offset 0x1, size 0x1
    u16 auth; // offset 0x2, size 0x2
} LCPOptPAP;

typedef struct LCPOptCHAP {
    // total size: 0x6
    u8 type; // offset 0x0, size 0x1
    u8 len; // offset 0x1, size 0x1
    u16 auth; // offset 0x2, size 0x2
    u8 algorithm; // offset 0x4, size 0x1
} LCPOptCHAP;

typedef struct PAPHeader {
    // total size: 0x4
    u8 code; // offset 0x0, size 0x1
    u8 id; // offset 0x1, size 0x1
    u16 len; // offset 0x2, size 0x2
} PAPHeader;

// IPPPP.c
int PPPLayerUp(PPPConf* conf);
int PPPLayerDown(PPPConf* conf);
int PPPLayerStarted(PPPConf* conf);
int PPPLayerFinished(PPPConf* conf);
void PPPInitializeRestartCount(PPPConf* conf);
void PPPZeroRestartCount(PPPConf* conf);
void PPPSetState(PPPConf* conf, int state);
int PPPGetState(PPPConf* conf);
void PPPIn(IPInterface* interface, u8* ppp, s32 len, u32 flag);
void PPPOpen(PPPConf* conf);
void PPPUp(PPPConf* conf);
void PPPDown(PPPConf* conf);
void PPPClose(PPPConf* conf);
void PPPTimeout(OSAlarm* alarm, OSContext* context);
u16 PPPDeleteOpt(u8* data, u16 len, LCPOpt* opt);
u16 PPPInsertOpt(u8* data, u16 len, LCPOpt* at, LCPOpt* opt);
int PPPInit(IPInterface* interface, PPPConf* lcp, PPPConf* ipcp, const char* peerid, const char* password);
char* PPPGetMessage(void);

// IPLcp.c
void PPPDumpLCP(LCPHeader* lcp);
int PPPInitLCP(PPPConf* conf, IPInterface* interface);
void PPPDumpLCP(LCPHeader* lcp);

// IPIpcp.c
void PPPInitIPCP(PPPConf* ipcp, IPInterface* interface);

// IPPap.c
void PAPOpen(PPPConf* conf);
void PAPUp(PPPConf* conf);
void PAPDown(PPPConf* conf);
void PAPClose(PPPConf* conf);
int PAPTimeout(PPPConf* conf);
void PAPIn(PPPConf* conf, PAPHeader* pap, s32 len, u32 flag);
void PAPInit(PPPConf* conf, IPInterface* interface);

// IPChap.c
void CHAPOpen(PPPConf* conf);
void CHAPUp(PPPConf* conf);
void CHAPDown(PPPConf* conf);
void CHAPClose(PPPConf* conf);
int CHAPTimeout(PPPConf* conf);
void CHAPIn(PPPConf* conf, CHAPHeader* chap, s32 len, u32 flag);
void CHAPInit(PPPConf* conf, IPInterface* interface);

#ifdef __cplusplus
}
#endif

#endif
