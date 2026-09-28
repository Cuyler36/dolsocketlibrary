#ifndef __IP_PRIVATE_H__
#define __IP_PRIVATE_H__

#include <dolphin/ip.h>
#include <dolphin/private/sdk.h>

#ifdef __cplusplus
extern "C" {
#endif

extern IPInterface __IFDefault;
extern SOResolver __SOResolver;
extern PPPConf PPPLcpConf;
extern PPPConf PPPIpcpConf;
extern PPPConf PPPAuthConf;
extern const u8 IPLimited[4];
extern IFQueue TCPInfoQueue;
extern TCPStatistics TCPStat;
extern int __TCPMaxPersist;
extern PPPAuth __PPPAuth;

#ifdef __cplusplus
}
#endif

#endif
