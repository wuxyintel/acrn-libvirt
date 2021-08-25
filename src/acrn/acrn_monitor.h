#ifndef __ACRN_DEVICE_H__
#define __ACRN_DEVICE_H__

#include "domain_conf.h"

typedef struct _acrnMonitor acrnMonitor;
typedef acrnMonitor *acrnMonitorPtr;
struct _acrnMonitor {
    int fd;
    virDomainObjPtr vm;
    virMutex lock;
};


int acrnMonitorSystemPowerdown(acrnMonitorPtr mon);
int acrnMonitorOpenUnix(const char *monitor);
void acrnMonitorClose(acrnMonitorPtr mon);
#endif /* __ACRN_DEVICE_H__ */
