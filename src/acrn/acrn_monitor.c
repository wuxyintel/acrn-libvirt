#include <config.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "virutil.h"
#include "vircommand.h"
#include "virthread.h"
#include "virstring.h"
#include "domain_event.h"
#include "acrn_monitor.h"
#include "virtime.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_ACRN
#define ACRN_DEFAULT_MONITOR_WAIT 30

VIR_LOG_INIT("acrn.acrn_monitor");

static int
acrnMonitorIOWriteWithFD(acrnMonitorPtr mon,
                         const char *data,
                         size_t len,
                         int fd)
{
    struct msghdr msg;
    struct iovec iov[1];
    int ret;
    char control[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));

    iov[0].iov_base = (void *)data;
    iov[0].iov_len = len;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&msg);
    /* Some static analyzers, like clang 2.6-0.6.pre2, fail to see
       that our use of CMSG_FIRSTHDR will not return NULL.  */
    sa_assert(cmsg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    do {
        ret = sendmsg(mon->fd, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    return ret;
}
int
acrnMonitorSystemPowerdown(acrnMonitorPtr mon)
{
    char cmd_name[10] = "shutdown";
    int ret;

    if (!mon)
        return -1;

    ret = acrnMonitorIOWriteWithFD(mon, cmd_name, sizeof(cmd_name), mon->fd);
    return ret;
}
int
acrnMonitorOpenUnix(const char *monitor)
{
    struct sockaddr_un addr;
    int monfd;
    int ret = -1;
    virTimeBackOffVar timebackoff;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }
    VIR_DEBUG("acrnMonitorOpenUnix:create sock");
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Monitor path %s too big for destination"), monitor);
        goto error;
    }
    if (virTimeBackOffStart(&timebackoff, 1, ACRN_DEFAULT_MONITOR_WAIT * 1000) < 0)
            goto error;
    while (virTimeBackOffWait(&timebackoff)) {
        ret = connect(monfd, (struct sockaddr *) &addr, sizeof(addr));
        if (ret == 0)
                break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
                * ECONNREFUSED : Leftover socket hasn't been removed yet */
                continue;
        }
        virReportSystemError(errno, "%s",
                        _("failed to connect to monitor socket"));
        goto error;
    }
    VIR_DEBUG("acrnMonitorOpenUnix:connect to monitor sock:fd=%d", monfd);
    return monfd;

 error:
    VIR_FORCE_CLOSE(monfd);
    return -1;
}
void
acrnMonitorClose(acrnMonitorPtr mon)
{
    if (!mon)
        return;
    virMutexLock(&mon->lock);
    if (mon->fd >= 0) {
        VIR_FORCE_CLOSE(mon->fd);
    }
    virMutexUnlock(&mon->lock);
}