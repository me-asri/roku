#define _POSIX_C_SOURCE 200112L

#include "sigfd.h"

#include <stdarg.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <threads.h>

#include <sys/types.h>
#include <sys/signalfd.h>

#include "log.h"

thread_local static sigset_t sigs_blocked;

int sigfd_setup(unsigned int count, ...)
{
    va_list args;
    unsigned int n;

    int sigfd;

    sigemptyset(&sigs_blocked);

    va_start(args, count);
    for (n = 0; n < count; n++) {
        sigaddset(&sigs_blocked, va_arg(args, int));
    }
    va_end(args);

    if (sigprocmask(SIG_BLOCK, &sigs_blocked, NULL) != 0) {
        elog_e("Failed to mask signals");
        return -1;
    }

    sigfd = signalfd(-1, &sigs_blocked, 0);
    if (sigfd < 0) {
        elog_e("signalfd() failed");

        sigprocmask(SIG_UNBLOCK, &sigs_blocked, NULL);
        return -1;
    }
    return sigfd;
}

int sigfd_destroy(int fd)
{
    int ret = 0;

    if (sigprocmask(SIG_UNBLOCK, &sigs_blocked, NULL) != 0) {
        elog_e("Failed to unblock signals");
        ret = 1;
    }
    if (close(fd) != 0) {
        elog_e("Failed to close signalfd");
        ret = 1;
    }

    return ret;
}

int sigfd_read(int fd)
{
    struct signalfd_siginfo siginfo;
    ssize_t recvd;

    for (;;) {
        recvd = read(fd, &siginfo, sizeof(siginfo));
        if (recvd < 0) {
            if (errno == EINTR) {
                continue;
            }

            elog_e("Failed to read signal from signalfd");
            return 1;
        }
        return siginfo.ssi_signo;
    }

    return -1;
}