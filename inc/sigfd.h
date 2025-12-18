#pragma once

#include <stdint.h>

#include <signal.h>

/* Setup a signalfd for specified signals and block them until `sigfd_destroy` is called */
int sigfd_setup(unsigned int count, ...);
/* Destroy singalfd created by `sigfd_create` and unblock signals blocked by `sigfd_setup` */
int sigfd_destroy(int fd);
/* Read signal received in sigfd */
int sigfd_read(int fd);
