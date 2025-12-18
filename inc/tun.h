#pragma once

#include <net/if.h>

/* Open and create a new TUN device */
int tun_open(const char* preferred_name, char name[IF_NAMESIZE]);

/* Bring up TUN device */
int tun_up(const char* ifname);
