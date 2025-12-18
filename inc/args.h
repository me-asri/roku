#pragma once

#include <stdbool.h>

#include "clat.h"
#include "log.h"

typedef struct args {
    const char* tun_name;
    clat_params_t clat;
    log_level_t log_level;
    bool add_route;
    bool add_fw_rules;
    bool enable_ip_fwd;
} args_t;

int args_parse(args_t* args, int argc, char** argv);
