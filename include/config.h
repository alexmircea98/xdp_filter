#include <argp.h>	/* argp                        */
#include <stdint.h>	/* [u]int*_t                   */
#include <net/if.h>	/* IF_NAMESIZE, if_nametoindex */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef _CLI_ARGS_H
#define _CLI_ARGS_H

/* structure holding arguments information */
struct config
{
    uint32_t xdp_flags;
    uint8_t  unload;
    uint8_t  reuse;
    int32_t  ifindex;
    char     ifname[IF_NAMESIZE];
    char     obj_path[256];
    char     section[256];
    char     pin_dir[256];
};

typedef struct i_data
{
    int       map_fd;
    int          ans;
    int32_t  ifindex;
    int32_t  prog_fd;
    char     ifname[IF_NAMESIZE];
    struct bpf_object   *bpf_obj;
    struct bpf_map_info map_expect;
    struct bpf_map_info info;
    
} i_data;

extern struct argp   argp;
extern struct config cfg;
extern struct i_data i_dat[32];

#endif
