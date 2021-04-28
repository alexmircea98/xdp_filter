#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

//interfaces
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>

#include <error.h>
#include <errno.h>

//local
#include "config.h"
#include "xdp_filter_common.h"

#ifndef _HELPERS_H
#define _HELPERS_H

#define NI_NUMERICHOST	1	/* Don't try to look up hostname.  */
#define NI_MAXHOST 1025

int xdp_link_detach(int ifindex, uint32_t xdp_flags);
int load_bpf_and_xdp_attach(struct i_data *i_dat, struct config *cfg);

// int load_xdp_obj_map(struct bpf_object *bpf_obj, struct config *cfg);
int add_entry_to_map(int map_fd, char *ipsrc, int port);

void print_interfaces_info();
uint32_t ip_to_uint(char *ip_str);

int load_interface(char *interface);
int unload_interface(char *interface);

int add_to_interface(char *interface, char *ipsrc, int port);
int delete_from_interface(char *interface, char *ipsrc, int port);

#endif

