#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/types.h>

//interfaces
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>



#include <error.h>
#include <errno.h>

//json
#include <json.h>

//local
#include "config.h"
#include "xdp_filter_common.h"

#ifndef _HELPERS_H
#define _HELPERS_H

#define NI_NUMERICHOST	1	/* Don't try to look up hostname.  */
#define NI_MAXHOST 1025
extern struct i_data i_dat[32];

int xdp_link_detach(int ifindex, uint32_t xdp_flags);
int load_bpf_and_xdp_attach(struct i_data *i_dat, struct config *cfg);

// int load_xdp_obj_map(struct bpf_object *bpf_obj, struct config *cfg);
int add_entry_to_map(int map_fd, char *ipsrc, int port);

void print_interfaces_info();
uint32_t ip_to_uint(char *ip_str);

int load_interface(char *interface);
int unload_interface(char *interface);

int add_to_interface(char *interface, char *data);
int delete_from_interface(char *interface);

char *command_interpreter(char *interf, char *payload);
int get_interface_data(char *interface);

#endif

