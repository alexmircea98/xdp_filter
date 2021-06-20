// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_drop"
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stddef.h>
#include <linux/ipv6.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdatomic.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "xdp_filter_common.h"

//make it percpu
#define MAX_NR_PORTS 65536
#define MAX_NR_OF_RULES 100
#define TEST_NR 1

struct bpf_map_def SEC("maps") black_list = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32), //ip value
	.value_size = sizeof(struct ipv4_entry), // hashmap of ports
	.max_entries = MAX_NR_OF_RULES,
};

struct bpf_map_def SEC("maps") rule_list = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32), //ip value
	.value_size = sizeof(struct rule), // hashmap of ports
	.max_entries = MAX_NR_OF_RULES,
};

// static inline int get_tcp_dest_port(void *data, __u64 nh_off, void *data_end) {
//     struct tcphdr *tcph = data + nh_off;

//     if (data + nh_off + sizeof(struct tcphdr) > data_end)
//         return 0;
//     return tcph->dest;
// }

/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 *nh_off, void *data_end,
			     __u32 *src, __u32 *dest)
{
	struct iphdr *iph = data + *nh_off;

	if (iph + 1 > data_end)
		return 0;

	*nh_off += iph->ihl << 2;

	*src = iph->saddr;
	*dest = iph->daddr;
	return iph->protocol;
}

/* Parse UDP packet to get source port, destination port and UDP header size */
static inline int parse_udp(void *data, __u64 th_off, void *data_end,
			     __u16 *src_port, __u16 *dest_port)
{
	struct udphdr *uh = data + th_off;

	if (uh + 1 > data_end)
		return 0;

	/* keep life easy and require 0-checksum */
	if (uh->check)
		return 0;

	*src_port = uh->source;
	*dest_port = uh->dest;
	return __constant_ntohs(uh->len);
}


#define bpf_printk(fmt, ...)                                    \
({                                                              \
		char ____fmt[] = fmt;                            \
		bpf_trace_printk(____fmt, sizeof(____fmt),       \
				##__VA_ARGS__);                 \
})

SEC("prog")
int xdp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;    // include/uapi/linux/if_ether.h
    
	
	struct ethhdr *eth = data;    // needed to pass the bpf verifier
    __u64 nh_off = 0;
    __u16 dest_port;
	int i;

	nh_off = sizeof(*eth);

    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;    // we're only interested in IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)){
		return XDP_PASS;    // include/uapi/linux/ip.h
	}
       
	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);    // needed to pass the bpf verifier
    
	if ((void *)(ipv4_hdr + 1) > data_end)
        return XDP_PASS;    // check if the saddr matches

	//bpf_printk("Protocol value %u\n", ipv4_hdr->protocol);
	
	
	__u16 portv = 0;
	if (ipv4_hdr->protocol == IPPROTO_UDP) {
		bpf_printk("UDP packet\n");
        struct udphdr *udp = (void*)ipv4_hdr + sizeof(*ipv4_hdr);
        if ((void*)udp + sizeof(*udp) <= data_end) {
			portv = bpf_htons(udp->dest);
        }
    } else if(ipv4_hdr->protocol == IPPROTO_TCP) {
		bpf_printk("TCP packet\n");
		struct tcphdr *tcph = (data + sizeof(struct ethhdr) + (ipv4_hdr->ihl * 4));

		// Check TCP header.
		if (tcph + 1 > (struct tcphdr *)data_end)
		{
			return XDP_DROP;
		}
			
		portv = bpf_htons(tcph->dest);
	} else {
		return XDP_PASS;
	}
	bpf_printk("Port value %u\n", portv);
	
	if (portv < 0){
		return XDP_PASS;
	}
	if (portv > 65335){
		return XDP_PASS;
	}

	struct rule *test;
	//int idx;

	//#pragma clang loop unroll(full)
	for (uint8_t idx = 0; idx < 10; idx++)
	{	
		uint32_t key = idx;
		test = bpf_map_lookup_elem(&rule_list, &key);
		
		if (test){
			//bpf_printk("Got Here, NULL\n");
			return XDP_PASS;
		}
	}

	struct ipv4_entry *entry;

	entry = bpf_map_lookup_elem(&black_list, &(ipv4_hdr->saddr));
	
	if (entry){
		
		unsigned char d = (unsigned char)(entry->ports[portv]);
		bpf_printk("port match %d\n", d);
		if(d == 1){//here should be diff
			
			entry->count++;
			bpf_printk("Dropped val: %u, port %u, count %d\n", ipv4_hdr->saddr, portv, entry->count);
			return XDP_DROP; //if it finds a match in the list, drop it
		}
		
	}
    bpf_printk("Passed\n");
	return XDP_PASS;
}
unsigned int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
