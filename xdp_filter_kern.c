// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_drop"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "xdp_filter_common.h"

struct bpf_map_def SEC("maps") black_list = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 16,
	.map_flags   = 0
};

// struct bpf_map_def SEC("maps") black_list_v2 = {
// 	.type = BPF_MAP_TYPE_PERCPU_HASH,
// 	.key_size = sizeof(__u32),
// 	.value_size = sizeof(const char[16]),
// 	.max_entries = 16,
// };

/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 *nh_off, void *data_end,
			     __be32 *src, __be32 *dest)
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
			     __be16 *src_port, __be16 *dest_port)
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
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	void *verif = 0;

	struct ethhdr *eth = data;
	struct stats_entry *stats;
	__u16 h_proto;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_p;
	__u64 offset;
	unsigned len;
	int ipproto;

	bpf_printk("xdp filter got packet\n");
	

	offset = sizeof(*eth);

		//AICI CRAPA VVVVVVVVVVVVVVVV

	ipproto = parse_ipv4(data, &offset, data_end, &src_ip, &dst_ip);
	bpf_printk("verif2 source: %u\n", src_ip);

	int tst = 0; 
	// insert here verif
	verif = bpf_map_lookup_elem(&black_list, &tst);
	

	//tst = *((unsigned int *)verif);
	if (bpf_map_lookup_elem(&black_list, &tst) != 0) {
		bpf_printk("hit\n");
		goto drop;
	}

	bpf_printk("verif3: PASS\n");

pass:
	return XDP_PASS;
drop:
	bpf_printk("dropped : %s\n", verif);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
