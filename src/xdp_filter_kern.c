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
#include <stddef.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "xdp_filter_common.h"

struct bpf_map_def SEC("maps") rule_list = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32), //index
	.value_size = sizeof(struct rule), //
	.max_entries = MAX_NR_OF_RULES,
};

struct bpf_map_def SEC("maps") rule_list_cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32), //index
	.value_size = sizeof(struct rule_cnt), //
	.max_entries = MAX_NR_OF_RULES,
};

struct bpf_map_def SEC("maps") drop_count = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32), //index
	.value_size = sizeof(__u64), //
	.max_entries = 1,
};

/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 *nh_off, void *data_end,
			     __u32 *src, __u32 *dest)
{
	struct iphdr *iph = data + *nh_off;

	if ((void *)(iph + 1) > data_end)
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

	if ((void *)(uh + 1) > data_end)
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
    
	bpf_printk("/-----------------------------------------------------/\n");
	struct ethhdr *eth = data;    // needed to pass the bpf verifier
    __u64 nh_off = 0;            // offset where the eth header ends also neded for verifier and to know where next header 
    __u64 *drop;
	__u32 cnt_key = 0;
	__u16 dest_port;
	
	struct iphdr *ipv4_hdr;
	struct tcphdr *tcph;
	struct udphdr *udp;
	
	struct rule *rule;
	struct rule_cnt *rule_cnt;
	__u32 xrr = 0;
	nh_off = sizeof(*eth);

    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;    // we're only interested in IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)){
		return XDP_PASS;    // include/uapi/linux/ip.h
	}
       
	ipv4_hdr = data + sizeof(struct ethhdr);    // needed to pass the bpf verifier
    
	if ((void *)(ipv4_hdr + 1) > data_end)
        return XDP_PASS;    // check if the saddr matches

	//bpf_printk("Protocol value %u\n", ipv4_hdr->protocol);
	

	int protocol = -1; // to make sure, default 0 for TCP, 1 for UDP
	// __u16 portv = 0;

	if (ipv4_hdr->protocol == IPPROTO_UDP) {
		bpf_printk("UDP packet\n");
        udp = (void*)ipv4_hdr + sizeof(*ipv4_hdr);
        if ((void*)udp + sizeof(*udp) >= data_end) {
			return XDP_PASS;
        }
		protocol = 1;
		//portv = bpf_htons(udp->dest);
    } else if(ipv4_hdr->protocol == IPPROTO_TCP) {
		bpf_printk("TCP packet\n");
		tcph = (data + sizeof(struct ethhdr) + (ipv4_hdr->ihl * 4));

		// Check TCP header.
		if (tcph + 1 > (struct tcphdr *)data_end)
		{
			return XDP_PASS;
		}
		protocol = 0;
		//portv = bpf_htons(tcph->dest);
	} else {
		return XDP_PASS;
	}
	
	//bpf_printk("Port value %u\n", portv);

	
	
	for (uint8_t idx = 0; idx < MAX_NR_OF_RULES; idx++)
	{	
		bpf_printk("Index: %u\n", idx);
		__u32 key = idx;
		rule = bpf_map_lookup_elem(&rule_list, &key);
		__u32 valid = rule->ip;
		if (rule && valid){
			bpf_printk("ip src: %u\n", ipv4_hdr->saddr);
			bpf_printk("rule->mask: %u\n", rule->mask);
			bpf_printk("rule->ip: %u\n", rule->ip);
			xrr = (__u32)(ipv4_hdr->saddr&rule->mask); 
			bpf_printk("xrr: %u\n", xrr);
			//bpf_printk("rule->ipv4_hdr.protocol: %u\n", rule->protocol);
			if ( xrr == rule->ip ){ // match found

				bpf_printk("match here\n");
				bpf_printk("rule->iph %u\n", rule->iph);
				bpf_printk("rule->tcph %u\n", rule->tcph);
				bpf_printk("rule->udph %u\n", rule->udph);
				if ( rule->iph == 0 && rule->tcph == 0 && rule->udph == 0 ){ 
					bpf_printk("NO HEADER\n");
					goto drop;
				}

				if (rule->iph){
					bpf_printk("CHECK IP HEADER\n");
					if (rule->ipv4_hdr.protocol == ipv4_hdr->protocol) goto drop;;
					if (rule->ipv4_hdr.check == ipv4_hdr->check) goto drop;;
					if (rule->ipv4_hdr.ttl == ipv4_hdr->ttl) goto drop;;
					if (rule->ipv4_hdr.daddr == ipv4_hdr->daddr) goto drop;;
					
				}

				rule_cnt = bpf_map_lookup_elem(&rule_list_cnt, &key);
				
				if (!protocol){
					if (rule->tcph && rule_cnt){
						bpf_printk("CHECK TCP HEADER\n");
						bpf_printk("rule->source %u\n", rule_cnt->tcph.source);
						//bpf_printk("tcph->source %u\n", tcph->source);
						if (rule_cnt->tcph.source == tcph->source) goto drop;;
						bpf_printk("rule->dest %u\n", rule_cnt->tcph.dest);
						//bpf_printk("tcph->dest %u\n", tcph->dest);
						if (rule_cnt->tcph.dest == tcph->dest) goto drop;;
						if (rule_cnt->tcph.check == tcph->check) goto drop;;
					}
				} else {
					if (rule->udph && rule_cnt){
						bpf_printk("CHECK UDP HEADER\n");
						if (rule_cnt->udp.source == udp->source) return XDP_DROP;
						if (rule_cnt->udp.dest == udp->dest) return XDP_DROP;
						//if (rule_cnt->udp.len == udp->len) return XDP_DROP;
						//if (rule_cnt->udp.check == udp->check) return XDP_DROP;
						
					}
				}

			}
		} else {
			break;
		}
	}

    bpf_printk("PASSED\n");
	return XDP_PASS;
drop:
	drop = bpf_map_lookup_elem(&drop_count, &cnt_key);
	if(drop)
		*drop += 1;
	bpf_printk("DROPPED\n");
	return XDP_DROP;
}
unsigned int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
