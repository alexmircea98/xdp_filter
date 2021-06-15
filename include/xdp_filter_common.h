
struct ipv4_entry {
	//char ip_str[16]; //ipv4 in string format
	char ports[65536];
	__u16 ports_nr;
	__u64 count;
};

// ingress/egress set bu flags

//for (size_t i=0; i<20; ++i)
//	if (iph[i] & mask[i] != match[i]) return false;

struct rule {
	__u32 ip;
	__u32 mask;

	struct iphdr *ipv4_hdr;
	struct tcphdr *tcph;
	struct udphdr *udp;
	//-------ipv4-------//
	// __u8	tos;
	// __be16	tot_len;
	// __be16	id;
	// __be16	frag_off;
	// __u8	ttl;
	// __u8	protocol;
	// __sum16	check;
	// __be32	saddr;
	// __be32	daddr;
	//-------TCP-------//
	// __be16	source;
	// __be16	dest;
	// __be32	seq;
	// __be32	ack_seq;
	// __be16	window;
	// __sum16	check;
	// __be16	urg_ptr;
	//-------UDP-------//
	// __be16	source;
	// __be16	dest;
	// __be16	len;
	// __sum16	check;

};