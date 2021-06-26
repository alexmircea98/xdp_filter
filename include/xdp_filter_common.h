#define MAX_NR_OF_RULES 150 // max 255

struct rule {
	__u32 ip;
	__u32 mask;
	struct iphdr ipv4_hdr;
	unsigned char iph;
	unsigned char tcph;
	unsigned char udph;
	
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
	

};

struct rule_cnt {
	struct tcphdr tcph;
	struct udphdr udp;
	__u32 cnt;
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
