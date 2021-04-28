
struct ipv4_entry {
	//char ip_str[16]; //ipv4 in string format
	char ports[65536];
	__u16 ports_nr;
	__u64 count;
};