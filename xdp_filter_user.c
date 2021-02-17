#include <arpa/inet.h>
#include <net/if.h>
#include <error.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_filter_common.h"

#define MAX_TUNNELS 2

static bool interrupted;

static void sigint_handler(int signum)
{
	printf("interrupted\n");
	interrupted = true;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

#define INVALID 0
//reverse order
unsigned int my_aton(unsigned int ip)
{
    return  ((ip & 0xff000000) >> 24) |
	    ((ip & 0x00ff0000) >>  8) |
	    ((ip & 0x0000ff00) <<  8) |
	    ((ip & 0x000000ff) << 24);        
}


unsigned int ip_to_int (const char * ip, int aton)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
   /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            /* We insist on stopping at "." if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return INVALID;
            }
        }
        if (n >= 256) {
            return INVALID;
        }
        v *= 256;
        v += n;
    }
    if (aton == 1)
    	v = my_aton(v);
	    
    return v;
}

int main(int argc, char *argv[])
{
	//take the created obj
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "xdp_filter_kern.o",
	};
	

	int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	struct ipv4_entry *ipv4_entr;
	int decap_ifindex[MAX_TUNNELS];
	struct bpf_object *obj;
	int prog_fd;
	int mapb_fd;
	struct bpf_map *mapb;
	int tunnel_nr = 0;
	int ifindex;
	int i, j;

	// if (argc < 2) // enable to use args
	// 	error(1, 0, "syntax:%s <NIC> <decap target> <local ip> <local port> <vni>", argv[0]);
    
	static const char ipsrc[] = "192.168.109.131";
  	__u32 ipu = 0;
	ipu = ip_to_int(ipsrc, 1);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	printf("Started running.\n");

	// ipv4_entr = calloc(nr_cpus, sizeof(struct ipv4_entry));
	// if (!ipv4_entr)
	// 	error(1, 0, "can't allocate entry\n");

	
	//sprintf(ipv4_entr[0].ip_str, "%s", ipsrc);
	// ipv4_entr[0].ip_val = ipu;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		error(1, errno, "can't load file %s", prog_load_attr.file);

	printf("Loaded object.\n");


	ifindex = if_nametoindex(argv[1]);
	// printf("%s\n", argv[1]);

	// printf("%d\n", ifindex);
	
	//change later
	for( i=1; i <= MAX_TUNNELS; i++)
		printf("interface %d:%s\n", i, if_indextoname(i, (char *)&decap_ifindex));


	if (!ifindex)
		error(1, errno, "unknown interface %s\n", argv[i]);
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0)
		error(1, errno, "can't attach xdp program to interface %s:%d: "
			"%d:%s\n", argv[1], ifindex, errno, strerror(errno));
	printf("Attached to interface %s\n", if_indextoname(ifindex, (char *)&decap_ifindex));


	mapb = bpf_object__find_map_by_name(obj, "black_list");
	if (!mapb)
		error(1, errno, "can't load black_list");
	printf("Blacklist Map loaded!\n");

	mapb_fd = bpf_map__fd(mapb);
	if (mapb_fd < 0)
		error(1, errno, "can't get black_list fd");
	printf("Got map fd!\n");

	int tst = 0;

	printf("%u\n", ipu);
	if (bpf_map_update_elem(mapb_fd, &tst, &ipu, BPF_ANY))
		error(1, errno, "can't add ip to map %s\n", ipsrc);

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	while (!interrupted) {
		sleep(1);

		// for (i = 0; i < tunnel_nr; ++i) {
		// 	struct vxlan_decap_key *key = &decap_key[i];
		// 	struct vxlan_decap_entry all = { 0, 0, 0};

		// 	if (bpf_map_lookup_elem(map_fd, key, decap_entry))
		// 		error(1, errno, "no stats for tunnel %x:%d:%d\n",
		// 		      key->addr, key->port, key->id);

		// 	for (j = 0; j < nr_cpus; j++) {
		// 		all.packets += decap_entry[j].packets;
		// 		all.bytes += decap_entry[j].bytes;
		// 	}

		// 	printf("tunnel %x:%d:%d drop %lld:%lld\n", key->addr,
		// 	       key->port, key->id, all.packets, all.bytes);
		// }
	}

	for (i = 0; i < tunnel_nr; ++i)
		bpf_set_link_xdp_fd(decap_ifindex[i], -1, 0);
	return 0;
}