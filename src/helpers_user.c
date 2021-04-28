#include <string.h>     /* strerror */

#include "helpers.h"
#include "config.h"
#include "util.h"

/* load_bpf_object_file - extracts eBPF bytecode and uploads it in kernel
 *  @obj_path : eBPF object location on disk
 *
 *  @return : loaded program object or NULL on error
 */
struct bpf_object *load_bpf_object_file(char *obj_path)
{
    struct bpf_object *bpf_obj;
    int               first_prog_fd = -1;
    int               ans;

    /* don't care for hardware offloading */
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file      = obj_path,
        .ifindex   = 0,
    };

    /* extract eBPF bytecode from ELF object and load it in kernel */
    ans = bpf_prog_load_xattr(&prog_load_attr, &bpf_obj, &first_prog_fd);
    RET(ans, NULL, "Unable to load eBPF object: %s", strerror(-ans));

    return bpf_obj;
}

/* xdp_link_attach - attaches program to network device's XDP hook
 *  @ifindex   : index of network device
 *  @xdp_flags : flags
 *  @prog_fd   : fd that represents eBPF program in specific section
 *
 *  @return : 0 if everything went ok
 */
int xdp_link_attach(int ifindex, uint32_t xdp_flags, int prog_fd)
{
    int ans;

    /* attach prograim to network device */
    ans = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    WAR(ans == EOPNOTSUPP, "No driver support for native XDP");
    WAR(ans == EBUSY || ans == EEXIST,
        "XDP program already loaded on device; use --force");

    /* program already exists but we couldn't replace (force flag give) *
     * because it was registered at another hook (e.g.: SKB, not DRV)   */
    if (ans == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        WAR(1, "An XDP program is already registered at another hook");

        /* alter flags to reflect alternate insertion mode */
        uint32_t alt_flags = xdp_flags;
        alt_flags &= ~XDP_FLAGS_MODES;
        alt_flags |= (xdp_flags & XDP_FLAGS_SKB_MODE)
            ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

        /* attempt to remove existing program */
        ans = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
        RET(ans, 1, "Unable to remove existing program from XDP hook");

        /* retry uploading the program */
        ans = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
        RET(ans, 1, "Unable to link program to XDP hook");
    }

    return 0;
}

/* load_bpf_and_xdp_attach - loads and attaches eBPF prog to XDP hook
 *  @cfg : configuration parameters structure
 *
 *  @return : loaded program object or NULL on error
 */
int load_bpf_and_xdp_attach(struct i_data *i_dat, struct config *cfg)
{
    struct bpf_program  *bpf_prog;

    /* load eBPF object in kernel for verification */
    if (cfg->reuse) //if cfg file exist
        RET(1, NULL, "Nu mai am chef sa implemetez asta acum; vezi si tu");
    else
        i_dat->bpf_obj = load_bpf_object_file(cfg->obj_path);
    RET(!i_dat->bpf_obj, NULL, "Unable to load eBPF object in kernel");

    /* select program from object by section name to attach to XDP hook */
    bpf_prog = bpf_object__find_program_by_title(i_dat->bpf_obj, cfg->section);
    RET(!bpf_prog, NULL, "Unable to find section in eBPF object");

    /* generate fd representing target program */
    i_dat->prog_fd = bpf_program__fd(bpf_prog);
    RET(i_dat->prog_fd < 0, NULL, "Unable to generate fd representing program");



    /* attach program to XDP hook */
    // i_dat->ans = xdp_link_attach(i_dat->ifindex, cfg->xdp_flags, i_dat->prog_fd);
    // RET(i_dat->ans, NULL, "Unable to attach program to XDP hook");

    if (bpf_set_link_xdp_fd(i_dat->ifindex, i_dat->prog_fd, 0) < 0)
		error(1, errno, "can't attach xdp program to interface %s:%d: "
			"%d:%s\n", if_indextoname(i_dat->ifindex, i_dat->ifname), i_dat->ifindex, errno, strerror(errno));
	printf("Attached to interface %s\n", if_indextoname(i_dat->ifindex, i_dat->ifname));

    return 0;
}

/* xdp_link_detach - detaches a program from an interface's XDP hook
 *  @ifindex   : interface intex
 *  @xdp_flags : flags
 *
 *  @return : 0 if nothing went wrong
 */
int xdp_link_detach(int ifindex, uint32_t xdp_flags)
{
    uint32_t curr_prog_id;
    int ans;

    /* get id of program currently running on interface */
    ans = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
    RET(ans, 1, "Unable to get link xdp id: %s", strerror(-ans));

    /* not a problem if no program was found */
    RET(!curr_prog_id, 0, "No program found on given interface");

    /* unlink program from XDP hook on given interface */
    ans = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    RET(ans < 0, 1, "Unable to unlink program from XDP hook: %s",
        strerror(-ans));

    return 0;
}


int find_map_fd(struct i_data *i_dat, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(i_dat->bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		return 0;
	}

	i_dat->map_fd = bpf_map__fd(map);

    return 0;
}

// MY SHIT FCTS//////////////////////////////////////////////////////////////////////////////

// prints info about interfaces
// change output model
void print_interfaces_info()
{

	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
	if (getifaddrs(&ifaddr) == -1)
		error(1, errno, "can't get interfaces");

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

       family = ifa->ifa_addr->sa_family;

       /* Display interface name and family (including symbolic
           form of the latter for the common families) */

       printf("%s  address family: %d%s\n",
                ifa->ifa_name, family,
                (family == AF_PACKET) ? " (AF_PACKET)" :
                (family == AF_INET) ?   " (AF_INET)" :
                (family == AF_INET6) ?  " (AF_INET6)" : "");

       /* For an AF_INET* interface address, display the address */

       if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                          sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            printf("\taddress: <%s>\n", host);
        }
    }

	//printf("name: %s, address %s, netmask %s", ifap[0]->ifa_name, ifap[0]->ifa_addr->sa_data, ifap[0]->ifa_netmask->sa_data);
	freeifaddrs(ifaddr);
}

//reverse order
unsigned int my_aton(unsigned int ip)
{
    return  ((ip & 0xff000000) >> 24) |
	    ((ip & 0x00ff0000) >>  8) |
	    ((ip & 0x0000ff00) <<  8) |
	    ((ip & 0x000000ff) << 24);        
}

uint32_t ip_to_uint(char *ip_str)
{
    uint32_t ip_int;
    uint8_t *p = (uint8_t *) &ip_int;

    sscanf(ip_str, "%hhd.%hhd.%hhd.%hhd", p+0, p+1, p+2, p+3);

    return ip_int;
}


//INTERACTION WITH kernel maps

int add_entry_to_map(int map_fd, char *ipsrc, int port)
{
	struct ipv4_entry *value = NULL;
	__u32 key = 0;

	key = ip_to_uint(ipsrc);

	printf("Fd data: %d, %s, %d.\n", map_fd, ipsrc, port);

	bpf_map_lookup_elem(map_fd, &key, value);
	printf("Lookup ok.\n");
	if(!value){
		printf("First entry for this ip.\n");
		value = (struct ipv4_entry *)malloc(sizeof(struct ipv4_entry));
		memset(value->ports, 0, 65536);
		value->ports[port] = 1;
        value->ports_nr = 1;
		value->count = 0;
	}
    else
    {
        if (value->ports[port] == 1){
            printf("Port already exists in list.\n");
            goto done;
        }
        else
        {
            if (value->ports_nr < 65536)
            {
                value->ports[port] = 1;
                value->ports_nr += 1;
            }
            else
            {   //Should never happen
                printf("Port list is full.\n");
                printf("WARNING: This should never happen.\n");
                goto done;
            }
            
        }
	}

	if (bpf_map_update_elem(map_fd, &key, value, BPF_ANY))
		error(1, errno, "can't add ip to map %s\n", ipsrc);

	printf("ip added %s with port %d\n", ipsrc, port);

done:

    free(value);

	return 0;
}

int delete_entry_from_map(int map_fd, char *ipsrc, int port)
{
	struct ipv4_entry *value = NULL;
	__u32 key = 0;

	key = ip_to_uint(ipsrc);

	printf("Fd data: %d, %s, %d.\n", map_fd, ipsrc, port);

	bpf_map_lookup_elem(map_fd, &key, value);
	printf("Lookup ok.\n");
	if(!value){
		printf("No entry for this ip");
	} else {
		if (value->ports[port] == 1)
        {
            value->ports[port] = 0;
            value->ports_nr--;
            if(value->ports_nr == 0)
            {
                if (bpf_map_delete_elem(map_fd, &key))
                error(1, errno, "can't delete ip from map %s\n", ipsrc);
                printf("ip added %s with port %d\n", ipsrc, port);
            }
            else
            {
                if (bpf_map_update_elem(map_fd, &key, value, BPF_ANY))
                error(1, errno, "can't update (delete) map %s\n", ipsrc);
                printf("ip added %s with port %d\n", ipsrc, port);
            }
        }
        else
        {
            printf("port was not in list");
        }
	}

    free(value);

	return 0;
}

//useless
// void load_xdp_obj_map(struct i_data *i_dat, struct config *cfg)
// {

//     struct bpf_map *map;

//     map = bpf_object__find_map_by_name(i_dat->bpf_obj, "black_list");
// 	if (!map)
// 		error(1, errno, "can't load black_list");
// 	printf("Blacklist Map loaded!\n");
	
// 	i_dat->map_fd = bpf_map__fd(map);
// 	if (i_dat->map_fd < 0)
// 		error(1, errno, "can't get black_list map fd");
// 	printf("Got map fd!\n");

// 	// if (bpf_set_link_xdp_fd(cfg->ifindex, cfg->prog_fd, 0) < 0)
// 	// 	error(1, errno, "can't attach xdp program to interface %s:%d: "
// 	// 		"%d:%s\n", if_indextoname(cfg->ifindex, cfg->ifname), cfg->ifindex, errno, strerror(errno));
// 	// printf("Attached to interface %s\n", if_indextoname(cfg->ifindex, cfg->ifname));
	
// }

int load_interface(char *interface)
{
    
    int ifindex = if_nametoindex(interface);
	if (ifindex < 0)
		error(1, errno, "unknown interface %s\n", interface);
    printf("WTF INTERF %d\n", ifindex);
    i_dat[ifindex] = (i_data){
        .ifname      = { [0 ... IF_NAMESIZE-1] = 0 },
        .ifindex     = ifindex,  /* bad */
        .map_fd      = -1,
        .ans         = 0,
        .prog_fd     = -1,
        .bpf_obj     = NULL,
        .map_expect = { 0 },
        .info = { 0 },
    };

    strncpy(cfg.ifname, interface, IF_NAMESIZE);

    load_bpf_and_xdp_attach(&i_dat[ifindex], &cfg);
    DIE(!i_dat[ifindex].bpf_obj, "Failed to load XDP program");
	
	//i_dat[ifindex].map_fd = find_map_fd(&i_dat[ifindex].bpf_obj, "black_list");
    find_map_fd(&i_dat[ifindex], "black_list");
    
    //for debugging purposes===========//
    char *ipsrc = "192.168.109.131";
	int chk = add_entry_to_map(i_dat[ifindex].map_fd, ipsrc, 80);
	printf("Inserted to %d, if:%d\n", i_dat[ifindex].map_fd, ifindex);
    return 0;
    //==================================//
}

int unload_interface(char *interface)
{
    int ifindex = if_nametoindex(interface);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", interface);

    return xdp_link_detach(ifindex, cfg.xdp_flags);
}

int add_to_interface(char *interface, char *ipsrc, int port)
{
    int ifindex = if_nametoindex(interface);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", interface);

    
    printf("WTF INTERF %d and mapFD :%d\n", ifindex, i_dat[ifindex].map_fd);
    
    int chk = add_entry_to_map(i_dat[ifindex].map_fd, ipsrc, port);
	printf("Inserted to %d\n", i_dat[ifindex].map_fd);
    return 0;
}

int delete_from_interface(char *interface, char *ipsrc, int port)
{
    int ifindex = if_nametoindex(interface);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", interface);
    printf("WTF INTERF %d\n", ifindex);

    int chk = add_entry_to_map(i_dat[ifindex].map_fd, ipsrc, port);
	printf("Deleted from %d\n", i_dat[ifindex].map_fd);
    return 0;
}