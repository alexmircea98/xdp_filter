#include <string.h>     /* strerror */

#include "config.h"
#include "helpers.h"
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
    printf("Map fd: %d\n", i_dat->map_fd);
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

char *uint_to_ip(uint32_t ip_int)
{   
    struct in_addr addr = {ip_int};
    return inet_ntoa( addr );
}


//INTERACTION WITH kernel maps


void print_rule(struct rule *rule){
    printf("Ip address: %s\n", uint_to_ip(rule->ip));
    printf("Address mask: %s\n", uint_to_ip(rule->mask));
    if (rule->ipv4_hdr){
        printf("IPv4: \n");
        printf("Protocol: %u\n", rule->ipv4_hdr->protocol);
        // printf("Ip address: %u\n",rule->ip);
        // printf("Address mask: %u\n",rule->ip);
    }
    if (rule->tcph){
        printf("TCP: \n");
        printf("Source port: %u\n", htons(rule->tcph->source));
        printf("Destination port: %u\n", htons(rule->tcph->dest));
        // printf("Ip address: %u\n",rule->ip);
        // printf("Address mask: %u\n",rule->ip);
    }
}



int add_rule_to_map(int map_fd, int32_t index, struct rule *rule)
{
	if (bpf_map_update_elem(map_fd, &index, rule, BPF_ANY))
    {
        error(1, errno, "can't add rule %d to map\n", index);
    }
	printf("Rule nr %d added to %d map_fd.\n ", index, map_fd);
	return 0;
}

int handle_IP(struct json_object *jobj, struct rule *rule)
{
    rule->ipv4_hdr = malloc(sizeof(struct iphdr));
    json_object_object_foreach(jobj, key, val) 
    {
        printf("key: \"%s\", val: \"%s\"\n", key, json_object_get_string(val));

        if (strcmp(key, "protocol") == 0) // is cmd
        {
            printf("key: \"%s\", val: %d\n", key, json_object_get_int(val));
            rule->ipv4_hdr->protocol = (uint8_t)json_object_get_int(val);
            printf("Saved protocol %u\n", rule->ipv4_hdr->protocol);
        }
        // else if (strcmp(key, "mask") == 0) /* unload: */
        // {
        //     rule.mask = ip_to_uint(json_object_get_string(val));
        // }
        // else if (strcmp(key, "ip_header") == 0) /* unload: */
        // {
        //     handle_IP(val, &rule);
        // }
        // else if (strcmp(key, "tcp_header") == 0) /* unload: */
        // {
        //     handle_TCP(val, &rule);
        // }
        // else if (strcmp(key, "udp_header") == 0) /* unload: */
        // {
        //     handle_UDP(val, &rule);
        // }
        else /* default: */
        {
            RET(0, 1, "Attribute not recognised");
        }
    }
}

int handle_TCP(struct json_object *jobj, struct rule *rule)
{
    rule->tcph = malloc(sizeof(struct tcphdr));
    json_object_object_foreach(jobj, key, val) 
    {
        if (strcmp(key, "source") == 0) // is cmd
        {
            printf("key: \"%s\", val: %d\n", key, json_object_get_int(val));
            rule->tcph->source = (uint16_t)ntohs(json_object_get_int(val));
            printf("New net val %u\n", rule->tcph->source);
        }
        else if (strcmp(key, "dest") == 0) /* unload: */
        {
            printf("key: \"%s\", val: %d\n", key, json_object_get_int(val));
            // json_object_get
            rule->tcph->dest = (uint16_t)ntohs((uint16_t)json_object_get_int(val));
            printf("New net val %u\n", rule->tcph->dest);
        }
        // else if (strcmp(key, "ip_header") == 0) /* unload: */
        // {
        //     handle_IP(val, &rule);
        // }
        // else if (strcmp(key, "tcp_header") == 0) /* unload: */
        // {
        //     handle_TCP(val, &rule);
        // }
        // else if (strcmp(key, "udp_header") == 0) /* unload: */
        // {
        //     handle_UDP(val, &rule);
        // }
        else /* default: */
        {
            RET(0, 1, "Attribute not recognised");
        }
    }
}

int handle_UDP(struct json_object *jobj, struct rule *rule)
{
    // __be16	source;
	// __be16	dest;
}

int create_and_add_rule(int map_fd, int32_t index, char *data)
{
    struct json_object *jobj;
    struct rule rule;

    jobj = json_tokener_parse(data);
    json_object_object_foreach(jobj, key, val) 
    {
        //printf("key: \"%s\", val: \"%s\"\n", key, json_object_get_string(val));

        if (strcmp(key, "ip") == 0) /* ip address */
        {
            rule.ip = ip_to_uint((char *)json_object_get_string(val));
            printf("key: \"%s\", val: \"%s\"\n", key, json_object_get_string(val));
        }
        else if (strcmp(key, "mask") == 0) /* mask: */
        {
            rule.mask = ip_to_uint((char *)json_object_get_string(val));
            printf("key: \"%s\", val: \"%s\"\n", key, json_object_get_string(val));
        }
        else if (strcmp(key, "ip_header") == 0) /* unload: */
        {
            printf("key: \"%s\"\n", key, json_object_get_string(val));
            handle_IP(val, &rule);
        }
        else if (strcmp(key, "tcp_header") == 0) /* unload: */
        {
            handle_TCP(val, &rule);
        }
        else if (strcmp(key, "udp_header") == 0) /* unload: */
        {
            handle_UDP(val, &rule);
        }
        else /* default: */
        {
            RET(0, 1, "Attribute not recognised");
        }
    }
    print_rule(&rule);
    add_rule_to_map(map_fd, index, &rule);
}

int pop_rule(int map_fd, int32_t index)
{

}

int load_interface(char *interface)
{
    
    int ifindex = if_nametoindex(interface);
	if (ifindex < 0)
		error(1, errno, "unknown interface %s\n", interface);

    load_bpf_and_xdp_attach(&i_dat[ifindex], &cfg);
    DIE(!i_dat[ifindex].bpf_obj, "Failed to load XDP program");

    find_map_fd(&i_dat[ifindex], "rule_list");

    printf("INTERF %d and mapFD :%d and progFD: %d\n", ifindex, i_dat[ifindex].map_fd, i_dat[ifindex].prog_fd);

    return 0;
    
}

int unload_interface(char *interface)
{
    int ifindex = if_nametoindex(interface);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", interface);

    return xdp_link_detach(ifindex, cfg.xdp_flags);
}

int add_to_interface(char *interface, char *data)
{
    
    int ifindex = if_nametoindex(interface);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", interface);
    
    printf("INTERF %d and mapFD :%d\n", ifindex, i_dat[ifindex].map_fd);
    
    int chk = create_and_add_rule(i_dat[ifindex].map_fd, i_dat[ifindex].map_index, data);
    return 0;
}

int delete_from_interface(char *interface)
{
    int ifindex = if_nametoindex(interface);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", interface);
    printf("WTF INTERF %d\n", ifindex);

    find_map_fd(&i_dat[ifindex], "rule_list");

    int chk = pop_rule(i_dat[ifindex].map_fd, i_dat[ifindex].map_index);
	printf("Deleted from %d\n", i_dat[ifindex].map_fd);
    return 0;
}

char *command_interpreter(char *interf, char *payload)
{
    struct json_object *jobj;
    jobj = json_tokener_parse(payload);

    json_object_object_foreach(jobj, key, val) 
    {
        printf("key: %s, val: \"%s\"\n", key, json_object_get_string(val));

        if (strcmp(key, "cmd") == 0) // is cmd
        {

            if (strcmp(json_object_get_string(val), "load") == 0) /* load: */
            {
                load_interface(interf);
            } 
            else if (strcmp(json_object_get_string(val), "unload") == 0) /* unload: */
            {
                unload_interface(interf);
            }
            else /* default: */
            {
                return "ERR: Command not recognised.";
            }
        }
        else /* default: */
        {
            return "ERR: Expected a command.";
        }
    }
    // printf("mapFD :%d\n", i_dat[2].map_fd);
    return "SUCCESS.";
}

int command_parser(){

}