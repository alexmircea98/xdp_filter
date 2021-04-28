#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>


#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>

// eBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "helpers.h"
#include "httpd.h"
#include "util.h"

#include "config.h"

static bool interrupted;

// static void sigint_handler(int signum)
// {
// 	printf("interrupted\n");
// 	interrupted = true;
// }

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

int main(int argc, char *argv[])
{	
	// struct bpf_map_info map_expect = { 0 };
    // struct bpf_map_info info = { 0 };
	

	/* parse cli arguments */
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    //DIE(cfg.ifindex == -1, "Missing target network device name"); //CHANGE THIS
    DIE(!cfg.unload && !strlen(cfg.obj_path), "Missing XDP object path");
    DIE(!cfg.unload && !strlen(cfg.section), "Missing section name");

    /* if user wants to unload, end it at that */
    if (cfg.unload)
        return xdp_link_detach(cfg.ifindex, cfg.xdp_flags);

	bump_memlock_rlimit();

	print_interfaces_info();

    int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	
	
	
	printf("Started running.\n");


	// signal(SIGINT, sigint_handler);
	// signal(SIGPIPE, sigint_handler);

	serve_forever("12914");
	
	return 0;
}

void route()
{
    ROUTE_START()

    ROUTE_GET("/")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Hello! You are using %s", request_header("User-Agent"));
    }

	ROUTE_GET("/firewall/ubuntu/v1/interface")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Hello! You are using %s", request_header("User-Agent"));
		print_interfaces_info();
    }

    ROUTE_POST("/firewall/ubuntu/v1/interface")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
        printf("Fetch the data using `payload` variable.");
		
    }

	ROUTE_POST("/firewall/ubuntu/v1/interface/ens33/load")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Loaded interface filter. \r\n", payload_size);
		load_interface("ens33");
	}

	ROUTE_POST("/firewall/ubuntu/v1/interface/ens33/unload")
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Unloaded interface filter. :%s\r\n", unload_interface("ens33"));
        
	}

    ROUTE_POST("/firewall/ubuntu/v1/interface/ens33/a")//p=92.168.109.131&port=40
    {
        char *interf = "ens33";
        char *ip = "192.168.109.131";
        int port = 40;

        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Adding %s:%d to interface %s.\r\n", ip, port, interf);
		add_to_interface(interf, ip, port);
	}

    ROUTE_POST("/firewall/ubuntu/v1/interface/ens33/d")//ip=92.168.109.131&port=40
    {
        char *interf = "ens33";
        char *ip = "192.168.109.131";
        int port = 40;
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Adding %s:%d to interface %s.\r\n", ip, port, interf);
		delete_from_interface(interf, ip, port);
	}
    
    ROUTE_END()
}
