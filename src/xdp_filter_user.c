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

#include "config.h"
#include "helpers.h"
#include "httpd.h"
#include "util.h"



static bool interrupted;
int test;
//struct i_data i_dat[32];
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

	/* parse cli arguments */
    argp_parse(&argp, argc, argv, 0, 0, &cfg);
    DIE(cfg.unload && cfg.ifindex == -1, "Missing target network device name");
    DIE(!cfg.unload && !strlen(cfg.obj_path), "Missing XDP object path");
    DIE(!cfg.unload && !strlen(cfg.section), "Missing section name");

    /* if user wants to unload, end it at that */
    if (cfg.unload)
        return xdp_link_detach(cfg.ifindex, cfg.xdp_flags);

	bump_memlock_rlimit();

	//print_interfaces_info();

    int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	
	sprintf(route_path, "/firewall/%s/%s/interface", cfg.os_name, cfg.version);

	printf("Started running.\n");

	serve_forever("12913");
	
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

	ROUTE_GET(route_path) // /firewall/ubuntu/v1/interface GET INFO ABOUT INTERFACES
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        
        if(qs){
            printf("Req interface: %s \r\n", qs+2);
            get_interface_data(qs+2);
        } else {
            print_interfaces_info();
        }
		
    }

    ROUTE_POST(route_path) // /firewall/ubuntu/v1/interface?i=ens33 -- COMMAND LOAD/UNLOAD
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
		printf("uri: %s \r\n", uri);
        printf("interface: %s \r\n", qs+2);
        printf("Payload size: %d \r\n", payload_size);
        printf("Payload: %s \r\n", payload);
        printf("%s \r\n", command_interpreter(qs+2, payload));
    }

	ROUTE_PUT(route_path) // /firewall/ubuntu/v1/interface?i=ens33 -- add rule
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
		printf("uri: %s \r\n", uri);
        printf("interface: %s \r\n", qs+2);
        printf("Payload size: %d \r\n", payload_size);
        printf("Payload: %s \r\n", payload);
        add_to_interface(qs+2, payload);
     
	}

	ROUTE_DELETE(route_path) //delete (pop) rule
    {
        printf("HTTP/1.1 200 OK\r\n\r\n");
        printf("Wow, seems that you POSTed %d bytes. \r\n", payload_size);
		printf("uri: %s \r\n", uri);
        printf("interface: %s \r\n", qs+2);
        printf("Payload size: %d \r\n", payload_size);
        printf("Payload: %s \r\n", payload);
        delete_from_interface(qs+2);  
	}

    ROUTE_END()
}
