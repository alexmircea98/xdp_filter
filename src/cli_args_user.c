#include <string.h>		        /* strncmp            */
#include <linux/if_link.h>      /* xdp flag         s */

#include "config.h"           /* cfg vars & headers */
#include "util.h"               /* DIE, ABORT, RET    */


/* command line arguments */
static struct argp_option options[] = {
    { "iface",       'i', "IFNAME", 0, "Network device name"               },
    { "driver-mode", 'd', NULL,     0, "Hook program in network driver"    },
    { "force",       'f', NULL,     0, "Replace existing program on iface" },
    { "reuse",       'r', "PINDIR", 0, "Reuse existing maps from PINDIR"   },
    { "unload",      'u', NULL,     0, "Unload program instead of loading" },
    { "obj-path",    'o', "PATH",   0, "Path to XDP object"                },
    { "section",     's', "SEC",    0, "Load program in SEC of the ELF"    },
    { "os",          'n', "OS",    0, "Current Operating System name"    },
    { "version",     'v', "VER",    0, "Current version"    },
    { 0 }
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* description of accepted non-option arguments */
static char args_doc[] = "FILE";

/* program documentation */
static char doc[] = "xdp-filter -- loads an XDP filter and provisions rules";

/* declaration of relevant structures */
struct argp   argp = { options, parse_opt, args_doc, doc };
struct i_data i_dat[32];
struct config cfg = {
    .ifname      = { [0 ... IF_NAMESIZE-1] = 0 },
    .obj_path    = { [0 ... 255] = 0 },
    .section     = { [0 ... 255] = 0 },
    .os_name    = { [0 ... 15] = 0 },
    .version     = { [0 ... 7] = 0 },
    .xdp_flags   = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
    .unload      =  0,  /* no  */
    .reuse       =  0,  /* no  */
    .ifindex     = -1,  /* bad */
};

char route_path[] ={ [0 ... 63] = 0 };
/* parse_opt - parses one argument and updates relevant structures
 *  @key   : argument id
 *  @arg   : pointer to the actual argument
 *  @state : parsing state
 *
 *  @return : 0 if everything ok
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    switch (key) {
        /* interface */
        case 'i':
            strncpy(cfg.ifname, arg, IF_NAMESIZE); //for force unloadinglsb_release -a
            cfg.ifindex = if_nametoindex(arg);
            DIE(!cfg.ifindex, "Unknown network device name");

            break;
        /* driver mode */
        case 'd':
            cfg.xdp_flags |=  XDP_FLAGS_DRV_MODE;
            cfg.xdp_flags &= ~XDP_FLAGS_SKB_MODE;
            break;
        /* replace old */
        case 'f':
            cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        case 'r':
            cfg.reuse = 1;
            strncpy(cfg.pin_dir, arg, 256);
            break;
        /* unload */
        case 'u':
            cfg.unload = 1;
            break;
        /* XDP object path */
        case 'o':
            strncpy(cfg.obj_path, arg, 256);
            //strncpy(cfg.obj_path, "xdp_filter_kern.o", 256);
            break;
        /* section name */
        case 's':
            strncpy(cfg.section, arg, 256);
            break;
        case 'n':
            strncpy(cfg.os_name, arg, 16);
            break;
        case 'v':
            strncpy(cfg.version, arg, 8);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}
