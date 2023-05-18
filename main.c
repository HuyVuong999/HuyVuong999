#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "debug.h"
#include "domain_tree.h"
#include "filter.h"

// Init for externs in filter.h
domain_tree_char_node_ptr blocked_domain_tree_ptr = NULL;
bool is_redirect = false;
uint32_t n_queue = 1;
uint32_t starting_queue = 0;
char *filtered_iface = NULL;
uint8_t filtered_iface_mac[8] = {0};
char *config_file = NULL;
// For startup period, in this mode RST pkt would be sent to current connecting ssl sessions
uint32_t startup_timeout = 60;

void handle_sigint()
{
    filter_cleanup();
    exit(EXIT_SUCCESS);
}

void init_sig_handlers()
{
    signal(SIGINT, handle_sigint);
}

void check_special_char(char *inp)
{
    // TODO change if need more
    char *list = " /.";
    if (strpbrk(inp, list)) {
        printf("No special chars '%s' in %s\n", list, inp);
        exit(EXIT_FAILURE);
    }
}

void get_filtered_iface_mac()
{
    if(!filtered_iface) {
        printf("Use -i\n");
        exit(EXIT_FAILURE);
    }
    char name[100];
    strncpy(name, "/sys/class/net/", sizeof(name)); // null terminated
    strncat(name, filtered_iface, 76);
    strncat(name, "/address", 9);

    FILE *fp = fopen(name, "r");
    if (!fp){
        debug_print("%s read error: %s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    int n = fscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &filtered_iface_mac[0],
                                                        &filtered_iface_mac[1],
                                                        &filtered_iface_mac[2],
                                                        &filtered_iface_mac[3],
                                                        &filtered_iface_mac[4],
                                                        &filtered_iface_mac[5]);
    
    if (n != 6) {
        debug_print("Get interface mac failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    debug_print("%s MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", filtered_iface,
                                                           filtered_iface_mac[0],
                                                           filtered_iface_mac[1],
                                                           filtered_iface_mac[2],
                                                           filtered_iface_mac[3],
                                                           filtered_iface_mac[4],
                                                           filtered_iface_mac[5]);
#endif
}

void print_help()
{
    printf("HELP:\n");
    printf("REQUIRED:\n");
    printf("\t-c: block list config file\n");
    printf("\t-i: network interface that is filtered\n");
    printf("OPTIONAL:\n");
    printf("\t-r: (default disabled) enable http redirection after blocking\n");
    printf("\t-q: (default 0)        starting queue number\n");
    printf("\t-n: (default 1)        number of queue(s) to bind to start from queue number specified with -q\n");
    printf("\t-t: (default 60)       time to send wait and send rst to exisiting connection after startup (seconds)\n");
    printf("\t-h: print this help\n");
}

void parse_args(int argc, char *argv[])
{
    int opt;
    while((opt = getopt(argc, argv, ":c:rhq:n:t:i:")) != -1) {
        switch(opt){
            case 'c':
                config_file = realpath(optarg, NULL);
                if (!config_file) {
                    printf("Config file %s realpath error: %s\n", optarg, strerror(errno));
                    exit(EXIT_FAILURE);
                }
                break;
            case 'i':
                filtered_iface = optarg;
                break;
            case 't':
                startup_timeout = strtoul(optarg, 0, 0);
                break;
            case 'r':
                is_redirect = true;
                break;
            case 'q':
                starting_queue = strtoul(optarg, 0, 0);
                break;
            case 'n':
                n_queue = strtoul(optarg, 0, 0);
                break;
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            case ':':
                printf("Option -%c needs a value\n", optopt);
                exit(EXIT_FAILURE);
            case '?':
                printf("Unknown option: -%c\n", optopt);
                exit(EXIT_FAILURE);
            default:
                printf("Something wrong while parsing args!\n");
                exit(EXIT_FAILURE);
        }
    }
    if (!config_file | !filtered_iface) {
        printf("Missing args.\n");
        print_help();
        exit(EXIT_FAILURE);
    }
    check_special_char(filtered_iface);
}

void init_domain_block_list()
{
    if (!config_file) {
        debug_print("%s\n", "Config file is not set, use -c");
        exit(EXIT_FAILURE);
    }
    FILE *fp = fopen(config_file, "r");
    if (!fp){
        debug_print("Config file read error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    blocked_domain_tree_ptr = domain_tree_create_char_node(NULL);
    ssize_t domainlen = 0;
    size_t  buflen = 0;
    char *domain = NULL;
    while ((domainlen = getline(&domain, &buflen, fp)) != -1) {
        if (domain[domainlen - 1] == '\n') {
            domain[domainlen - 1] = '\x00';
            domainlen--;
        }
        debug_print("Adding domain to block list: %s\n", domain);
        domain_tree_insert(blocked_domain_tree_ptr, domain);
        free(domain);
        domain = NULL;
    }
    if (domain) {
        free(domain);
        domain = NULL;
    }
}

int main(int argc, char *argv[])
{
    parse_args(argc, argv);
    get_filtered_iface_mac();
    init_sig_handlers();
    init_domain_block_list();
    filter_init();
    filter_startup_wait();
    filter_wait();
}
