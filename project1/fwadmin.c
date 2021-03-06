#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#define __USE_MISC
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include "lkmfirewall_rule.h"
#include "fwadmin.h"

#define PROC_RULES_PATH "/proc/net/lkmfirewall/rules"
#define PROC_STATS_PATH "/proc/net/lkmfirewall/statistics"
#define TABLE_HEADER "rule\tact\tdirc\tproto\tifc\tsrcip\t\tsrcmsk\t\tsrcport\tdestip\t\tdesmsk\t\tdestport\n"
#define STAT_HEADER "rule\tblocked\n"
int help(){
	return printf("fwadmin manages lkmfirewall."
			"It takes one of the following commands:\n"
			"\t--action {BLOCK,UNBLOCK}\tblock or unblock\n"
				"\t\t\t\t\tpackets meeting the specified rule.\n"
			"\t--print\t\t\t\tPrint the existing rules.\n"
			"\t--delete RULE_NUM\t\tdelete the rule corresponding to RULE_NUM.\n"
			"\t--stats\t\t\t\tPrint number of packets blocked per rule.\n"
			"\t--help\t\t\t\tPrint this help menu.\n"
			"Rules must include\n"
			"\t--proto {TCP,UDP,ICMP,ALL}\tWhich protocol the rule is for.\n"
			"and optionally:\n"
			"\t--in\t\t\t\t\tThe rule applies to only incoming packets\n"
			"\t--out\t\t\t\t\tThe rule applies to only outgoing packets.\n"
			"\t--ifcae interface\t\tThe interface the rule applies to.\n"
			"\t--srcip ip\t\t\tThe source ip the rule applies to.\n"
			"\t--srcport port\t\t\tThe source port the rule applies to\n"
			"\t--srcnetmask netmask\t\tThe mask applied when comparing the source ip.\n"
				"\t\t\t\t\tMust be used with --srcip \n"
			"The corresponding flags for matching the destination of a packet:\n"
			"\t--destip\n"
			"\t--destport\n"
			"\t--destnetmask\n"
	);
}
int print_rules() {
	return print_info(PROC_RULES_PATH, TABLE_HEADER);
}

int print_statistics(){
	return print_info(PROC_STATS_PATH, STAT_HEADER);
}

/*Prints data from the specified file to standard in
 * after printing the given header*/
int print_info(const char* path, const char* header){
	FILE * fp;
	char buf[2048] = "";
	if (!(fp = fopen(path, "r"))) {
		fprintf(stderr,"Error reading %s. Please ensure the module is load",
				path);
		perror("");
		return -1;
	}
	printf("");
	printf("%s", header);
	while (fgets(buf, sizeof(buf), fp)){
		printf("%s", buf);
	}
	fclose(fp);

	return 1;
}
/*Writes the firewall rule to the proc file system*/
int write_rule(const struct firewall_rule rule) {
	FILE * fp = fopen(PROC_RULES_PATH, "w");
	if (fp == NULL) {
		perror("Error setting firewall rule");
		return -1;
	}
	serialize_rule(rule, fp);
	fclose(fp);
	return 1;
}

/*Deletes rule corresponding to the supplied number.
 * These numbers are merely the order in which the rules are
 * stored in the kernel module, starting at zero*/
int delete_rule(const unsigned int rule) {
	FILE * fp = fopen(PROC_RULES_PATH,"w");
	if(fp == NULL || 0 > fprintf(fp,"DELETE %d",rule)){
		perror("Error deleting firewall rule. Please ensure the module is loaded");
		return -1;
	}
	return 1;
}



/* This function is modified from the GNU get opts example at
 * http://www.gnu.org/s/libc/manual/html_node/
 * Getopt-Long-Option-Example.html#Getopt-Long-Option-Example
 * */
int main(int argc, char **argv) {
	static struct firewall_rule rule;
	rule.src_netmask = UINT32_MAX; // set netmask to 255.255.255.255
	rule.dest_netmask = UINT32_MAX;
	int action_set = 0;
	int direction_set = 0;
	int proto_set = 0;
	int src_net_msk_set = 0;
	int dest_net_msk_set = 0;
	int src_ip_set = 0;
	int dest_ip_set = 0;
	int src_port_set = 0;
	int dest_port_set = 0;
	int rule_numb;
	while (1) {
		static struct option long_options[] = {
				{ "in", no_argument, 0, 'i' },
				{ "out", no_argument, 0, 'o' },
				{ "proto", required_argument, 0, 'p' },
				{ "action", required_argument, 0, 'a' },
				{ "srcip", required_argument, 0, 's' },
				{ "srcport", required_argument, 0, 't' },
				{ "srcnetmask",	required_argument, 0, 'u' },
				{ "destip",	required_argument, 0, 'd' },
				{ "destport", required_argument, 0, 'e' },
				{ "destnetmask", required_argument, 0, 'f' },
				{ "iface", required_argument, 0, 'q' },
				{ "print", no_argument, 0, 'r' },
				{ "help",no_argument,0,'w'},
				{ "delete", required_argument, 0, 'y'},
				{ "stats", no_argument, 0, 'z'},
				{ 0, 0, 0, 0 }
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		int c = getopt_long(argc, argv, "", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0) {
				break;
			}
			printf("option %s", long_options[option_index].name);
			if (optarg) {
				printf(" with arg %s", optarg);
			}
			printf("\n");
			break;
		case 'i':
			printf("Direction IN\n");
			//direction = "IN";
			rule.direction = IN;
			direction_set = 1;
			break;
		case 'o':
			printf("Direction OUT\n");
			rule.direction = OUT;
			direction_set = 1;
			break;
		case 'p': // protocol
			proto_set = 1;
			//proto = optarg;
			if (strcmp(optarg, "TCP") == 0) {
				rule.protocol = TCP;
			} else if (strcmp(optarg, "UDP") == 0) {
				rule.protocol = UDP;
			} else if (strcmp(optarg, "ICMP") == 0) {
				rule.protocol = ICMP;
			} else if (strcmp(optarg, "ALL") == 0) {
				rule.protocol = ALL;
			} else {
				proto_set = 0;
				printf(
						"Invalid protocol: %s. \n Valid protocols are TCP, UDP, ICMP, ALL\n",
						optarg);
				return -1;
			}

			break;

		case 'a': // action
			printf("Action: %s\n", optarg);
			if (strcmp(optarg, "BLOCK") == 0) {
				rule.action = DENY;
				action_set = 1;
			} else if (strcmp(optarg, "UNBLOCK") == 0) {
				rule.action = ALLOW;
				action_set = 1;
			} else {
				fprintf(
						stderr,
						"Invalid argument : --action accepts BLOCK and UNBLOCK, not  %s\n",
						optarg);
				return -1;
			}
			break;
		case 's': // source ip
			printf("source ip %s\n", optarg);
			if (handle_ip("source ip", optarg, &(rule.src_ip), 1) == 1) {
				src_ip_set  = 1;
			} else {
				return -1;
			}
			break;
		case 't': // source port
			if (handle_port("source port", optarg, &(rule.src_port), 1) == 1) {
				src_port_set = 1;
			} else {
				return -1;
			}
			break;
		case 'u': // source netmask
			printf("src netmask with %s\n", optarg);
			if (handle_ip("source netmask", optarg, &(rule.src_netmask), 1)
					== 1) {
				src_net_msk_set = 1;
			}
			break;
		case 'd': // destination ip
			printf("destination ip %s\n", optarg);
			if (handle_ip("destination ip", optarg, &(rule.dest_ip), 1) == 1) {
				dest_ip_set = 1;
			} else {
				return -1;
			}
			break;
		case 'e': // destination  port
			printf("destination port %s \n", optarg);
			if (handle_port("destination port", optarg,
					&(rule.dest_port), 1) == 1) {
				dest_port_set = 1;
			} else {
				return -1;
			}
			break;
		case 'f': // destination netmask
			printf("destination netmask with %s\n", optarg);
			if (handle_ip("destination netmask", optarg, &(rule.dest_netmask),
					1) == 1) {
			  dest_net_msk_set = 1;
			} else {
				return -1;
			}
			break;
		case 'q'://interface flag
			rule.iface = optarg;
			break;
		case 'r': // print flag
			return print_rules();
		case 'w':
			return help();
		case 'y': // delete flag
			rule_numb = atoi(optarg);
			if(0 <= rule_numb){
				return delete_rule(rule_numb);
			} else {
				fprintf(stderr,"Invalid rule number %d."
						"Rule numbers must be positive.\n",rule_numb);
				return -1;
			}
			break;
		case 'z': // statistics flag
			return print_statistics();
			break;
		case '?':
			/* getopt_long already printed an error message. */
			break;
		default:
			return -1;
		}
		if (rule.iface == NULL) {
			rule.iface = "ANY";
		}
	}

	if (!action_set) {
		fprintf(stderr,
				"Please specify an action of BLOCK or UNBLOCK using --action ACTION.\n");
		return -1;
	}

	if (!proto_set) {
		fprintf(stderr,
				"Please specify a protocol of TCP, UDP, ICMP, or ALL using --proto PROTO\n");
		return -1;
	}

	if((src_net_msk_set && !src_ip_set) || dest_net_msk_set && !dest_ip_set){
		fprintf(stderr,"If you specify a source or destination netmask\n"
			"you must specify the corresponding ip address.\n");
		return 0;
	}

	// if someone left off source/ dest IP
	// Then implicitly they set the netmask to zero.
	if(!src_ip_set){
		rule.src_netmask = 0 ;
	}
	if(!dest_ip_set){
		rule.dest_netmask = 0;
	}
//	serialize_rule(rule, stdout);
	return write_rule(rule);
}

int handle_ip(const char * name, const char *ip, __be32 *ip_num, int printerr) {
	struct in_addr ip_addr;
	if (inet_aton(ip, &ip_addr)) {
		*ip_num = ip_addr.s_addr;
		return 1;
	} else if (printerr) {
		fprintf(stderr, "Invalid %s : %s \n", name, ip);
		fprintf(
				stderr,
				"The %s must be between 0.0.0.0 and 255.255.255.255 inclusive.\n",
				name);
		return -1;
	} else {
		return -1;
	}
}

int handle_port(const char *name, const char *port, __be32 *port_num,
		int printerr) {
	int tmp = atoi(port);
	if (tmp >= 0 && tmp <= 65535) {
		*port_num = tmp;
		return 1;
	} else if (printerr) {
		fprintf(stderr, "Invalid %s  : %s\n", name, optarg);
		fprintf(stderr, "%s must be between 0 and 65535 inclusive.\n", name);
		return -1;
	} else {
		return -1;
	}
}

int handle_netmask(const char * name, const char * netmask,
		__be32 *net_mask_num, int printerr) {
	return handle_ip(name, netmask, net_mask_num, printerr);
}

void serialize_rule(const struct firewall_rule rule, FILE *fp) {
	char *direction = "";
	char *proto = "";
	char *action = "";
	char src_ip[512];
	char src_port[6]; // max size of a valid source port
	char src_netmask[512];
	char dest_ip[512];
	char dest_port[6]; // max size of a valid destination port
	char dest_netmask[512];
	if (rule.action == ALLOW) {
		action = "ALLOW";
	} else if (rule.action == DENY) {
		action = "DENY";
	}

	if (rule.direction == IN) {
		direction = "IN";
	} else if (rule.direction == OUT) {
		direction = "OUT";
	}

	if (rule.protocol == ALL) {
		proto = "ALL";
	} else if (rule.protocol == TCP) {
		proto = "TCP";
	} else if (rule.protocol == UDP) {
		proto = "UDP";
	} else if (rule.protocol == ICMP) {
		proto = "ICMP";
	}

	inet_ntop(AF_INET, &rule.src_ip, src_ip, sizeof src_ip);
	sprintf(src_port, "%d", rule.src_port);
	inet_ntop(AF_INET, &rule.src_netmask, src_netmask, sizeof src_netmask);

	inet_ntop(AF_INET, &rule.dest_ip, dest_ip, sizeof dest_ip);
	sprintf(dest_port, "%d", rule.dest_port);
	inet_ntop(AF_INET, &rule.dest_netmask, dest_netmask, sizeof dest_netmask);

	char *fmt = "ADD %s %s %s %s %s %s %s %s %s %s\n";
	if(fprintf(fp, fmt, action, direction, proto, rule.iface, src_ip, src_port,
			src_netmask, dest_ip, dest_port, dest_netmask) < 0){
			perror("Error writing to file "PROC_RULES_PATH);
	}
}

