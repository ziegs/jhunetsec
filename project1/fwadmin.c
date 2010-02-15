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
/*This file modifed from the GNU get opts example at
 * http://www.gnu.org/s/libc/manual/html_node/
 * Getopt-Long-Option-Example.html#Getopt-Long-Option-Example
 * */
int main(int argc, char **argv) {
	static struct firewall_rule rule;
	static int in_out;
	char * direction = "";
	char * proto = "";
	char * action = "";
	char * scrip = "";
	char * srcport = "";
	char * srcnetmask = "";
	char * destip = "";
	char * destport = "";
	char * destnetmask = "";

	while (1) {
		static struct option long_options[] = {
				{ "in", no_argument, 0,'i' },
				{ "out", no_argument,0,'o' },
				{ "proto", required_argument, 0, 'p' },
				{ "action",required_argument, 0, 'a' },
				{ "srcip", required_argument, 0,'s' },
				{ "srcport", required_argument, 0, 't' },
				{"srcnetmask", required_argument, 0, 'u' },
				{ "destip",required_argument, 0, 'd' },
				{ "destport", required_argument,0, 'e' },
				{ "destnetmask", required_argument, 0, 'f' },
				{ 0, 0,0, 0 } };
		/* getopt_long stores the option index here. */
		int option_index = 0;

		int c = getopt_long(argc, argv, "", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0){
				break;
			}
			printf("option %s", long_options[option_index].name);
			if (optarg){
				printf(" with arg %s", optarg);
			}
			printf("\n");
			break;
		case 'i':
			direction = "IN";
			rule.direction=IN;
			break;
		case 'o':
			direction = "OUT";
			rule.direction=OUT;
			break;
		case 'p': // protocol
			printf("protocal with %s\n", optarg);
			proto = optarg;
			if (strcmp(optarg, "TCP") == 0) {
				rule.protocol = TCP;
			} else if (strcmp(optarg, "UDP") == 0) {
				rule.protocol = UDP;
			} else if (strcmp(optarg, "ICMP") == 0) {
				rule.protocol = ICMP;
			} else if (strcmp(optarg, "ANY") == 0) {
				rule.protocol = ANY;
			} else {
				proto = "";
				printf("Invald protcal : %s. \n Valid protocasl are TCP,UDP,ICMP,ALL",
						optarg);
				abort();
			}

			break;

		case 'a': // action
			printf("action with %s", optarg);
			if (strcmp(optarg, "BLOCK") == 0) {
				action = optarg;
				rule.action = BLOCK;
			} else if (strcmp(optarg, "UNBLOCK")) {
				action = optarg;
				rule.action = ALLOW;
			} else {
				fprintf(
						stderr,
						"Invalid argument : --action accepts BLOCK and UNBLOCK, not  %s\n",
						optarg);
				abort();
			}
			break;
		case 's': // source ip
			printf("source ip %s\n", optarg);
			if (handle_ip("source ip", optarg, &(rule.src_ip), 1)) {
				scrip = optarg;
			} else {
				abort();
			}
			break;
		case 't': // source port
			if (handle_port("source port", optarg, &(rule.src_port), 1)) {
				srcport = optarg;
			} else {
				abort();
			}
			break;
		case 'u': // source netmask
			printf("src netmask with %s\n", optarg);
			if (handle_ip("source netmask", optarg, &(rule.src_port), 1)) {
				srcnetmask = optarg;
			}
			break;
		case 'd': // destination ip
			printf("destination ip %s\n", optarg);
			if (handle_ip("destination ip", optarg, &(rule.dest_ip), 1)) {
				destip = optarg;
			} else {
				abort();
			}
			break;
		case 'e': // destination  port
			printf("destination port %s \n", optarg);
			if (handle_port("destination port", optarg, &(rule.dest_port), 1)) {
				destport = optarg;
			} else {
				abort();
			}
			break;
		case 'f': // destination netmask
			printf("destination netmask with %s\n", optarg);
			if (handle_ip("destination netmask", optarg, &(rule.dest_port), 1)) {
				destnetmask = optarg;
			} else {
				abort();
			}
			break;
		case '?':
			/* getopt_long already printed an error message. */
			break;

		default:
			abort();
		}
	}
	serialize_rule(rule);
}

int handle_ip(const char * name, const char *ip, __be32 *ip_num,
		 int printerr) {
	struct in_addr ip_addr;
	if (inet_aton(ip,&ip_addr)) {
		*ip_num = ip_addr.s_addr;
		return 1;
	} else if (printerr) {
		fprintf(stderr, "Invalid %s : %s \n", name, ip);
		fprintf(stderr,"The %s must be between 0.0.0.0 and 255.255.255.255 inclusive",name);
		return 0;
	} else {
		return 0;
	}
}
int handle_port(const char * name, const char * port, __be32 *port_num,
		 int printerr) {
	int tmp = atoi(port);
	if (tmp > 0 && tmp < 65535) {
		*port_num = tmp;
		return 1;
	} else if (printerr) {
		fprintf(stderr, "Invalid %s  : %s\n", name, optarg);
		fprintf(stderr, "%s bust be between 0 and 65535 inclusive.\n", name);
		return 0;
	} else {
		return 0;
	}
}
int handle_netmask(const char * name, const char * netmask,
		__be32 *net_mask_num,  int printerr) {
	return handle_ip(name, netmask, net_mask_num, printerr);
}
void serialize_rule(const struct firewall_rule rule){
	char * direction = "";
	char * proto = "";
	char * action = "";
	char * src_ip = "";
	char src_port[6]; // max size of a valid source port
	char * src_netmask = "";
	char * dest_ip = "";
	char  dest_port[6]; // max size of a valid destination port
	char * dest_netmask = "";
	if (rule.action == ALLOW){
		action = "ALLLOW";
	}else if(rule.action == BLOCK){
		action = "BLOCK";
	}

	if(rule.direction == IN ){
		direction = "IN";
	}else if (rule.direction == OUT){
		direction = "OUT";
	}

	if(rule.protocol == ANY){
		proto = "ANY";
	}else if (rule.protocol == TCP){
		proto = "TCP";
	}else if(rule.protocol == UDP){
		proto = "UDP";
	}else if (rule.protocol == ICMP){
		proto = "ICMP";
	}
	struct in_addr tmp;
	tmp.s_addr = rule.src_ip;
	src_ip = inet_ntoa(tmp);
	sprintf(src_port,"%d",rule.src_port);
	tmp.s_addr = rule.src_netmask;
	src_netmask= inet_ntoa(tmp);
	tmp.s_addr=rule.dest_ip;
	dest_ip = inet_ntoa(tmp);
	sprintf(dest_port,"%d",rule.dest_port);
	tmp.s_addr=rule.dest_netmask;
	dest_netmask = inet_ntoa(tmp);
	int s = 0;
	char * fmt =
			"act %s\ndir %s\npro %s\nsip %s\nspt %s\nsnm %s\ndip %s\ndprt %s\ndnm %s\n\n";
	printf(fmt,action,direction, proto,src_ip,src_port, src_netmask, dest_ip,
			dest_port,dest_netmask);
	/*char str[s];
	sprintf(str,fmt,action,direction, proto,src_ip,src_port, src_netmask, dest_ip,
			dest_port,dest_netmask);
	puts(str);*/
}
