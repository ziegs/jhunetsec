/*
 * fwadmin.h
 *
 *  Created on: Feb 13, 2010
 *      Author: user
 */
#include <linux/types.h>
#include "lkmfirewall_rule.h"
#ifndef FWADMIN_H_
#define FWADMIN_H_

#define checkEnum(enum,name){ if(enum.name ==)}
int handle_ip(const char * name, const char *ip, __be32 *ip_num,
		 int printerr);
int handle_port(const char * name, const char * port, __be32 *port_num,
		 int printerr);
int handle_netmask(const char * name, const char * netmask,
		__be32 *net_mask_num,  int printerr);
void serialize_rule(const struct firewall_rule rule,  FILE * fp);
int print_rules();
int write_rule(const struct firewall_rule rule);
#endif /* FWADMIN_H_ */


