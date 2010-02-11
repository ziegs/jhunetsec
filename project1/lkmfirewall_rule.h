/*
 * lkmfirewall_rule.h
 *
 *  Created on: Feb 10, 2010
 *      Author: Ian Miers
 *      Author: Matt Ziegelbaum
 */

#ifndef LKMFIREWALL_RULE_H_
#define LKMFIREWALL_RULE_H_

#include <linux/types.h>
#include <linux/list.h>

struct firewall_rule {
	/* Linux kernel linked list pointer. */
	struct list_head list;
	/* The action the rule specifies. */
	enum {ALLOW, BLOCK} action;
	/* Specifies if  the rule for outbound traffic or inbound traffic. */
	enum {IN, OUT} direction;
	/* Specifies which protocol the rule is for. */
	enum{
		TCP,
		UDP,
		ICMP,
		ANY
	} protocol;
	/* Interface */
	char* iface;
	/* Source identifying rules */
	__be32 src_ip;
	__be32 src_netmask;
	__be32 src_port;
	/* Destination identifying rules*/
	__be32 dest_ip;
	__be32 dest_port;
	__be32 dest_netmask;
};

#endif /* LKMFIREWALL_RULE_H_ */
