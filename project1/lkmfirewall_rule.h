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
#ifdef __KERNEL__
#include <linux/list.h>
#endif

struct firewall_rule {
	/* Linux kernel linked list pointer. We use this header in  */
#ifdef __KERNEL__
	struct list_head list;
#endif
	/* The action the rule specifies. */
	enum {ALLOW, DENY} action;
	/* Specifies if  the rule for outbound traffic or inbound traffic. */
	enum {IN, OUT, BOTH} direction;
	/* Specifies which protocol the rule is for. */
	enum{
		TCP,
		UDP,
		ICMP,
		ALL
	} protocol;
	/* Interface */
	char* iface;
	/* Source identifying rules */
	__be32 src_ip;
	__be32 src_netmask;
	__be32 src_port;
	/* Destination identifying rules*/
	__be32 dest_ip;
	__be32 dest_netmask;
	__be32 dest_port;

	/* For statistics */
	unsigned int applied;
};

typedef struct firewall_rule firewall_rule_t;

#endif /* LKMFIREWALL_RULE_H_ */
