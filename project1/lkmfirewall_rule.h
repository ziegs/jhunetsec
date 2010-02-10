/*
 * lkmFirewall_rule.h
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
	struct list_head list;
	enum {IN, OUT} direction;
	/** what protocol the rule is for */
	enum {
		TCP,
		UDP,
		ICMP,
	} protocol;
	__be32 src_ip;
	__be32 src_netmask;
	__be32 src_port;

	__be32 dest_ip;
	__be32 dest_port;
	__be32 dest_netmask;
};

#endif /* LKMFIREWALL_RULE_H_ */
