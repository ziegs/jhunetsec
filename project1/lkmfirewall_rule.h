/*
 * lkmFirewall_rule.h
 *
 *  Created on: Feb 10, 2010
 *      Author: Ian Miers
 */

#ifndef LKMFIREWALL_RULE_H_
#define LKMFIREWALL_RULE_H_
#include <linux/types.h>
#include <linux/list.h>
struct firewall_rule {
	struct list_head list;
	enum { IN,OUT} in_or_out;
	/** what protocal the rule is for */
	enum{
		TCP,
		UDP,
		ICMP,
	} protocal;
	_be32 src_ip;
	_be32 src_netmask;
	_be32 src_port;

	_be32 dest_ip;
	_be32 dest_port;
	_be32 dest_netmask;
};

#endif /* LKMFIREWALL_RULE_H_ */
