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
	/* The list we are in. This uses linux kernel lists */
	struct list_head list;
	/* The action the rule specifies*/
	enum { ALLOW,BLOCK} allow_or_block;
	/*Specifies if  the rule for outbound traffic or inbound traffic*/
	enum { IN,OUT} in_or_out;
	/* What protocol the rule is for*/
	enum{
		TCP,
		UDP,
		ICMP,
	} protocol;
	/* Source identifying rules */
	_be32 src_ip;
	_be32 src_netmask;
	_be32 src_port;

	/* Destination identifying rules*/
	_be32 dest_ip;
	_be32 dest_port;
	_be32 dest_netmask;
};

#endif /* LKMFIREWALL_RULE_H_ */
