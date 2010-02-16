/*
 * lkmfirewall.c
 *
 *  Created on: Feb 10, 2010
 *      Author: Matthew Ziegelbaum
 *      Author: Ian Miers
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/parser.h>
#include <net/net_namespace.h>

#include "lkmfirewall.h"
#include "lkmfirewall_rule.h"

#define DRV_DESCRIPTION "A Simple Firewall Module"
#define DRV_NAME "lkmfirewall"
#define DRV_VERSION "0.1"
#define DRV_AUTHOR "Matthew Ziegelbaum and Ian Miers"
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_VERSION(DRV_VERSION);

static struct proc_dir_entry *firewall_proc;
static struct nf_hook_ops in_hook_opts;
static struct nf_hook_ops out_hook_opts;

enum {
	opt_direction,
	opt_action,
	opt_protocol,
	opt_iface,
	opt_saddr,
	opt_sport,
	opt_smask,
	opt_daddr,
	opt_dport,
	opt_dmask
};

static const match_table_t tokens = {
     { opt_direction, "dir=%s" },
     { opt_action, "act=%s" },
     { opt_protocol, "pro=%s" },
     { opt_iface, "pro=%s" },
     { opt_saddr, "sip=%s" },
     { opt_sport, "sprt=%d" },
     { opt_smask, "snm=%s" },
     { opt_daddr, "dip=%s" },
     { opt_dport, "dprt=%d" },
     { opt_dmask, "dnm=%s" }
};


/*
 * The list of firewall rules.
 */
struct firewall_rule rule_list;

void protocol_to_string(int protocol, char* dst) {
	switch(protocol) {
	case TCP:
		dst = "TCP\0";
		break;
	case UDP:
		dst = "UDP\0";
		break;
	case ICMP:
		dst = "ICMP";
		break;
	default:
		dst = "ALL\0";
		break;
	}
}

void action_to_string(int action, char* dst) {
	switch(action) {
	case ALLOW:
		dst = "ALLOW";
		break;
	case DENY:
		dst = "DENY";
		break;
	default:
		dst = "ERROR";
	}
}

void direction_to_string(int direction, char* dst) {
	switch(direction) {
	case IN:
		dst = "IN";
		break;
	case OUT:
		dst = "OUT";
		break;
	default:
		dst = "OMG";
	}
}

int get_stats(char *page, char **start, off_t off, int count, int *eof,
		void *data) {
	return 0;
}

/* Sends the user the rule list. Matches-ish iptables output format:
 * rule_num action direction iface protocol src src_netmask src_port dst dst_netmask dst_port
 */
int get_rules(char *page, char **start, off_t off, int count, int *eof,
		void *data) {
	int len;
	struct list_head *p, *n;
	struct firewall_rule *rule;
	unsigned int rule_num;
	char protocol[16], action[16], direction[16];

	if (off > 0) {
		*eof = 1;
	}
	len = 0;
	rule_num = 0;
	list_for_each_safe(p, n, &(rule_list.list)) {
		rule = list_entry(p, struct firewall_rule, list);
		protocol_to_string(rule->protocol, protocol);
		action_to_string(rule->action, action);
		direction_to_string(rule->direction, direction);

		len += sprintf(page, "%d %s %s %s %s %pI4. %pI4. %d %pI4. %pI4. %d\n", rule_num++,
				action, direction, rule->iface, protocol,
				&rule->src_ip, &rule->src_netmask, rule->src_port,
				&rule->dest_ip, &rule->dest_netmask, rule->dest_port);
	}

	return len;
}

ssize_t set_rules(struct file *filp, const char __user *buff,
		unsigned long len, void *data) {
	char *rule_string, *p, *val;
	int token;
	substring_t args[MAX_OPT_ARGS];
	struct firewall_rule *rule;

	rule_string = kmalloc(len*sizeof(char), GFP_KERNEL);
	if (copy_from_user(rule_string, buff, len) != 0) {
		return -EFAULT;
	}

	rule = kmalloc(sizeof(struct firewall_rule), GFP_KERNEL);

	while ((p = strsep(&rule_string, " ")) != NULL) {
		LKMFIREWALL_INFO("Parsing rule %s", p);
		if (!strlen(p))
			continue;
		token = match_token(p, tokens, args);
		val = match_strdup(&args[0]);
		switch (token) {
		case opt_direction:
			if (strcmp(val, "IN"))
				rule->direction = IN;
			else if (strcmp(val, "OUT"))
				rule->direction = OUT;
			else
				rule->direction = BOTH;
			break;
		case opt_action:
			if (strcmp(val, "DENY"))
				rule->action = DENY;
			else
				rule->action = ALLOW;
			break;
		case opt_protocol:
			if (strcmp(val, "TCP"))
				rule->protocol = TCP;
			else if (strcmp(val, "UDP"))
				rule->protocol = UDP;
			else if (strcmp(val, "ICMP"))
				rule->protocol = ICMP;
			else
				rule->protocol = ALL;
			break;
		case opt_iface:
			rule->iface = val;
			break;
		case opt_saddr:
			in4_pton(val, strlen(val), (void *)rule->src_ip, '\n', NULL);
			break;
		case opt_sport:
			break;
		case opt_smask:
			in4_pton(val, strlen(val), (void *)rule->src_netmask, '\n', NULL);
			break;
		case opt_daddr:
			in4_pton(val, strlen(val), (void *)rule->dest_ip, '\n', NULL);
			break;
		case opt_dmask:
			in4_pton(val, strlen(val), (void *)rule->dest_netmask, '\n', NULL);
			break;
		case opt_dport:
			break;
		default:
			continue;
		}
	}
	list_add_tail_rcu(&rule->list, &rule_list.list);

	return len;
}

unsigned int process_packet(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out, int(*okfun)(
				struct sk_buff *)) {
	struct list_head *p, *n;
	struct firewall_rule *rule;
	int decision;

	decision = NF_DROP;
	list_for_each_safe(p, n, &(rule_list.list)) {
		rule = list_entry(p, struct firewall_rule, list);
		LKMFIREWALL_ERROR("iface: %s", rule->iface);
		if (hooknum == NF_INET_PRE_ROUTING && (rule->direction == IN || rule->direction == ALL)) {
			return NF_DROP;
		} else if (hooknum == NF_INET_POST_ROUTING && (rule->direction == OUT || rule->direction == ALL)) {
			return NF_ACCEPT;
		}
	}
	printk("Got one!\n");
	return decision;
}

int filter_init(void) {
	printk(KERN_INFO "Matt and Ian's Firewall Fun Time\n");

	init_hooks();

	return init_procfs();
}

void filter_exit(void) {
	printk(KERN_INFO "Exiting firewall...\n");
	nf_unregister_hook(&in_hook_opts);
	nf_unregister_hook(&out_hook_opts);
	remove_proc_entry("statistics", firewall_proc);
	remove_proc_entry("rules", firewall_proc);
	remove_proc_entry(DRV_NAME, init_net.proc_net);
	firewall_proc = NULL;
}

int init_procfs(void) {
	struct proc_dir_entry *stats_proc;
	struct proc_dir_entry *rules_proc;


	firewall_proc = proc_mkdir(DRV_NAME, init_net.proc_net);
	if (!firewall_proc) {
		LKMFIREWALL_ERROR("Unable to create " DRV_NAME "'s proc entry");
		return -EIO;
	}

	stats_proc = create_proc_entry("statistics", S_IFREG | S_IRUGO,
			firewall_proc);
	if (!stats_proc) {
		remove_proc_entry(DRV_NAME, init_net.proc_net);
		firewall_proc = NULL;
		return -EIO;
	}
	stats_proc->read_proc = get_stats;

	rules_proc = create_proc_entry("rules", S_IFREG | S_IRUGO | S_IWUSR,
			firewall_proc);
	if (!rules_proc) {
		remove_proc_entry(DRV_NAME, init_net.proc_net);
		firewall_proc = NULL;
		return -EIO;
	}
	rules_proc->read_proc = get_rules;
	rules_proc->write_proc = set_rules;

	return 0;
}

void init_hooks(void) {
	in_hook_opts.hook = process_packet;
	in_hook_opts.hooknum = NF_INET_PRE_ROUTING;
	in_hook_opts.pf = PF_INET;
	in_hook_opts.priority = NF_IP_PRI_FIRST;
	in_hook_opts.owner = THIS_MODULE;

	out_hook_opts.hook = process_packet;
	out_hook_opts.hooknum = NF_INET_POST_ROUTING;
	out_hook_opts.pf = PF_INET;
	out_hook_opts.priority = NF_IP_PRI_FIRST;
	out_hook_opts.owner = THIS_MODULE;

	nf_register_hook(&in_hook_opts);
	nf_register_hook(&out_hook_opts);

	INIT_LIST_HEAD(&rule_list.list);
}

module_init(filter_init)
;
module_exit(filter_exit)
;
