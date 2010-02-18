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
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/parser.h>
#include <linux/types.h>
#include <net/ip.h>
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

/*
 * The list of firewall rules.
 */
struct firewall_rule rule_list;

char* protocol_to_string(int protocol) {
	switch(protocol) {
	case TCP:
		return "TCP";
	case UDP:
		return "UDP";
	case ICMP:
		return "ICMP";
	default:
		return "ALL";
	}
}

char* action_to_string(int action) {
	switch(action) {
	case ALLOW:
		return "ALLOW";
	case DENY:
		return "DENY";
	default:
		return "";
	}
}

char* direction_to_string(int direction) {
	switch(direction) {
	case IN:
		return "IN";
	case OUT:
		return "OUT";
	default:
		return "";
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
	char *protocol, *action, *direction;

	if (off > 0) {
		*eof = 1;
	}
	len = 0;
	rule_num = 0;
	list_for_each_safe(p, n, &(rule_list.list)) {
		rule = list_entry(p, struct firewall_rule, list);
		protocol = protocol_to_string(rule->protocol);
		action = action_to_string(rule->action);
		direction = direction_to_string(rule->direction);
		len += sprintf(&page[len], "%-5d\t%s\t%s\t%s\t%s\t%-15pI4\t%-15pI4\t%-5d\t%-15pI4\t%-15pI4\t%-5d\n",
				rule_num++,	action, direction, protocol, rule->iface,
				&rule->src_ip, &rule->src_netmask, rule->src_port,
				&rule->dest_ip, &rule->dest_netmask, rule->dest_port);
	}

	return len;
}

int delete_rule(int rule_num) {
	int i = 0;
	struct list_head *p, *n;
	struct list_head *found = NULL;
	struct firewall_rule *found_rule = NULL;

	list_for_each_safe(p, n, &(rule_list.list)) {
		if (rule_num == i) {
			found = p;
			break;
		}
		i++;
	}

	if (found) {
		found_rule = list_entry(found, struct firewall_rule, list);
		list_del_rcu(p);
		kfree(found_rule);
		return 1;
	}

	return 0;
}

int add_rule(char *rule_string, int len) {
	char *p;
	struct firewall_rule *rule;
	int token;

	rule = kmalloc(sizeof(struct firewall_rule), GFP_KERNEL);
	token = 0;
	LKMFIREWALL_ERROR("%s", rule_string);
	while ((p = strsep(&rule_string, " ")) != NULL) {
		if (!strlen(p))
			continue;
		switch (token) {
		case 0: //action
			if (strcmp(p, "ALLOW") == 0)
				rule->action = ALLOW;
			else if (strcmp(p, "DENY") == 0)
				rule->action = DENY;
			else {
				kfree(rule);
				return -EINVAL;
			}
			break;
		case 1: // direction
			if (strcmp(p, "IN") == 0)
				rule->direction = IN;
			else if (strcmp(p, "OUT") == 0)
				rule->direction = OUT;
			else if (strcmp(p, "BOTH") == 0)
				rule->direction = BOTH;
			else {
				kfree(rule);
				return -EINVAL;
			}
			break;
		case 2: // protocol
			if (strcmp(p, "TCP") == 0)
				rule->protocol = TCP;
			else if (strcmp(p, "UDP") == 0)
				rule->protocol = UDP;
			else if (strcmp(p, "ICMP") == 0)
				rule->protocol = ICMP;
			else
				rule->protocol = ALL;
			break;
		case 3: // iface
			rule->iface = p;
			break;
		case 4: // source ip
			in4_pton(p, strlen(p), (u8 *) &rule->src_ip, '\n', NULL);
			break;
		case 5: // source port
			rule->src_port = simple_strtoul(p, NULL, 0);
			break;
		case 6: // source netmask
			in4_pton(p, strlen(p), (u8 *) &rule->src_netmask, '\n', NULL);
			break;
		case 7: // dest ip
			in4_pton(p, strlen(p), (u8 *) &rule->dest_ip, '\n', NULL);
			break;
		case 8: // dest port
			rule->dest_port = simple_strtoul(p, NULL, 0);
			break;
		case 9: // dest netmask
			in4_pton(p, strlen(p), (u8 *) &rule->dest_netmask, '\n', NULL);
			break;
		default:
			LKMFIREWALL_WARNING("Too many arguments to add: %s", p);
			kfree(rule);
			return -E2BIG;
		}
		token++;
	}
	list_add_tail_rcu(&rule->list, &rule_list.list);
	return len;
}

ssize_t set_rules(struct file *filp, const char __user *buff,
		unsigned long len, void *data) {
	char *rule_string, *p;
	int token;

	rule_string = kmalloc(len*sizeof(char), GFP_KERNEL);
	if (copy_from_user(rule_string, buff, len) != 0) {
		return -EFAULT;
	}

	if ((p = strsep(&rule_string, " ")) == NULL)
		return -EINVAL;

	if (strcmp(p, "ADD") == 0) {
		return add_rule(rule_string, len);
	} else if (strcmp(p, "DELETE") == 0) {
		if ((p = strsep(&rule_string, " ")) == NULL)
			return -EINVAL;
		token = simple_strtoul(p, NULL, 0);
		if (!delete_rule(token)) {
			LKMFIREWALL_WARNING("Could not delete rule %d", token);
		}
	} else {
		LKMFIREWALL_ERROR("Invalid firewall command.");
		return -EINVAL;
	}
	return len;
}

int check_ip_packet(struct firewall_rule *rule, struct sk_buff *skb) {
	const struct iphdr *iph;
	const struct udphdr *hdr, *_hdr;
	const struct icmphdr *icmphdr, *_icmphdr;
	__be32 daddr, saddr;
	__be32 dport, sport;

	if (!skb)
		return true; // If there's no socket buffer its nonsense anyway.
	if (!(iph = ip_hdr(skb)))
		return true; // If there's no IP header, just pass it on through.
	if (iph->protocol == rule->protocol || rule->protocol == ALL) {
		if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
			hdr = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
			if (!hdr)
				return false;
			saddr = iph->saddr;
			daddr = iph->daddr;
			sport = hdr->source;
			dport = hdr->dest;
			if ((rule->src_port == sport || rule->src_port == 0) &&
					(rule->dest_port == dport || rule->dest_port == 0)) {
				LKMFIREWALL_INFO("%pI4", &saddr);
				LKMFIREWALL_INFO("%pI4", &rule->src_ip);
				LKMFIREWALL_INFO("%pI4", &daddr);
				LKMFIREWALL_INFO("%pI4", &rule->dest_ip);
				LKMFIREWALL_INFO("%d", (saddr & rule->src_netmask));
				LKMFIREWALL_INFO("%d", (rule->src_ip & rule->src_netmask));
				LKMFIREWALL_INFO("%d", (daddr & rule->dest_netmask));
				LKMFIREWALL_INFO("%d", (rule->dest_ip & rule->dest_netmask));
				if (((saddr & rule->src_netmask) == (rule->src_ip & rule->src_netmask)) &&
						((daddr & rule->dest_netmask) == (rule->dest_ip & rule->dest_netmask)))
					return true;
				return false;
			}

		} else if (iph->protocol == IPPROTO_ICMP) {
			icmphdr = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_icmphdr), &_icmphdr);
			if (!icmphdr)
				return false;
		} else {
			return false;
		}
	}
	return false;
}


int check_rule(struct firewall_rule *rule, struct sk_buff *skb,
		const struct net_device *dev) {
	if (rule->iface == dev->name || strcmp(rule->iface, "ANY") == 0)
		return check_ip_packet(rule, skb);
	return false;
}

unsigned int process_packet(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out, int(*okfun)(
				struct sk_buff *)) {
	struct list_head *p, *n;
	struct firewall_rule *rule, *filter;
	int decision;

	decision = NF_ACCEPT;
	filter = NULL;
	/* Loop through each rule, and check to see if it applies. The last
	 * applicable rule in the chain is the one we use. This ensures UNBLOCK
	 * commands get applied (assuming they come after a more broad rule). */
	list_for_each_safe(p, n, &(rule_list.list)) {
		rule = list_entry(p, struct firewall_rule, list);
		if (hooknum == NF_INET_LOCAL_IN && (rule->direction == IN || rule->direction == BOTH)) {
			if (check_rule(rule, skb, in))
				filter = rule;
		} else if (hooknum == NF_INET_LOCAL_OUT && (rule->direction == OUT || rule->direction == BOTH)) {
			if (check_rule(rule, skb, in))
				filter = rule;
		}
	}

	if (filter) {
		LKMFIREWALL_INFO("Applying rule %pI4:%d, mask %pI4\n", &rule->src_ip,
				rule->src_port, &rule->src_netmask);
		filter->applied++;
		return filter->action;
	} else {
		return NF_ACCEPT;
	}
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
	in_hook_opts.hooknum = NF_INET_LOCAL_IN;
	in_hook_opts.pf = PF_INET;
	in_hook_opts.priority = NF_IP_PRI_FIRST;
	in_hook_opts.owner = THIS_MODULE;

	out_hook_opts.hook = process_packet;
	out_hook_opts.hooknum = NF_INET_LOCAL_OUT;
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
