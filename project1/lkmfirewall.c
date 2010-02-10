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
#include <net/net_namespace.h>

#include "lkmfirewall.h"

#define DRV_DESCRIPTION "A Simple Firewall Module"
#define DRV_NAME "lkmfirewall"
#define DRV_VERSION "0.1"
#define DRV_AUTHOR "Matthew Ziegelbaum and Ian Miers"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_AUTHOR);
MODULE_VERSION(DRV_VERSION);

static struct proc_dir_entry *firewall_proc;
static struct nf_hook_ops hook_opts;

int get_stats(char *page, char **start, off_t off, int count, int *eof,
		void *data) {
	return 0;
}

int get_rules(char *page, char **start, off_t off, int count, int *eof,
		void *data) {
	return 0;
}

ssize_t set_rules(struct file *filp, const char __user *buff,
		unsigned long len, void *data) {
	return len;
}

int process_packet(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int(*okfun)(struct sk_buff *)) {
	printk(KERN_INFO "Got one!");
	return NF_DROP;
}

int filter_init(void) {
	printk(KERN_INFO "Matt and Ian's Firewall Fun Time\n");

	hook_opts.hook = process_packet;
	hook_opts.hooknum = NF_INET_PRE_ROUTING;
	hook_opts.pf = PF_INET;
	hook_opts.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&hook_opts);

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

void filter_exit(void) {
	printk(KERN_INFO "Exiting firewall...\n");
	nf_unregister_hook(&hook_opts);
	remove_proc_entry("statistics", firewall_proc);
	remove_proc_entry("rules", firewall_proc);
	remove_proc_entry(DRV_NAME, init_net.proc_net);
	firewall_proc = NULL;
}
module_init(filter_init)
;
module_exit(filter_exit)
;
