/*
 * lkmfirewall.h
 *
 *  Created on: Feb 10, 2010
 *      Author: Matt Ziegelbaum
 *      Author: Ian Miers
 */

#ifndef LKMFIREWALL_H_
#define LKMFIREWALL_H_

// Gently borrowed from some other network code in the kernel
#define LKMFIREWALL_INFO(f, a...) printk(KERN_INFO "lkmfirewall: " f, ## a)
#define LKMFIREWALL_ERROR(f, a...) printk(KERN_ERR "lkmfirewall: " f, ## a)
#define LKMFIREWALL_WARNING(f, a...) printk(KERN_WARNING "lkmfirewall: " f, ## a)

void init_hooks(void);
int init_procfs(void);
#endif /* LKMFIREWALL_H_ */
