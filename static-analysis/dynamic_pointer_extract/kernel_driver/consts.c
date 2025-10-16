/*
 * (C) 2009 Cam Macdonell
 * based on Hilscher CIF card driver (C) 2007 Hans J. Koch <hjk@linutronix.de>
 *
 * Licensed under GPL version 2 only.
 *
 */

#include <linux/module.h>     /* Needed by all modules */ 
#include <linux/kernel.h>     /* Needed for KERN_INFO */ 
#include <linux/init.h>       /* Needed for the macros */ 
#include <linux/debugfs.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <net/sock.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marius Fleischer");
MODULE_DESCRIPTION("Module for constant extraction");
MODULE_VERSION("0.1");

#include <uapi/linux/net.h>
#include <linux/net.h>
#include "consts.h"

static struct dentry *debugfs_root;

static int consts_open(struct inode *inode, struct file *file) {
	return 0;
}

static long consts_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
	struct ops_info info;
	char *buf = (char *)arg;
	int max;
	int err;
	struct socket *sock;
	struct file *file;

	switch(cmd) {
		case RETRIEVE_SOCK_INFO:
			if (copy_from_user(&info, buf, sizeof(struct ops_info))) {
				printk(KERN_ERR "[CONSTS] Could not copy from user\n");
				return -1;
			}
			if (info.fd < 0 || info.size_ops < sizeof(struct proto_ops)
					|| info.size_prot < sizeof(struct proto)
					|| info.size_sock < sizeof(struct sock)) {
				printk(KERN_ERR "[CONSTS] Invalid arguments: %d|%d vs %ld| %d vs %ld|%d vs %ld\n",
						info.fd, info.size_ops, sizeof(struct proto_ops), info.size_prot,
						sizeof(struct proto), info.size_sock, sizeof(struct sock));
				return -1;
			}

			sock = sockfd_lookup(info.fd, &err);
			if (!sock) {
				printk(KERN_ERR "[CONSTS] Could not lookup socket\n");
				return err;
			}

			if (copy_to_user(info.ops, sock->ops, sizeof(struct proto_ops))) {
				printk(KERN_ERR "[CONSTS] Could not copy to user\n");
				fput(sock->file);
				return -1;
			}
			if (copy_to_user(info.prot, sock->sk->sk_prot, sizeof(struct proto))) {
				printk(KERN_ERR "[CONSTS] Could not copy to user\n");
				fput(sock->file);
				return -1;
			}
			if (copy_to_user(info.sock, sock->sk, sizeof(struct sock))) {
				printk(KERN_ERR "[CONSTS] Could not copy to user\n");
				fput(sock->file);
				return -1;
			}
			fput(sock->file);
			break;
		case RETRIEVE_SOCK_MAX:
			max = SOCK_MAX;
			if (copy_to_user(buf, &max, sizeof(int))) {
				printk(KERN_ERR "[CONSTS] Could not copy to user\n");
				return -1;
			}
			break;
		case RETRIEVE_FAMILY_MAX:
			max = NPROTO;
			if (copy_to_user(buf, &max, sizeof(int))) {
				printk(KERN_ERR "[CONSTS] Could not copy to user\n");
				return -1;
			}
			break;
		case RETRIEVE_FD_INFO:
			if (copy_from_user(&info, buf, sizeof(struct ops_info))) {
				printk(KERN_ERR "[CONSTS] Could not copy from user\n");
				return -1;
			}

			if (info.fd < 0 || info.size_fops < sizeof(struct file_operations)) {
				printk(KERN_ERR "[CONSTS] Invalid arguments: %d|%d vs %ld\n",
						info.fd, info.size_fops, sizeof(struct file_operations));
				return -1;
			}
			if (info.size_fops < 0) {
				printk(KERN_ERR "[CONSTS] Invalid size: %d vs %ld\n",
						info.size_fops, sizeof(struct file_operations));
				return -1;
			}

			file = fget(info.fd);
			if (!file) {
				printk(KERN_ERR "[CONSTS] Could not lookup socket\n");
				return -1;
			}

			//printk(KERN_INFO "[CONSTS] f.file->f_op: %px\n", f.file->f_op->read);
			//printk(KERN_INFO "[CONSTS] f.file->f_op: %px\n", f.file->f_op->write);
			if (copy_to_user(info.fops, file->f_op, sizeof(struct file_operations))) {
				printk(KERN_ERR "[CONSTS] Could not copy to user\n");
				fput(file);
				return -1;
			}
			fput(file);
			break;
		default:
			return -ENOTTY;
	}
	return 0;
}

static int consts_release(struct inode *inode, struct file *file) {
	return 0;
}

static const struct file_operations fops = {
	.open = consts_open,
	.unlocked_ioctl = consts_ioctl,
	.compat_ioctl = consts_ioctl,
	.release = consts_release,
};

static int __init start(void) {
	int sock_max = SOCK_MAX;
	int family_max = NPROTO;
	
	printk(KERN_INFO "[CONSTS] SOCK_MAX: %d\n", sock_max);
	printk(KERN_INFO "[CONSTS] NPROTO: %d\n", family_max);


	debugfs_root = debugfs_create_dir("consts", NULL);
	if (!debugfs_root) {
		printk(KERN_ERR "[CONSTS] Could not create debugfs directory\n");
		return -1;
	}

	debugfs_create_file("sock_info", 0600, debugfs_root, NULL, &fops);

	return 0;
}

static void __exit end(void) {
	debugfs_remove_recursive(debugfs_root);
}

module_init(start);
module_exit(end);
