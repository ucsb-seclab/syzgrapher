#include <linux/types.h>

#define RETRIEVE_SOCK_INFO	_IOWR('f', 0x30, struct ops_info)
#define RETRIEVE_SOCK_MAX	_IOR('f', 0x31, int)
#define RETRIEVE_FAMILY_MAX	_IOR('f', 0x32, int)
#define RETRIEVE_FD_INFO	_IOR('f', 0x33, int)

struct ops_info {
	int fd;
	int size_ops;
	int size_prot;
	int size_sock;
	int size_fops;
	char *ops;
	char *prot;
	char *sock;
	char *fops;
};

struct sock_info {
	int domain;
	int type;
	int protocol;
	int success;
	struct ops_info *ops_info;
};
