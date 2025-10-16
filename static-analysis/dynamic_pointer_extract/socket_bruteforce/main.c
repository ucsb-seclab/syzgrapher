#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "extract.h"

static FILE *logging;
static FILE *network_data;
static FILE *fd_data;
static int kmod;

int parse_input(char *argv[], int (*inputs)[7]) {
	char *endptr;
	for (int i = 0; i < 5; ++i) {
		errno = 0;
		(*inputs)[i+2] = strtol(argv[i+1], &endptr, 10);
		if (errno != 0 || *endptr != '\0') {
			printf("invalid argument: %s\n", argv[i]);
			perror("invalid argument");
			return 1;
		}
	}

	return 0;
}

int get_domain_type(int (*inputs)[7]) {
	int family, type;
	if (ioctl(kmod, RETRIEVE_FAMILY_MAX, &family) == -1) {
		perror("ioctl");
		return -1;
	}

	if (ioctl(kmod, RETRIEVE_SOCK_MAX, &type) == -1) {
		perror("ioctl");
		return -1;
	}

	(*inputs)[0] = family;
	(*inputs)[1] = type;
	return 0;
}

/* storage file format:
 * 1. file: fd_info.txt - each line of format <file_path> [success|failed]
 * 2. file: fd_data.bin - one entry per success entry in fd_info.txt; each entry is of format
 *     <file_path><size_fops><fops> 0xbeefdead
 */
int write_fd_info_to_file(struct ops_info *info, int success, char *file_path) {
	int ret, magic_number = 0xbeefdead;
	if (success == 0) {
		ret = fprintf(logging, "%s failed\n", file_path);
		if (ret < 0) {
			perror("fprintf");
			return -1;
		}
		fflush(logging);
		return 0;
	}

	ret = fprintf(logging, "%s success\n", file_path);
	if (ret < 0) {
		perror("fprintf");
		return -1;
	}
	fflush(logging);
	// write data
	// write fd info and size
	fwrite(file_path, 1, strlen(file_path)+1, fd_data);
	fwrite(&info->size_fops, 1, 4, fd_data);
	// write struct byte by byte
	if (info->size_fops)
		fwrite(info->fops, 1, info->size_fops, fd_data);
	// write magic number
	fwrite(&magic_number, 1, 4, fd_data);
	fflush(fd_data);

	return 0;
}

/* storage file format:
 * 1. file: network_stack_info.txt - each line of format <domain> | <type> | <protocol> [success|failed]
 * 2. file: network_data.bin - one entry per success entry in network_stack_info.txt; each entry is of format
 *     <domain><type><protocol><size_ops><size_prot><size_sock><size_fops><ops><prot><sock><fops> 0xbeefdead
 */
int write_network_info_to_file(struct sock_info *info) {
	int ret, magic_number = 0xbeefdead;
	if (info->success == 0) {
		ret = fprintf(logging, "%d | %d | %d failed\n", info->domain, info->type, info->protocol);
		if (ret < 0) {
			perror("fprintf");
			return -1;
		}
		fflush(logging);
		return 0;
	}

	ret = fprintf(logging, "%d | %d | %d success\n", info->domain, info->type, info->protocol);
	if (ret < 0) {
		perror("fprintf");
		return -1;
	}
	fflush(logging);
	// write data
	// write sock info and sizes
	fwrite(&info->domain, 1, 4, network_data);
	fwrite(&info->type, 1, 4, network_data);
	fwrite(&info->protocol, 1, 4, network_data);
	fwrite(&info->ops_info->size_ops, 1, 4, network_data);
	fwrite(&info->ops_info->size_prot, 1, 4, network_data);
	fwrite(&info->ops_info->size_sock, 1, 4, network_data);
	fwrite(&info->ops_info->size_fops, 1, 4, network_data);
	// write structs byte by byte
	if (info->ops_info->size_ops)
		fwrite(info->ops_info->ops, 1, info->ops_info->size_ops, network_data);
	if (info->ops_info->size_prot)
		fwrite(info->ops_info->prot, 1, info->ops_info->size_prot, network_data);
	if (info->ops_info->size_sock)
		fwrite(info->ops_info->sock, 1, info->ops_info->size_sock, network_data);
	if (info->ops_info->size_fops)
		fwrite(info->ops_info->fops, 1, info->ops_info->size_fops, network_data);
	// write magic number
	fwrite(&magic_number, 1, 4, network_data);
	fflush(network_data);

	return 0;
}

// given this fd and the size of the fops struct, put me the fops struct into the pointer in this struct
int handle_fops(int fd, int size_fops, struct ops_info *info) {
	int err;
	info->fd = fd;
	info->size_fops = size_fops;
	info->fops = malloc(size_fops);
	if (info->fops == NULL) {
		perror("malloc");
		return -1;
	}

	err = ioctl(kmod, RETRIEVE_FD_INFO, info);
	if (err == -1) {
		perror("ioctl");
		free(info->fops);
		return -1;
	}
}

int handle_socket(int domain, int type, int protocol,
		int size_ops, int size_prot, int size_sock,
		int size_fops) {
	struct sock_info sock_info = {
		.domain = domain,
		.type = type,
		.protocol = protocol,
	};
	struct ops_info ops_info;
	int err;
	int sockfd = socket(domain, type, protocol);
	if (sockfd == -1) {
		sock_info.success = 0;
		return write_network_info_to_file(&sock_info);
	}

	// get function pointers from kernel module, write them to file
	ops_info.fd = sockfd;
	ops_info.size_ops = size_ops;
	ops_info.size_prot = size_prot;
	ops_info.size_sock = size_sock;
	ops_info.ops = malloc(size_ops);
	if (ops_info.ops == NULL) {
		perror("malloc");
		close(sockfd);
		return -1;
	}
	ops_info.prot = malloc(size_prot);
	if (ops_info.prot == NULL) {
		perror("malloc");
		free(ops_info.ops);
		close(sockfd);
		return -1;
	}
	ops_info.sock = malloc(size_sock);
	if (ops_info.sock == NULL) {
		perror("malloc");
		free(ops_info.ops);
		free(ops_info.prot);
		close(sockfd);
		return -1;
	}

	err = ioctl(kmod, RETRIEVE_SOCK_INFO, &ops_info);
	if (err == -1) {
		perror("ioctl");
		free(ops_info.ops);
		free(ops_info.prot);
		free(ops_info.sock);

		close(sockfd);
		return -1;
	}

	err = handle_fops(sockfd, size_fops, &ops_info);
	if (err == -1) {
		// fops is not required for socks
		ops_info.size_fops = 0;
	}

	sock_info.ops_info = &ops_info;
	sock_info.success = 1;
	write_network_info_to_file(&sock_info);

	free(ops_info.ops);
	free(ops_info.prot);
	free(ops_info.sock);
	free(ops_info.fops);

	close(sockfd);
}

void iterate_sockets(int inputs[7]) {
	for (int domain = 0; domain <= inputs[0]; domain++) {
		for (int type = 0; type <= inputs[1]; type++) {
			for (int protocol = 0; protocol <= inputs[2]; protocol++) {
				handle_socket(domain, type, protocol,
						inputs[3], inputs[4],
						inputs[5], inputs[6]);
			}
		}
	}
}

void iterate_fds(int inputs[7], char *files_path) {
	char * line = NULL;
	size_t len = 0;
	int success = 0;
	FILE *fd_file = fopen(files_path, "r");
	if (!fd_file) {
		perror("fopen");
		return;
	}

	struct ops_info *ops_info = malloc(sizeof(struct ops_info));

	while(getline(&line, &len, fd_file) != -1) {
		if (strlen(line) == 0) {
			continue;
		}
		memset(ops_info, 0, sizeof(struct ops_info));
		int fd = open(line, O_RDONLY);
		if (fd == -1) {
			//perror("open");
			continue;
		}
		if (handle_fops(fd, inputs[6], ops_info) == -1) {
			success = 0;
		} else {
			success = 1;
		}

		write_fd_info_to_file(ops_info, success, line);

		close(fd);
	}

	if (line)
		free(line);
	fclose(fd_file);
}

int main(int argc, char *argv[]) {
	int inputs[7];
	char *endptr;

	if (argc < 7) {
		printf("usage: %s <max_protocol> <size_ops> <size_prot> <size_sock> <size_fops> <path_to_fd_file\n", argv[0]);
		return 1;
	}

	if (parse_input(argv, &inputs) != 0) {
		return 1;
	}

	kmod = open(KMOD_PATH, O_RDWR);
	if (kmod == -1) {
		perror("open");
		return 1;
	}

	if (get_domain_type(&inputs)) {
		printf("error: could not get domain and type\n");
		return 1;
	}

	printf("max_domain: %d, max_type: %d, max_protocol: %d\n", inputs[0], inputs[1], inputs[2]);
	printf("size_ops: %d, size_prot: %d, size_sock: %d\n", inputs[3], inputs[4], inputs[5]);

	logging = fopen("./network_stack_info.txt", "w+");
	if (!logging) {
		perror("open");
		return 1;
	}
	network_data = fopen("./network_data.bin", "w+");
	if (!network_data) {
		perror("open");
		return 1;
	}

	fd_data = fopen("./fd_data.bin", "w+");
	if (!fd_data) {
		perror("open");
		return 1;
	}

	iterate_sockets(inputs);

	iterate_fds(inputs, argv[6]);

	fclose(fd_data);
	fclose(network_data);
	fclose(logging);
	close(kmod);

	return 0;
}
