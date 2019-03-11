#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

#define CHUNK_SIZE 0x100
#define pr_debug(fmt, ...) \
	do { \
		fprintf(stderr, "[+] "); \
		fprintf(stderr, fmt, ## __VA_ARGS__); \
	} while (0)

struct file {
	char *data;
	size_t size;
};

struct chunk {
	uint32_t size;
	uint32_t seq_num;
	char data[];
};

static int setup(void)
{
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket()");
		return -1;
	}

	return sock;
}

static int mmap_file(const char *filename, struct file *f)
{
	int fd;
	size_t size;
	char *map;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		perror("open()");
		return -1;
	}

	size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		perror("mmap()");
		return -1;
	}

	f->data = map;
	f->size = size;

	return 0;
}

static void send_chunk(int sock, struct sockaddr_in *addr,
		       const char *data, size_t len, size_t seq)
{
	char chunk_max[sizeof(struct chunk) + CHUNK_SIZE] = { 0 };
	struct chunk *chunk = (struct chunk *)chunk_max;

	if (seq > UINT32_MAX)
		return;

	chunk->seq_num = htonl((uint32_t)seq);
	chunk->size = htonl((uint32_t)len);
	if (data)
		memcpy(chunk->data, data, len);

	sendto(sock, chunk, sizeof(struct chunk) + len, 0,
	       (struct sockaddr *)addr, sizeof(struct sockaddr_in));
}

static void send_file(int sock, const char *host, int port, struct file *f)
{
	size_t num_chunks = !(f->size % CHUNK_SIZE) ? f->size / CHUNK_SIZE :
					          (f->size / CHUNK_SIZE) + 1;
	struct sockaddr_in addr = { 0 };
	size_t idx;

	inet_aton(host, &addr.sin_addr);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;

	for (size_t i = 0; i < num_chunks; i++) {
		idx = i;

		size_t size = f->size - (CHUNK_SIZE * idx);
		size = size > CHUNK_SIZE ? CHUNK_SIZE : size;

		send_chunk(sock, &addr, f->data + (idx * CHUNK_SIZE), size, idx);
		//usleep(1000);
	}

	send_chunk(sock, &addr, NULL, 0, 0);
}

int main(int argc, char *argv[])
{
	int sock;
	struct file file;

	/* TODO: real argument parsing */
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <host> <port> <file>\n", argv[0]);
		return 0;
	}

	sock = setup();
	if (sock == -1)
		exit(EXIT_FAILURE);
	if (mmap_file(argv[3], &file))
		goto out_close;

	send_file(sock, argv[1], atoi(argv[2]), &file);

out_close:
	close(sock);

	return 0;
}
