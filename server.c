#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define CLIENTS 100
#define PORT 5000

#define BUFLEN 1024

// The following bits depend on UNUSED_SOCKET and NULL to be 0, otherwise
// initialization doesn't work as intended.
#define UNUSED_SOCKET 0
int sockets[CLIENTS] = {UNUSED_SOCKET};

int master_socket;

int nfds = 0;

#define MAX(x, y) ((x) > (y) ? (x) : (y))

void drop_connection(int index);
void cleanup();
void prepare_master_socket();
int find_free_socket_index();
void sigint_cb(int signum);
void handle_incoming_message(int src_index);
void handle_new_connection();
void cleanup() {
	int i;
	printf("Cleanup on aisle %d...\n", getpid());
	for (i = 0; i < CLIENTS; i++) {
		if (sockets[i] != UNUSED_SOCKET) {
			drop_connection(i);
		}
	}
	shutdown(master_socket, SHUT_RDWR);
	close(master_socket);
	printf("All clean\n");
}

void prepare_master_socket() {
	struct sockaddr_in local;

	printf("Listening on port %d...\n", PORT);

	bzero(&local, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(PORT);

	master_socket = socket(AF_INET, SOCK_STREAM, 0);

	if (bind(master_socket, (struct sockaddr *) &local, sizeof(local)) != 0)
	{
		perror("bind");
		exit(1);
	}

	if (listen(master_socket, 1) != 0) {
		perror("listen");
		exit(1);
	}
}

int find_free_socket_index() {
	int i;
	for (i = 0; i < CLIENTS; i++) {
		if (sockets[i] == UNUSED_SOCKET) {
			return i;
		}
	}
	return -1;
}

void sigint_cb(int signum) {
	cleanup();
	exit(0);
}

void drop_connection(int index) {
	fprintf(stderr, "Dropping connection on socket %d.\n", sockets[index]);
	shutdown(sockets[index], SHUT_RDWR);
	close(sockets[index]);
	sockets[index] = UNUSED_SOCKET;
}

void handle_incoming_message(int src_index) {
	int n;
	int dest;
	int src_socket = sockets[src_index];
	int ret;
	static char buf[BUFLEN] = {0};

	printf("On socket %d:\n", src_socket);
	bzero(buf, BUFLEN);

	ret = recv(src_socket, buf, BUFLEN, 0);

	if (ret == 0) {
		printf("Socket %d closed on other end, closing.\n", src_socket);
		drop_connection(src_index);
	}
	else {
		n = ret;
		if (buf[0] == 'q') {
			puts("Ooh, a quit signal! Bye now!");
			cleanup();
			exit(0);
		}
	}

	printf("%s", buf);

	for (dest = 0; dest < CLIENTS; dest++) {
		if (dest == src_index) {
			continue;
		}
		if (sockets[dest] == 0) {
			continue;
		}

		send(sockets[dest], buf, n, 0);
	}
}

void handle_new_connection() {
	struct sockaddr_in remote;
	int remote_size = sizeof(remote);
	char * addr_str;
	int i = find_free_socket_index();
	int fd = accept(master_socket , (struct sockaddr *)&remote, &remote_size);
	if (fd == -1) {
		perror("accept");
		return;
	}
	addr_str = (char *)inet_ntoa(remote.sin_addr);
	printf("Accepting a connection on socket %d from %s\n", fd, addr_str);
	if (i == -1) {
		printf("...but rejecting it because of too many open sockets.\n");
		send(fd, "Sorry, too many open connections.\n",
				strlen("Sorry, too many open connections.\n"), 0);
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
	else {
		sockets[i] = fd;
		nfds = MAX(nfds, fd);
	}
}

int main() {
	fd_set socketset;
	int retval;
	int i;

	prepare_master_socket();

	nfds = MAX(nfds, master_socket);

	signal(SIGINT, sigint_cb);

	for (;;) {
		FD_ZERO(&socketset);

		FD_SET(master_socket, &socketset);

		for (i = 0; i < CLIENTS; i++) {
			if (sockets[i] != UNUSED_SOCKET) {
				FD_SET(sockets[i], &socketset);
			}
		}

		retval = select(nfds + 1, &socketset, NULL, NULL, NULL);

		if (retval == 0) {
			continue;
		}

		if (retval == -1) {
			perror("select");
			exit(1);
		}

		if (FD_ISSET(master_socket, &socketset)) {
			handle_new_connection();
		}

		for (i = 0; i < CLIENTS; i++) {
			if ((sockets[i] != UNUSED_SOCKET) &&
					FD_ISSET(sockets[i], &socketset)) {
				handle_incoming_message(i);
			}
		}
	}
}
