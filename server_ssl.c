#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <openssl/ssl.h>

#define CLIENTS 100
#define PORT 6000

#define BUFLEN 1024

// The following bits depend on UNUSED_SOCKET and NULL to be 0, otherwise
// initialization doesn't work as intended.
#define UNUSED_SOCKET 0
int sockets[CLIENTS] = {UNUSED_SOCKET};
SSL * ssl_objects[CLIENTS] = {NULL};

int master_socket;

int nfds = 0;

#define MAX(x, y) ((x) > (y) ? (x) : (y))

SSL_CTX* ctx;

void drop_connection(int index);
void cleanup();
void prepare_master_socket();
int find_free_socket_index();
void sigint_cb(int signum);
void handle_incoming_message(int src_index);
void handle_new_connection();
void prepare_ssl_stuff();

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
	SSL_CTX_free(ctx);
	ERR_free_strings();
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
	SSL_shutdown(ssl_objects[index]);
	SSL_free(ssl_objects[index]);
	ssl_objects[index] = NULL;
	close(sockets[index]);
	sockets[index] = UNUSED_SOCKET;
}

void handle_incoming_message(int src_index) {
	int n;
	int dest;
	int src_socket = sockets[src_index];
	int ret;
	SSL * ssl = ssl_objects[src_index];
	static char buf[BUFLEN] = {0};

	printf("On socket %d:\n", src_socket);

	if (SSL_in_accept_init(ssl)) {
		// Even though we've already accepted the socket, there needs to be
		// some SSL negotiation before we can actually SSL_read - we need to
		// SSL_accept.
		printf("Accepting SSL connection...\n");
		ret = SSL_accept(ssl);
		switch(SSL_get_error(ssl, ret)) {
			case SSL_ERROR_NONE:
				printf("Done accepting!\n");
				break;
			case SSL_ERROR_WANT_READ:
				printf("Waiting for more.\n");
				return; // We'll be back for more.
				break;
			case SSL_ERROR_SYSCALL:
				if (ret == 0) {
					printf("Premature EOF\n");
				}
				else {
					perror("SSL_accept");
				}
				drop_connection(src_index);
				return;
				break;
			case SSL_ERROR_SSL:
				fprintf(stderr, "SSL negotiation error.\n");
				ERR_print_errors_fp(stderr);
				drop_connection(src_index);
				return;
			case SSL_ERROR_ZERO_RETURN:
				printf("Odd, they just dropped the connection.\n");
			default:
				ERR_print_errors_fp(stderr);
				drop_connection(src_index);
				return;
		}
	}

	// TODO authenticate client certificate

	bzero(buf, BUFLEN);

	ret = SSL_read(ssl_objects[src_index], buf, BUFLEN);

	switch(SSL_get_error(ssl, ret)) {
		case SSL_ERROR_NONE:
			n = ret;
			break;
		case SSL_ERROR_WANT_READ:
			return;
			break;
		case SSL_ERROR_ZERO_RETURN:
			printf("Socket %d closed on other end, closing.\n", src_socket);
			drop_connection(src_index);
			return;
			break;
		case SSL_ERROR_SYSCALL:
			if (ret == 0) {
				printf("Premature EOF\n");
			}
			else {
				perror("SSL_read");
			}
			drop_connection(src_index);
			return;
			break;
		default:
			ERR_print_errors_fp(stderr);
			exit(1);
	}

	if (buf[0] == 'q') {
		puts("Ooh, a quit signal! Bye now!");
		cleanup();
		exit(0);
	}

	printf("%s", buf);

	for (dest = 0; dest < CLIENTS; dest++) {
		if (dest == src_index) {
			continue;
		}
		if (sockets[dest] == 0) {
			continue;
		}


		while (ret = SSL_write(ssl_objects[dest], buf, n) < 0) {
			fd_set socketset;
			switch (SSL_get_error(ssl_objects[dest], ret)) {
				case SSL_ERROR_NONE:
					// This shouldn't happen, we would've gotten ret >= 0
					break;
				case SSL_ERROR_WANT_WRITE:
					printf("Waiting to write some more...\n");

					// Keep looping, we'll keep writing. This is correct usage
					// - just send the same buffer again. However, in this
					// form, we'll be blocking until we can write, which
					// might be a performance issue.

					FD_ZERO(&socketset);
					FD_SET(sockets[dest], &socketset);
					select(sockets[dest] + 1, NULL, &socketset, NULL, NULL);

					break;
				default:
					ERR_print_errors_fp(stderr);
					exit(1);
			}
		}
	}
}

void handle_new_connection() {
	struct sockaddr_in remote;
	int remote_size = sizeof(remote);
	char * addr_str;
	int i = find_free_socket_index();
	// We have to specify SOCK_NONBLOCK. Otherwise, we might get blocked in the
	// middle of SSL_accept, even though select said the socket was ready for
	// reading.
	int fd = accept4(master_socket, (struct sockaddr *)&remote, &remote_size,
			SOCK_NONBLOCK);
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
		ssl_objects[i] = SSL_new(ctx);
		if (ssl_objects[i] == NULL) {
			ERR_print_errors_fp(stderr);
			exit(6);
		}
		SSL_set_fd(ssl_objects[i], fd);

		nfds = MAX(nfds, fd);
	}
}

void prepare_ssl_stuff() {
	SSL_load_error_strings();
	SSL_library_init();
	SSL * ssl;
	SSL_METHOD * meth;

	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}

	// TODO should this be the same file?
	if (SSL_CTX_use_PrivateKey_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
}

int main() {
	fd_set socketset;
	int retval;
	int i;

	prepare_ssl_stuff();
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
