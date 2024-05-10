#ifndef TLS_HELPER_H
#define TLS_HELPER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "config.h"

struct options {
	struct addrinfo hints;
	int ipv6_only;
	char *cert_file;
	int crlf;
	char **exec_argv;
	int wait_mode;
	int local_fds[4];
	char *key_file;
	int keep_alive;
	int become_daemon;
	int queue_length;
	char *ca_file;
};

extern unsigned char help[];
extern volatile sig_atomic_t complete;
extern struct options opts;
extern int (*report_error)(const char *format, ...);
extern pid_t cpid;
extern int errcode;
extern char errmsg[];
extern struct addrinfo *res;
extern int sockfd;
extern WOLFSSL_CTX *context;
extern WOLFSSL *session;

void signal_handler(int signum);
int close_local_fds(void);
void finish(void);
int init_local_fds(void);
int parse_argv(int argc, char **argv, int start);
int vsnprintf_error(char *str, size_t size, const char *format, va_list ap);
int vsprintf_error(char *str, const char *format, va_list ap);
int printf_error(const char *format, ...);
int open_socket(const char *node, const char *service);
void cleanup(void);
int send_and_receive(void);

#endif /* !TLS_HELPER_H */