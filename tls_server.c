#include <syslog.h>
#include <bsddaemon.h>
#include "tls_helper.h"

int connfd = -1;

int logf_error(const char *format, ...)
{
	va_list ap;
	char *str;
	int len;

	va_start(ap, format);
	len = vsnprintf_error(NULL, 0, format, ap);
	str = malloc(len + 1);
	memset(str, 0, len + 1);
	va_end(ap);

	va_start(ap, format);
	vsprintf_error(str, format, ap);
	if (str[len] == '\n')
		str[len] = '\0';
	va_end(ap);

	if (strcmp(format, "\n") != 0)
		syslog(LOG_ERR, "%s", str);
	free(str);
	return len;
}

void daemon_finish(void)
{
	syslog(LOG_NOTICE, "%s", "Daemon finished.");
	closelog();
}

void closedown(void)
{
	if (connfd != -1) {
		close(connfd);
		connfd = -1;
	}
}

int main(int argc, char **argv)
{
	int closedown_engaged = 0;
	int cleanup_engaged = 0;

	signal_handler(0);

	atexit(finish);

	if (parse_argv(argc, argv, 2) == -1) {
		printf(help, argv[0], opts.cert_file, opts.key_file, opts.queue_length);
		return EXIT_FAILURE;
	}

	opts.hints.ai_flags |= AI_PASSIVE;

	if (opts.become_daemon) {
		if (opts.exec_argv == NULL) {
			report_error("Invalid arguments.\nRun %s -h for usage information.\n", argv[0]);
			return EXIT_FAILURE;
		}
		if (daemon(0, 0) == -1) {
			report_error("Failed to initialize daemon: %m\n");
			return EXIT_FAILURE;
		}
		openlog(argv[0], LOG_PID, LOG_DAEMON);
		syslog(LOG_NOTICE, "%s", "Now running as daemon.");
		atexit(daemon_finish);
		report_error = logf_error;
	}

	wolfSSL_Init();

	switch (open_socket(NULL, argv[1])) {
	case -2:
		if (errcode == EAI_SYSTEM)
			report_error("Cannot open socket: %#m: %m\n");
		else
			report_error("Cannot open socket: %#m\n");
		goto common;
	case -1:
		report_error("Cannot open socket: %m\n");
	common:
		return EXIT_FAILURE;
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));

	if ((context = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
		report_error("Cannot initialize SSL context\n");
		return EXIT_FAILURE;
	}

	if (wolfSSL_CTX_use_certificate_file(context, opts.cert_file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
		report_error("Cannot load certificate file %s\n", opts.cert_file);
		return EXIT_FAILURE;
	}

	if (wolfSSL_CTX_use_PrivateKey_file(context, opts.key_file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
		report_error("Cannot load key file %s\n", opts.key_file);
		return EXIT_FAILURE;
	}

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		report_error("Binding failed: %m\n");
		return EXIT_FAILURE;
	}

	freeaddrinfo(res);
	res = NULL;

	if (listen(sockfd, opts.queue_length) == -1) {
		report_error("Cannot listen for incoming connections: %m\n");
		return EXIT_FAILURE;
	}

	do {
		init_local_fds();

		if (!closedown_engaged) {
			atexit(closedown);
			closedown_engaged = 1;
		}

		if ((connfd = accept(sockfd, NULL, NULL)) == -1) {
			report_error("Cannot accept incoming connection: %m\n");
			return EXIT_FAILURE;
		}

		if (!cleanup_engaged) {
			atexit(cleanup);
			cleanup_engaged = 1;
		}

		if ((session = wolfSSL_new(context)) == NULL) {
			report_error("Cannot initialize TLS session\n");
			return EXIT_FAILURE;
		}

		if ((errcode = wolfSSL_set_fd(session, connfd)) != WOLFSSL_SUCCESS) {
			wolfSSL_ERR_error_string(errcode, errmsg);
			report_error("Cannot set socket file descriptor: %s\n", errmsg);
			return EXIT_FAILURE;
		}

		if ((errcode = wolfSSL_accept(session)) != WOLFSSL_SUCCESS) {
			wolfSSL_ERR_error_string(wolfSSL_get_error(session, errcode), errmsg);
			report_error("Cannot secure connection: %s\n", errmsg);
			return EXIT_FAILURE;
		}

		if (send_and_receive() == -1) {
			report_error("Network error: %m\n");
			return EXIT_FAILURE;
		}

		cleanup();
		closedown();
		close_local_fds();
	} while (opts.keep_alive);

	return EXIT_SUCCESS;
}
