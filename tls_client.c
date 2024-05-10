#include "tls_helper.h"

int main(int argc, char **argv)
{
	signal_handler(0);

	atexit(finish);

	if (parse_argv(argc, argv, 3) == -1) {
		printf(help, argv[0]);
		return EXIT_FAILURE;
	}

	init_local_fds();

	switch (open_socket(argv[1], argv[2])) {
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

	if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
		report_error("Cannot connect: %m\n");
		return EXIT_FAILURE;
	}

	freeaddrinfo(res);
	res = NULL;

	wolfSSL_Init();

	if ((context = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
		report_error("Cannot initialize SSL context\n");
		return EXIT_FAILURE;
	}

	if (opts.ca_file == NULL) {
		if (wolfSSL_CTX_load_system_CA_certs(context) != WOLFSSL_SUCCESS) {
			report_error("Cannot load system certificates\n");
			return EXIT_FAILURE;
		}
	} else {
		if (wolfSSL_CTX_load_verify_locations(context, opts.ca_file, NULL) != WOLFSSL_SUCCESS) {
			report_error("Cannot load certificate file %s\n", opts.ca_file);
			return EXIT_FAILURE;
		}
	}

	atexit(cleanup);

	if ((session = wolfSSL_new(context)) == NULL) {
		report_error("Cannot initialize TLS session\n");
		return EXIT_FAILURE;
	}

	if ((errcode = wolfSSL_set_fd(session, sockfd)) != WOLFSSL_SUCCESS) {
		wolfSSL_ERR_error_string(wolfSSL_get_error(session, errcode), errmsg);
		report_error("Failed to set socket file descriptor: %s\n", errmsg);
		return EXIT_FAILURE;
	}

	if ((errcode = wolfSSL_connect(session)) != WOLFSSL_SUCCESS) {
		wolfSSL_ERR_error_string(wolfSSL_get_error(session, errcode), errmsg);
		report_error("Failed to connect to wolfSSL: %s\n", errmsg);
		return EXIT_FAILURE;
	}

	if (send_and_receive() == -1) {
		report_error("Network error: %m\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
