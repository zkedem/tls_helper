#include "tls_helper.h"

volatile sig_atomic_t complete = 0;
struct options opts = {
	.hints = {
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,
		.ai_addrlen = 0,
		.ai_addr = NULL,
		.ai_canonname = NULL,
		.ai_next = NULL
	},
	.ipv6_only = 0,
	.cert_file = CERT_FILE,
	.crlf = 0,
	.exec_argv = NULL,
	.wait_mode = 0,
	.local_fds = { STDIN_FILENO, -1, -1, STDOUT_FILENO },
	.key_file = KEY_FILE,
	.keep_alive = 0,
	.become_daemon = 0,
	.queue_length = QUEUE_LENGTH,
	.ca_file = NULL
};
int (*report_error)(const char *format, ...) = printf_error;
pid_t cpid = 0;
int errcode = 0;
char errmsg[80] = { '\0' };
struct addrinfo *res = NULL;
int sockfd = -1;
WOLFSSL_CTX *context = NULL;
WOLFSSL *session = NULL;

void signal_handler(int signum)
{
	struct sigaction act = {
		.sa_handler = signal_handler,
		.sa_flags = SA_RESETHAND | SA_NODEFER | SA_RESTART
	};

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		exit(EXIT_SUCCESS);
	case SIGCHLD:
		complete = 1;
	}
	
	sigemptyset(&act.sa_mask);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
}

int close_local_fds(void)
{
	int ret = 0;

	for (int i = 0; i < 4; i++)
		if (opts.local_fds[i] > STDERR_FILENO)
			ret = close(opts.local_fds[i]);
	return ret;
}

void finish(void)
{
	if (context != NULL)
		wolfSSL_CTX_free(context);
	wolfSSL_Cleanup();
	if (res != NULL)
		freeaddrinfo(res);
	close_local_fds();
}

int init_local_fds(void)
{
	int oerrno;

	if (opts.exec_argv != NULL) {
		if (pipe(opts.local_fds) == -1)
			goto fail;
		
		if (pipe(&opts.local_fds[2]) == -1)
			goto fail;
			
		switch (cpid = fork()) {
		case -1:
			goto fail;
		case 0:
			setsid();
			dup2(opts.local_fds[2], STDIN_FILENO);
			dup2(opts.local_fds[1], STDOUT_FILENO);
			dup2(opts.local_fds[1], STDERR_FILENO);
			close_local_fds();
			if (opts.wait_mode) {
				fd_set readfrom;
				FD_ZERO(&readfrom);
				FD_SET(STDIN_FILENO, &readfrom);
				select(STDIN_FILENO + 1, &readfrom, NULL, NULL, NULL);
			}
			execvp(opts.exec_argv[0], opts.exec_argv);
		}
	}
	
	return 0;
	
fail:
	oerrno = errno;
	close_local_fds();
	errno = oerrno;
	return -1;
}

int parse_argv(int argc, char **argv, int start)
{
	if (argc < start)
		return -1;
		
	for (int i = 1; i < argc; ++i)
		if (strcmp(argv[i], "-h") == 0)
			return -1;

	if (argc > start)
		for (int i = start; i < argc; ++i) {
			if (strcmp(argv[i], "-4") == 0)
				opts.hints.ai_family = AF_INET;
			if (strcmp(argv[i], "-6") == 0) {
				opts.hints.ai_family = AF_INET6;
				opts.ipv6_only = 1;
			}
			if (strcmp(argv[i], "-C") == 0)
				opts.cert_file = argv[++i];
			if (strcmp(argv[i], "-c") == 0)
				opts.crlf = 1;
			if (strncmp(argv[i], "-e", 2) == 0) {
				close_local_fds();
				opts.exec_argv = &argv[++i];
				if (argv[i][2] == 'w')
					opts.wait_mode = 1;
				break;
			}
			if (strncmp(argv[i], "-f", 2) == 0) {
				if (argv[i][2] == 'i' && opts.local_fds[0] == STDIN_FILENO)
					opts.local_fds[0] = open(argv[++i], O_RDONLY);
				if (argv[i][2] == 'o' && opts.local_fds[3] == STDOUT_FILENO)
					opts.local_fds[3] = open(argv[++i], O_WRONLY | O_CREAT, 0666);
			}
			if (strcmp(argv[i], "-K") == 0)
				opts.key_file = argv[++i];
			if (strncmp(argv[i], "-k", 2) == 0) {
				opts.keep_alive = 1;
				if (argv[i][2] == 'd')
					opts.become_daemon = 1;
			}
			if (strcmp(argv[i], "-n") == 0)
				opts.hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
			if (strcmp(argv[i], "-q") == 0)
				opts.queue_length = atoi(argv[++i]);
			if (strcmp(argv[i], "-R") == 0)
				opts.ca_file = argv[++i];
		}
	
	return 0;
}

static char *repl_str(const char *str, const char *from, const char *to)
{
	size_t from_len = strlen(from);
	size_t to_len = strlen(to);
	int i, j = 0;
	int from_cnt = 0;
	
	for (i = 0; str[i] != '\0'; i++)
		if (strstr(&str[i], from) == &str[i]) {
			from_cnt++;
			i += from_len - 1;
		}
	
	char *str_new = malloc(from_cnt * (to_len - from_len) + i + 1);
	
	for (i = 0; str[j] != '\0';)
		 if (strstr(&str[j], from) == &str[j]) {
		 	strcpy(&str_new[i], to);
		 	i += to_len;
		 	j += from_len;
		 } else {
		 	str_new[i++] = str[j++];
		 }
	
	str_new[i] = '\0';
	return str_new;
}

int vsnprintf_error(char *str, size_t size, const char *format, va_list ap)
{
	char *format_exp1 = repl_str(format, "%m", strerror(errno));
	char *format_exp2 = repl_str(format_exp1, "%#m", gai_strerror(errcode));
	int ret = vsnprintf(str, size, format_exp2, ap);
	free(format_exp2);
	free(format_exp1);
	return ret;
}

int vsprintf_error(char *str, const char *format, va_list ap)
{
	va_list aq;
	int ret;
	
	va_copy(aq, ap);
	ret = vsnprintf_error(str, vsnprintf_error(NULL, 0, format, ap) + 1, format, aq);
	va_end(aq);
	return ret;
}

int printf_error(const char *format, ...)
{
	va_list ap;
	char *str;
	int len;
	int ret;
	
	va_start(ap, format);
	len = vsnprintf_error(NULL, 0, format, ap);
	str = malloc(len + 1);
	memset(str, 0, len + 1);
	va_end(ap);

	va_start(ap, format);
	vsprintf_error(str, format, ap);
	va_end(ap);

	ret = fputs(str, stderr);
	free(str);
	return ret;
}

int open_socket(const char *node, const char *service)
{
	if ((errcode = getaddrinfo(node, service, &opts.hints, &res)) != 0) 
		return -2;
	
	if ((sockfd = socket(res->ai_family, res->ai_socktype, 0)) == -1)
		return -1;
	
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &opts.ipv6_only, sizeof(int));

	return 0;
}

void cleanup(void)
{
	if (session != NULL) {
		while (wolfSSL_shutdown(session) == WOLFSSL_SHUTDOWN_NOT_DONE);
		wolfSSL_free(session);
		session = NULL;
	}
}

int send_and_receive(void)
{
	fd_set readfrom;
	static char buff[8192];
	int len;
	int crlf_len;
	int fdremote = wolfSSL_get_fd(session);

	for (complete = 0; !complete;) {
		len = 0;
		crlf_len = 0;
		
		FD_ZERO(&readfrom);
		FD_SET(opts.local_fds[0], &readfrom);
		FD_SET(fdremote, &readfrom);

		if (select(fdremote + 1, &readfrom, NULL, NULL, NULL) == -1)
			if (errno == EINTR && complete) {
				waitpid(cpid, NULL, 0);
				continue;
			} else {
				goto fail;
			}

		if (FD_ISSET(opts.local_fds[0], &readfrom)) {
			if ((len = read(opts.local_fds[0], buff, sizeof(buff))) == 0)
				goto success;
			if (opts.crlf && buff[len] == '\0')
				if (strcmp(&buff[len - 1], "\n") == 0) {
					strcpy(&buff[len - 1], "\r\n");
					crlf_len = 1;
				}
			wolfSSL_write(session, buff, len + crlf_len);
		}

		if (FD_ISSET(fdremote, &readfrom)) {
			if ((len = wolfSSL_read(session, buff, sizeof(buff))) == 0)
				goto success;
			if (opts.crlf && buff[len] == '\0')
				if (strcmp(&buff[len - 2], "\r\n") == 0) {
					strcpy(&buff[len - 2], "\n");
					crlf_len = 1;
				}
			write(opts.local_fds[3], buff, len - crlf_len);
		}

		memset(buff, 0, sizeof(buff));
	}

success:
	errno = 0;
	return 0;

fail:
	return -1;
}