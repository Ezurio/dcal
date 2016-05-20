#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <stdarg.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "dcal_api.h"
#include "sess_opts.h"

int verbose_lvl = 0;
char * application_name = NULL;

void printmsg( int lvl, char * format, ...)
{
	va_list args;
	if (lvl <= verbose_lvl)
	{
		va_start( args, format );
		vprintf(format, args);
		va_end (args );
	}
}

void usage(char * app_name)
{
	printf("usage: %s [OPTIONS]\n\n", app_name);
	printf("Device Control API Library (DCAL) application: %s\n", application_name);
	printf("dcal library version %d.%d.%d.%d\n\n",
	        (DCAL_API_VERSION & 0xff000000) >> 24,
	        (DCAL_API_VERSION & 0x00ff0000) >> 16,
	        (DCAL_API_VERSION & 0x0000ff00) >> 8,
	        (DCAL_API_VERSION & 0x000000ff));

	printf("  -h <value>      DCAS server address (default is localhost)\n"
	       "  -p <value>      port for ssh connection\n"
	       "  -u <value>      user name for ssh connection\n"
	       "  -P <value>      password for ssh connection\n"
	       "  -v              enable verbose ssh output\n"
	       "  -d              increase debug verbosity (example -ddd for level 3)\n"
	       "\nexample: %s -h 192.168.2.114 -p 1234 -u username -P apwd -ddd\n\n", app_name);
}

#define DEFAULT_HOST "localhost"
#define DEFAULT_USER "libssh"
#define DEFAULT_PWD  "libssh"

#define param_max_sz 127
#define param_max_sz_with_null (param_max_sz+1)

int session_connect_with_opts( laird_session_handle session, int argc, char *argv[])
{
	int verbosity = SSH_LOG_PROTOCOL;
	DCAL_ERR ret;
	unsigned int port = 2222;
	char user[param_max_sz_with_null] = {0};
	char host[param_max_sz_with_null] = {0};
	char password[param_max_sz_with_null] = {0};

	// Define the options structure
	static struct option longopt[] = {
		{"host", required_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{"user", required_argument, NULL, 'u'},
		{"verbose", no_argument, NULL, 'v'},
		{"password", required_argument, NULL, 'P'},
		{"debug", no_argument, NULL, 'd'},
		{NULL, 0, NULL, 0}
	};
	int c;
	int optidx=0;

	strncpy(host, DEFAULT_HOST, param_max_sz);
	strncpy(user, DEFAULT_USER, param_max_sz);
	strncpy(password, DEFAULT_PWD, param_max_sz);

	while ((c=getopt_long(argc,argv,"h:p:u:P:vd?",longopt,&optidx)) != -1) {
		switch(c) {
		case 'v':
			ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
			break;
		case 'h':
			strncpy(host, optarg, param_max_sz);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			strncpy(user, optarg, param_max_sz);
			break;
		case 'P':
			strncpy(password, optarg, param_max_sz);
			break;
		case 'd':
			verbose_lvl++;
			break;
		case '?':
			usage(argv[0]);
			exit(0);
			break;
		}
	}

	DBGDEBUG( "Setting host: %s\n", host );
	ret = dcal_set_host(session, host);
	if (ret!= DCAL_SUCCESS) {
		DBGERROR("Error setting host: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto exit;
	}

	DBGDEBUG( "Setting port: %u\n", port);
	ret = dcal_set_port(session, port);
	if (ret!=DCAL_SUCCESS) {
		DBGERROR("Error setting port: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto exit;
	}

	DBGDEBUG("Setting user: %s\n", user);
	ret = dcal_set_user(session, user);
	if (ret!=DCAL_SUCCESS) {
		DBGERROR("Error setting user: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto exit;
	}

	DBGDEBUG("Setting password: %s\n", password);
	ret = dcal_set_pw(session, password);
	if (ret!=DCAL_SUCCESS) {
		DBGERROR("Error setting password: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto exit;
	}

	ret = dcal_session_open(session);
	if (ret != DCAL_SUCCESS) {
			DBGERROR("Error connecting to host %s: %s\n", host, dcal_err_to_string(ret));
		goto exit;
	}

	DBGINFO("SSH connection!\n");

exit:

	return ret;
}

