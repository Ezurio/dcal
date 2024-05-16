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

static int verbose_lvl = 0;
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

void common_usage(char * app_name)
{
	printf("usage: %s [OPTIONS]\n\n", app_name);
	printf("Device Control API Library (DCAL) application: %s\n", application_name);
	printf("dcal library version %s\n\n", DCAL_VERSION_STR);

	printf("  -h <value>      DCAS server address (default is localhost)\n"
	       "  -p <value>      port for ssh connection\n"
	       "  -u <value>      user name for ssh connection\n"
	       "  -P <value>      password for ssh connection\n"
	       "  -k <value>      private key path and file name of key pair\n"
	       "  -v              enable verbose ssh output\n"
	       "  -d              increase libssh verbosity (example -ddd for level 3)\n"
	       "\nlibrary can be compiled with DEBUG=1. If so, debug can be enabled by \n"
	       "setting environment variables DCAL_DEBUG, and DCAL_DEBUG_LEVEL.  Example:\n"
	       "  export DCAL_DEBUG=time\n"
	       "  export DCAL_DEBUG_LEVEL=3\n"
	       "\nexample:\n %s -h 192.168.2.114 -p 1234 -u username -P apwd -k keyfile -ddd\n\n", app_name);
}

#define DEFAULT_HOST "localhost"

#define param_max_sz 127
#define param_max_sz_with_null (param_max_sz+1)

int session_connect_with_opts( session_handle session, int argc, char *argv[], bool connect)
{
	int verbosity = SSH_LOG_PROTOCOL;
	DCAL_ERR ret=DCAL_SUCCESS;
	unsigned int port = 2222;
	char user[param_max_sz_with_null] = {0};
	char host[param_max_sz_with_null] = {0};
	char password[param_max_sz_with_null] = {0};
	char keyfile[param_max_sz_with_null] = {0};

	// Define the options structure
	static struct option longopt[] = {
		{"host", required_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{"user", required_argument, NULL, 'u'},
		{"password", required_argument, NULL, 'P'},
		{"keyfile", required_argument, NULL, 'k'},
		{"verbose", no_argument, NULL, 'v'},
		{"debug", no_argument, NULL, 'd'},
		{NULL, 0, NULL, 0}
	};
	int c;
	int optidx=0;

	strncpy(host, DEFAULT_HOST, param_max_sz);

	while ((c=getopt_long(argc,argv,"h:p:u:P:k:vd?",longopt,&optidx)) != -1) {
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
		case 'k':
			strncpy(keyfile, optarg, param_max_sz);
			break;
		case 'd':
			verbose_lvl++;
			break;
		case '?':
			common_usage(argv[0]);
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

	if (user[0]){
		DBGDEBUG("Setting user: %s\n", user);
		ret = dcal_set_user(session, user);
		if (ret!=DCAL_SUCCESS) {
			DBGERROR("Error setting user: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
			goto exit;
		}
	}

	if(password[0]){
		DBGDEBUG("Setting password: %s\n", password);
		ret = dcal_set_pw(session, password);
		if (ret!=DCAL_SUCCESS) {
			DBGERROR("Error setting password: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
			goto exit;
		}
	}

	if(keyfile[0]){
		DBGDEBUG("Setting keyfile: %s\n", keyfile);
		ret = dcal_set_keyfile(session, keyfile);
		if (ret!=DCAL_SUCCESS) {
			DBGERROR("Error setting keyfile: Received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
			goto exit;
		}
	}

	if(connect){
		ret = dcal_session_open(session);
		if (ret != DCAL_SUCCESS) {
				DBGERROR("Error connecting to host %s: %s\n", host, dcal_err_to_string(ret));
			goto exit;
		}

	DBGINFO("SSH connection!\n");
	}

exit:
	return ret;
}

