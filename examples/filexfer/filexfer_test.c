#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include "dcal_api.h"
#include "sess_opts.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#define file_size 256
#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

#define DEFAULT_HOST "localhost"
#define DEFAULT_USER "libssh"
#define DEFAULT_PWD  "libssh"

#define param_max_sz 127
#define param_max_sz_with_null (param_max_sz+1)

char local_file[file_size];
char remote_file[file_size];
bool sendfile = true;
bool certificate = false;
int verbose_lvl = 0;

void usage(char * app_name)
{
	printf("usage: %s [OPTIONS]\n\n", app_name);
	printf("Device Control API Library (DCAL) application: %s\n", application_name);
	printf("dcal library version %s\n\n", DCAL_VERSION_STR);

	printf("  -h <value>      DCAS server address (default is localhost)\n"
	       "  -p <value>      port for ssh connection\n"
	       "  -u <value>      user name for ssh connection\n"
	       "  -P <value>      password for ssh connection\n"
	       "  -v              enable verbose ssh output\n"
	       "  -d              increase debug verbosity (example -ddd for level 3)\n"
	       "  -l <value>      local filename (with path) (defaults to remote name)\n"
	       "  -r <value>      remote filename (defaults to local basename)\n"
	       "  -x <value>      g==get file from remote, otherwise send to remote\n"
	       "  -c <value>      local certificate (with path)\n"
	       "\nexample: %s -h 192.168.2.114 -p 1234 -u username -P apwd -ddd -l foo.txt -r foo.txt -x g\n\n", app_name);
	printf("(note sending a file to remote will always be placed in remote's /tmp directory\n");
}

int session_connect( session_handle session, int argc, char *argv[])
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
		{"local_file", required_argument, NULL, 'l'},
		{"remote_file", required_argument, NULL, 'r'},
		{"direction", required_argument, NULL, 'x'},
		{"certificate", required_argument, NULL, 'c'},
		{NULL, 0, NULL, 0}
	};
	int c;
	int optidx=0;

	strncpy(host, DEFAULT_HOST, param_max_sz);
	strncpy(user, DEFAULT_USER, param_max_sz);
	strncpy(password, DEFAULT_PWD, param_max_sz);

	while ((c=getopt_long(argc,argv,"h:p:u:P:l:r:x:vd:c:?",longopt,&optidx)) != -1) {
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
		case 'l':
			strncpy(local_file, optarg, file_size);
			break;
		case 'r':
			strncpy(remote_file, optarg, file_size);
			break;
		case 'x':
			sendfile = *((char*)optarg)!='g';
			break;
		case 'c':
			strncpy(local_file, optarg, file_size);
			certificate = true;
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

	if ((remote_file[0]==0) && (local_file[0]==0)){
		DBGERROR("Error - must provide a local or remote file name (or both)\n");
		usage(argv[0]);
		goto exit;
	}

	if (sendfile){
		if (remote_file[0]==0)
			strncpy(remote_file, local_file, file_size);
	}
	else if (local_file[0]==0){
		char temp[file_size];
		strncpy(temp, remote_file, file_size);
		strncpy(local_file, basename(temp), file_size);
	}

	ret = dcal_session_open(session);
	if (ret != DCAL_SUCCESS) {
			DBGERROR("Error connecting to host %s: %s\n", host, dcal_err_to_string(ret));
		goto exit;
	}

	DBGINFO("SSH connection!\n");

	printf("\n%s file\n", sendfile?"send":"get");
	printf("local file: %s\n", local_file);
	printf("remote file: %s\n", remote_file);

exit:

	return ret;
}

int main (int argc, char *argv[])
{
	int ret;

	session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "filexfer";

	if((ret = session_connect(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

	// device interaction
	if (sendfile) {
		if (certificate)
			ret = dcal_cert_push_to_wb(session, local_file);
		else
			ret = dcal_file_push_to_wb(session, local_file, remote_file);
	}
	else
		ret = dcal_file_pull_from_wb(session, remote_file, local_file);

	if (ret)
		printf("error in %s(): %s\n",sendfile ? "push" : "pull", dcal_err_to_string(ret));
	else
		printf("file %s\n", sendfile ? "sent" : "received");

cleanup:

	return (ret!=DCAL_SUCCESS);

}
