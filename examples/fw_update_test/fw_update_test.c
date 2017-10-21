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

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

#define DEFAULT_HOST "localhost"
#define DEFAULT_USER "libssh"
#define DEFAULT_PWD  "libssh"

#define param_max_sz 127
#define param_max_sz_with_null (param_max_sz+1)

char local_file[256];
char remote_file[256];
bool sendfile = true;
int verbose_lvl = 0;

void usage(char * app_name)
{
	common_usage(app_name);
	printf("(note sending a file to remote will always be placed in remote's /tmp directory\n");
}

int main (int argc, char *argv[])
{
	int ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "fw_update_test";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	char *files[] = {"at91bs.bin",
                   "fw.txt",
                   "fw_usi",
                   "rootfs.bin",
                   "fw_select",
                   "fw_update",
                   "kernel.bin",
                   "u-boot.bin"};

	int i;

	for (i=0; i<sizeof(files)/sizeof(files[0]); i++){
		printf("attempting to send: %s\n", files[i]);
		ret =dcal_file_push_to_wb(session, files[i], files[i]);
		if (ret==DCAL_LOCAL_FILE_ACCESS_DENIED)
			printf("missing file: %s\n", files[i]);
		else if (ret)
			printf("error sending file %s: %s\n", files[i], dcal_err_to_string(ret));
	}

	int flags = FWU_FORCE | FWU_DISABLE_TRANSFER;

	ret = dcal_fw_update(session, flags);


	if (ret)
		printf("error in dcal_fw_update: %s\n",dcal_err_to_string(ret));

	ret = dcal_file_pull_from_wb(session, "/tmp/fw_update.out", "fw_update.out");
	if (ret)
		printf("Failed to get error file.  error: %s\n", dcal_err_to_string(ret));

cleanup:

	return (ret!=DCAL_SUCCESS);

}
