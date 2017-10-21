#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define cert_size 1024

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	int ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "fw_update";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		common_usage(application_name);
		dcal_session_close(session);
		session = NULL;
		printf("\nThis example will take as a parameter, an fw.txt file (including path),\nsend the file to the wb, and then call fw_update.  This assumes you\nhave previously transfered any image files you want installed.\n\n");
		goto cleanup;
	}

	if ((optind > argc) || (argv[optind]==NULL))
	{
		ret = DCAL_INVALID_PARAMETER;
		printf("missing filename for fw.txt\n");
		goto cleanup;
	}

	printf("fw.txt file: %s\n", argv[optind]);

	ret =dcal_file_push_to_wb(session, argv[optind], argv[optind]);

	if (ret) printf("error pushing fw.txt: %s\n", dcal_err_to_string(ret));

	int flags = FWU_FORCE | FWU_DISABLE_TRANSFER;

	ret = dcal_fw_update(session, flags);

	if (ret) printf("error in fw_update(): %s\n",dcal_err_to_string(ret));

cleanup:
	if(session)
		dcal_session_close(session);
	return (ret!=DCAL_SUCCESS);

}
