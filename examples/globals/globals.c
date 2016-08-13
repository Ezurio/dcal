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

	application_name = "global_test";

	if((ret = session_connect_with_opts(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	laird_global_handle global;
	ret = dcal_wifi_global_create(&global);
	if (ret)
		printf("error in global_create(): %s\n",dcal_err_to_string(ret));
	else
		dcal_wifi_global_printf(global);

	ret = dcal_wifi_global_close_handle(global);
	if (ret) printf("error in close_handle(): %s\n",dcal_err_to_string(ret));

	ret = dcal_wifi_global_pull( session, &global);
	if (ret)
		printf("error in global_pull(): %s\n",dcal_err_to_string(ret));
	else{

		ret = dcal_wifi_global_set_achannel_mask(global, a_full);
		if (ret)  printf("error in set achannel_mask: %d\n", ret);

		ret = dcal_wifi_global_set_bchannel_mask(global, b_1|b_6|b_11);
		if (ret)  printf("error in set bchannel_mask: %d\n", ret);

		ret = dcal_wifi_global_set_roam_periodms(global, 4000);
		if (ret)  printf("error in set roam_periodms: %d\n", ret);

		ret = dcal_wifi_global_set_fips(global, 1);
		if (ret)  printf("error in set fips: %d\n", ret);

		printf("\n\npulled globals with local changes:\n");
		dcal_wifi_global_printf(global);

		ret = dcal_wifi_global_push( session, global);

		#define NUMSECS 10
		int i;
		printf("\nSleeping for %d seconds", NUMSECS);
		for (i=0; i<NUMSECS; i++) {
			sleep(1);
			printf(".");
			fflush(stdout);
		}
		printf("\n");

		ret = dcal_wifi_global_set_fips(global, 0);
		if (ret)  printf("error in set fips: %d\n", ret);

		dcal_wifi_global_printf(global);
		ret = dcal_wifi_global_push( session, global);
		if (ret) printf("error in push(): %d\n", ret);

		ret = dcal_wifi_global_close_handle(global);
		if (ret)
			printf("error in close_handle(): %s\n",dcal_err_to_string(ret));

		ret = dcal_wifi_global_pull( session, &global);
		if (ret) printf("error in pull(): %d\n", ret);

		printf("\n\npulled globals:\n");
		dcal_wifi_global_printf(global);

		ret = dcal_wifi_global_close_handle(global);
		if (ret)
			printf("error in close_handle(): %s\n",dcal_err_to_string(ret));
	}

cleanup:
	if(session)
		dcal_session_close(session);
	return (ret!=DCAL_SUCCESS);

}
