#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define DUMPLOCATION {printf("%s: %d\n", __func__, __LINE__);}

int main (int argc, char *argv[])
{
	DCAL_ERR ret;

	laird_session_handle session;

	ret = dcal_session_create( &session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

	application_name = "interface_test";

	if((ret = session_connect_with_opts(session, argc, argv))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

// device interaction
	laird_interface_handle interface;

	ret = dcal_wifi_interface_create(&interface);
	if (ret == DCAL_SUCCESS){
		ret = dcal_wifi_interface_set_interface_name(interface, "test0");
		if (ret == DCAL_SUCCESS){
			ret = dcal_wifi_interface_set_method(interface, "dhcp");
			if (ret != DCAL_SUCCESS)
				printf("unable to set method\n");

			ret = dcal_wifi_interface_set_auto_start(interface, 0);
			if (ret != DCAL_SUCCESS)
				printf("unable to set method\n");

			ret = dcal_wifi_interface_push( session, interface);
			if (ret == DCAL_SUCCESS){
				ret = dcal_wifi_interface_delete( session, interface);
				if (ret != DCAL_SUCCESS)
					printf("unable to delete interface\n");

			} else {
				printf("push return code: %d\n", ret);
			}
		} else {
			printf("unable to set interface_name\n");
		}
	} else {
		printf("unable to create interface\n");
	}

	ret = dcal_wifi_interface_close_handle(interface);
	if (ret != DCAL_SUCCESS)
		printf("unable to close\n");

	ret = dcal_session_close( session );
	if (ret!= DCAL_SUCCESS) {
		printf("received %s at line %d\n", dcal_err_to_string(ret), __LINE__-2);
		goto cleanup;
	}

cleanup:

	return (ret!=DCAL_SUCCESS);

}