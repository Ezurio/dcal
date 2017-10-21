#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define LRD_ROUTE_STR_SZ 20

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

	application_name = "default_route_test";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

	// device interaction
	laird_default_route_handle default_route;
	char interface_name[] = "wlan0";

	// Get default_route settings
	// If interface_name is NULL, the first default route will be returned.
	// If interface_name is a valid interface, a default route will be returned
	// for that specific interface if one exists.
	ret = dcal_wifi_default_route_pull(session, &default_route, interface_name);
	if (ret == DCAL_SUCCESS){
		char interface[LRD_ROUTE_STR_SZ];
		char destination[LRD_ROUTE_STR_SZ];
		char gateway[LRD_ROUTE_STR_SZ];
		int flags;
		unsigned int metric;
		char subnet_mask[LRD_ROUTE_STR_SZ];
		unsigned int mtu;
		unsigned int window;
		unsigned int irtt;

		ret = dcal_wifi_default_route_get_interface(default_route, interface, sizeof(interface));
		if (ret == DCAL_SUCCESS)
			if (interface[0] != '\0')
				printf("Default route for %s:\n",interface);

		ret = dcal_wifi_default_route_get_destination(default_route, destination, sizeof(destination));
		if (ret == DCAL_SUCCESS)
			if (destination[0] != '\0')
				printf("\t Destination: %s\n",destination);

		ret = dcal_wifi_default_route_get_gateway(default_route, gateway, sizeof(gateway));
		if (ret == DCAL_SUCCESS)
			if (gateway[0] != '\0')
				printf("\t gateway: %s\n",gateway);

		ret = dcal_wifi_default_route_get_flags(default_route, &flags);
		if (ret == DCAL_SUCCESS)
				printf("\t Flags: %d\n",flags);

		ret = dcal_wifi_default_route_get_metric(default_route, &metric);
		if (ret == DCAL_SUCCESS)
				printf("\t Metric: %d\n",metric);

		ret = dcal_wifi_default_route_get_subnet_mask(default_route, subnet_mask, sizeof(subnet_mask));
		if (ret == DCAL_SUCCESS)
			if (subnet_mask[0] != '\0')
				printf("\t Subnet mask: %s\n",subnet_mask);

		ret = dcal_wifi_default_route_get_mtu(default_route, &mtu);
		if (ret == DCAL_SUCCESS)
				printf("\t MTU: %d\n",mtu);

		ret = dcal_wifi_default_route_get_window(default_route, &window);
		if (ret == DCAL_SUCCESS)
				printf("\t Window: %d\n",window);

		ret = dcal_wifi_default_route_get_irtt(default_route, &irtt);
		if (ret == DCAL_SUCCESS)
				printf("\t IRTT: %d\n",irtt);

	} else {
		printf("unable to pull default route: return code:%d\n",ret);
	}

	ret = dcal_wifi_default_route_close_handle(default_route);
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
