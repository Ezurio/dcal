#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
	char interface_name[] = "test0";

	ret = dcal_wifi_interface_create(&interface);
	if (ret == DCAL_SUCCESS){
		ret = dcal_wifi_interface_set_interface_name(interface, interface_name);
		if (ret == DCAL_SUCCESS){
			// Setup interface
			ret = dcal_wifi_interface_set_method(interface, "dhcp");
			if (ret != DCAL_SUCCESS)
				printf("unable to set method\n");

			ret = dcal_wifi_interface_set_auto_start(interface, 0);
			if (ret != DCAL_SUCCESS)
				printf("unable to set method\n");

			ret = dcal_wifi_interface_set_address(interface, "192.168.9.9");
			if (ret != DCAL_SUCCESS)
				printf("unable to set address\n");

			ret = dcal_wifi_interface_set_netmask(interface, "255.255.255.0");
			if (ret != DCAL_SUCCESS)
				printf("unable to set netmask\n");

			ret = dcal_wifi_interface_set_gateway(interface, "192.168.9.1");
			if (ret != DCAL_SUCCESS)
				printf("unable to set gateway\n");

			ret = dcal_wifi_interface_set_nameserver(interface, "8.8.8.8");
			if (ret != DCAL_SUCCESS)
				printf("unable to set nameserver\n");

			ret = dcal_wifi_interface_set_broadcast_address(interface, "192.168.9.255");
			if (ret != DCAL_SUCCESS)
				printf("unable to set broadcast\n");

			// Interface is paired with wlan0, wlan0 cannot have this set
			if (strcmp(interface_name, "wlan0") != 0){
				ret = dcal_wifi_interface_set_bridge(interface, 1);
				if (ret != DCAL_SUCCESS)
					printf("unable to enable bridge\n");
			}

			// Only wlan0 can set ap mode on
			if (strcmp(interface_name, "wlan0") == 0){
				ret = dcal_wifi_interface_set_ap_mode(interface, 1);
				if (ret != DCAL_SUCCESS)
					printf("unable to enable ap mode\n");
			}

			ret = dcal_wifi_interface_set_nat(interface, 1);
			if (ret != DCAL_SUCCESS)
				printf("unable to enable NAT\n");

			// Push interface settings
			ret = dcal_wifi_interface_push( session, interface);
			if (ret != DCAL_SUCCESS)
				printf("push return code: %d\n", ret);

			//Clear properties
			ret = dcal_wifi_interface_clear_property( interface, ADDRESS);
			if (ret != DCAL_SUCCESS)
				printf("unable to clear address\n");

			ret = dcal_wifi_interface_clear_property( interface, NETMASK);
			if (ret != DCAL_SUCCESS)
				printf("unable to clear netmask\n");

			ret = dcal_wifi_interface_clear_property( interface, GATEWAY);
			if (ret != DCAL_SUCCESS)
				printf("unable to clear gateway\n");

			ret = dcal_wifi_interface_clear_property( interface, BROADCAST);
			if (ret != DCAL_SUCCESS)
				printf("unable to clear broadcast\n");

			ret = dcal_wifi_interface_clear_property( interface, NAMESERVER);
			if (ret != DCAL_SUCCESS)
				printf("unable to clear nameserver\n");

			// Interface is paired with wlan0, wlan0 cannot have this set
			if (strcmp(interface_name, "wlan0") != 0){
				ret = dcal_wifi_interface_set_bridge(interface, 0);
				if (ret != DCAL_SUCCESS)
					printf("unable to disable bridge\n");
			}

			// Only wlan0 can set ap mode off
			if (strcmp(interface_name, "wlan0") == 0){
				ret = dcal_wifi_interface_set_ap_mode(interface, 0);
				if (ret != DCAL_SUCCESS)
					printf("unable to disable ap mode\n");
			}

			ret = dcal_wifi_interface_set_nat(interface, 0);
			if (ret != DCAL_SUCCESS)
				printf("unable to disable NAT\n");

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