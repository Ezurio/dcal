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

	if((ret = session_connect_with_opts(session, argc, argv, true))){
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
			// Setup IPv4 interface
			ret = dcal_wifi_interface_set_method(interface, "dhcp");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 method\n");

			ret = dcal_wifi_interface_set_auto_start(interface, 0);
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 auto start\n");

			ret = dcal_wifi_interface_set_address(interface, "192.168.9.9");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 address\n");

			ret = dcal_wifi_interface_set_netmask(interface, "255.255.255.0");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 netmask\n");

			ret = dcal_wifi_interface_set_gateway(interface, "192.168.9.1");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 gateway\n");

			ret = dcal_wifi_interface_set_nameserver(interface, "8.8.8.8");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 nameserver\n");

			ret = dcal_wifi_interface_set_broadcast_address(interface, "192.168.9.255");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv4 broadcast\n");

			// Interface is paired with wlan0, wlan0 cannot have this set
			if (strcmp(interface_name, "wlan0") != 0){
				ret = dcal_wifi_interface_set_bridge(interface, 1);
				if (ret != DCAL_SUCCESS)
					printf("unable to enable IPv4 bridge\n");
			}

			// Only wlan0 can set ap mode on
			if (strcmp(interface_name, "wlan0") == 0){
				ret = dcal_wifi_interface_set_ap_mode(interface, 1);
				if (ret != DCAL_SUCCESS)
					printf("unable to enable ap mode\n");
			}

			ret = dcal_wifi_interface_set_nat(interface, 1);
			if (ret != DCAL_SUCCESS)
				printf("unable to enable IPv4 NAT\n");

			// Setup IPv6 interface
			ret = dcal_wifi_interface_set_method6(interface, "static");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv6 method\n");

			// SLAAC is "0", Stateless DHCPv6 is "1"
			// This property is only used when IPv6 method is set to "auto"
			ret = dcal_wifi_interface_set_dhcp6(interface, "1");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv6 DHCP option\n");

			ret = dcal_wifi_interface_set_address6(interface, "2001:DB88:1234:1234:1234:1234:1234:1111");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv6 address\n");

			ret = dcal_wifi_interface_set_netmask6(interface, "64");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv6 netmask\n");

			ret = dcal_wifi_interface_set_gateway6(interface, "2001:DB88:1234:1234:1234:1234:1234:2222");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv6 gateway\n");

			ret = dcal_wifi_interface_set_nameserver6(interface, "2001:DB88:1234:1234:1234:1234:1234:3333");
			if (ret != DCAL_SUCCESS)
				printf("unable to set IPv6 nameserver\n");

			ret = dcal_wifi_interface_set_nat6(interface, 1);
			if (ret != DCAL_SUCCESS)
				printf("unable to enable IPv6 NAT\n");

			// Push interface settings
			ret = dcal_wifi_interface_push( session, interface);
			if (ret != DCAL_SUCCESS)
				printf("push return code: %d, line: %d\n", ret, __LINE__);

			ret = dcal_wifi_interface_close_handle(interface);
				if (ret != DCAL_SUCCESS)
					printf("Unable to close handle at line:%d\n",__LINE__);

			// Get interface settings
			ret = dcal_wifi_interface_pull(session, &interface, interface_name);
			if (ret == DCAL_SUCCESS){
				bool auto_start;
				bool ipv4;
				bool ipv6;

				printf("Interface: %s\n",interface_name);
				ret = dcal_wifi_interface_get_auto_start(interface, &auto_start);
				if (ret == DCAL_SUCCESS){
					if (auto_start){
						printf("auto start is enabled\n");
					} else {
						printf("auto start is disabled\n");
					}
				}
				//IPv4
				ret = dcal_wifi_interface_get_ipv4_state(interface, &ipv4);
				if (ret == DCAL_SUCCESS && ipv4){
					char method[STR_SZ];
					char address[IP6_STR_SZ];
					char netmask[IP6_STR_SZ];
					char gateway[IP6_STR_SZ];
					char broadcast[IP6_STR_SZ];
					char nameserver[IP6_STR_SZ];
					bool bridge_ports;
					bool ap_mode;
					bool nat;

					printf("IPv4:\n");

					ret = dcal_wifi_interface_get_method(interface, method, sizeof(method));
					if (ret == DCAL_SUCCESS){
						if (method[0] != '\0')
							printf("\t method %s\n",method);
					}
					ret = dcal_wifi_interface_get_address(interface, address, sizeof(address));
					if (ret == DCAL_SUCCESS){
						if (address[0] != '\0')
							printf("\t address %s\n",address);
					}
					ret = dcal_wifi_interface_get_netmask(interface, netmask, sizeof(netmask));
					if (ret == DCAL_SUCCESS){
						if (netmask[0] != '\0')
							printf("\t netmask %s\n",netmask);
					}
					ret = dcal_wifi_interface_get_gateway(interface, gateway, sizeof(gateway));
					if (ret == DCAL_SUCCESS){
						if (gateway[0] != '\0')
							printf("\t gateway %s\n",gateway);
					}
					ret = dcal_wifi_interface_get_broadcast_address(interface, broadcast, sizeof(broadcast));
					if (ret == DCAL_SUCCESS){
						if (broadcast[0] != '\0')
							printf("\t broadcast %s\n",broadcast);
					}
					ret = dcal_wifi_interface_get_nameserver(interface, nameserver, sizeof(nameserver));
					if (ret == DCAL_SUCCESS){
						if (nameserver[0] != '\0')
							printf("\t nameserver %s\n",nameserver);
					}
					ret = dcal_wifi_interface_get_bridge(interface, &bridge_ports);
					if (ret == DCAL_SUCCESS){
						if (bridge_ports)
							printf("\t bridge is enabled\n");
					}
					ret = dcal_wifi_interface_get_ap_mode(interface, &ap_mode);
					if (ret == DCAL_SUCCESS){
						if (ap_mode)
							printf("\t AP mode is enabled\n");
					}
					ret = dcal_wifi_interface_get_nat(interface, &nat);
					if (ret == DCAL_SUCCESS){
						if (nat)
							printf("\t NAT is enabled\n");
					}
				} else {
					printf("%s IPv4 is not present\n",interface_name);
				}
				//IPv6
				ret = dcal_wifi_interface_get_ipv6_state(interface, &ipv6);
				if (ret == DCAL_SUCCESS && ipv6){
					char method6[STR_SZ];
					char dhcp6[STR_SZ];
					char address6[IP6_STR_SZ];
					char netmask6[IP6_STR_SZ];
					char gateway6[IP6_STR_SZ];
					char nameserver6[IP6_STR_SZ];
					bool nat6;

					printf("IPv6:\n");

					ret = dcal_wifi_interface_get_method6(interface, method6, sizeof(method6));
					if (ret == DCAL_SUCCESS){
						if (method6[0] != '\0')
							printf("\t method %s\n",method6);
					}
					ret = dcal_wifi_interface_get_dhcp6(interface, dhcp6, sizeof(dhcp6));
					if (ret == DCAL_SUCCESS){
						if (dhcp6[0] != '\0')
							printf("\t DHCP %s\n",dhcp6);
					}
					ret = dcal_wifi_interface_get_address6(interface, address6, sizeof(address6));
					if (ret == DCAL_SUCCESS){
						if (address6[0] != '\0')
							printf("\t address %s\n",address6);
					}
					ret = dcal_wifi_interface_get_netmask6(interface, netmask6, sizeof(netmask6));
					if (ret == DCAL_SUCCESS){
						if (netmask6[0] != '\0')
							printf("\t netmask %s\n",netmask6);
					}
					ret = dcal_wifi_interface_get_gateway6(interface, gateway6, sizeof(gateway6));
					if (ret == DCAL_SUCCESS){
						if (gateway6[0] != '\0')
							printf("\t gateway %s\n",gateway6);
					}
					ret = dcal_wifi_interface_get_nameserver6(interface, nameserver6, sizeof(nameserver6));
					if (ret == DCAL_SUCCESS){
						if (nameserver6[0] != '\0')
							printf("\t nameserver %s\n",nameserver6);
					}
					ret = dcal_wifi_interface_get_nat6(interface, &nat6);
					if (ret == DCAL_SUCCESS){
						if (nat6)
							printf("\t NAT is enabled\n");
					}
				} else {
					printf("%s IPv6 is not present\n",interface_name);
				}
			} else {
				printf("unable to pull interface: return code:%d\n",ret);
			}

			ret = dcal_wifi_interface_close_handle(interface);
				if (ret != DCAL_SUCCESS)
					printf("Unable to close handle at line:%d\n",__LINE__);

			interface = NULL;

			ret = dcal_wifi_interface_create(&interface);
			if (ret == DCAL_SUCCESS){
				ret = dcal_wifi_interface_set_interface_name(interface, interface_name);
				if (ret == DCAL_SUCCESS){
					if (ret == DCAL_SUCCESS){
						//Clear IPv4 properties
						ret = dcal_wifi_interface_clear_property( interface, ADDRESS);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv4 address\n");

						ret = dcal_wifi_interface_clear_property( interface, NETMASK);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv4 netmask\n");

						ret = dcal_wifi_interface_clear_property( interface, GATEWAY);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv4 gateway\n");

						ret = dcal_wifi_interface_clear_property( interface, BROADCAST);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv4 broadcast\n");

						ret = dcal_wifi_interface_clear_property( interface, NAMESERVER);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv4 nameserver\n");

						// Interface is paired with wlan0, wlan0 cannot have this set
						if (strcmp(interface_name, "wlan0") != 0){
							ret = dcal_wifi_interface_set_bridge(interface, 0);
							if (ret != DCAL_SUCCESS)
								printf("unable to disable IPv4 bridge\n");
						}

						// Only wlan0 can set ap mode off
						if (strcmp(interface_name, "wlan0") == 0){
							ret = dcal_wifi_interface_set_ap_mode(interface, 0);
							if (ret != DCAL_SUCCESS)
								printf("unable to disable ap mode\n");
						}

						ret = dcal_wifi_interface_set_nat(interface, 0);
						if (ret != DCAL_SUCCESS)
							printf("unable to disable IPv4 NAT\n");

						//Clear IPv6 properties
						ret = dcal_wifi_interface_clear_property6( interface, ADDRESS);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv6 address\n");

						ret = dcal_wifi_interface_clear_property6( interface, NETMASK);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv6 netmask\n");

						ret = dcal_wifi_interface_clear_property6( interface, GATEWAY);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv6 gateway\n");

						ret = dcal_wifi_interface_clear_property6( interface, NAMESERVER);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv6 nameserver\n");

						ret = dcal_wifi_interface_clear_property6( interface, DHCP);
						if (ret != DCAL_SUCCESS)
							printf("unable to clear IPv6 DHCP option\n");

						ret = dcal_wifi_interface_set_nat6(interface, 0);
						if (ret != DCAL_SUCCESS)
							printf("unable to disable IPv6 NAT\n");

						ret = dcal_wifi_interface_push( session, interface);
						if (ret == DCAL_SUCCESS){
							ret = dcal_wifi_interface_delete( session, interface);
							if (ret != DCAL_SUCCESS)
								printf("unable to delete interface\n");

						} else {
							printf("push return code: %d, line: %d\n", ret, __LINE__);
						}
					}
				} else {
					printf("unable to set interface_name, line %d\n", __LINE__);
				}
			} else {
				printf("unable to create interface, line %d\n", __LINE__);
			}
		} else {
			printf("unable to set interface_name, line %d\n", __LINE__);
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
