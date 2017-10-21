#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dcal_api.h"
#include "sess_opts.h"

#define LEASE_SMALL_STR_SZ 20
#define LEASE_LARGE_STR_SZ 100
#define LEASE_DOMAIN_STR_SZ 200
#define LEASE_TIMER_STR_SZ 30

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

	application_name = "lease_test";

	if((ret = session_connect_with_opts(session, argc, argv, true))){
		printf("unable to make connection\n");
		dcal_session_close(session);
		session = NULL;
		goto cleanup;
	}

	// device interaction
	laird_lease_handle lease;
	char interface_name[] = "wlan0";

	// Get lease settings
	ret = dcal_wifi_lease_pull(session, &lease, interface_name);
	if (ret == DCAL_SUCCESS){
		char interface[LEASE_SMALL_STR_SZ];
		char address[LEASE_SMALL_STR_SZ];
		char subnet_mask[LEASE_SMALL_STR_SZ];
		char routers[LEASE_LARGE_STR_SZ];
		long lease_time;
		int message_type;
		char dns_servers[LEASE_LARGE_STR_SZ];
		char dhcp_server[LEASE_SMALL_STR_SZ];
		char domain_name[LEASE_DOMAIN_STR_SZ];
		char renew[LEASE_TIMER_STR_SZ];
		char rebind[LEASE_TIMER_STR_SZ];
		char expire[LEASE_TIMER_STR_SZ];

		ret = dcal_wifi_lease_get_message_type(lease, &message_type);
		if (ret == DCAL_SUCCESS && message_type){
			ret = dcal_wifi_lease_get_interface(lease, interface, sizeof(interface));
			if (ret == DCAL_SUCCESS)
				if (interface[0] != '\0')
					printf("%s",interface);

			printf(" IPv4 DCHP lease:\n");

			ret = dcal_wifi_lease_get_address(lease, address, sizeof(address));
			if (ret == DCAL_SUCCESS)
				if (address[0] != '\0')
					printf("\t Address: %s\n",address);

			ret = dcal_wifi_lease_get_subnet_mask(lease, subnet_mask, sizeof(subnet_mask));
			if (ret == DCAL_SUCCESS)
				if (subnet_mask[0] != '\0')
					printf("\t Subnet mask: %s\n",subnet_mask);

			ret = dcal_wifi_lease_get_routers(lease, routers, sizeof(routers));
			if (ret == DCAL_SUCCESS)
				if (routers[0] != '\0')
					printf("\t Routers: %s\n",routers);

			ret = dcal_wifi_lease_get_lease_time(lease, &lease_time);
			if (ret == DCAL_SUCCESS)
				if (lease_time)
					printf("\t Lease time: %ld\n",lease_time);

			ret = dcal_wifi_lease_get_dns_servers(lease, dns_servers, sizeof(dns_servers));
			if (ret == DCAL_SUCCESS)
				if (dns_servers[0] != '\0')
					printf("\t DNS servers: %s\n",dns_servers);

			ret = dcal_wifi_lease_get_dhcp_server(lease, dhcp_server, sizeof(dhcp_server));
			if (ret == DCAL_SUCCESS)
				if (dhcp_server[0] != '\0')
					printf("\t DHCP server: %s\n",dhcp_server);

			ret = dcal_wifi_lease_get_domain_name(lease, domain_name, sizeof(domain_name));
			if (ret == DCAL_SUCCESS)
				if (domain_name[0] != '\0')
					printf("\t Domain name: %s\n",domain_name);

			ret = dcal_wifi_lease_get_renew(lease, renew, sizeof(renew));
			if (ret == DCAL_SUCCESS)
				if (renew[0] != '\0')
					printf("\t Renew: %s\n",renew);

			ret = dcal_wifi_lease_get_rebind(lease, rebind, sizeof(rebind));
			if (ret == DCAL_SUCCESS)
				if (rebind[0] != '\0')
					printf("\t Rebind: %s\n",rebind);

			ret = dcal_wifi_lease_get_expire(lease, expire, sizeof(expire));
			if (ret == DCAL_SUCCESS)
				if (expire[0] != '\0')
					printf("\t Expire: %s\n",expire);
		} else {
			printf("No valid lease found for %s\n", interface_name);
		}
	} else {
		printf("unable to pull lease: return code:%d\n",ret);
	}

	ret = dcal_wifi_lease_close_handle(lease);
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
