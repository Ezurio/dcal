#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_api.h"
#include "dcal_internal_api.h"
#include "lease.h"
#include "session.h"
#include "buffer.h"
#include "common.h"

#ifdef STATIC_MEM

static internal_lease_struct static_lease = { 0 };

#else

#include "lists.h"
static pointer_list * leases = NULL;

#endif

void __attribute__ ((constructor)) initleases(void)
{
	int rc;
	rc = initlist(&leases);
	if (rc)
		DBGERROR("initlist() failed for leases list with:%d\n", rc);
}

void __attribute__ ((destructor)) leases_fini(void)
{
	int rc;
	rc = freelist(&leases);
	leases = NULL;
	if(rc)
		DBGERROR("freelist() failed for leases list with: %d\n", rc);
}

static int lease_create( laird_lease_handle * lease)
{
	internal_lease_handle handle=NULL;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (lease==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else {
	#if STATIC_MEM
		if(static_lease.valid)
			ret = DCAL_HANDLE_IN_USE;
		else
			handle = &static_lease;
			memset(handle, 0, sizeof(internal_lease_struct));
	#else // not STATIC_MEM
	#ifdef DEBUG
		if(validate_handle(leases, lease))
			ret = DCAL_HANDLE_IN_USE;
		else
	#endif
		{
			handle = (internal_lease_handle) malloc(sizeof(internal_lease_struct));
			if (handle==NULL)
				ret = DCAL_NO_MEMORY;
			else {
				memset(handle, 0, sizeof(internal_lease_struct));
				ret = add_to_list(&leases, handle);
			}
		}
	#endif // STATIC_MEM
	}
	if (ret==DCAL_SUCCESS)
		*lease = handle;
	return REPORT_RETURN_DBG(ret);
}


int dcal_wifi_lease_pull( laird_session_handle session,
                                 laird_lease_handle * lease,
                                 char * interfaceName)
{
	int ret = DCAL_SUCCESS;
	REPORT_ENTRY_DEBUG;

	if ((session == NULL) || (lease == NULL) || (interfaceName == NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if ((ret = lease_create(lease)) != DCAL_SUCCESS)
		return ret;
	else if (validate_handle(leases, lease))
		ret = DCAL_HANDLE_IN_USE;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	else {
		internal_session_handle s = (internal_session_handle)session;
		// Attempt to retrieve lease from device
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);
		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_command_add(B, ns(Commands_GETLEASE)));

		ns(Command_cmd_pl_Lease_start(B));
		ns(String_value_create_str(B, interfaceName));
		ns(Command_cmd_pl_Lease_end(B));

		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);

		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS) {
			unlock_session_channel(session);
			return REPORT_RETURN_DBG(ret);
		}

		//get response
		size=BUF_SZ;
		ret = dcal_read_buffer(session, buffer, &size);
		unlock_session_channel(session);

		if (ret != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		//is return buffer an ack buffer?
		buftype = verify_buffer(buffer, size);
		if(buftype != ns(Lease_type_hash)) {
			if(buftype != ns(Handshake_type_hash)){
				DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
				return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
			}

			ret =handshake_error_code(ns(Handshake_as_root(buffer)));

			DBGERROR("Failed to retrieve lease.  Error received: %d\n",ret);
			return REPORT_RETURN_DBG(ret);
		}

		assert(*lease);
		//copy data from buffer to handle
		internal_lease_handle l = (internal_lease_handle)*lease;

		ns(Lease_table_t) it = ns(Lease_as_root(buffer));

		strncpy(l->interface, ns(Lease_interface(it)), LEASE_SMALL_STR_SZ);
		strncpy(l->address, ns(Lease_address(it)), LEASE_SMALL_STR_SZ);
		strncpy(l->subnet_mask, ns(Lease_subnet_mask(it)), LEASE_SMALL_STR_SZ);
		strncpy(l->routers, ns(Lease_routers(it)), LEASE_LARGE_STR_SZ);
		l->lease_time=ns(Lease_lease_time(it));
		l->message_type=ns(Lease_message_type(it));
		strncpy(l->dns_servers, ns(Lease_dns_servers(it)), LEASE_LARGE_STR_SZ);
		strncpy(l->dhcp_server, ns(Lease_dhcp_server(it)), LEASE_SMALL_STR_SZ);
		strncpy(l->domain_name, ns(Lease_domain_name(it)), LEASE_DOMAIN_STR_SZ);
		strncpy(l->renew, ns(Lease_renew(it)), LEASE_TIMER_STR_SZ);
		strncpy(l->rebind, ns(Lease_rebind(it)), LEASE_TIMER_STR_SZ);
		strncpy(l->expire, ns(Lease_expire(it)), LEASE_TIMER_STR_SZ);

		#ifdef STATIC_MEM
		l->valid = true;
		#endif

	}
	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_close_handle( laird_lease_handle i)
{
	internal_lease_handle lease = (internal_lease_handle)i;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if(lease==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, i))
		ret = DCAL_INVALID_HANDLE;
	else {
		#ifdef STATIC_MEM
			((laird_lease_handle)lease)->valid = false;
		#else
			ret = remove_from_list(&leases, lease);
			if (ret==DCAL_SUCCESS)
				lease = NULL;
		#endif
	}

	return REPORT_RETURN_DBG(ret);

}

int dcal_wifi_lease_get_interface( laird_lease_handle lease,
                                  char *interface, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((interface==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(interface, l->interface, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_address( laird_lease_handle lease,
                                  char *address, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((address==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(address, l->address, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_subnet_mask( laird_lease_handle lease,
                                  char *subnet_mask, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((subnet_mask==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(subnet_mask, l->subnet_mask, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_routers( laird_lease_handle lease,
                                  char *routers, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((routers==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(routers, l->routers, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_lease_time( laird_lease_handle lease,
                                  long *lease_time)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if (lease_time==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		*lease_time = l->lease_time;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_message_type( laird_lease_handle lease,
                                  int *message_type)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle g = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if (message_type==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		*message_type = g->message_type;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_dns_servers( laird_lease_handle lease,
                                  char *dns_servers, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((dns_servers==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(dns_servers, l->dns_servers, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_dhcp_server( laird_lease_handle lease,
                                  char *dhcp_server, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((dhcp_server==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(dhcp_server, l->dhcp_server, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_domain_name( laird_lease_handle lease,
                                  char *domain_name, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((domain_name==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(domain_name, l->domain_name, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_renew( laird_lease_handle lease,
                                  char *renew, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((renew==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(renew, l->renew, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_rebind( laird_lease_handle lease,
                                  char *rebind, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((rebind==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(rebind, l->rebind, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_lease_get_expire( laird_lease_handle lease,
                                  char *expire, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_lease_handle l = (internal_lease_handle)lease;
	REPORT_ENTRY_DEBUG;

	if ((expire==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(leases, lease))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(expire, l->expire, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}
