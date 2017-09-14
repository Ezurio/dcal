#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_api.h"
#include "dcal_internal_api.h"
#include "default_route.h"
#include "session.h"
#include "buffer.h"

#ifdef STATIC_MEM

static internal_default_route_struct static_default_route = { 0 };

#else

#include "lists.h"
static pointer_list * default_routes = NULL;

#endif

void __attribute__ ((constructor)) initdefault_routes(void)
{
	int rc;
	rc = initlist(&default_routes);
	if (rc)
		DBGERROR("initlist() failed for default_routes list with:%d\n", rc);
}

void __attribute__ ((destructor)) default_routes_fini(void)
{
	int rc;
	rc = freelist(&default_routes);
	default_routes = NULL;
	if(rc)
		DBGERROR("freelist() failed for default_routes list with: %d\n", rc);
}


static void clear_and_strncpy( char * dest, const char * src, size_t size)
{
	assert(dest);
	assert(src);
	memset(dest,0,size);
	strncpy(dest, src, size);
}

int dcal_wifi_default_route_create( laird_default_route_handle * default_route)
{
	internal_default_route_handle handle=NULL;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (default_route==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else {
	#if STATIC_MEM
		if(static_default_route.valid)
			ret = DCAL_HANDLE_IN_USE;
		else
			handle = &static_default_route;
			memset(handle, 0, sizeof(internal_default_route_struct));
	#else // not STATIC_MEM
	#ifdef DEBUG
		if(validate_handle(default_routes, default_route))
			ret = DCAL_HANDLE_IN_USE;
		else
	#endif
		{
			handle = (internal_default_route_handle) malloc(sizeof(internal_default_route_struct));
			if (handle==NULL)
				ret = DCAL_NO_MEMORY;
			else {
				memset(handle, 0, sizeof(internal_default_route_struct));
				ret = add_to_list(&default_routes, handle);
			}
		}
	#endif // STATIC_MEM
	}
	if (ret==DCAL_SUCCESS);
		*default_route = handle;
	return REPORT_RETURN_DBG(ret);
}


int dcal_wifi_default_route_pull( laird_session_handle session,
                                  laird_default_route_handle * default_route,
                                  char * interface_name)
{
	int ret = DCAL_SUCCESS;
	REPORT_ENTRY_DEBUG;

	//Its ok if interface_name is NULL
	if ((session == NULL) || (default_route == NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if (validate_handle(default_routes, default_route))
		ret = DCAL_HANDLE_IN_USE;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	else {
		internal_session_handle s = (internal_session_handle)session;
		ns(Cmd_pl_union_ref_t) cmd_pl;
		// Attempt to retrieve default_route from device
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		ns(String_start(B));
		if (interface_name != NULL){
			ns(String_value_create_str(B, interface_name));
		}

		cmd_pl.String = ns(String_end(B));
		cmd_pl.type = ns(Cmd_pl_String);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_cmd_pl_add(B, cmd_pl));
		ns(Command_command_add(B, ns(Commands_GETDEFAULTROUTE)));
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
		if(buftype != ns(Default_route_type_hash)) {
			if(buftype != ns(Handshake_type_hash)){
				DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
				return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
			}

			ret =handshake_error_code(ns(Handshake_as_root(buffer)));

			DBGERROR("Failed to retrieve default_route.  Error received: %d\n",ret);
			return REPORT_RETURN_DBG(ret);
		}

		//if valid, get handle (ifdef for STATIC or not)
		if (dcal_wifi_default_route_create(default_route) != DCAL_SUCCESS)
			return REPORT_RETURN_DBG(ret);

		assert(*default_route);
		//copy data from buffer to handle
		internal_default_route_handle dr = (internal_default_route_handle)*default_route;

		ns(Default_route_table_t) drt = ns(Default_route_as_root(buffer));

		strncpy(dr->interface, ns(Default_route_interface(drt)), LRD_ROUTE_STR_SZ);
		strncpy(dr->destination, ns(Default_route_destination(drt)), LRD_ROUTE_STR_SZ);
		strncpy(dr->gateway, ns(Default_route_gateway(drt)), LRD_ROUTE_STR_SZ);
		dr->flags=ns(Default_route_flags(drt));
		dr->metric=ns(Default_route_metric(drt));
		strncpy(dr->subnet_mask, ns(Default_route_subnet_mask(drt)), LRD_ROUTE_STR_SZ);
		dr->mtu=ns(Default_route_mtu(drt));
		dr->window=ns(Default_route_window(drt));
		dr->irtt=ns(Default_route_irtt(drt));

		#ifdef STATIC_MEM
		dr->valid = true;
		#endif

	}
	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_close_handle( laird_default_route_handle i)
{
	internal_default_route_handle default_route = (internal_default_route_handle)i;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if(default_route==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, i))
		ret = DCAL_INVALID_HANDLE;
	else {
		#ifdef STATIC_MEM
			((laird_default_route_handle)default_route)->valid = false;
		#else
			ret = remove_from_list(&default_routes, default_route);
			if (ret==DCAL_SUCCESS)
				default_route = NULL;
		#endif
	}

	return REPORT_RETURN_DBG(ret);

}

int dcal_wifi_default_route_get_interface( laird_default_route_handle default_route,
                                  char *interface, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if ((interface==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(interface, dr->interface, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_destination( laird_default_route_handle default_route,
                                  char *destination, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if ((destination==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(destination, dr->destination, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_gateway( laird_default_route_handle default_route,
                                  char *gateway, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if ((gateway==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(gateway, dr->gateway, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_flags( laird_default_route_handle default_route,
                                  int *flags)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if (flags==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		*flags = dr->flags;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_metric( laird_default_route_handle default_route,
                                  unsigned int *metric)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if (metric==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		*metric = dr->metric;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_subnet_mask( laird_default_route_handle default_route,
                                  char *subnet_mask, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if ((subnet_mask==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(subnet_mask, dr->subnet_mask, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_mtu( laird_default_route_handle default_route,
                                  unsigned int *mtu)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if (mtu==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		*mtu = dr->mtu;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_window( laird_default_route_handle default_route,
                                  unsigned int *window)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if (window==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		*window = dr->window;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_default_route_get_irtt( laird_default_route_handle default_route,
                                  unsigned int *irtt)
{
	int ret = DCAL_SUCCESS;
	internal_default_route_handle dr = (internal_default_route_handle)default_route;
	REPORT_ENTRY_DEBUG;

	if (irtt==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(default_routes, default_route))
		ret = DCAL_INVALID_HANDLE;
	else {
		*irtt = dr->irtt;
	}

	return REPORT_RETURN_DBG(ret);
}
