#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "dcal_api.h"
#include "dcal_internal_api.h"
#include "interface.h"
#include "session.h"
#include "buffer.h"

#ifdef STATIC_MEM

static internal_interface_struct static_interface = { 0 };

#else

#include "lists.h"
static pointer_list * interfaces = NULL;

#endif

void __attribute__ ((constructor)) initinterfaces(void)
{
	int rc;
	rc = initlist(&interfaces);
	if (rc)
		DBGERROR("initlist() failed for interfaces list with:%d\n", rc);
}

void __attribute__ ((destructor)) interfaces_fini(void)
{
	int rc;
	rc = freelist(&interfaces);
	interfaces = NULL;
	if(rc)
		DBGERROR("freelist() failed for interfaces list with: %d\n", rc);
}


static void clear_and_strncpy( char * dest, const char * src, size_t size)
{
	assert(dest);
	assert(src);
	memset(dest,0,size);
	strncpy(dest, src, size);
}

int dcal_wifi_interface_create( laird_interface_handle * interface)
{
	internal_interface_handle handle=NULL;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if (interface==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else {
	#if STATIC_MEM
		if(static_interface.valid)
			ret = DCAL_HANDLE_IN_USE;
		else
			handle = &static_interface;
			memset(handle, 0, sizeof(internal_interface_struct));
	#else // not STATIC_MEM
	#ifdef DEBUG
		if(validate_handle(interfaces, interface))
			ret = DCAL_HANDLE_IN_USE;
		else
	#endif
		{
			handle = (internal_interface_handle) malloc(sizeof(internal_interface_struct));
			if (handle==NULL)
				ret = DCAL_NO_MEMORY;
			else {
				memset(handle, 0, sizeof(internal_interface_struct));
				ret = add_to_list(&interfaces, handle);
			}
		}
	#endif // STATIC_MEM
	}
	if (ret==DCAL_SUCCESS);
		*interface = handle;
	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_pull( laird_session_handle session,
                                 laird_interface_handle * interface,
                                 char * interfaceName)
{
	int ret = DCAL_SUCCESS;
	REPORT_ENTRY_DEBUG;

	if ((session == NULL) || (interface == NULL) || (interfaceName == NULL))
		ret = DCAL_INVALID_PARAMETER;
	else if (validate_handle(interfaces, interface))
		ret = DCAL_HANDLE_IN_USE;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	else {
		internal_session_handle s = (internal_session_handle)session;
		ns(Cmd_pl_union_ref_t) cmd_pl;
		// Attempt to retrieve interface from device
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		ns(String_start(B));
		ns(String_value_create_str(B, interfaceName));

		cmd_pl.String = ns(String_end(B));
		cmd_pl.type = ns(Cmd_pl_String);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_cmd_pl_add(B, cmd_pl));
		ns(Command_command_add(B, ns(Commands_GETINTERFACE)));
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
		if(buftype != ns(Interface_type_hash)) {
			if(buftype != ns(Handshake_type_hash)){
				DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
				return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
			}

			ret =handshake_error_code(ns(Handshake_as_root(buffer)));

			DBGERROR("Failed to retrieve interface.  Error received: %d\n",ret);
			return REPORT_RETURN_DBG(ret);
		}

		//if valid, get handle (ifdef for STATIC or not)
		dcal_wifi_interface_create( interface);

		assert(*interface);
		//copy data from buffer to handle
		internal_interface_handle i = (internal_interface_handle)*interface;

		ns(Interface_table_t) it = ns(Interface_as_root(buffer));

		i->ipv4=ns(Interface_ipv4(it));
		i->auto_start=ns(Interface_auto_start(it));
		strncpy(i->method, ns(Interface_method(it)), STR_SZ);
		strncpy(i->address, ns(Interface_address(it)), STR_SZ);
		strncpy(i->netmask, ns(Interface_netmask(it)), STR_SZ);
		strncpy(i->gateway, ns(Interface_gateway(it)), STR_SZ);
		strncpy(i->broadcast, ns(Interface_broadcast(it)), STR_SZ);
		strncpy(i->nameserver, ns(Interface_nameserver(it)), STR_SZ);
		i->bridge=ns(Interface_bridge(it));
		i->ap_mode=ns(Interface_ap_mode(it));
		i->nat=ns(Interface_nat(it));

		#ifdef STATIC_MEM
		i->valid = true;
		#endif

	}
	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_close_handle( laird_interface_handle i)
{
	internal_interface_handle interface = (internal_interface_handle)i;
	int ret = DCAL_SUCCESS;

	REPORT_ENTRY_DEBUG;

	if(interface==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, i))
		ret = DCAL_INVALID_HANDLE;
	else {
		#ifdef STATIC_MEM
			((laird_interface_handle)interface)->valid = false;
		#else
			ret = remove_from_list(&interfaces, interface);
			if (ret==DCAL_SUCCESS)
				interface = NULL;
		#endif
	}

	return REPORT_RETURN_DBG(ret);

}

//  push sends the local interface to the remote
//  radio device.
int dcal_wifi_interface_push( laird_session_handle session,
                                 laird_interface_handle interface)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	internal_session_handle s = (internal_session_handle)session;
	ns(Cmd_pl_union_ref_t) cmd_pl;
	REPORT_ENTRY_DEBUG;

	if (session==NULL)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	else {
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		ns(Interface_start(B));

		ns(Interface_interface_name_create_str(B, i->interface_name));
		ns(Interface_prop_add(B, i->prop));
		ns(Interface_ipv4_add(B, i->ipv4));
		ns(Interface_method_create_str(B, i->method));
		ns(Interface_auto_start_add(B, i->auto_start));
		ns(Interface_address_create_str(B, i->address));
		ns(Interface_netmask_create_str(B, i->netmask));
		ns(Interface_gateway_create_str(B, i->gateway));
		ns(Interface_broadcast_create_str(B, i->broadcast));
		ns(Interface_nameserver_create_str(B, i->nameserver));
		ns(Interface_state_add(B, i->state));
		ns(Interface_bridge_add(B, i->bridge));
		ns(Interface_ap_mode_add(B, i->ap_mode));
		ns(Interface_nat_add(B, i->nat));
		ns(Interface_ipv6_add(B, i->ipv6));
		ns(Interface_prop6_add(B, i->prop6));
		ns(Interface_method6_create_str(B, i->method6));
		ns(Interface_address6_create_str(B, i->address6));
		ns(Interface_netmask6_create_str(B, i->netmask6));
		ns(Interface_gateway6_create_str(B, i->gateway6));
		ns(Interface_nameserver6_create_str(B, i->nameserver6));
		ns(Interface_state6_add(B, i->state6));
		ns(Interface_nat6_add(B, i->nat6));

		cmd_pl.Interface = ns(Interface_end(B));
		cmd_pl.type = ns(Cmd_pl_Interface);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_cmd_pl_add(B, cmd_pl));
		ns(Command_command_add(B, ns(Commands_SETINTERFACE)));
		ns(Command_end_as_root(B));

		size=flatcc_builder_get_buffer_size(B);
		assert(size<=BUF_SZ);
		flatcc_builder_copy_buffer(B, buffer, size);
		ret = lock_session_channel(session);
		if(ret)
			return REPORT_RETURN_DBG(ret);
		ret = dcal_send_buffer(session, buffer, size);

		if (ret != DCAL_SUCCESS){
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

		if(buftype != ns(Handshake_type_hash)){
			DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
			return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
		}

		ret = handshake_error_code(ns(Handshake_as_root(buffer)));

	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_delete( laird_session_handle session,
                                  char * interface_name)
{
	int ret = DCAL_SUCCESS;
	internal_session_handle s = (internal_session_handle)session;
	ns(Cmd_pl_union_ref_t) cmd_pl;
	REPORT_ENTRY_DEBUG;

	if ((interface_name==NULL) || (interface_name[0]==0))
		ret = DCAL_INVALID_PARAMETER;
	else if (!validate_session(session))
		return DCAL_INVALID_HANDLE;
	else {
		flatcc_builder_t *B;
		char buffer[BUF_SZ] = {0};
		size_t size = BUF_SZ;
		flatbuffers_thash_t buftype;

		B = &s->builder;
		flatcc_builder_reset(B);

		ns(String_start(B));
		ns(String_value_create_str(B, interface_name));

		cmd_pl.String = ns(String_end(B));
		cmd_pl.type = ns(Cmd_pl_String);

		flatbuffers_buffer_start(B, ns(Command_type_identifier));
		ns(Command_start(B));
		ns(Command_cmd_pl_add(B, cmd_pl));
		ns(Command_command_add(B, ns(Commands_DELINTERFACE)));
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

		if(buftype != ns(Handshake_type_hash)){
			DBGERROR("could not verify handshake buffer.  Validated as: %s\n", buftype_to_string(buftype));
			return REPORT_RETURN_DBG(DCAL_FLATBUFF_ERROR);
		}

		ret =handshake_error_code(ns(Handshake_as_root(buffer)));

	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_interface_name( laird_interface_handle interface,
                                  char * interface_name)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->interface_name, interface_name, CONFIG_NAME_SZ);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_ipv4_state( laird_interface_handle interface,
                                  bool * state)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if (state == NULL)
		ret = DCAL_INVALID_PARAMETER;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (i->ipv4)
			*state = true;
		else
			*state = false;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_method( laird_interface_handle interface,
                                  char * method)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if (method == NULL)
		ret = DCAL_INVALID_PARAMETER;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->method, method, CONFIG_NAME_SZ);
		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_method( laird_interface_handle interface,
                                    char *method, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if ((method==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(method, i->method, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_auto_start( laird_interface_handle interface,
                                  bool auto_start)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (auto_start)
			i->auto_start = INTERFACE_ENABLE;
		else
			i->auto_start = INTERFACE_DISABLE;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_auto_start( laird_interface_handle interface,
                                  bool * auto_start)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if (auto_start == NULL)
		ret = DCAL_INVALID_PARAMETER;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (i->auto_start){
			*auto_start = true;
		} else {
			*auto_start = false;
		}
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_address( laird_interface_handle interface,
                                  char * address)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->address, address, CONFIG_NAME_SZ);
		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_address( laird_interface_handle interface,
                                    char *address, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if ((address==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(address, i->address, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_netmask( laird_interface_handle interface,
                                  char * netmask)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->netmask, netmask, CONFIG_NAME_SZ);
		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_netmask( laird_interface_handle interface,
                                    char *netmask, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if ((netmask==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(netmask, i->netmask, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_gateway( laird_interface_handle interface,
                                  char * gateway)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->gateway, gateway, CONFIG_NAME_SZ);
		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_gateway( laird_interface_handle interface,
                                    char *gateway, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if ((gateway==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(gateway, i->gateway, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_broadcast_address( laird_interface_handle interface,
                                  char * broadcast)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->broadcast, broadcast, CONFIG_NAME_SZ);
		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_broadcast_address( laird_interface_handle interface,
                                    char *broadcast, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if ((broadcast==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(broadcast, i->broadcast, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}


int dcal_wifi_interface_set_nameserver( laird_interface_handle interface,
                                  char * nameserver)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->nameserver, nameserver, CONFIG_NAME_SZ);
		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_nameserver( laird_interface_handle interface,
                                    char *nameserver, size_t buf_len)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if ((nameserver==NULL) || buf_len == 0)
		ret = DCAL_INVALID_PARAMETER;
	else if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(nameserver, i->nameserver, buf_len);
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_state( laird_interface_handle interface,
                                  bool state)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (state)
			i->state = INTERFACE_ENABLE;
		else
			i->state = INTERFACE_DISABLE;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_bridge( laird_interface_handle interface,
                                  bool bridge)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (bridge)
			i->bridge = INTERFACE_ENABLE;
		else
			i->bridge = INTERFACE_DISABLE;

		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_bridge( laird_interface_handle interface,
                                  bool * bridge)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if (bridge == NULL)
		ret = DCAL_INVALID_PARAMETER;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (i->bridge){
			*bridge = true;
		} else {
			*bridge = false;
		}
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_ap_mode( laird_interface_handle interface,
                                  bool ap_mode)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (ap_mode)
			i->ap_mode = INTERFACE_ENABLE;
		else
			i->ap_mode = INTERFACE_DISABLE;

		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_ap_mode( laird_interface_handle interface,
                                  bool * ap_mode)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if (ap_mode == NULL)
		ret = DCAL_INVALID_PARAMETER;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (i->ap_mode){
			*ap_mode = true;
		} else {
			*ap_mode = false;
		}
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_nat( laird_interface_handle interface,
                                  bool nat)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (nat)
			i->nat = INTERFACE_ENABLE;
		else
			i->nat = INTERFACE_DISABLE;

		i->ipv4 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_get_nat( laird_interface_handle interface,
                                  bool * nat)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if (nat == NULL)
		ret = DCAL_INVALID_PARAMETER;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (i->nat){
			*nat = true;
		} else {
			*nat = false;
		}
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_clear_property( laird_interface_handle interface,
                                  INTERFACE_PROPERTY prop)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		i->prop |= prop;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_method6( laird_interface_handle interface,
                                  char * method6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->method6, method6, CONFIG_NAME_SZ);
		i->ipv6 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_address6( laird_interface_handle interface,
                                  char * address6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->address6, address6, CONFIG_NAME_SZ);
		i->ipv6 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_netmask6( laird_interface_handle interface,
                                  char * netmask6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->netmask6, netmask6, CONFIG_NAME_SZ);
		i->ipv6 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_gateway6( laird_interface_handle interface,
                                  char * gateway6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->gateway6, gateway6, CONFIG_NAME_SZ);
		i->ipv6 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_nameserver6( laird_interface_handle interface,
                                  char * nameserver6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->nameserver6, nameserver6, CONFIG_NAME_SZ);
		i->ipv6 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_state6( laird_interface_handle interface,
                                  bool state6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (state6)
			i->state6 = INTERFACE_ENABLE;
		else
			i->state6 = INTERFACE_DISABLE;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_set_nat6( laird_interface_handle interface,
                                  bool nat6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		if (nat6)
			i->nat6 = INTERFACE_ENABLE;
		else
			i->nat6 = INTERFACE_DISABLE;

		i->ipv6 = 1;
	}

	return REPORT_RETURN_DBG(ret);
}

int dcal_wifi_interface_clear_property6( laird_interface_handle interface,
                                  INTERFACE_PROPERTY prop6)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		i->prop6 |= prop6;
	}

	return REPORT_RETURN_DBG(ret);
}