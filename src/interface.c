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
		ns(Interface_ipv4_add(B, i->ipv4));
		ns(Interface_method_create_str(B, i->method));
		ns(Interface_auto_start_add(B, i->auto_start));
		ns(Interface_ipv6_add(B, i->ipv6));

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

int dcal_wifi_interface_set_method( laird_interface_handle interface,
                                  char * method)
{
	int ret = DCAL_SUCCESS;
	internal_interface_handle i = (internal_interface_handle)interface;
	REPORT_ENTRY_DEBUG;

	if(!validate_handle(interfaces, interface))
		ret = DCAL_INVALID_HANDLE;
	else {
		clear_and_strncpy(i->method, method, CONFIG_NAME_SZ);
		i->ipv4 = 1;
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