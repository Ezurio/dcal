#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "dcal_api.h"
#include "debug.h"
#include "buffer.h"


// a 0 return code means invalid buffer
flatbuffers_thash_t verify_buffer(const void * buf, const size_t size)
{
	flatbuffers_thash_t ret;
	if ((buf==NULL) || (size==0))
		return 0;

	ret = flatbuffers_get_type_hash(buf);
	switch(ret) {
		case ns(Handshake_type_hash):
			if(ns(Handshake_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Status_type_hash):
			if(ns(Status_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Command_type_hash):
			if(ns(Command_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(U32_type_hash):
			if(ns(U32_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Version_type_hash):
			if(ns(Version_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Globals_type_hash):
			if(ns(Globals_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Profile_type_hash):
			if(ns(Profile_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(P_entry_type_hash):
			if(ns(P_entry_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Profile_list_type_hash):
			if(ns(Profile_list_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Interface_type_hash):
			if(ns(Interface_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Lease_type_hash):
			if(ns(Lease_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Default_route_type_hash):
			if(ns(Default_route_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Time_type_hash):
			if(ns(Time_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Scan_item_type_hash):
			if(ns(Scan_item_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Scan_list_type_hash):
			if(ns(Scan_list_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		case ns(Filexfer_type_hash):
			if(ns(Filexfer_verify_as_root(buf,size))){
				DBGERROR("%s: unable to verify buffer\n", __func__);
				ret = 0;
				}
			break;
		default:
			DBGERROR("%s: buffer hash invalid: %lx\n", __func__, (unsigned long)ret);
			ret = 0;
	}
	return ret;
}

char * buftype_to_string(flatbuffers_thash_t buftype)
{
	switch(buftype) {
		case ns(Handshake_type_hash):
			return "Handshake";
			break;
		case ns(Status_type_hash):
			return "Status";
			break;
		case ns(Command_type_hash):
			return "Command";
			break;
		case ns(U32_type_hash):
			return "U32";
			break;
		case ns(Version_type_hash):
			return "Version";
			break;
		case ns(Globals_type_hash):
			return "Globals";
			break;
		case ns(Profile_type_hash):
			return "Profile";
			break;
		case ns(P_entry_type_hash):
			return "P_entry";
		case ns(Profile_list_type_hash):
			return "Profile_list";
			break;
		case ns(Time_type_hash):
			return "Time";
			break;
		case ns(Scan_item_type_hash):
			return "Scan_item";
			break;
		case ns(Scan_list_type_hash):
			return "Scan_list";
			break;
		case ns(Filexfer_type_hash):
			return "Filexfer";
			break;

		default:
			return("unrecognized\n");
	}
}

int handshake_error_code (ns(Handshake_table_t) handshake){
	return ns(Handshake_error(handshake));
}


