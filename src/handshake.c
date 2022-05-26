#include "handshake.h"
#include "buffer.h"
#include "debug.h"
#include "dcal_api.h"
#include "dcal_internal_api.h"

int build_hello(flatcc_builder_t *B)
{
	if (flatcc_builder_reset(B))
		return DCAL_FLATBUFF_ERROR;

	flatbuffers_buffer_start(B, ns(Handshake_type_identifier));
	ns(Handshake_start(B));
	ns(Handshake_magic_add(B, ns(Magic_HELLO)));
//	TODO - do we want to identify our IP on outbound handshake?
//	ns(Handshake_ip_create_str(B, "127.0.0.1"));
	ns(Handshake_api_level_add(B, DCAL_VERSION));
	ns(Handshake_end_as_root(B));

	return 0;
}

// returns 0 for valid ack
int is_handshake_ack_valid( ns(Handshake_table_t) handshake)
{
	switch(ns(Handshake_magic(handshake))){
		case ns(Magic_ACK):
			DBGINFO("ACK received\n");
			return 0;
		case ns(Magic_NACK):
			DBGINFO("NACK received\n");
			break;
		case ns(Magic_HELLO):
			DBGINFO("Hello received\n");
			break;
		default:
			DBGINFO("no handshake magic\n");
		}

	return 1;
}

int handshake_init(internal_session_handle s)
{
	int rc = DCAL_SUCCESS;
	flatcc_builder_t *B;
	flatbuffers_thash_t buftype;

	if (s == NULL)
		return DCAL_INVALID_PARAMETER;

	B = &s->builder;
	flatcc_builder_init(B);

	rc = build_hello(B);
	if (!rc){
		char buffer[BUF_SZ];
		size_t size;

		size = flatcc_builder_get_buffer_size(B);
		if ((size > BUF_SZ) || (size==0)) {
			rc = DCAL_FLATBUFF_ERROR;
			goto exit;
		}
		flatcc_builder_copy_buffer(B, buffer, BUF_SZ);

		//send hello
		rc = lock_session_channel(s);
		if(rc) goto exit;
		rc = dcal_send_buffer( s, buffer, size );
		if(rc) {
			unlock_session_channel(s);
			goto exit;
		}

		//verify ack
		size = BUF_SZ;
		rc = dcal_read_buffer( s, buffer, &size );
		unlock_session_channel(s);
		if (rc) goto exit;

		buftype = verify_buffer(buffer, size);
		if (buftype != ns(Handshake_type_hash))
			rc = DCAL_FLATBUFF_ERROR;
		else
			rc = is_handshake_ack_valid(ns(Handshake_as_root(buffer)));

		if(!rc)
		{
			s->builder_init = true;
			rc = version_pull(s);
		}
	}

exit:
	return rc;
}

