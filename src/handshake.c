#include "handshake.h"
#include "debug.h"
#include "dcal_api.h"
#include "dcal_internal_api.h"

int build_hello(flatcc_builder_t *B)
{
	if (flatcc_builder_reset(B))
		return DCAL_FLATBUFF_ERROR;

	ns(Handshake_start(B));
	ns(Handshake_magic_add(B, ns(Magic_HELLO)));
//	TODO - do we want to identify our IP on outbound handshake?
//	ns(Handshake_ip_create_str(B, "127.0.0.1"));
	ns(Handshake_api_level_add(B, DCAL_API_VERSION));
	ns(Handshake_ref_t) hs = ns(Handshake_end(B));

	ns(Any_union_ref_t) any;
	any.Handshake = hs;
	any.type = ns(Any_Handshake);

	ns(Payload_start_as_root(B));
	ns(Payload_message_add(B, any));
	ns(Payload_end_as_root(B));

	return 0;
}

// returns 0 for valid ack
int is_handshake_ack_valid(void *buf, size_t nbytes)
{
	ns(Payload_table_t) payload;
	ns(Handshake_table_t) handshake;
	ns(Any_union_type_t) any;
	int ret;

	if((ret = ns(Payload_verify_as_root(buf, nbytes)))){
		DBGERROR("could not verify buffer, got %s\n", flatcc_verify_error_string(ret));
		return 1;
	}

	if (!(payload = ns(Payload_as_root(buf)))) {
		DBGERROR("Not a Payload\n");
		return 1;
	}

	any = ns(Payload_message_type(payload));

	if (any == ns(Any_Handshake))
		handshake = ns(Payload_message(payload));
	else{
		DBGERROR("Payload message was not a Handshake\n");
		return 1;
	}
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

	if (s == NULL)
		return DCAL_INVALID_PARAMETER;

	B = &s->builder;
	flatcc_builder_init(B);

	rc = build_hello(B);
	if (!rc){
		char buffer[BUF_SZ];
		size_t size;

		flatcc_builder_copy_buffer(B, buffer, BUF_SZ);
		size = flatcc_builder_get_buffer_size(B);
		if ((size > BUF_SZ) || (size==0)) {
			rc = DCAL_FLATBUFF_ERROR;
			goto exit;
		}

		//send hello
		rc = dcal_send_buffer( s, buffer, size );
		if (rc) goto exit;

		//verify ack
		size = BUF_SZ;
		rc = dcal_read_buffer( s, buffer, &size );
		if (rc) goto exit;

		rc = is_handshake_ack_valid( buffer, size);
	}

exit:
	return rc;
}

