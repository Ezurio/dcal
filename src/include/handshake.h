#ifndef __handshake_h__
#define __handshake_h__

#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)
#include "session.h"

int handshake_init(internal_session_handle s);
int is_handshake_ack_valid( ns(Handshake_table_t) handshake);
int version_pull(internal_session_handle s);

#endif // __handshake_h__
