#ifndef __buffer_h__
#define __buffer_h__

#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)
#include "session.h"

#endif // __buffer_h__
