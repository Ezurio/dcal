#ifndef __session_h__
#define __session_h__

typedef struct _internal_session_handle {
	uint32_t version;
	uint8_t state;
	uint8_t data[TBD];
} internal_session_struct;
typedef internal_session_struct * internal_session_handle;

// session states
#define SESSION_INVALID 0
#define SESSION_ALLOCATED 1
#define SESSION_ACTIVE 2

#endif //__session_h__
