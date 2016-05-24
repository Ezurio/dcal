#ifndef __profile_h__
#define __profile_h__

#include <stdbool.h>
#include "dcal_api.h"
#include "flatcc/dcal_builder.h"
#include "flatcc/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)

#define DEFAULT_PSP_DELAY 200  // msec

typedef struct _internal_profile_handle {
	#ifdef STATIC_MEM
	bool valid;
	#endif
	char profilename[CONFIG_NAME_SZ];
	LRD_WF_SSID ssid;
	char clientname[CLIENT_NAME_SZ];
	int txpower;
	AUTH authtype;
	EAPTYPE eap;
	bool aes;
	bool psk;
	unsigned int txkey;
	POWERSAVE powersave;
	unsigned int pspdelay;
	WEPTYPE weptype;
	BITRATE bitrate;
	RADIOMODE radiomode;
	bool autoprofile;
	char security1[CRYPT_BUFFER_SIZE];
	char security2[CRYPT_BUFFER_SIZE];
	char security3[CRYPT_BUFFER_SIZE];
	char security4[CRYPT_BUFFER_SIZE];
	char security5[CRYPT_BUFFER_SIZE];
} internal_profile_struct, * internal_profile_handle;


#endif //__profile_h__
