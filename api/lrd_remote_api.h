/*
Copyright (c) 2016, Laird
Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

// This header file is for use in end users applications which utilize
// the Laird remote API to setup and get status from Laird workplace bridges

#ifndef _LRD_REMOTE_API_
#define _LRD_REMOTE_API_

#ifdef __cplusplus
extern "C" {
#endif

#include "sdc_sdk.h"

#define LRD_REMOTE_VERSION 0x01010101

typedef enum _LRD_ERR{
	LRD_SUCCESS = 0,
	LRD_INVALID_PARAMETER,
	LRD_INVALID_HANDLE,
	LRD_HANDLE_IN_USE,
	LRD_HANDLE_NOT_ACTIVE,
	LRD_NO_NETWORK_ACCESS,
	LRD_NO_MEMORY,
	LRD_NOT_IMPLEMENTED,
} LRD_ERR;

#define TBD 20*4 // arbitrary size.  Will be specific once the internal structure elements are fully defined.
typedef char * FQDN;

typedef void * laird_session_handle;
typedef void * laird_profile_handle;

typedef struct _laird_status_struct {
	uint32_t interesting_items[TBD];
} LRD_STATUS_STRUCT;

// API session management

LRD_ERR LRD_session_create( laird_session_handle * session);
LRD_ERR LRD_setip( laird_session_handle session, FQDN address );
LRD_ERR LRD_setkey( laird_session_handle session, char * keydata, int size);
LRD_ERR LRD_session_open ( laird_session_handle session );
LRD_ERR LRD_session_close( laird_session_handle session);

// Device Status

LRD_ERR LRD_DeviceStatus( laird_session_handle session, LRD_STATUS_STRUCT * status_struct);

// WiFi Management

// WiFi Profile Management
LRD_ERR LRD_PROFILE_Create(laird_profile_handle * handle);
LRD_ERR LRD_PROFILE_Pull(laird_session_handle session, laird_profile_handle handle, char *profileName);
LRD_ERR LRD_PROFILE_Push(laird_session_handle session, laird_profile_handle handle);
LRD_ERR LRD_PROFILE_Set_profileName(laird_profile_handle profile, char * name);
LRD_ERR LRD_PROFILE_Get_profileName(laird_profile_handle profile, char * name);
LRD_ERR LRD_PROFILE_Set_SSID(laird_profile_handle profile, LRD_WF_SSID *ssid);
LRD_ERR LRD_PROFILE_Get_SSID(laird_profile_handle profile, LRD_WF_SSID *ssid);
LRD_ERR LRD_PROFILE_Set_txPower(laird_profile_handle profile, int txPower);
LRD_ERR LRD_PROFILE_Get_txPower(laird_profile_handle profile, int txPower);
LRD_ERR LRD_PROFILE_Set_authType(laird_profile_handle profile, AUTH auth);
LRD_ERR LRD_PROFILE_Get_authType(laird_profile_handle profile, AUTH auth);
LRD_ERR LRD_PROFILE_Set_eapType(laird_profile_handle profile, EAPTYPE eap);
LRD_ERR LRD_PROFILE_Get_eapType(laird_profile_handle profile, EAPTYPE eap);
LRD_ERR LRD_PROFILE_Set_powerSave(laird_profile_handle profile, POWERSAVE powersave);
LRD_ERR LRD_PROFILE_Get_powerSave(laird_profile_handle profile, POWERSAVE powersave);
LRD_ERR LRD_PROFILE_Set_pspDelay(laird_profile_handle profile, int pspdelay);
LRD_ERR LRD_PROFILE_Get_pspDelay(laird_profile_handle profile, int pspdelay);
LRD_ERR LRD_PROFILE_Set_wepType(laird_profile_handle profile, WEPTYPE wepType);
LRD_ERR LRD_PROFILE_Get_wepType(laird_profile_handle profile, WEPTYPE wepType);
LRD_ERR LRD_PROFILE_Set_bitRate(laird_profile_handle profile, BITRATE bitrate);
LRD_ERR LRD_PROFILE_Get_bitRate(laird_profile_handle profile, BITRATE bitrate);
LRD_ERR LRD_PROFILE_Set_radioMode(laird_profile_handle profile, RADIOMODE radiomode);
LRD_ERR LRD_PROFILE_Get_radioMode(laird_profile_handle profile, RADIOMODE radiomode);
LRD_ERR LRD_PROFILE_Set_username(laird_profile_handle profile, char * username, char * len);
LRD_ERR LRD_PROFILE_Get_username(laird_profile_handle profile, char * username, char * len);
LRD_ERR LRD_PROFILE_Set_userPwd(laird_profile_handle profile, char * userpwd, char * len);
LRD_ERR LRD_PROFILE_Get_userPwd(laird_profile_handle profile, char * userpwd, char * len);
LRD_ERR LRD_PROFILE_Set_PSK(laird_profile_handle profile, char * userpwd, char * len);
LRD_ERR LRD_PROFILE_Get_PSK(laird_profile_handle profile, char * userpwd, char * len);

// interesting stuff

const char *LRD_ERR_to_string( LRD_ERR code);

#ifdef __cplusplus
}
#endif
#endif //_LRD_REMOTE_API
