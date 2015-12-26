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

typedef enum _LRD_API_RETURN_CODES{
LRD_API_SUCCESS,
LRD_API_INVALID_HANDLE,
LRD_API_NO_NETWORK_ACCESS
} LRD_API_ERR;

// interesting stuff


#ifdef __cplusplus
}
#endif
#endif //_LRD_REMOTE_API
