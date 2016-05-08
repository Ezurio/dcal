#ifndef DCAL_BUILDER_H
#define DCAL_BUILDER_H

/* Generated by flatcc 0.3.3 FlatBuffers schema compiler for C by dvide.com */

#ifndef DCAL_READER_H
#include "dcal_reader.h"
#endif
#ifndef FLATBUFFERS_COMMON_BUILDER_H
#include "flatbuffers_common_builder.h"
#endif
#define PDIAGNOSTIC_IGNORE_UNUSED
#include "flatcc/portable/pdiagnostic_push.h"
#ifndef flatbuffers_identifier
#define flatbuffers_identifier 0
#endif
#ifndef flatbuffers_extension
#define flatbuffers_extension ".bin"
#endif

#define __DCAL_session_Magic_formal_args , DCAL_session_Magic_enum_t v0
#define __DCAL_session_Magic_call_args , v0
__flatbuffers_build_scalar(flatbuffers_, DCAL_session_Magic, DCAL_session_Magic_enum_t)
#define __DCAL_session_Commands_formal_args , DCAL_session_Commands_enum_t v0
#define __DCAL_session_Commands_call_args , v0
__flatbuffers_build_scalar(flatbuffers_, DCAL_session_Commands, DCAL_session_Commands_enum_t)

typedef struct DCAL_session_Any_union_ref DCAL_session_Any_union_ref_t;

static const flatbuffers_voffset_t __DCAL_session_Handshake_required[] = {0 };
__flatbuffers_build_table(flatbuffers_, DCAL_session_Handshake, 4)
static const flatbuffers_voffset_t __DCAL_session_Status_required[] = {0 };
__flatbuffers_build_table(flatbuffers_, DCAL_session_Status, 17)
static const flatbuffers_voffset_t __DCAL_session_Command_required[] = {0 };
__flatbuffers_build_table(flatbuffers_, DCAL_session_Command, 1)
static const flatbuffers_voffset_t __DCAL_session_Payload_required[] = {0 };
__flatbuffers_build_table(flatbuffers_, DCAL_session_Payload, 2)
#define __DCAL_session_Handshake_formal_args , flatbuffers_bool_t v0, DCAL_session_Magic_enum_t v1, flatbuffers_string_ref_t v2, uint32_t v3
#define __DCAL_session_Handshake_call_args , v0, v1, v2, v3
static inline DCAL_session_Handshake_ref_t DCAL_session_Handshake_create(flatbuffers_builder_t *B __DCAL_session_Handshake_formal_args);
#define __DCAL_session_Status_formal_args ,\
  uint32_t v0, flatbuffers_string_ref_t v1, flatbuffers_uint8_vec_ref_t v2, uint32_t v3,\
  uint32_t v4, int32_t v5, flatbuffers_string_ref_t v6, flatbuffers_uint8_vec_ref_t v7,\
  flatbuffers_uint8_vec_ref_t v8, flatbuffers_string_vec_ref_t v9, flatbuffers_uint8_vec_ref_t v10, flatbuffers_uint8_vec_ref_t v11,\
  flatbuffers_string_ref_t v12, uint32_t v13, uint32_t v14, uint32_t v15, uint32_t v16
#define __DCAL_session_Status_call_args ,\
  v0, v1, v2, v3,\
  v4, v5, v6, v7,\
  v8, v9, v10, v11,\
  v12, v13, v14, v15, v16
static inline DCAL_session_Status_ref_t DCAL_session_Status_create(flatbuffers_builder_t *B __DCAL_session_Status_formal_args);
#define __DCAL_session_Command_formal_args , DCAL_session_Commands_enum_t v0
#define __DCAL_session_Command_call_args , v0
static inline DCAL_session_Command_ref_t DCAL_session_Command_create(flatbuffers_builder_t *B __DCAL_session_Command_formal_args);
#define __DCAL_session_Payload_formal_args , DCAL_session_Any_union_ref_t v1
#define __DCAL_session_Payload_call_args , v1
static inline DCAL_session_Payload_ref_t DCAL_session_Payload_create(flatbuffers_builder_t *B __DCAL_session_Payload_formal_args);

struct DCAL_session_Any_union_ref {
    DCAL_session_Any_union_type_t type;
    union {
        flatbuffers_ref_t _member;
        flatbuffers_ref_t NONE;
        DCAL_session_Handshake_ref_t Handshake;
        DCAL_session_Command_ref_t Command;
        DCAL_session_Status_ref_t Status;
    };
};

static inline DCAL_session_Any_union_ref_t DCAL_session_Any_as_NONE()
{ DCAL_session_Any_union_ref_t uref; uref.type = DCAL_session_Any_NONE; uref._member = 0; return uref; }
static inline DCAL_session_Any_union_ref_t DCAL_session_Any_as_Handshake(DCAL_session_Handshake_ref_t ref)
{ DCAL_session_Any_union_ref_t uref; uref.type = DCAL_session_Any_Handshake; uref.Handshake = ref; return uref; }
static inline DCAL_session_Any_union_ref_t DCAL_session_Any_as_Command(DCAL_session_Command_ref_t ref)
{ DCAL_session_Any_union_ref_t uref; uref.type = DCAL_session_Any_Command; uref.Command = ref; return uref; }
static inline DCAL_session_Any_union_ref_t DCAL_session_Any_as_Status(DCAL_session_Status_ref_t ref)
{ DCAL_session_Any_union_ref_t uref; uref.type = DCAL_session_Any_Status; uref.Status = ref; return uref; }

__flatbuffers_build_scalar_field(0, flatbuffers_, DCAL_session_Handshake_server, flatbuffers_bool, flatbuffers_bool_t, 1, 1, 0)
__flatbuffers_build_scalar_field(1, flatbuffers_, DCAL_session_Handshake_magic, DCAL_session_Magic, DCAL_session_Magic_enum_t, 4, 4, 0)
__flatbuffers_build_string_field(2, flatbuffers_, DCAL_session_Handshake_ip)
__flatbuffers_build_scalar_field(3, flatbuffers_, DCAL_session_Handshake_api_level, flatbuffers_uint32, uint32_t, 4, 4, 0)

static inline DCAL_session_Handshake_ref_t DCAL_session_Handshake_create(flatbuffers_builder_t *B __DCAL_session_Handshake_formal_args)
{
    if (DCAL_session_Handshake_start(B)
        || DCAL_session_Handshake_magic_add(B, v1)
        || DCAL_session_Handshake_ip_add(B, v2)
        || DCAL_session_Handshake_api_level_add(B, v3)
        || DCAL_session_Handshake_server_add(B, v0)) {
        return 0;
    }
    return DCAL_session_Handshake_end(B);
}
__flatbuffers_build_table_prolog(flatbuffers_, DCAL_session_Handshake, DCAL_session_Handshake_identifier, DCAL_session_Handshake_type_identifier)

__flatbuffers_build_scalar_field(0, flatbuffers_, DCAL_session_Status_cardState, flatbuffers_uint32, uint32_t, 4, 4, 0)
__flatbuffers_build_string_field(1, flatbuffers_, DCAL_session_Status_ProfileName)
__flatbuffers_build_vector_field(2, flatbuffers_, DCAL_session_Status_ssid, flatbuffers_uint8, uint8_t)
__flatbuffers_build_scalar_field(3, flatbuffers_, DCAL_session_Status_ssid_len, flatbuffers_uint32, uint32_t, 4, 4, 0)
__flatbuffers_build_scalar_field(4, flatbuffers_, DCAL_session_Status_channel, flatbuffers_uint32, uint32_t, 4, 4, 0)
__flatbuffers_build_scalar_field(5, flatbuffers_, DCAL_session_Status_rssi, flatbuffers_int32, int32_t, 4, 4, 0)
__flatbuffers_build_string_field(6, flatbuffers_, DCAL_session_Status_clientName)
__flatbuffers_build_vector_field(7, flatbuffers_, DCAL_session_Status_mac, flatbuffers_uint8, uint8_t)
__flatbuffers_build_vector_field(8, flatbuffers_, DCAL_session_Status_ip, flatbuffers_uint8, uint8_t)
__flatbuffers_build_string_vector_field(9, flatbuffers_, DCAL_session_Status_ipv6)
__flatbuffers_build_vector_field(10, flatbuffers_, DCAL_session_Status_AP_mac, flatbuffers_uint8, uint8_t)
__flatbuffers_build_vector_field(11, flatbuffers_, DCAL_session_Status_AP_ip, flatbuffers_uint8, uint8_t)
__flatbuffers_build_string_field(12, flatbuffers_, DCAL_session_Status_AP_name)
__flatbuffers_build_scalar_field(13, flatbuffers_, DCAL_session_Status_bitRate, flatbuffers_uint32, uint32_t, 4, 4, 0)
__flatbuffers_build_scalar_field(14, flatbuffers_, DCAL_session_Status_txPower, flatbuffers_uint32, uint32_t, 4, 4, 0)
__flatbuffers_build_scalar_field(15, flatbuffers_, DCAL_session_Status_dtim, flatbuffers_uint32, uint32_t, 4, 4, 0)
__flatbuffers_build_scalar_field(16, flatbuffers_, DCAL_session_Status_beaconPeriod, flatbuffers_uint32, uint32_t, 4, 4, 0)

static inline DCAL_session_Status_ref_t DCAL_session_Status_create(flatbuffers_builder_t *B __DCAL_session_Status_formal_args)
{
    if (DCAL_session_Status_start(B)
        || DCAL_session_Status_cardState_add(B, v0)
        || DCAL_session_Status_ProfileName_add(B, v1)
        || DCAL_session_Status_ssid_add(B, v2)
        || DCAL_session_Status_ssid_len_add(B, v3)
        || DCAL_session_Status_channel_add(B, v4)
        || DCAL_session_Status_rssi_add(B, v5)
        || DCAL_session_Status_clientName_add(B, v6)
        || DCAL_session_Status_mac_add(B, v7)
        || DCAL_session_Status_ip_add(B, v8)
        || DCAL_session_Status_ipv6_add(B, v9)
        || DCAL_session_Status_AP_mac_add(B, v10)
        || DCAL_session_Status_AP_ip_add(B, v11)
        || DCAL_session_Status_AP_name_add(B, v12)
        || DCAL_session_Status_bitRate_add(B, v13)
        || DCAL_session_Status_txPower_add(B, v14)
        || DCAL_session_Status_dtim_add(B, v15)
        || DCAL_session_Status_beaconPeriod_add(B, v16)) {
        return 0;
    }
    return DCAL_session_Status_end(B);
}
__flatbuffers_build_table_prolog(flatbuffers_, DCAL_session_Status, DCAL_session_Status_identifier, DCAL_session_Status_type_identifier)

__flatbuffers_build_scalar_field(0, flatbuffers_, DCAL_session_Command_command, DCAL_session_Commands, DCAL_session_Commands_enum_t, 4, 4, 0)

static inline DCAL_session_Command_ref_t DCAL_session_Command_create(flatbuffers_builder_t *B __DCAL_session_Command_formal_args)
{
    if (DCAL_session_Command_start(B)
        || DCAL_session_Command_command_add(B, v0)) {
        return 0;
    }
    return DCAL_session_Command_end(B);
}
__flatbuffers_build_table_prolog(flatbuffers_, DCAL_session_Command, DCAL_session_Command_identifier, DCAL_session_Command_type_identifier)

__flatbuffers_build_union_field(1, flatbuffers_, DCAL_session_Payload_message, DCAL_session_Any)
__flatbuffers_build_union_member_field(flatbuffers_, DCAL_session_Payload_message, DCAL_session_Any, Handshake, DCAL_session_Handshake)
__flatbuffers_build_union_member_field(flatbuffers_, DCAL_session_Payload_message, DCAL_session_Any, Command, DCAL_session_Command)
__flatbuffers_build_union_member_field(flatbuffers_, DCAL_session_Payload_message, DCAL_session_Any, Status, DCAL_session_Status)

static inline DCAL_session_Payload_ref_t DCAL_session_Payload_create(flatbuffers_builder_t *B __DCAL_session_Payload_formal_args)
{
    if (DCAL_session_Payload_start(B)
        || DCAL_session_Payload_message_add_member(B, v1)
        || DCAL_session_Payload_message_add_type(B, v1.type)) {
        return 0;
    }
    return DCAL_session_Payload_end(B);
}
__flatbuffers_build_table_prolog(flatbuffers_, DCAL_session_Payload, DCAL_session_Payload_identifier, DCAL_session_Payload_type_identifier)

#include "flatcc/portable/pdiagnostic_pop.h"
#endif /* DCAL_BUILDER_H */
