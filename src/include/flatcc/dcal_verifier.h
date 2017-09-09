#ifndef DCAL_VERIFIER_H
#define DCAL_VERIFIER_H

/* Generated by flatcc 0.3.3 FlatBuffers schema compiler for C by dvide.com */

#ifndef DCAL_READER_H
#include "dcal_reader.h"
#endif
#include "flatcc/flatcc_verifier.h"
#define PDIAGNOSTIC_IGNORE_UNUSED
#include "flatcc/portable/pdiagnostic_push.h"

static int __DCAL_session_Handshake_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Event_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_U32_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_String_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Status_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Version_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Globals_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Profile_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Interface_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Lease_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_P_entry_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Profile_list_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Scan_item_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Scan_list_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Time_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Filexfer_table_verifier(flatcc_table_verifier_descriptor_t *td);
static int __DCAL_session_Command_table_verifier(flatcc_table_verifier_descriptor_t *td);

static int __DCAL_session_Cmd_pl_union_verifier(flatcc_table_verifier_descriptor_t *td, flatbuffers_voffset_t id, uint8_t type)
{
    switch(type) {
    case 1: return flatcc_verify_table_field(td, id, 0, __DCAL_session_Globals_table_verifier);
    case 2: return flatcc_verify_table_field(td, id, 0, __DCAL_session_Profile_table_verifier);
    case 3: return flatcc_verify_table_field(td, id, 0, __DCAL_session_Interface_table_verifier);
    case 4: return flatcc_verify_table_field(td, id, 0, __DCAL_session_Lease_table_verifier);
    case 5: return flatcc_verify_table_field(td, id, 0, __DCAL_session_U32_table_verifier);
    case 6: return flatcc_verify_table_field(td, id, 0, __DCAL_session_String_table_verifier);
    case 7: return flatcc_verify_table_field(td, id, 0, __DCAL_session_Time_table_verifier);
    case 8: return flatcc_verify_table_field(td, id, 0, __DCAL_session_Filexfer_table_verifier);
    default: return flatcc_verify_ok;
    }
}

static int __DCAL_session_Handshake_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 1, 1) /* server */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* magic */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 2, 0) /* ip */)) return ret;
    if ((ret = flatcc_verify_field(td, 3, 4, 4) /* api_level */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 4, 4) /* error */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Handshake_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Handshake_identifier, &__DCAL_session_Handshake_table_verifier);
}

static inline int DCAL_session_Handshake_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Handshake_type_identifier, &__DCAL_session_Handshake_table_verifier);
}

static inline int DCAL_session_Handshake_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Handshake_table_verifier);
}

static inline int DCAL_session_Handshake_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Handshake_table_verifier);
}

static int __DCAL_session_Event_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* e_type */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* status */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 4, 4) /* reason */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 3, 0) /* eth_addr */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 2, 2) /* flags */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Event_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Event_identifier, &__DCAL_session_Event_table_verifier);
}

static inline int DCAL_session_Event_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Event_type_identifier, &__DCAL_session_Event_table_verifier);
}

static inline int DCAL_session_Event_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Event_table_verifier);
}

static inline int DCAL_session_Event_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Event_table_verifier);
}

static int __DCAL_session_U32_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* value */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_U32_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_U32_identifier, &__DCAL_session_U32_table_verifier);
}

static inline int DCAL_session_U32_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_U32_type_identifier, &__DCAL_session_U32_table_verifier);
}

static inline int DCAL_session_U32_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_U32_table_verifier);
}

static inline int DCAL_session_U32_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_U32_table_verifier);
}

static int __DCAL_session_String_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_string_field(td, 0, 0) /* value */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_String_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_String_identifier, &__DCAL_session_String_table_verifier);
}

static inline int DCAL_session_String_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_String_type_identifier, &__DCAL_session_String_table_verifier);
}

static inline int DCAL_session_String_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_String_table_verifier);
}

static inline int DCAL_session_String_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_String_table_verifier);
}

static int __DCAL_session_Status_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* cardState */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 1, 0) /* ProfileName */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 2, 0, 1, 1, 4294967295) /* ssid */)) return ret;
    if ((ret = flatcc_verify_field(td, 3, 4, 4) /* channel */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 4, 4) /* rssi */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 5, 0) /* clientName */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 6, 0, 1, 1, 4294967295) /* mac */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 7, 0, 1, 1, 4294967295) /* ip */)) return ret;
    if ((ret = flatcc_verify_string_vector_field(td, 8, 0) /* ipv6 */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 9, 0, 1, 1, 4294967295) /* AP_mac */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 10, 0, 1, 1, 4294967295) /* AP_ip */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 11, 0) /* AP_name */)) return ret;
    if ((ret = flatcc_verify_field(td, 12, 4, 4) /* bitRate */)) return ret;
    if ((ret = flatcc_verify_field(td, 13, 4, 4) /* txPower */)) return ret;
    if ((ret = flatcc_verify_field(td, 14, 4, 4) /* dtim */)) return ret;
    if ((ret = flatcc_verify_field(td, 15, 4, 4) /* beaconPeriod */)) return ret;
    if ((ret = flatcc_verify_field(td, 16, 4, 4) /* numipv6addrs */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Status_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Status_identifier, &__DCAL_session_Status_table_verifier);
}

static inline int DCAL_session_Status_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Status_type_identifier, &__DCAL_session_Status_table_verifier);
}

static inline int DCAL_session_Status_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Status_table_verifier);
}

static inline int DCAL_session_Status_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Status_table_verifier);
}

static int __DCAL_session_Version_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* sdk */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* chipset */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 4, 4) /* sys */)) return ret;
    if ((ret = flatcc_verify_field(td, 3, 4, 4) /* driver */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 4, 0) /* firmware */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 5, 0) /* supplicant */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 6, 0) /* release */)) return ret;
    if ((ret = flatcc_verify_field(td, 7, 4, 4) /* dcas */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Version_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Version_identifier, &__DCAL_session_Version_table_verifier);
}

static inline int DCAL_session_Version_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Version_type_identifier, &__DCAL_session_Version_table_verifier);
}

static inline int DCAL_session_Version_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Version_table_verifier);
}

static inline int DCAL_session_Version_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Version_table_verifier);
}

static int __DCAL_session_Globals_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* auth */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* channel_set_a */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 4, 4) /* channel_set_b */)) return ret;
    if ((ret = flatcc_verify_field(td, 3, 1, 1) /* auto_profile */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 4, 4) /* beacon_miss */)) return ret;
    if ((ret = flatcc_verify_field(td, 5, 1, 1) /* ccx */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 6, 0) /* cert_path */)) return ret;
    if ((ret = flatcc_verify_field(td, 7, 1, 1) /* date_check */)) return ret;
    if ((ret = flatcc_verify_field(td, 8, 4, 4) /* def_adhoc */)) return ret;
    if ((ret = flatcc_verify_field(td, 9, 1, 1) /* fips */)) return ret;
    if ((ret = flatcc_verify_field(td, 10, 4, 4) /* pmk */)) return ret;
    if ((ret = flatcc_verify_field(td, 11, 4, 4) /* probe_delay */)) return ret;
    if ((ret = flatcc_verify_field(td, 12, 4, 4) /* regdomain */)) return ret;
    if ((ret = flatcc_verify_field(td, 13, 4, 4) /* roam_periodms */)) return ret;
    if ((ret = flatcc_verify_field(td, 14, 4, 4) /* roam_trigger */)) return ret;
    if ((ret = flatcc_verify_field(td, 15, 4, 4) /* rts */)) return ret;
    if ((ret = flatcc_verify_field(td, 16, 4, 4) /* scan_dfs */)) return ret;
    if ((ret = flatcc_verify_field(td, 17, 4, 4) /* ttls */)) return ret;
    if ((ret = flatcc_verify_field(td, 18, 1, 1) /* uapsd */)) return ret;
    if ((ret = flatcc_verify_field(td, 19, 1, 1) /* wmm */)) return ret;
    if ((ret = flatcc_verify_field(td, 20, 1, 1) /* ignore_null_ssid */)) return ret;
    if ((ret = flatcc_verify_field(td, 21, 4, 4) /* dfs_channels */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Globals_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Globals_identifier, &__DCAL_session_Globals_table_verifier);
}

static inline int DCAL_session_Globals_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Globals_type_identifier, &__DCAL_session_Globals_table_verifier);
}

static inline int DCAL_session_Globals_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Globals_table_verifier);
}

static inline int DCAL_session_Globals_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Globals_table_verifier);
}

static int __DCAL_session_Profile_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_string_field(td, 0, 0) /* name */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 1, 0, 1, 1, 4294967295) /* ssid */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 2, 0) /* client_name */)) return ret;
    if ((ret = flatcc_verify_field(td, 3, 4, 4) /* txPwr */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 4, 4) /* pwrsave */)) return ret;
    if ((ret = flatcc_verify_field(td, 5, 4, 4) /* pspDelay */)) return ret;
    if ((ret = flatcc_verify_field(td, 6, 4, 4) /* weptype */)) return ret;
    if ((ret = flatcc_verify_field(td, 7, 4, 4) /* auth */)) return ret;
    if ((ret = flatcc_verify_field(td, 8, 4, 4) /* eap */)) return ret;
    if ((ret = flatcc_verify_field(td, 9, 4, 4) /* bitrate */)) return ret;
    if ((ret = flatcc_verify_field(td, 10, 4, 4) /* radiomode */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 11, 0) /* security1 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 12, 0) /* security2 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 13, 0) /* security3 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 14, 0) /* security4 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 15, 0) /* security5 */)) return ret;
    if ((ret = flatcc_verify_field(td, 16, 4, 4) /* weptxkey */)) return ret;
    if ((ret = flatcc_verify_field(td, 17, 1, 1) /* autoprofile */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Profile_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Profile_identifier, &__DCAL_session_Profile_table_verifier);
}

static inline int DCAL_session_Profile_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Profile_type_identifier, &__DCAL_session_Profile_table_verifier);
}

static inline int DCAL_session_Profile_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Profile_table_verifier);
}

static inline int DCAL_session_Profile_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Profile_table_verifier);
}

static int __DCAL_session_Interface_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_string_field(td, 0, 0) /* interface_name */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* prop */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 1, 1) /* ipv4 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 3, 0) /* method */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 4, 4) /* auto_start */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 5, 0) /* address */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 6, 0) /* netmask */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 7, 0) /* netmask6 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 8, 0) /* gateway */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 9, 0) /* broadcast */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 10, 0) /* nameserver */)) return ret;
    if ((ret = flatcc_verify_field(td, 11, 4, 4) /* state */)) return ret;
    if ((ret = flatcc_verify_field(td, 12, 4, 4) /* bridge */)) return ret;
    if ((ret = flatcc_verify_field(td, 13, 4, 4) /* ap_mode */)) return ret;
    if ((ret = flatcc_verify_field(td, 14, 4, 4) /* nat */)) return ret;
    if ((ret = flatcc_verify_field(td, 15, 4, 4) /* prop6 */)) return ret;
    if ((ret = flatcc_verify_field(td, 16, 1, 1) /* ipv6 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 17, 0) /* method6 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 18, 0) /* dhcp6 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 19, 0) /* address6 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 20, 0) /* gateway6 */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 21, 0) /* nameserver6 */)) return ret;
    if ((ret = flatcc_verify_field(td, 22, 4, 4) /* state6 */)) return ret;
    if ((ret = flatcc_verify_field(td, 23, 4, 4) /* nat6 */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Interface_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Interface_identifier, &__DCAL_session_Interface_table_verifier);
}

static inline int DCAL_session_Interface_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Interface_type_identifier, &__DCAL_session_Interface_table_verifier);
}

static inline int DCAL_session_Interface_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Interface_table_verifier);
}

static inline int DCAL_session_Interface_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Interface_table_verifier);
}

static int __DCAL_session_Lease_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_string_field(td, 0, 0) /* interface */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 1, 0) /* address */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 2, 0) /* subnet_mask */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 3, 0) /* routers */)) return ret;
    if ((ret = flatcc_verify_field(td, 4, 8, 8) /* lease_time */)) return ret;
    if ((ret = flatcc_verify_field(td, 5, 4, 4) /* message_type */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 6, 0) /* dns_servers */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 7, 0) /* dhcp_server */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 8, 0) /* domain_name */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 9, 0) /* renew */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 10, 0) /* rebind */)) return ret;
    if ((ret = flatcc_verify_string_field(td, 11, 0) /* expire */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Lease_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Lease_identifier, &__DCAL_session_Lease_table_verifier);
}

static inline int DCAL_session_Lease_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Lease_type_identifier, &__DCAL_session_Lease_table_verifier);
}

static inline int DCAL_session_Lease_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Lease_table_verifier);
}

static inline int DCAL_session_Lease_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Lease_table_verifier);
}

static int __DCAL_session_P_entry_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_string_field(td, 0, 0) /* name */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 1, 1) /* active */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 1, 1) /* autoprof */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_P_entry_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_P_entry_identifier, &__DCAL_session_P_entry_table_verifier);
}

static inline int DCAL_session_P_entry_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_P_entry_type_identifier, &__DCAL_session_P_entry_table_verifier);
}

static inline int DCAL_session_P_entry_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_P_entry_table_verifier);
}

static inline int DCAL_session_P_entry_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_P_entry_table_verifier);
}

static int __DCAL_session_Profile_list_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_table_vector_field(td, 0, 0, &__DCAL_session_P_entry_table_verifier) /* profiles */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Profile_list_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Profile_list_identifier, &__DCAL_session_Profile_list_table_verifier);
}

static inline int DCAL_session_Profile_list_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Profile_list_type_identifier, &__DCAL_session_Profile_list_table_verifier);
}

static inline int DCAL_session_Profile_list_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Profile_list_table_verifier);
}

static inline int DCAL_session_Profile_list_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Profile_list_table_verifier);
}

static int __DCAL_session_Scan_item_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 1, 1) /* channel */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* rssi */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 4, 4) /* securityMask */)) return ret;
    if ((ret = flatcc_verify_field(td, 3, 1, 1) /* bss */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 4, 0, 1, 1, 4294967295) /* mac */)) return ret;
    if ((ret = flatcc_verify_vector_field(td, 5, 0, 1, 1, 4294967295) /* ssid */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Scan_item_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Scan_item_identifier, &__DCAL_session_Scan_item_table_verifier);
}

static inline int DCAL_session_Scan_item_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Scan_item_type_identifier, &__DCAL_session_Scan_item_table_verifier);
}

static inline int DCAL_session_Scan_item_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Scan_item_table_verifier);
}

static inline int DCAL_session_Scan_item_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Scan_item_table_verifier);
}

static int __DCAL_session_Scan_list_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_table_vector_field(td, 0, 0, &__DCAL_session_Scan_item_table_verifier) /* items */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Scan_list_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Scan_list_identifier, &__DCAL_session_Scan_list_table_verifier);
}

static inline int DCAL_session_Scan_list_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Scan_list_type_identifier, &__DCAL_session_Scan_list_table_verifier);
}

static inline int DCAL_session_Scan_list_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Scan_list_table_verifier);
}

static inline int DCAL_session_Scan_list_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Scan_list_table_verifier);
}

static int __DCAL_session_Time_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* tv_sec */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* tv_usec */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Time_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Time_identifier, &__DCAL_session_Time_table_verifier);
}

static inline int DCAL_session_Time_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Time_type_identifier, &__DCAL_session_Time_table_verifier);
}

static inline int DCAL_session_Time_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Time_table_verifier);
}

static inline int DCAL_session_Time_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Time_table_verifier);
}

static int __DCAL_session_Filexfer_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_string_field(td, 0, 0) /* file_path */)) return ret;
    if ((ret = flatcc_verify_field(td, 1, 4, 4) /* size */)) return ret;
    if ((ret = flatcc_verify_field(td, 2, 4, 4) /* mode */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Filexfer_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Filexfer_identifier, &__DCAL_session_Filexfer_table_verifier);
}

static inline int DCAL_session_Filexfer_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Filexfer_type_identifier, &__DCAL_session_Filexfer_table_verifier);
}

static inline int DCAL_session_Filexfer_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Filexfer_table_verifier);
}

static inline int DCAL_session_Filexfer_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Filexfer_table_verifier);
}

static int __DCAL_session_Command_table_verifier(flatcc_table_verifier_descriptor_t *td)
{
    int ret;
    if ((ret = flatcc_verify_field(td, 0, 4, 4) /* command */)) return ret;
    if ((ret = flatcc_verify_union_field(td, 2, 0, &__DCAL_session_Cmd_pl_union_verifier) /* cmd_pl */)) return ret;
    return flatcc_verify_ok;
}

static inline int DCAL_session_Command_verify_as_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Command_identifier, &__DCAL_session_Command_table_verifier);
}

static inline int DCAL_session_Command_verify_as_typed_root(const void *buf, size_t bufsiz)
{
    return flatcc_verify_table_as_root(buf, bufsiz, DCAL_session_Command_type_identifier, &__DCAL_session_Command_table_verifier);
}

static inline int DCAL_session_Command_verify_as_root_with_identifier(const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_verify_table_as_root(buf, bufsiz, fid, &__DCAL_session_Command_table_verifier);
}

static inline int DCAL_session_Command_verify_as_root_with_type_hash(const void *buf, size_t bufsiz, flatbuffers_thash_t thash)
{ __flatbuffers_thash_write_to_pe(&thash, thash);
  return flatcc_verify_table_as_root(buf, bufsiz, thash ? (const char *)&thash : 0, &__DCAL_session_Command_table_verifier);
}

#include "flatcc/portable/pdiagnostic_pop.h"
#endif /* DCAL_VERIFIER_H */
