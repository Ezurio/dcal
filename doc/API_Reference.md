# Device Control API Library *(DCAL)* Reference #

This document describes the usage and APIs of DCAL for interaction with a Wireless Bridge (WB) from an external host.
***
## About this document
This document used markdown and can be viewed in text but formatting is best viewed with a markdown viewer, such as a web browser.

### version history
| Date        | Version | Note |
|:------------|:--------|:-----|
|Oct. 8, 2017 | 3.1.5   |      |
|Oct. 20, 2017 | 3.1.6  | added dcal_set_key and dcal_get_auth_methods; |
|             |         | documentation edits                           |
|Mar. 16, 2018 | 3.1.7  | added functions to get and set enhanced UAPSD;|
|             |         | In src/include/globals.h, bool uapsd;         |
|             |         | is now unsigned int uapsd;                    |
***
## Introduction ##

DCAL will allow a host to communicate with a WB, in order to configure the WB as well as gather status and logging information from the WB.
While the details of the communication are abstracted from the API, the underlying communication utilizes SSH over TCP to provide a secure communication channel.

The DCAL repository contains a number of examples of usage for the various APIs.

## Expected resources host-side ##
C11 compatible compiler/library

## Building ##

The instructions for building DCAL and the Wireless Test Framework (WTF) are contained within the README.md file in the root directory of the DCAL repository.

## Memory Management

The API can be configured for either static or dynamic memory usage.  The recommended and default is dynamic memory and this will allow the most flexibility in the system.  For example, the API will allow the concurrent use of multiple handles of each type if using dynamic memory.

*If configured for static memory usage, a handle of each type can be used.  If a new handle is attempted to be created/loaded without first closing the existing handle, the previous handle's data would be overwritten, therefore an error will be returned.*
***
## API ##

The below sections hold the API function calls and respective data components.

### API Session management ###

DCAL will allow configuration of a single device, or if configured for dynamic memory management - its default configuration - multiple devices.  A single device would be the typical usage when running on a connected host, while multiple device usage would be for setting up multiple devices from one controlling system.

*Note that even when the use case is for a single device, dynamic memory management will allow for the most flexibility and is recommended for all cases where memory usage is not constrained.*

**Error codes -**
All of the APIs that return a value use int which will be a value from the enums in the .h file.  0 == success; values 1-99 are errors from the attached WB, and values >= 100 are errors from DCAL.
For assistance in development/debugging, the API provides a conversion to string for use in printing errors:
````
const char *dcal_err_to_string(int code);
````

**Sessions -**
Each active communication path is called a session.

In order to establish communication with a wb, a session needs to be created, configured, and then opened. Once communication is no longer desired, the session is closed.

````
int dcal_session_create( session_handle * session);
int dcal_set_host( session_handle session, FQDN address );
int dcal_set_port( session_handle session, unsigned int port );
int dcal_set_user( session_handle session, char * user );
int dcal_set_pw( session_handle session, char * pw );
int dcal_set_keyfile( session_handle session, char * filename);
int dcal_get_auth_methods ( session_handle s, int * method );
int dcal_session_open ( session_handle session );
int dcal_session_close( session_handle session);
````
#### int dcal_session_create( session_handle \* session);
The dcal\_session\_create call will allocate the session handle. If the API is configured for static memory, there is only a single handle available.    By default the API is configured for dynamic memory use and so multiple calls to create_session will result in multiple handles, each independent from the next.
#### int dcal_set_host( session_handle session, FQDN address );
dcal_set_host allows the ip address to be specified for the session.  Currently IP address is "a.b.c.d" format only.

#### int dcal_set_port( session_handle session, unsigned int port );
dcal_set_port allows the selection of the tcp port at the host

<span style="color:red">
Note about authentication:

dcal will first attempt to authenticate with the keys in the user's .ssh
directory. If the user has provided a key via the following dcal_set_keyfile function, that key will be tried if still not-authenticated.  If a username and password are supplied, password authentication will then be attempted if authentication has not yet been achieved.
</span>

#### int dcal_set_user( session_handle session, char * user );
dcal_set_user allows the setting of the user for authentication
#### int dcal_set_pw( session_handle session, char * pw );
dcal_set_pw allows the setting of the password for authentication
#### int dcal_set_keyfile( session_handle session, char * filename);
dcal_set_keyfile allows the user to specify a specific key file for authentication. Specify the private key file name.  The public key should be named the same with the '.pub' extention.
#### int dcal_get_auth_methods ( session_handle s, int * method );
dcal_get_auth_methods will return the types of methods via bitwise values.
DCAS supports METHOD_PUBKEY and METHOD_PASSWORD.
_both host and port should be set before calling_
#### int dcal_session_open ( session_handle session );
dcal_session_open will attempt to authenticate with the specified WB.  Once a session is open, it will remain open and available until either closed by the dcal_session_close() API, a power-mode (shutdown, suspend) API, or a loss of network communication.
#### int dcal_session_close( session_handle session);
dcal_session_close will close the connection and invalidate the handle.  The handle can no longer be used.
***

### Version ###
````
int dcal_get_sdk_version(session_handle session, unsigned int *sdk);
int dcal_get_chipset_version(session_handle session,
                              RADIOCHIPSET *chipset);
int dcal_get_system_version(session_handle session,
                              LRD_SYSTEM *sys);
int dcal_get_driver_version(session_handle session,
                              unsigned int *driver);
int dcal_get_dcas_version(session_handle session,
                              unsigned int *dcas);
int dcal_get_dcal_version(session_handle session,
                              unsigned int *dcal);
int dcal_get_firmware_version(session_handle session,
                              char *firmware, size_t buflen);
int dcal_get_supplicant_version(session_handle session,
                              char *supplicant, size_t buflen);
int dcal_get_release_version(session_handle session,
                              char *release, size_t buflen);
````

All version info is gathered from the WB session as part of the dcal_session_open() call. If these APIs are called without a valid session handle (ie a session not yet opened, or after a close) the error DCAL_INVALID_HANDLE will be returned.  If an invalid pointer is used, the error DCAL_INVALID_PARAMETER will be returned.  It is recommended that buffers be of STR_SZ or greater in order to receive entire data.

***
### Device Status ###

Status retrieval is a two step process:  First, the API dcal_device_status_pull() is called which will pull all status data from the WB.  Second, the desired API is called to collected the desired data.  A CACHE_TIME value from src/include/session.h is utilized to set the timeout for status validity, after which, the reporting APIs will return DCAL_DATA_STALE. dcal_device_status_pull() can be called multiple times as necessary.

````
int dcal_device_status_pull( session_handle session);

int dcal_device_status_get_settings( session_handle session,
                                     char * profilename,
                                     size_t profilename_buflen,
                                     LRD_WF_SSID *ssid,
                                     unsigned char *mac,
                                     size_t mac_buflen);

int dcal_device_status_get_ccx( session_handle session,
                                       unsigned char *ap_ip,
                                       size_t ap_ip_buflen,
                                       char *ap_name,
                                       size_t ap_name_buflen,
                                       char * clientname,
                                       size_t clientname_buflen);

int dcal_device_status_get_ipv4( session_handle session,
                                       unsigned char *ipv4,
                                       size_t buflen);

int dcal_device_status_get_ipv6_count( session_handle session,
                                       size_t *count);

int dcal_device_status_get_ipv6_string_at_index( session_handle session,
                                       unsigned int index,
                                       char *ipv6,
                                       size_t buflen);
int dcal_device_status_get_connection( session_handle session,
                                       unsigned int * cardstate,
                                       unsigned int * channel,
                                       int * rssi,
                                       unsigned char *ap_mac,
                                       size_t ap_mac_buflen);

int dcal_device_status_get_connection_extended( session_handle session,
                                       unsigned int *bitrate,
                                       unsigned int *txpower,
                                       unsigned int *dtim,
                                       unsigned int *beaconperiod);
int dcal_device_status_get_cache_timeout( unsigned int *timeout);
````
#### int dcal_device_status_pull( session_handle session);
Retrieve the status values from the WB.  The values will go stale after CACHE_TIMEOUT seconds (see value in /src/include/session.h)

#### int dcal_device_status_get_settings( *< see parameter list above >* )
Get the current Wifi profile settings.

#### int dcal_device_status_get_ccx( *< see parameter list above >* )
Get the CCX values (only valid data when connected to a Cisco AP with CCX enabled)

#### int dcal_device_status_get_ipv4( *< see parameter list above >* )
Get the IPv4 address.

#### int dcal_device_status_get_ipv6_count( *< see parameter list above >* )
Get the count of IPv6 addresses

#### int dcal_device_status_get_ipv6_string_at_index( *< see parameter list above >* )
Get the nth IPv6 address

#### int dcal_device_status_get_connection( *< see parameter list above >* )
Get status for current connection.

#### int dcal_device_status_get_connection_extended( *< see parameter list above >* )
Get extended attributed for the current connection.

#### int dcal_device_status_get_cache_timeout( *< see parameter list above >* )
Get the cache timeout value.
***
### WiFi Management ###
WiFi management has two types of settings: Global and per profile.
Global settings are as expected, global and apply to all profiles and per profile which are specific to the profile specified.

### WiFi Control
````
int dcal_wifi_enable( session_handle session);
int dcal_wifi_disable( session_handle session);
````
#### int dcal_wifi_enable( session_handle session);
Enable the radio. The radio will attempt to connect to the currently selected profile (or profiles if auto-security is active)
#### int dcal_wifi_disable( session_handle session);
Disable the radio.


### WiFi Global Settings Management
In order to set or review any global setting, a global handle needs to be created or obtained with the dcal_wifi_global_create or dcal_wifi_global_pull APIs. The global settings can be sent to the WB with the dcal_wifi_global_push API. As with all handle types, dcal_wifi_global_close_handle should be called when access to the global settings is no longer needed.

````
int dcal_wifi_global_create( global_handle * global);
int dcal_wifi_global_pull( session_handle session,
                                 global_handle * global);
int dcal_wifi_global_close_handle( global_handle global);

int dcal_wifi_global_push( session_handle session,
                                 global_handle global);
````
#### int dcal_wifi_global_create( global_handle * global);
Create a global handle with no settings established.  It is recommended that this only be used when all global settings will be configured by the caller. Otherwise, the dcal_wifi_global_pull should be used to create the handle, only the settings desired to be changed should be modified, and then the globals pushed back to the wb.
#### int dcal_wifi_global_pull( session_handle session, global_handle * global);
Create a global handle with the current values of the session's WB's globals.
#### int dcal_wifi_global_close_handle( global_handle global);
Close the global handle
#### int dcal_wifi_global_push( session_handle session, global_handle global);
Push the current global settings to the WB associated with the session handle.

#### Auth Server
````
int dcal_wifi_global_set_auth_server( global_handle global,
                                      SERVER_AUTH auth);
int dcal_wifi_global_get_auth_server( global_handle global,
                                      SERVER_AUTH *auth);
````

Auth server type can be with `TYPE1==ACS` or `TYPE2==SBR`.

`TYPE1` - server that uses PEAPv1 for PEAP with EAP-MSCHAPV2 (PEAP-MSCHAP).  
`TYPE2` - uses PEAPv0 for PEAP-MSCHAP.

#### int dcal_wifi_global_set_auth_server( global_handle global, SERVER_AUTH auth);
Set auth server type.
#### int dcal_wifi_global_get_auth_server( global_handle global, SERVER_AUTH *auth);
Get auth server type.

#### Channel management
````
int dcal_wifi_global_set_achannel_mask( global_handle global,
                                        unsigned int channel_set_a);
int dcal_wifi_global_get_achannel_mask( global_handle global,
                                        unsigned int *channel_set_a);

int dcal_wifi_global_set_bchannel_mask( global_handle global,
                                        unsigned int channel_set_b);
int dcal_wifi_global_get_bchannel_mask( global_handle global,
                                        unsigned int *channel_set_b);

````

Channel management allows the caller to specify a set of channels that are allowed on the radio.  Channel sets can restrict the number of channels the radio can scan and connect.  Channel sets can not force channels outside of the current regulatory domain.  Sets are created by or'ing bit mask entries.
#### B Channel Masks
| Channel | Frequency (GHz) | Bitmask |
|:-------:|:---------------:|:-------:|
| 1       | 2412            | b_1     |
| 2       | 2417            | b_2     |
| 3       | 2422            | b_3     |
| 4       | 2427            | b_4     |
| 5       | 2432            | b_5     |
| 6       | 2437            | b_6     |
| 7       | 2442            | b_7     |
| 8       | 2447            | b_8     |
| 9       | 2452            | b_9     |
| 10      | 2457            | b_10    |
| 11      | 2462            | b_11    |
| 12      | 2467            | b_12    |
| 13      | 2472            | b_13    |
| 14      | 2484            | b_14    |
| full    | -NA-            | b_full  |
#### A Channel Masks
| Channel | Frequency (GHz) | Bitmask |
|:-------:|:---------------:|:-------:|
| 36      | 5180            | a_36    |
| 40      | 5200            | a_40    |
| 44      | 5220            | a_44    |
| 48      | 5240            | a_48    |
| 52      | 5260            | a_52    |
| 56      | 5280            | a_56    |
| 60      | 5300            | a_60    |
| 64      | 5320            | a_64    |
| 100     | 5500            | a_100   |
| 104     | 5520            | a_104   |
| 108     | 5540            | a_108   |
| 112     | 5560            | a_112   |
| 116     | 5580            | a_116   |
| 120     | 5600            | a_120   |
| 124     | 5620            | a_124   |
| 128     | 5640            | a_128   |
| 132     | 5660            | a_132   |
| 136     | 5680            | a_136   |
| 140     | 5700            | a_140   |
| 149     | 5745            | a_149   |
| 153     | 5765            | a_153   |
| 157     | 5785            | a_157   |
| 161     | 5805            | a_161   |
| 165     | 5825            | a_165   |
| full    | -NA-            | a_full  |

#### int dcal_wifi_global_set_achannel_mask( global_handle global, unsigned int channel_set_a);
Set the a channel bit mask channel set.
#### int dcal_wifi_global_get_achannel_mask( global_handle global, unsigned int *channel_set_a);
Get the a channel bit mask channel set.
#### int dcal_wifi_global_set_bchannel_mask( global_handle global, unsigned int channel_set_b);
Set the b channel bit mask channel set.
#### int dcal_wifi_global_get_bchannel_mask( global_handle global, unsigned int *channel_set_b);
Get the b channel bit mask channel set.

#### Auto-profile
Auto-profile allows the radio to attempt to connect to all profiles with auto-profile enabled.  The connection attempts are round-robin.  Profiles must have auto-profile enabled in the profile to be included in the list of attempted profiles.
````
int dcal_wifi_global_set_auto_profile( global_handle global,
                                       bool auto_profile);
int dcal_wifi_global_get_auto_profile( global_handle global,
                                       bool *auto_profile);
````
#### int dcal_wifi_global_set_auto_profile( global_handle global, bool auto_profile);
Set the global auto-profile control.
#### int dcal_wifi_global_get_auto_profile( global_handle global, bool *auto_profile);
Retrieve the current auto-profile control value.

#### Beacon Miss
Beacon Miss values can be 1000-5000 TUs
````
int dcal_wifi_global_set_beacon_miss( global_handle global,
                                      unsigned int beacon_miss);
int dcal_wifi_global_get_beacon_miss( global_handle global,
                                      unsigned int *beacon_miss);
````
#### int dcal_wifi_global_set_beacon_miss( global_handle global, unsigned int beacon_miss);
Set the global beacon miss count.
#### int dcal_wifi_global_get_beacon_miss( global_handle global, unsigned int *beacon_miss);
Retrieve the global beacon miss count.

#### CCX
CCX will enable capabilities that are unique to a Cisco CCX environment.

````
int dcal_wifi_global_set_ccx( global_handle global, bool ccx);
int dcal_wifi_global_get_ccx( global_handle global, bool *ccx);
````
#### int dcal_wifi_global_set_ccx( global_handle global, bool ccx);
Set the ccx value.
#### int dcal_wifi_global_get_ccx( global_handle global, bool *ccx);
Get the ccx value.


#### Cert Path
The cert_path is the directory on the WB where certificates are stored.
````
int dcal_wifi_global_set_cert_path( global_handle global,
                                    char *cert_path);
int dcal_wifi_global_get_cert_path( global_handle global,
                                    char *cert_path, size_t buf_len);
````
#### int dcal_wifi_global_set_cert_path( global_handle global, char *cert_path);
Set the cert_path to the string specified.
#### int dcal_wifi_global_get_cert_path( global_handle global, char *cert_path, size_t buf_len);
Get the current cert_path directory.

#### Date Check
Date check specifies if the supplicant should date check certificates.
````
int dcal_wifi_global_set_date_check( global_handle global,
                                     bool date_check);
int dcal_wifi_global_get_date_check( global_handle global,
                                     bool *date_check);
````
#### int dcal_wifi_global_set_date_check( global_handle global, bool date_check);
Set the  date check boolean
#### int dcal_wifi_global_get_date_check( global_handle global, bool *date_check);
Retrieve the date_check boolean

#### Def ad-hoc channel
Default ad-hoc channel utilized when in ad-hoc mode.
````
int dcal_wifi_global_set_def_adhoc_channel( global_handle global,
                                            unsigned int def_adhoc_channel);
int dcal_wifi_global_get_def_adhoc_channel( global_handle global,
                                            unsigned int *def_adhoc_channel);
````
#### int dcal_wifi_global_set_def_adhoc_channel( global_handle global, unsigned int def_adhoc_channel);
Set the default adhoc channel.
#### int dcal_wifi_global_get_def_adhoc_channel( global_handle global, unsigned int *def_adhoc_channel);
Retrieve the default adhoc channel.

#### Fips
The Federal Information Processing Standard (FIPS) capability can be controlled on the WB if the WB supports FIPS.
````
int dcal_wifi_global_set_fips( global_handle global, bool fips);
int dcal_wifi_global_get_fips( global_handle global, bool *fips);
````
#### int dcal_wifi_global_set_fips( global_handle global, bool fips);
Set FIPS enable/disable.
#### int dcal_wifi_global_get_fips( global_handle global, bool *fips);
Retrieve the current FIPS status

#### Set PMK
````
int dcal_wifi_global_set_pmk( global_handle global, DCAL_PMK_CACHING pmk);
int dcal_wifi_global_get_pmk( global_handle global, DCAL_PMK_CACHING *pmk);
````
pmk_caching has two settings:

`STANDARD` and
`OPMK` - Opportunistic Key Caching

#### int dcal_wifi_global_set_pmk( global_handle global, DCAL_PMK_CACHING pmk);
Set the pmk value.
#### int dcal_wifi_global_get_pmk( global_handle global, DCAL_PMK_CACHING *pmk);
Retrieve the current pmk setting.

#### Probe Delay
Probe Delay - 2-120 second delay before sending out probes when AP's aren't located.
````
int dcal_wifi_global_set_probe_delay( global_handle global,
                                      unsigned int probe_delay);
int dcal_wifi_global_get_probe_delay( global_handle global,
                                      unsigned int *probe_delay);
````
#### int dcal_wifi_global_set_probe_delay( global_handle global, unsigned int probe_delay);
Set the probe delay
#### int dcal_wifi_global_get_probe_delay( global_handle global, unsigned int *probe_delay);
retrieve the probe delay

#### Regulatory Domain

| Regulatory Domain/Country Code | enum value | notes |
|:-------------------------------|:----------:|:------|
| FCC                            | REG_FCC    | North America, South America, Central America, Australia, New Zealand, various parts of Asia |
| ETSI                           | REG_ETSI   | Europe, Middle East, Africa, various parts of Asia |
| TELEC                          | REG_TELEC  | Japan             |
| WW                             | REG_WW     | World Wide        |
| KCC                            | REG_KCC    | Korea             |
| CA                             | REG_CA     | Canada            |
| FR                             | REG_FR     | France            |
| GB                             | REG_GB     | United Kingdom    |
| AU                             | REG_AU     | Australia         |
| NZ                             | REG_NZ     | New Zealand       |
| CN                             | REG_CN     | China             |
| BR                             | REG_BR     | Brazil            |
| RU                             | REG_RU     | Russia            |
````
int dcal_wifi_global_get_regdomain( global_handle global,
                                    REG_DOMAIN *regdomain);
````
#### int dcal_wifi_global_get_regdomain( global_handle global, REG_DOMAIN *regdomain);
Retrieve the current regulatory domain


#### Roam Period MS
Roam scan period in milliseconds.  Valid range 10 - 60000 ms
````
int dcal_wifi_global_set_roam_periodms( global_handle global,
                                      unsigned int roam_periodms);
int dcal_wifi_global_get_roam_periodms( global_handle global,
                                      unsigned int *roam_periodms);
````
#### int dcal_wifi_global_set_roam_periodms( global_handle global, unsigned int roam_periodms);
Set the roam period ms value.
#### int dcal_wifi_global_get_roam_periodms( global_handle global, unsigned int *roam_periodms);
Retrieve the roam period ms value.

#### Roam Trigger
Roam Trigger value can be between 50-90 dBm
````
int dcal_wifi_global_set_roam_trigger( global_handle global,
                                       unsigned int roam_trigger);
int dcal_wifi_global_get_roam_trigger( global_handle global,
                                       unsigned int *roam_trigger);
````
#### int dcal_wifi_global_set_roam_trigger( global_handle global, unsigned int roam_trigger);
Set the roam trigger value.
#### int dcal_wifi_global_get_roam_trigger( global_handle global, unsigned int *roam_trigger);
Retrieve the roam trigger value.


#### RTS
````
int dcal_wifi_global_set_rts( global_handle global,
                              unsigned int rts);
int dcal_wifi_global_get_rts( global_handle global,
                              unsigned int *rts);
````
#### int dcal_wifi_global_set_rts( global_handle global, unsigned int rts);
Set the RTS value.
#### int dcal_wifi_global_get_rts( global_handle global, unsigned int *rts);
retrieve the RTS value.

#### DFS Time
Maximum time spent scanning each DFS channel during a scan. Range: 20-500ms
````
int dcal_wifi_global_set_scan_dfs_time( global_handle global,
                                        unsigned int scan_dfs);
int dcal_wifi_global_get_scan_dfs_time( global_handle global,
                                        unsigned int *scan_dfs);
````
#### int dcal_wifi_global_set_scan_dfs_time( global_handle global, unsigned int scan_dfs);
Set the DFS time value.
#### int dcal_wifi_global_get_scan_dfs_time( global_handle global, unsigned int *scan_dfs);
Retrieve the DFS time value.

#### TTLS inner method

Possible values: `TTLS_AUTO` (uses any available EAP method)  
`TTLS_MSCHAPV2,`
`TTLS_MSCHAP,`
`TTLS_PAP,`
`TTLS_CHAP,`
`TTLS_EAP_MSCHAPV2`
````
int dcal_wifi_global_set_ttls_inner_method( global_handle global,
                                TTLS_INNER_METHOD ttls_inner_method);
int dcal_wifi_global_get_ttls_inner_method( global_handle global,
                                TTLS_INNER_METHOD *ttls_inner_method);
````
#### int dcal_wifi_global_set_ttls_inner_method( global_handle global, TTLS_INNER_METHOD ttls_inner_method);
Set the TTLS inner method.
#### int dcal_wifi_global_get_ttls_inner_method( global_handle global, TTLS_INNER_METHOD *ttls_inner_method);
Retrieve the TTLS inner method.


#### UAPSD
Unscheduled Automatic Power Save Delivery (UAPSD) setting
````
int dcal_wifi_global_set_uapsd( global_handle global, bool uapsd);
int dcal_wifi_global_get_uapsd( global_handle global, bool *uapsd);
````
#### int dcal_wifi_global_set_uapsd( global_handle global, bool uapsd);
Set the UAPSD value. This can be used to enable all UAPSD access classes or disable all.
#### int dcal_wifi_global_get_uapsd( global_handle global, bool *uapsd);
Retrieve the UAPSD value.

Sets are created by or'ing bit mask entries.
#### UAPSD Masks
| Access class | Bitmask |
|:------------:|:-------:|
| Voice        | AC_VO   |
| Video        | AC_VI   |
| Background   | AC_BK   |
| Best Effort  | AC_BE   |

#### int dcal_wifi_global_set_uapsd_mask( global_handle global, unsigned int uapsd);
Set the enhanced UAPSD bit mask to allow selection of specific access classes.
#### int dcal_wifi_global_get_uapsd_mask( global_handle global, unsigned int *uapsd);
Get the enhanced UAPSD bit mask channel set.

#### WMM
Windows Multimedia Extension (WMM)
````
int dcal_wifi_global_set_wmm( global_handle global, bool wmm);
int dcal_wifi_global_get_wmm( global_handle global, bool *wmm);
````
#### int dcal_wifi_global_set_wmm( global_handle global, bool wmm);
Set the WMM value.
#### int dcal_wifi_global_get_wmm( global_handle global, bool *wmm);
Retrieve the WMM value.

#### Ignore NULL SSID
An early requirement of the WFA certification mandated a NULL device configured for with a NULL SSID to connect to any AP without encryption. This is no longer a requirement. Disable ignore_null_ssid to put the device into this deprecated mode.
````
int dcal_wifi_global_set_ignore_null_ssid( global_handle global,
                                           bool ignore_null_ssid);
int dcal_wifi_global_get_ignore_null_ssid( global_handle global,
                                           bool *ignore_null_ssid);
````
#### int dcal_wifi_global_set_ignore_null_ssid( global_handle global, bool ignore_null_ssid);
Set the ignore_null_ssid value.
#### int dcal_wifi_global_get_ignore_null_ssid( global_handle global, bool *ignore_null_ssid);
Retrieve the ignore_null_ssid value.

#### DFS Channels
Enable/Disable DFS channels (if allowable in current regulatory domain)
````
int dcal_wifi_global_set_dfs_channels( global_handle global,
                                       DFS_CHANNELS dfs_channels);
int dcal_wifi_global_get_dfs_channels( global_handle global,
                                       DFS_CHANNELS *dfs_channels);
````
#### int dcal_wifi_global_set_dfs_channels( global_handle global, DFS_CHANNELS dfs_channels);
Set the DFS value.
#### int dcal_wifi_global_get_dfs_channels( global_handle global, DFS_CHANNELS *dfs_channels);
Retrieve DFS value.

#### global printf
Handy global settings output
````
void dcal_wifi_global_printf( global_handle global);
````
***






### Interface Management
Interface management APIs allow configuration of the /etc/network/interface file on the WB. This controls all the network interfaces on the WB.  Both the interface create and pull routines will allocate a interface handle. The handle should be closed with the close handle function when no longer utilized.

````
int dcal_wifi_interface_create( interface_handle * interface);
int dcal_wifi_interface_pull( session_handle session,
                                 interface_handle * interface,
                                 char * interfaceName);

int dcal_wifi_interface_close_handle( interface_handle interface);

int dcal_wifi_interface_push( session_handle session,
                                  interface_handle interface);
````
#### int dcal_wifi_interface_create( interface_handle * interface);
Create an interface handle. All values are unset.
#### int dcal_wifi_interface_pull( session_handle session, interface_handle * interface, char * interfaceName);
Create an interface handle with the values of the name interfaceName string on the WB.
#### int dcal_wifi_interface_close_handle( interface_handle interface);
Close the interface handle.
#### int dcal_wifi_interface_push( session_handle session, interface_handle interface);
Push the interface handle's values to the WB.  Will replace the interfaceName interface if it exists.


APIs to set/get interface values:
````
int dcal_wifi_interface_delete( session_handle session,
                                  char * interface_name);

int dcal_wifi_interface_set_interface_name(interface_handle interface,
                                  char * interface_name );

int dcal_wifi_interface_get_ipv4_state( interface_handle interface,
                                  bool * state);

int dcal_wifi_interface_set_method( interface_handle interface,
                                  char * method);

int dcal_wifi_interface_get_method( interface_handle interface,
                                  char * method, size_t buf_len);

int dcal_wifi_interface_set_auto_start( interface_handle interface,
                                  bool auto_start);

int dcal_wifi_interface_get_auto_start( interface_handle interface,
                                  bool * auto_start);

int dcal_wifi_interface_set_address( interface_handle interface,
                                  char * address);

int dcal_wifi_interface_get_address( interface_handle interface,
                                  char * address, size_t buf_len);

int dcal_wifi_interface_set_netmask( interface_handle interface,
                                  char * netmask);

int dcal_wifi_interface_get_netmask( interface_handle interface,
                                  char * netmask, size_t buf_len);

int dcal_wifi_interface_set_gateway( interface_handle interface,
                                  char * gateway);

int dcal_wifi_interface_get_gateway( interface_handle interface,
                                  char * gateway, size_t buf_len);

int dcal_wifi_interface_set_broadcast_address( interface_handle interface,
                                  char * broadcast);

int dcal_wifi_interface_get_broadcast_address( interface_handle interface,
                                  char * broadcast, size_t buf_len);

int dcal_wifi_interface_set_nameserver( interface_handle interface,
                                  char * nameserver);

int dcal_wifi_interface_get_nameserver( interface_handle interface,
                                  char * nameserver, size_t buf_len);

int dcal_wifi_interface_set_state( interface_handle interface,
                                  bool state);

int dcal_wifi_interface_set_bridge( interface_handle interface,
                                  bool bridge);

int dcal_wifi_interface_get_bridge( interface_handle interface,
                                  bool * bridge);

int dcal_wifi_interface_set_ap_mode( interface_handle interface,
                                  bool ap_mode);

int dcal_wifi_interface_get_ap_mode( interface_handle interface,
                                  bool * ap_mode);

int dcal_wifi_interface_set_nat( interface_handle interface,
                                  bool nat);

int dcal_wifi_interface_get_nat( interface_handle interface,
                                  bool * nat);

int dcal_wifi_interface_clear_property( interface_handle interface,
                                  INTERFACE_PROPERTY prop);

int dcal_wifi_interface_get_ipv6_state( interface_handle interface,
                                  bool * state6);

int dcal_wifi_interface_set_dhcp6( interface_handle interface,
                                  char * dhcp6);

int dcal_wifi_interface_get_dhcp6( interface_handle interface,
                                  char * dhcp6, size_t buf_len);

int dcal_wifi_interface_set_method6( interface_handle interface,
                                  char * method6);

int dcal_wifi_interface_get_method6( interface_handle interface,
                                  char * method6, size_t buf_len);

int dcal_wifi_interface_set_address6( interface_handle interface,
                                  char * address6);

int dcal_wifi_interface_get_address6( interface_handle interface,
                                  char * address6, size_t buf_len);

int dcal_wifi_interface_set_netmask6( interface_handle interface,
                                  char * netmask6);

int dcal_wifi_interface_get_netmask6( interface_handle interface,
                                  char * netmask6, size_t buf_len);

int dcal_wifi_interface_set_gateway6( interface_handle interface,
                                  char * gateway6);

int dcal_wifi_interface_get_gateway6( interface_handle interface,
                                  char * gateway6, size_t buf_len);

int dcal_wifi_interface_set_nameserver6( interface_handle interface,
                                  char * nameserver6);

int dcal_wifi_interface_get_nameserver6( interface_handle interface,
                                  char * nameserver6, size_t buf_len);

int dcal_wifi_interface_set_state6( interface_handle interface,
                                  bool state6);

int dcal_wifi_interface_set_nat6( interface_handle interface,
                                  bool nat6);

int dcal_wifi_interface_get_nat6( interface_handle interface,
                                  bool * nat6);

int dcal_wifi_interface_clear_property6( interface_handle interface,
                                  INTERFACE_PROPERTY prop6);

````
***
### Interface Lease Retrieval

The interface lease retrieval pull function will create a handle and retrieve the lease data.  Once finished with the handle, close the handle with the close handle function.
````
int dcal_wifi_lease_pull( session_handle session,
                                  lease_handle * lease,
                                  char * interfaceName);

int dcal_wifi_lease_close_handle( lease_handle interface);

int dcal_wifi_lease_get_interface( lease_handle lease,
                                  char *interface, size_t buf_len);

int dcal_wifi_lease_get_address( lease_handle lease,
                                  char *address, size_t buf_len);

int dcal_wifi_lease_get_subnet_mask( lease_handle lease,
                                  char *subnet_mask, size_t buf_len);

int dcal_wifi_lease_get_routers( lease_handle lease,
                                  char *routers, size_t buf_len);

int dcal_wifi_lease_get_lease_time( lease_handle lease,
                                  long *lease_time);

int dcal_wifi_lease_get_message_type( lease_handle lease,
                                  int *message_type);

int dcal_wifi_lease_get_dns_servers( lease_handle lease,
                                  char *dns_servers, size_t buf_len);

int dcal_wifi_lease_get_dhcp_server( lease_handle lease,
                                  char *dhcp_server, size_t buf_len);

int dcal_wifi_lease_get_domain_name( lease_handle lease,
                                  char *domain_name, size_t buf_len);

int dcal_wifi_lease_get_renew( lease_handle lease,
                                  char *renew, size_t buf_len);

int dcal_wifi_lease_get_rebind( lease_handle lease,
                                  char *rebind, size_t buf_len);

int dcal_wifi_lease_get_expire( lease_handle lease,
                                  char *expire, size_t buf_len);
````
***

### Interface Default route Management
The default route pull function will allocate a handle and pull the default route information for the specified route.  If interface_name pointer is NULL, the first default route will be returned. When the route handle is no longer necessary, use the close handle function to close the handle.
````
int dcal_wifi_default_route_pull( session_handle session,
                                  default_route_handle * default_route,
                                  char * interface_name);

int dcal_wifi_default_route_close_handle( default_route_handle interface);

int dcal_wifi_default_route_get_interface( default_route_handle default_route,
                                  char *interface, size_t buf_len);

int dcal_wifi_default_route_get_destination( default_route_handle default_route,
                                  char *destination, size_t buf_len);

int dcal_wifi_default_route_get_gateway( default_route_handle default_route,
                                  char *gateway, size_t buf_len);

int dcal_wifi_default_route_get_flags( default_route_handle default_route,
                                  int *flags);

int dcal_wifi_default_route_get_metric( default_route_handle default_route,
                                  unsigned int *metric);

int dcal_wifi_default_route_get_subnet_mask( default_route_handle default_route,
                                  char *subnet_mask, size_t buf_len);

int dcal_wifi_default_route_get_mtu( default_route_handle default_route,
                                  unsigned int *mtu);

int dcal_wifi_default_route_get_window( default_route_handle default_route,
                                  unsigned int *window);

int dcal_wifi_default_route_get_irtt( default_route_handle default_route,
                                  unsigned int *irtt);
````
***

#### WiFi Scan
The pull scan list function will pull the scan list from the WB and return the number of scan items in the count parameter.  Each entry can then be interrogated with the various scan_list_entry* APIs
````
int dcal_wifi_pull_scan_list(session_handle session, size_t *count);
int dcal_wifi_get_scan_list_entry_ssid(session_handle session,
                                  int index, LRD_WF_SSID *ssid);
int dcal_wifi_get_scan_list_entry_bssid(session_handle session,
                         int index, unsigned char * bssid, int bssidbuflen);
int dcal_wifi_get_scan_list_entry_channel(session_handle session,
                                  int index, int * channel);
int dcal_wifi_get_scan_list_entry_rssi(session_handle session,
                                  int index, int * rssi);
int dcal_wifi_get_scan_list_entry_securityMask(session_handle session,
                                  int index, int * securityMask);
int dcal_wifi_get_scan_list_entry_type(session_handle session,
                                  int index, LRD_WF_BSSTYPE * bssType);
````


#### WiFi Profile Management
Profiles are the settings the radio software uses to connect to a specific WiFi network.  The radio software can store up to 20 different profiles and each profile must have a unique name.  The API can create a local (empty) profile, make the appropriate settings, and then push the profile to the WB.  In addition, an API is provided to pull an existing profile from a device, so a profile can be pulled, modified, and then pushed back to the device.
````
int dcal_wifi_profile_create( profile_handle * profile);
int dcal_wifi_profile_pull( session_handle session,
                                 profile_handle * profile,
                                 char * profilename);
int dcal_wifi_profile_close_handle( profile_handle profile);

int dcal_wifi_profile_push( session_handle session,
                                 profile_handle profile);
int dcal_wifi_profile_activate( session_handle session,
                                     profile_handle profile);
int dcal_wifi_profile_activate_by_name( session_handle session,
                                          char * profile_name);
int dcal_wifi_profile_delete_from_device( session_handle session,
                                          char * profile_name);

````
#### int dcal_wifi_profile_create( profile_handle * profile);
Creates an empty profile.  Settings can be made for eventual pushing to the connected WB.  Note a session is not necessary to create a profile with this API.

#### int dcal_wifi_profile_pull( session_handle session, profile_handle * profile, char * profilename);
Creates a profile with the settings of the same named profile on the connected WB.  Note a valid connected session is required with this API.
#### int dcal_wifi_profile_push( session_handle session, profile_handle profile);
Sends the profile to the device.  If a profile of the same name exists on the device, it will be overwritten with the values of this profile.
Note a valid connected session is required wth this API.  Also, this API can be called with multiple sessions in order to send the same profile to multiple WBs.
#### int dcal_wifi_profile_activate( session_handle session, profile_handle profile);
Causes the specified profile to become the active profile on the session WB.
#### int dcal_wifi_profile_activate_by_name( session_handle session, char * profile_name);
Causes the specified profile to become the active profile on the session WB.  (note that the name of the profile is used, no profile handle needed)

#### int dcal_wifi_profile_delete_from_device( session_handle session, char * profile_name);
Delete the named profile from the connected WB.



##### Profile get/set functions
These APIs set and get the various settings of a profile.
````
int dcal_wifi_profile_set_profilename(profile_handle profile,
                                           char * profilename );
int dcal_wifi_profile_get_profilename(profile_handle profile,
                                      char * profilename, size_t buflen );

// note the SSID is not a string, as SSIDs can contain embedded non-ascii
// characters including embedded nulls  (the SDK on the device may not yet
// support non-ascii characters but handling it as if it can will allow us
// future capabilities)
int dcal_wifi_profile_set_SSID( profile_handle profile,
                                       LRD_WF_SSID *ssid);
int dcal_wifi_profile_get_SSID( profile_handle profile,
                                       LRD_WF_SSID *ssid);

typedef enum _encyption_standards {
	ES_NONE = 0,
	ES_WEP,
	ES_WPA,
	ES_WPA2,
	ES_CCKM
} ENCRYPT_STD;

// security
// setting an encryption standard will clear all security fields
// if ES_WEP is configured
// dcal_wifi_profile_set_eap should be used to signify Dynamic WEP (802.1x) is desired
// or
// dcal_wifi_profile_set_wep_key should be used to signify WEP 40/128 is desired
// most recent configured option will determine which is used
int dcal_wifi_profile_set_encrypt_std( profile_handle profile,
                                            ENCRYPT_STD estd);
int dcal_wifi_profile_get_encrypt_std( profile_handle profile,
                                            ENCRYPT_STD *estd);
typedef enum _encryption {
	ENC_NONE = 0,
	ENC_AES,
	ENC_TKIP,
} ENCRYPTION;

int dcal_wifi_profile_set_encryption( profile_handle profile,
                                           ENCRYPTION enc);
int dcal_wifi_profile_get_encryption( profile_handle profile,
                                           ENCRYPTION *enc);
#ifndef _SDC_SDK_H_
typedef enum _auth_type {
	AUTH_OPEN = 0,  // only valid in profiles - no globals
	AUTH_SHARED,
	AUTH_NETWORK_EAP,
} AUTH;
#endif
int dcal_wifi_profile_set_auth( profile_handle profile,
                                     AUTH auth);
int dcal_wifi_profile_get_auth( profile_handle profile,
                                     AUTH *auth);

int dcal_wifi_profile_set_eap( profile_handle profile,
                                    EAPTYPE eap);
int dcal_wifi_profile_get_eap( profile_handle profile,
                                    EAPTYPE *eap);

int dcal_wifi_profile_set_psk( profile_handle profile,
                                    char * psk);
int dcal_wifi_profile_psk_is_set( profile_handle profile,
                                    bool * psk);

int dcal_wifi_profile_set_user( profile_handle profile,
                                     char * user);
int dcal_wifi_profile_user_is_set( profile_handle profile,
                                     bool * user);

int dcal_wifi_profile_set_password( profile_handle profile,
                                         char * password);
int dcal_wifi_profile_password_is_set( profile_handle profile,
                                         bool * password);

int dcal_wifi_profile_set_cacert( profile_handle profile,
                                       char * cacert);
int dcal_wifi_profile_cacert_is_set( profile_handle profile,
                                       bool * cacert);

int dcal_wifi_profile_set_pacfile( profile_handle profile,
                                 char * pacfilename);
int dcal_wifi_profile_pacfile_is_set( profile_handle profile,
                                 bool * pacfilename);

int dcal_wifi_profile_set_pacpassword( profile_handle profile,
                                 char * pacpassword);
int dcal_wifi_profile_pacpassword_is_set( profile_handle profile,
                                 bool * pacpassword_buffer);

int dcal_wifi_profile_set_usercert( profile_handle profile,
                                 char * usercert);
int dcal_wifi_profile_usercert_is_set( profile_handle profile,
                                 bool * usercert);

int dcal_wifi_profile_set_usercert_password( profile_handle profile,
                                 char * usercert_password);
int dcal_wifi_profile_usercert_password_is_set( profile_handle profile,
                                 bool * usercert_password);

int dcal_wifi_profile_set_wep_key( profile_handle profile,
                                 char * wepkey, int index);
int dcal_wifi_profile_wep_key_is_set( profile_handle profile,
                                 bool * wepkey, int index);

int dcal_wifi_profile_set_wep_txkey( profile_handle profile,
                                 unsigned int txkey);
int dcal_wifi_profile_get_wep_txkey( profile_handle profile,
                                 unsigned int *txkey);

// other profile settings

int dcal_wifi_profile_set_clientname( profile_handle profile,
                                char * clientname);
int dcal_wifi_profile_get_clientname( profile_handle profile,
                                char * clientname_buffer, size_t buflen);

int dcal_wifi_profile_set_radiomode( profile_handle profile,
                                RADIOMODE mode);
int dcal_wifi_profile_get_radiomode( profile_handle profile,
                                RADIOMODE * mode);

int dcal_wifi_profile_set_powersave( profile_handle profile,
                               POWERSAVE powersave);
int dcal_wifi_profile_get_powersave( profile_handle profile,
                               POWERSAVE * powersave);

int dcal_wifi_profile_set_psp_delay( profile_handle profile,
                               unsigned int pspdelay);
int dcal_wifi_profile_get_psp_delay( profile_handle profile,
                               unsigned int * pspdelay);

int dcal_wifi_profile_set_txpower( profile_handle profile,
                               int txpower);
int dcal_wifi_profile_get_txpower( profile_handle profile,
                               int *txpower);

int dcal_wifi_profile_set_bitrate( profile_handle profile,
                               BITRATE bitrate);
int dcal_wifi_profile_get_bitrate( profile_handle profile,
                               BITRATE *bitrate);

int dcal_wifi_profile_set_autoprofile( profile_handle profile,
                               bool autoprofile);
int dcal_wifi_profile_get_autoprofile( profile_handle profile,
                               bool *autoprofile);

// Note that encrypted fields are not sent from the host.  Therefore
// printing out locally created fields will allow the viewing of the
// security fields, while printing profiles pulled from host will only
// show if the security field has been set or not.
void dcal_wifi_profile_printf( profile_handle profile);
````

### System controls

````
int dcal_wifi_restart( session_handle session);
int dcal_system_restart( session_handle session);
````
#### int dcal_wifi_restart( session_handle session);
Restart the wifi system
#### int dcal_system_restart( session_handle session);
Restart the WB. Note dcal_system_restart will close the session handle

#### Time functions
The values for the time_set and time_get functions are the same values
as those used in the structure passed to the system functions
gettimeofday() and settimeofday()
````
int dcal_time_set( session_handle session, 
                      struct timeval *tv );
int dcal_time_get( session_handle session,
                      struct timeval *tv );
int dcal_ntpdate( session_handle session,
                      char * server_name );
````
#### int dcal_time_set( session_handle session, struct timeval *tv);
Set the system time on the WB
#### int dcal_time_get( session_handle session, struct timeval *tv);
Retrieve the system time on the WB
#### int dcal_ntpdate( session_handle session, char * server_name );
The dcal_ntpdate() function takes a character string which contains the ntp server that will be placed on the command line for a call to ntpdate.  
Example:  
      dcal_ntpdate( session, "pool.ntp.org");  
*only [a-z],[0-9],[-./],[A-Z] characters are valid*

### file handling
````
int dcal_file_push_to_wb(session_handle session,
                             char * local_file_name,
                             char * remote_file_name);
int dcal_file_pull_from_wb(session_handle session,
                             char * remote_file_name,
                             char * local_file_name);
int dcal_cert_push_to_wb(session_handle session,
                             char * local_cert_name);
````
#### int dcal_file_push_to_wb(session_handle session, char * local_file_name, char * remote_file_name);
local_file is the full path and file name on host. remote_file can be NULL in which case the basename of local_file will be used. The remote_file will be saved to /tmp/ on WB.  NOTE: /tmp is not persistent on the WB as /tmp is a ram disk.

#### int dcal_file_pull_from_wb(session_handle session, char * remote_file_name, char * local_file_name);
remote_file_name is full path and filename on WB.  local_file_name is the full path and file name on host. local_file_name can be NULL in which case remote_file_name base name will be used in the local directory

#### int dcal_cert_push_to_wb(session_handle session, char * local_cert_name);
local_cert_name is the full path and file name on local system.  files will be transferred to the the certificate path which can be changed by dcal_wifi_global_set_cert_path()

#### Misc
````
int dcal_fw_update(session_handle session, int flags);
int dcal_pull_logs(session_handle session, char * dest_file);
int dcal_process_cli_command_file(session_handle session, char * src_file);
````
#### int dcal_fw_update(session_handle session, int flags);
in order to issue the fw_update() function, the desired files must first be transferred to the remote device.  This includes the fw.txt file.  The files will be placed in the /tmp directory on the WB.  When this function is executed, firmware update will be attempted on the transferred fw.txt file in /tmp.  fw_update flags can be set in the flags variable.  Flags can also be set in the fw.txt file itself.  
*NOTE: The disable reboot flag will be added by dcas so the user must
specifically call dcal_system_restart() when desiring restart after
fw_update.*

#### int dcal_pull_logs(session_handle session, char * dest_file);
dest_file is full location and file name where log should be saved

#### int dcal_process_cli_command_file(session_handle session, char * src_file);
src_file is full location and file name where command file resides.


## Appendix A: References ##

# dcal_api.h file #
````
/*
Copyright (c) 2016, Ezurio
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
// the DCAL API to setup and get status from wireless bridges

#ifndef _DCAL_API_
#define _DCAL_API_

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

//these three values define the API version between DCAL and DCAS
#define SUMMIT_SDK_MSB       3
#define SUMMIT_DCAL_MAJOR    1
#define SUMMIT_DCAL_MINOR    6
#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sdc_sdk_legacy.h"

typedef enum _DCAL_ERR{
	DCAL_SUCCESS = 0,
	DCAL_WB_GENERAL_FAIL,
	DCAL_WB_INVALID_NAME,
	DCAL_WB_INVALID_CONFIG,
	DCAL_WB_INVALID_DELETE,
	DCAL_WB_POWERCYCLE_REQUIRED,
	DCAL_WB_INVALID_PARAMETER,
	DCAL_WB_INVALID_EAP_TYPE,
	DCAL_WB_INVALID_WEP_TYPE,
	DCAL_WB_INVALID_FILE,
	DCAL_WB_INSUFFICIENT_MEMORY,
	DCAL_WB_NOT_IMPLEMENTED,
	DCAL_WB_NO_HARDWARE,
	DCAL_WB_INVALID_VALUE,

	DCAL_INVALID_PARAMETER = 100,
	DCAL_INVALID_HANDLE,
	DCAL_HANDLE_IN_USE,
	DCAL_HANDLE_NOT_ACTIVE,
	DCAL_NO_NETWORK_ACCESS,
	DCAL_NO_MEMORY,
	DCAL_NOT_IMPLEMENTED,
	DCAL_INVALID_CONFIGURATION,
	DCAL_SSH_ERROR,
	DCAL_FLATBUFF_ERROR,
	DCAL_FLATCC_NOT_INITIALIZED,
	DCAL_FLATBUFF_VALIDATION_FAIL,
	DCAL_DATA_STALE,
	DCAL_LOCAL_FILE_ACCESS_DENIED,
	DCAL_REMOTE_FILE_ACCESS_DENIED,
	DCAL_FQDN_FAILURE,
	DCAL_REMOTE_SHELL_CMD_FAILURE,
	DCAL_RADIO_DISABLED,
	DCAL_INDEX_OUT_OF_BOUNDS,
	DCAL_BUFFER_TOO_SMALL,
} DCAL_ERR;

typedef char * FQDN;

typedef void * session_handle;
typedef void * profile_handle;
typedef void * global_handle;
typedef void * interface_handle;
typedef void * lease_handle;
typedef void * default_route_handle;

#define MAC_SZ 6
#define IP4_SZ 4
#define IP6_STR_SZ 46 //max string:0000:0000:0000:0000:0000:0000:xxx.xxx.xxx.xxx plus NULL
                      //(IPV4 mapped IPV6 address)
typedef char ipv6_str_type[IP6_STR_SZ];

#define NAME_SZ 48
#ifndef SSID_SZ
#define SSID_SZ 32
#endif

#define STR_SZ 80

// bitwise methods
#define METHOD_PUBKEY   1
#define METHOD_PASSWORD 2

// API session management

int dcal_session_create( session_handle * session);
int dcal_set_host( session_handle session, FQDN address );
int dcal_set_port( session_handle session, unsigned int port );
int dcal_set_user( session_handle session, char * user );
int dcal_set_pw( session_handle session, char * pw );
int dcal_set_keyfile( session_handle session, char * filename);
int dcal_get_auth_methods ( session_handle s, int * method );
int dcal_session_open ( session_handle session );
int dcal_session_close( session_handle session);

// Device Versions

int dcal_get_sdk_version(session_handle session, unsigned int *sdk);
int dcal_get_chipset_version(session_handle session,
                              RADIOCHIPSET *chipset);
int dcal_get_system_version(session_handle session,
                              LRD_SYSTEM *sys);
int dcal_get_driver_version(session_handle session,
                              unsigned int *driver);
int dcal_get_dcas_version(session_handle session,
                              unsigned int *dcas);
int dcal_get_dcal_version(session_handle session,
                              unsigned int *dcal);
int dcal_get_firmware_version(session_handle session,
                              char *firmware, size_t buflen);
int dcal_get_supplicant_version(session_handle session,
                              char *supplicant, size_t buflen);
int dcal_get_release_version(session_handle session,
                              char *release, size_t buflen);

// Device Status
int dcal_device_status_pull( session_handle session);

// things that are fairly static
int dcal_device_status_get_settings( session_handle session,
                                     char * profilename,
                                     size_t profilename_buflen,
                                     LRD_WF_SSID *ssid,
                                     unsigned char *mac,
                                     size_t mac_buflen);
// things that are ccx related
int dcal_device_status_get_ccx( session_handle session,
                                       unsigned char *ap_ip,
                                       size_t ap_ip_buflen,
                                       char *ap_name,
                                       size_t ap_name_buflen,
                                       char * clientname,
                                       size_t clientname_buflen);
// ip stack related
int dcal_device_status_get_ipv4( session_handle session,
                                       unsigned char *ipv4,
                                       size_t buflen);

int dcal_device_status_get_ipv6_count( session_handle session,
                                       size_t *count);

int dcal_device_status_get_ipv6_string_at_index( session_handle session,
                                       unsigned int index,
                                       char *ipv6,
                                       size_t buflen);

// things that could change moment to moment
int dcal_device_status_get_connection( session_handle session,
                                       unsigned int * cardstate,
                                       unsigned int * channel,
                                       int * rssi,
                                       unsigned char *ap_mac,
                                       size_t ap_mac_buflen);

int dcal_device_status_get_connection_extended( session_handle session,
                                       unsigned int *bitrate,
                                       unsigned int *txpower,
                                       unsigned int *dtim,
                                       unsigned int *beaconperiod);
int dcal_device_status_get_cache_timeout( unsigned int *timeout);

// WiFi Management
int dcal_wifi_enable( session_handle session);
int dcal_wifi_disable( session_handle session);

// WiFi Global Management_
// both the create and pull functions will allocate a global_handle
// that require the close_handle function to be called when done with the
// handle
int dcal_wifi_global_create( global_handle * global);
int dcal_wifi_global_pull( session_handle session,
                                 global_handle * global);
int dcal_wifi_global_close_handle( global_handle global);

// push sends the local global to the remote radio device.
int dcal_wifi_global_push( session_handle session,
                                 global_handle global);

//Type 1 - server that uses PEAPv1 for PEAP with EAP-MSCHAPV2 (PEAP-MSCHAP).
//Type 2 -uses PEAPv0 for PEAP-MSCHAP.
typedef enum _server_auth{
	TYPE1 = 0,
	TYPE2 = 1
} SERVER_AUTH;

int dcal_wifi_global_set_auth_server( global_handle global,
                                      SERVER_AUTH auth);
int dcal_wifi_global_get_auth_server( global_handle global,
                                      SERVER_AUTH *auth);

typedef enum _bchannels_masks{
	b_1 = 1<<0, //2412 GHz
	b_2 = 1<<1, //2417 GHz
	b_3 = 1<<2, //2422 GHz
	b_4 = 1<<3, //2427 GHz
	b_5 = 1<<4, //2432 GHz
	b_6 = 1<<5, //2437 GHz
	b_7 = 1<<6, //2442 GHz
	b_8 = 1<<7, //2447 GHz
	b_9 = 1<<8, //2452 GHz
	b_10 = 1<<9, //2457 GHz
	b_11 = 1<<10, //2462 GHz
	b_12 = 1<<11, //2467 GHz
	b_13 = 1<<12, //2472 GHz
	b_14 = 1<<13, //2484 GHz
	b_full = 0xffff // all channels
} B_CHAN_MASKS;

typedef enum _achannels_masks{
	a_36 = 1<<0, //5180 GHz (U-NII-1)
	a_40 = 1<<1, //5200 GHz
	a_44 = 1<<2, //5220 GHz
	a_48 = 1<<3, //5240 GHz
	a_52 = 1<<4, //5260 GHz (U-NII-2/DFS)
	a_56 = 1<<5, //5280 GHz
	a_60 = 1<<6, //5300 GHz
	a_64 = 1<<7, //5320 GHz
	a_100 = 1<<8, //5500 GHz
	a_104 = 1<<9, //5520 GHz
	a_108 = 1<<10, //5540 GHz
	a_112 = 1<<11, //5560 GHz
	a_116 = 1<<12, //5580 GHz
	a_120 = 1<<13, //5600 GHz
	a_124 = 1<<14, //5620 GHz
	a_128 = 1<<15, //5640 GHz
	a_132 = 1<<16, //5660 GHz
	a_136 = 1<<17, //5680 GHz
	a_140 = 1<<18, //5700 GHz
	a_149 = 1<<19, //5745 GHz (U-NII-3)
	a_153 = 1<<20, //5765 GHz
	a_157 = 1<<21, //5785 GHz
	a_161 = 1<<22, //5805 GHz
	a_165 = 1<<23, //5825 GHz
	a_full = 0xffffff // all channels
} A_CHAN_MASKS;

int dcal_wifi_global_set_achannel_mask( global_handle global,
                                        unsigned int channel_set_a);
int dcal_wifi_global_get_achannel_mask( global_handle global,
                                        unsigned int *channel_set_a);

int dcal_wifi_global_set_bchannel_mask( global_handle global,
                                        unsigned int channel_set_b);
int dcal_wifi_global_get_bchannel_mask( global_handle global,
                                        unsigned int *channel_set_b);

int dcal_wifi_global_set_auto_profile( global_handle global,
                                       bool auto_profile);
int dcal_wifi_global_get_auto_profile( global_handle global,
                                       bool *auto_profile);

int dcal_wifi_global_set_beacon_miss( global_handle global,
                                      unsigned int beacon_miss);
int dcal_wifi_global_get_beacon_miss( global_handle global,
                                      unsigned int *beacon_miss);

int dcal_wifi_global_set_ccx( global_handle global, bool ccx);
int dcal_wifi_global_get_ccx( global_handle global, bool *ccx);

int dcal_wifi_global_set_cert_path( global_handle global,
                                    char *cert_path);
int dcal_wifi_global_get_cert_path( global_handle global,
                                    char *cert_path, size_t buf_len);

int dcal_wifi_global_set_date_check( global_handle global,
                                     bool date_check);
int dcal_wifi_global_get_date_check( global_handle global,
                                     bool *date_check);

int dcal_wifi_global_set_def_adhoc_channel( global_handle global,
                                            unsigned int def_adhoc_channel);
int dcal_wifi_global_get_def_adhoc_channel( global_handle global,
                                            unsigned int *def_adhoc_channel);

int dcal_wifi_global_set_fips( global_handle global, bool fips);
int dcal_wifi_global_get_fips( global_handle global, bool *fips);

typedef enum _pmk_caching {
	STANDARD = 0,
	OPMK = 1,
} DCAL_PMK_CACHING;
int dcal_wifi_global_set_pmk( global_handle global, DCAL_PMK_CACHING pmk);
int dcal_wifi_global_get_pmk( global_handle global, DCAL_PMK_CACHING *pmk);

int dcal_wifi_global_set_probe_delay( global_handle global,
                                      unsigned int probe_delay);
int dcal_wifi_global_get_probe_delay( global_handle global,
                                      unsigned int *probe_delay);
#ifndef _SDC_SDK_H_
typedef enum _regulatory_domain{
	REG_FCC   = 0,	// North America, South America, Central America, Australia, New Zealand, various parts of Asia
	REG_ETSI  = 1,	// Europe, Middle East, Africa, various parts of Asia
	REG_TELEC = 2,	// Japan
	REG_WW    = 3,	// World Wide
	REG_KCC   = 4,	// Korea
	REG_CA    = 5,	// Canada
	REG_FR    = 6,	// France
	REG_GB    = 7,	// United Kingdom
	REG_AU    = 8,	// Australia
	REG_NZ    = 9,	// New Zealand
	REG_CN    = 10,	// China
	REG_BR    = 11,	// Brazil
	REG_RU    = 12,	// Russia
} REG_DOMAIN;
#endif
int dcal_wifi_global_get_regdomain( global_handle global,
                                    REG_DOMAIN *regdomain);

int dcal_wifi_global_set_roam_periodms( global_handle global,
                                      unsigned int roam_periodms);
int dcal_wifi_global_get_roam_periodms( global_handle global,
                                      unsigned int *roam_periodms);

int dcal_wifi_global_set_roam_trigger( global_handle global,
                                       unsigned int roam_trigger);
int dcal_wifi_global_get_roam_trigger( global_handle global,
                                       unsigned int *roam_trigger);

int dcal_wifi_global_set_rts( global_handle global,
                              unsigned int rts);
int dcal_wifi_global_get_rts( global_handle global,
                              unsigned int *rts);

int dcal_wifi_global_set_scan_dfs_time( global_handle global,
                                        unsigned int scan_dfs);
int dcal_wifi_global_get_scan_dfs_time( global_handle global,
                                        unsigned int *scan_dfs);

#ifndef _SDC_SDK_H_
typedef enum _ttls_internal_method {
	TTLS_AUTO = 0,	// uses any available EAP method
	TTLS_MSCHAPV2,
	TTLS_MSCHAP,
	TTLS_PAP,
	TTLS_CHAP,
	TTLS_EAP_MSCHAPV2,
} TTLS_INNER_METHOD;
#endif
int dcal_wifi_global_set_ttls_inner_method( global_handle global,
                                TTLS_INNER_METHOD ttls_inner_method);
int dcal_wifi_global_get_ttls_inner_method( global_handle global,
                                TTLS_INNER_METHOD *ttls_inner_method);

int dcal_wifi_global_set_uapsd( global_handle global, bool uapsd);
int dcal_wifi_global_get_uapsd( global_handle global, bool *uapsd);

int dcal_wifi_global_set_wmm( global_handle global, bool wmm);
int dcal_wifi_global_get_wmm( global_handle global, bool *wmm);

int dcal_wifi_global_set_ignore_null_ssid( global_handle global,
                                           bool ignore_null_ssid);
int dcal_wifi_global_get_ignore_null_ssid( global_handle global,
                                           bool *ignore_null_ssid);

#ifndef _SDC_SDK_H_
typedef enum _dfs_channels {
	DFS_OFF = 0,
	DFS_FULL,
	DFS_OPTIMIZED
} DFS_CHANNELS;
#endif
int dcal_wifi_global_set_dfs_channels( global_handle global,
                                       DFS_CHANNELS dfs_channels);
int dcal_wifi_global_get_dfs_channels( global_handle global,
                                       DFS_CHANNELS *dfs_channels);

void dcal_wifi_global_printf( global_handle global);

// Interface Management
// the create function will allocate a interface_handle
// that will require the close_handle function to be called when done with the
// handle
int dcal_wifi_interface_create( interface_handle * interface);
int dcal_wifi_interface_pull( session_handle session,
                                 interface_handle * interface,
                                 char * interfaceName);

int dcal_wifi_interface_close_handle( interface_handle interface);

// push sends the local interface to the remote radio device.
int dcal_wifi_interface_push( session_handle session,
                                  interface_handle interface);

int dcal_wifi_interface_delete( session_handle session,
                                  char * interface_name);

int dcal_wifi_interface_set_interface_name(interface_handle interface,
                                  char * interface_name );

int dcal_wifi_interface_get_ipv4_state( interface_handle interface,
                                  bool * state);

int dcal_wifi_interface_set_method( interface_handle interface,
                                  char * method);

int dcal_wifi_interface_get_method( interface_handle interface,
                                  char * method, size_t buf_len);

int dcal_wifi_interface_set_auto_start( interface_handle interface,
                                  bool auto_start);

int dcal_wifi_interface_get_auto_start( interface_handle interface,
                                  bool * auto_start);

int dcal_wifi_interface_set_address( interface_handle interface,
                                  char * address);

int dcal_wifi_interface_get_address( interface_handle interface,
                                  char * address, size_t buf_len);

int dcal_wifi_interface_set_netmask( interface_handle interface,
                                  char * netmask);

int dcal_wifi_interface_get_netmask( interface_handle interface,
                                  char * netmask, size_t buf_len);

int dcal_wifi_interface_set_gateway( interface_handle interface,
                                  char * gateway);

int dcal_wifi_interface_get_gateway( interface_handle interface,
                                  char * gateway, size_t buf_len);

int dcal_wifi_interface_set_broadcast_address( interface_handle interface,
                                  char * broadcast);

int dcal_wifi_interface_get_broadcast_address( interface_handle interface,
                                  char * broadcast, size_t buf_len);

int dcal_wifi_interface_set_nameserver( interface_handle interface,
                                  char * nameserver);

int dcal_wifi_interface_get_nameserver( interface_handle interface,
                                  char * nameserver, size_t buf_len);

int dcal_wifi_interface_set_state( interface_handle interface,
                                  bool state);

int dcal_wifi_interface_set_bridge( interface_handle interface,
                                  bool bridge);

int dcal_wifi_interface_get_bridge( interface_handle interface,
                                  bool * bridge);

int dcal_wifi_interface_set_ap_mode( interface_handle interface,
                                  bool ap_mode);

int dcal_wifi_interface_get_ap_mode( interface_handle interface,
                                  bool * ap_mode);

int dcal_wifi_interface_set_nat( interface_handle interface,
                                  bool nat);

int dcal_wifi_interface_get_nat( interface_handle interface,
                                  bool * nat);

typedef enum _interface_property {
	ADDRESS		= 1 << 0,
	NETMASK		= 1 << 1,
	GATEWAY		= 1 << 2,
	BROADCAST	= 1 << 3,
	NAMESERVER	= 1 << 4,
	DHCP		= 1 << 5,
} INTERFACE_PROPERTY;

int dcal_wifi_interface_clear_property( interface_handle interface,
                                  INTERFACE_PROPERTY prop);

int dcal_wifi_interface_get_ipv6_state( interface_handle interface,
                                  bool * state6);

int dcal_wifi_interface_set_dhcp6( interface_handle interface,
                                  char * dhcp6);

int dcal_wifi_interface_get_dhcp6( interface_handle interface,
                                  char * dhcp6, size_t buf_len);

int dcal_wifi_interface_set_method6( interface_handle interface,
                                  char * method6);

int dcal_wifi_interface_get_method6( interface_handle interface,
                                  char * method6, size_t buf_len);

int dcal_wifi_interface_set_address6( interface_handle interface,
                                  char * address6);

int dcal_wifi_interface_get_address6( interface_handle interface,
                                  char * address6, size_t buf_len);

int dcal_wifi_interface_set_netmask6( interface_handle interface,
                                  char * netmask6);

int dcal_wifi_interface_get_netmask6( interface_handle interface,
                                  char * netmask6, size_t buf_len);

int dcal_wifi_interface_set_gateway6( interface_handle interface,
                                  char * gateway6);

int dcal_wifi_interface_get_gateway6( interface_handle interface,
                                  char * gateway6, size_t buf_len);

int dcal_wifi_interface_set_nameserver6( interface_handle interface,
                                  char * nameserver6);

int dcal_wifi_interface_get_nameserver6( interface_handle interface,
                                  char * nameserver6, size_t buf_len);

int dcal_wifi_interface_set_state6( interface_handle interface,
                                  bool state6);

int dcal_wifi_interface_set_nat6( interface_handle interface,
                                  bool nat6);

int dcal_wifi_interface_get_nat6( interface_handle interface,
                                  bool * nat6);

int dcal_wifi_interface_clear_property6( interface_handle interface,
                                  INTERFACE_PROPERTY prop6);

// Interface Lease Management
// dcal_wifi_lease_pull will require the close_handle function to be called
// when done with the handle
int dcal_wifi_lease_pull( session_handle session,
                                  lease_handle * lease,
                                  char * interfaceName);

int dcal_wifi_lease_close_handle( lease_handle interface);

int dcal_wifi_lease_get_interface( lease_handle lease,
                                  char *interface, size_t buf_len);

int dcal_wifi_lease_get_address( lease_handle lease,
                                  char *address, size_t buf_len);

int dcal_wifi_lease_get_subnet_mask( lease_handle lease,
                                  char *subnet_mask, size_t buf_len);

int dcal_wifi_lease_get_routers( lease_handle lease,
                                  char *routers, size_t buf_len);

int dcal_wifi_lease_get_lease_time( lease_handle lease,
                                  long *lease_time);

int dcal_wifi_lease_get_message_type( lease_handle lease,
                                  int *message_type);

int dcal_wifi_lease_get_dns_servers( lease_handle lease,
                                  char *dns_servers, size_t buf_len);

int dcal_wifi_lease_get_dhcp_server( lease_handle lease,
                                  char *dhcp_server, size_t buf_len);

int dcal_wifi_lease_get_domain_name( lease_handle lease,
                                  char *domain_name, size_t buf_len);

int dcal_wifi_lease_get_renew( lease_handle lease,
                                  char *renew, size_t buf_len);

int dcal_wifi_lease_get_rebind( lease_handle lease,
                                  char *rebind, size_t buf_len);

int dcal_wifi_lease_get_expire( lease_handle lease,
                                  char *expire, size_t buf_len);

// Interface Default route Management
// dcal_wifi_default_route_pull will require the close_handle function to be called
// when done with the handle.
// If interface_name pointer is NULL, the first default route will be returned.
// If interface_name is a valid interface, a default route will be returned
// for that specific interface if one exists.
int dcal_wifi_default_route_pull( session_handle session,
                                  default_route_handle * default_route,
                                  char * interface_name);

int dcal_wifi_default_route_close_handle( default_route_handle interface);

int dcal_wifi_default_route_get_interface( default_route_handle default_route,
                                  char *interface, size_t buf_len);

int dcal_wifi_default_route_get_destination( default_route_handle default_route,
                                  char *destination, size_t buf_len);

int dcal_wifi_default_route_get_gateway( default_route_handle default_route,
                                  char *gateway, size_t buf_len);

int dcal_wifi_default_route_get_flags( default_route_handle default_route,
                                  int *flags);

int dcal_wifi_default_route_get_metric( default_route_handle default_route,
                                  unsigned int *metric);

int dcal_wifi_default_route_get_subnet_mask( default_route_handle default_route,
                                  char *subnet_mask, size_t buf_len);

int dcal_wifi_default_route_get_mtu( default_route_handle default_route,
                                  unsigned int *mtu);

int dcal_wifi_default_route_get_window( default_route_handle default_route,
                                  unsigned int *window);

int dcal_wifi_default_route_get_irtt( default_route_handle default_route,
                                  unsigned int *irtt);

// Wifi Scan
int dcal_wifi_pull_scan_list(session_handle session, size_t *count);
int dcal_wifi_get_scan_list_entry_ssid(session_handle session,
                                  int index, LRD_WF_SSID *ssid);
int dcal_wifi_get_scan_list_entry_bssid(session_handle session,
                         int index, unsigned char * bssid, int bssidbuflen);
int dcal_wifi_get_scan_list_entry_channel(session_handle session,
                                  int index, int * channel);
int dcal_wifi_get_scan_list_entry_rssi(session_handle session,
                                  int index, int * rssi);
int dcal_wifi_get_scan_list_entry_securityMask(session_handle session,
                                  int index, int * securityMask);
#ifndef _SDC_SDK_H_
typedef enum _LRD_WF_BSSTYPE {
    INFRASTRUCTURE = 0,
    ADHOC
} LRD_WF_BSSTYPE;
#endif
int dcal_wifi_get_scan_list_entry_type(session_handle session,
                                  int index, LRD_WF_BSSTYPE * bssType);

// WiFi Profile Management_
// both the create and pull functions will allocate a profile_handle
// that require the close_handle function to be called when done with then
// handle
int dcal_wifi_pull_profile_list(session_handle session, size_t *count);
int dcal_wifi_get_profile_list_entry_profilename(session_handle session, int index, char * profilename, size_t buflen);
int dcal_wifi_get_profile_list_entry_autoprofile(session_handle session, int index, bool *autoprofile);
int dcal_wifi_get_profile_list_entry_active(session_handle session, int index, bool * active);

int dcal_wifi_profile_create( profile_handle * profile);
int dcal_wifi_profile_pull( session_handle session,
                                 profile_handle * profile,
                                 char * profilename);
int dcal_wifi_profile_close_handle( profile_handle profile);

// push and profile_activate both send the local profile to the remote radio
// device.  Activate_by_name only activates the named profile on the remote
// radio
int dcal_wifi_profile_push( session_handle session,
                                 profile_handle profile);
int dcal_wifi_profile_activate( session_handle sesion,
                                     profile_handle profile);
int dcal_wifi_profile_activate_by_name( session_handle session,
                                          char * profile_name);
int dcal_wifi_profile_delete_from_device( session_handle session,
                                          char * profile_name);

int dcal_wifi_profile_set_profilename(profile_handle profile,
                                           char * profilename );
int dcal_wifi_profile_get_profilename(profile_handle profile,
                                      char * profilename, size_t buflen );

// note the SSID is not a string, as SSIDs can contain embedded non-ascii
// characters including embedded nulls  (the SDK on the device may not yet
// support non-ascii characters but handling it as if it can will allow us
// future capabilities)
int dcal_wifi_profile_set_SSID( profile_handle profile,
                                       LRD_WF_SSID *ssid);
int dcal_wifi_profile_get_SSID( profile_handle profile,
                                       LRD_WF_SSID *ssid);

typedef enum _encyption_standards {
	ES_NONE = 0,
	ES_WEP,
	ES_WPA,
	ES_WPA2,
	ES_CCKM
} ENCRYPT_STD;

// security
// setting an encryption standard will clear all security fields
// if ES_WEP is configured
// dcal_wifi_profile_set_eap should be used to signify Dynamic WEP (802.1x) is desired
// or
// dcal_wifi_profile_set_wep_key should be used to signify WEP 40/128 is desired
// most recent configured option will determine which is used
int dcal_wifi_profile_set_encrypt_std( profile_handle profile,
                                            ENCRYPT_STD estd);
int dcal_wifi_profile_get_encrypt_std( profile_handle profile,
                                            ENCRYPT_STD *estd);
typedef enum _encryption {
	ENC_NONE = 0,
	ENC_AES,
	ENC_TKIP,
} ENCRYPTION;

int dcal_wifi_profile_set_encryption( profile_handle profile,
                                           ENCRYPTION enc);
int dcal_wifi_profile_get_encryption( profile_handle profile,
                                           ENCRYPTION *enc);
#ifndef _SDC_SDK_H_
typedef enum _auth_type {
	AUTH_OPEN = 0,  // only valid in profiles - no globals
	AUTH_SHARED,
	AUTH_NETWORK_EAP,
} AUTH;
#endif
int dcal_wifi_profile_set_auth( profile_handle profile,
                                     AUTH auth);
int dcal_wifi_profile_get_auth( profile_handle profile,
                                     AUTH *auth);

int dcal_wifi_profile_set_eap( profile_handle profile,
                                    EAPTYPE eap);
int dcal_wifi_profile_get_eap( profile_handle profile,
                                    EAPTYPE *eap);

int dcal_wifi_profile_set_psk( profile_handle profile,
                                    char * psk);
int dcal_wifi_profile_psk_is_set( profile_handle profile,
                                    bool * psk);

int dcal_wifi_profile_set_user( profile_handle profile,
                                     char * user);
int dcal_wifi_profile_user_is_set( profile_handle profile,
                                     bool * user);

int dcal_wifi_profile_set_password( profile_handle profile,
                                         char * password);
int dcal_wifi_profile_password_is_set( profile_handle profile,
                                         bool * password);

int dcal_wifi_profile_set_cacert( profile_handle profile,
                                       char * cacert);
int dcal_wifi_profile_cacert_is_set( profile_handle profile,
                                       bool * cacert);

int dcal_wifi_profile_set_pacfile( profile_handle profile,
                                 char * pacfilename);
int dcal_wifi_profile_pacfile_is_set( profile_handle profile,
                                 bool * pacfilename);

int dcal_wifi_profile_set_pacpassword( profile_handle profile,
                                 char * pacpassword);
int dcal_wifi_profile_pacpassword_is_set( profile_handle profile,
                                 bool * pacpassword_buffer);

int dcal_wifi_profile_set_usercert( profile_handle profile,
                                 char * usercert);
int dcal_wifi_profile_usercert_is_set( profile_handle profile,
                                 bool * usercert);

int dcal_wifi_profile_set_usercert_password( profile_handle profile,
                                 char * usercert_password);
int dcal_wifi_profile_usercert_password_is_set( profile_handle profile,
                                 bool * usercert_password);

int dcal_wifi_profile_set_wep_key( profile_handle profile,
                                 char * wepkey, int index);
int dcal_wifi_profile_wep_key_is_set( profile_handle profile,
                                 bool * wepkey, int index);

int dcal_wifi_profile_set_wep_txkey( profile_handle profile,
                                 unsigned int txkey);
int dcal_wifi_profile_get_wep_txkey( profile_handle profile,
                                 unsigned int *txkey);

// other profile settings

int dcal_wifi_profile_set_clientname( profile_handle profile,
                                char * clientname);
int dcal_wifi_profile_get_clientname( profile_handle profile,
                                char * clientname_buffer, size_t buflen);

int dcal_wifi_profile_set_radiomode( profile_handle profile,
                                RADIOMODE mode);
int dcal_wifi_profile_get_radiomode( profile_handle profile,
                                RADIOMODE * mode);

int dcal_wifi_profile_set_powersave( profile_handle profile,
                               POWERSAVE powersave);
int dcal_wifi_profile_get_powersave( profile_handle profile,
                               POWERSAVE * powersave);

int dcal_wifi_profile_set_psp_delay( profile_handle profile,
                               unsigned int pspdelay);
int dcal_wifi_profile_get_psp_delay( profile_handle profile,
                               unsigned int * pspdelay);

int dcal_wifi_profile_set_txpower( profile_handle profile,
                               int txpower);
int dcal_wifi_profile_get_txpower( profile_handle profile,
                               int *txpower);

int dcal_wifi_profile_set_bitrate( profile_handle profile,
                               BITRATE bitrate);
int dcal_wifi_profile_get_bitrate( profile_handle profile,
                               BITRATE *bitrate);

int dcal_wifi_profile_set_autoprofile( profile_handle profile,
                               bool autoprofile);
int dcal_wifi_profile_get_autoprofile( profile_handle profile,
                               bool *autoprofile);

// Note that encrypted fields are not sent from the host.  Therefore
// printing out locally created fields will allow the viewing of the
// security fields, while printing profiles pulled from host will only
// show if the security field has been set or not.
void dcal_wifi_profile_printf( profile_handle profile);

// system controls

int dcal_wifi_restart( session_handle session);
// dcal_system_restart will close the session handle
int dcal_system_restart( session_handle session);

// Time functions
//  the values for the time_set and time_get functions are the same values
//  as those used in the structure passed to the system functions
//  gettimeofday() and settimeofday()
int dcal_time_set( session_handle session,
                      time_t tv_sec, suseconds_t tv_usec);
int dcal_time_get( session_handle session,
                      time_t *tv_sec, suseconds_t *tv_usec);

// the dcal_ntpdate() function takes a character string which contains
// the ntp server that will be placed on the command line for a call
// to ntpdate.  Example:
//      dcal_ntpdate( session, "pool.ntp.org");
// only [a-z],[0-9],[-./],[A-Z] characters are valid
int dcal_ntpdate( session_handle session,
                      char * server_name );
// file handling

// local_file is the full path and file name on host. remote_file can be
// NULL in which case the basename of local_file will be used. The
// remote_file will be saved to /tmp/ on WB.  NOTE: /tmp is not persistent
// ont he WB as /tmp is a ramdisk.
int dcal_file_push_to_wb(session_handle session,
                             char * local_file_name,
                             char * remote_file_name);

// remote_file_name is full path and filename on WB.  local_file_name is
// the full path and file name on host. local_file_name can be NULL in
// which case remote_file_name base name will be used in the local directory
int dcal_file_pull_from_wb(session_handle session,
                             char * remote_file_name,
                             char * local_file_name);

// local_cert_name is the full path and file name on local system.
// files will be transfered to the the certificate path
// which can be changed by dcal_wifi_global_set_cert_path()
int dcal_cert_push_to_wb(session_handle session,
                             char * local_cert_name);

typedef enum _fw_update_flags {
	FWU_FORCE            = 1 << 0, // force image overwrite
	FWU_DISABLE_NOTIFY   = 1 << 1, // disable notification when complete
	FWU_DISABLE_TRANSFER = 1 << 2  // disable transference
} FW_UPDATE_FLAGS;

// in order to issue the fw_update() function, the desired files must first
// be transfered to the remote device.  This includes the fw.txt file.  The
// files will be placed in the /tmp directory on the WB.  When this function
// is executed, firmware update will be attempted on the transfered fw.txt
// file in /tmp.  fw_update flags can be set in the flags variable.  Flags
// can also be set in the fw.txt file itself.
// NOTE: The disable reboot flag will be added by dcas so the user must
// specifically call dcal_system_restart() when desiring restart after
// fw_update.
int dcal_fw_update(session_handle session, int flags);

// dest_file is full location and file name where log should be saved
int dcal_pull_logs(session_handle session, char * dest_file);

// src_file is full location and file name where command file resides.
int dcal_process_cli_command_file(session_handle session, char * src_file);

// misc

const char *dcal_err_to_string( int code);

#ifdef __cplusplus
}
#endif
#endif //_DCAL_API_
