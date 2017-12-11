#include <boost/python.hpp>
#include <iostream>
#include <time.h>

#include "dcal_api.h"

// First have to "object-ize" our api, because we have handles, but we can't
// easily send those back and forth to python

class generic_int
{
  public:
	int gen_int;
};

class generic_uint
{
  public:
	int gen_uint;
};

class generic_string
{
  public:
	char _gen_string[STR_SZ];
	boost::python::object gen_string() const { return boost::python::object(_gen_string); }
};

class settings
{
  public:
	char _profilename[NAME_SZ];
	boost::python::object profilename() const { return boost::python::object(_profilename); }
	char _ssid[SSID_SZ];
	boost::python::object ssid() const { return boost::python::object(_ssid); }
	unsigned int ssid_len;
	char _mac[STR_SZ];
	boost::python::object mac() const { return boost::python::object(_mac); }
};

class ccx
{
  public:
	char _ap_ip[STR_SZ];
	boost::python::object ap_ip() const { return boost::python::object(_ap_ip); }
	char _ap_name[NAME_SZ];
	boost::python::object ap_name() const { return boost::python::object(_ap_name); }
	char _clientname[NAME_SZ];
	boost::python::object clientname() const { return boost::python::object(_clientname); }
};

class connection
{
  public:
	unsigned int cardstate;
	unsigned int channel;
	int rssi;
	char _ap_mac[STR_SZ];
	boost::python::object ap_mac() const { return boost::python::object(_ap_mac); }
};

class connection_extended
{
  public:
	unsigned int bitrate;
	unsigned int txpower;
	unsigned int dtim;
	unsigned int beaconperiod;
};

class profile_SSID
{
  public:
	int len;
	char _val[LRD_WF_MAX_SSID_LEN];
	boost::python::object val() const { return boost::python::object(_val); }
};

class dcal_time
{
  public:
	time_t tv_sec;
	suseconds_t tv_usec;
};

class dcal
{
  public:
	// Session management
	int session_create(void) { return dcal_session_create(&(this->session)); };
	int host(FQDN address) { return dcal_set_host(session, address); };
	int port(unsigned int port) { return dcal_set_port(session, port); };
	int user(char * user) { return dcal_set_user(session, user); };
	int pw(char * pw) { return dcal_set_pw(session, pw); };
	int session_open() { return dcal_session_open(session); };
	int session_close() { return dcal_session_close(session); };

	// Device Status
	int get_sdk_version( class generic_uint & g ){
		int ret;
		unsigned int sdk;

		ret = dcal_get_sdk_version( session, &sdk );

		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = sdk;
		}
		return ret;
	};

	int get_chipset_version( class generic_int & g ){
		int ret;
		RADIOCHIPSET chipset;

		ret = dcal_get_chipset_version( session, &chipset );

		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = chipset;
		}
		return ret;
	};

	int get_system_version( class generic_int & g ){
		int ret;
		LRD_SYSTEM sys;

		ret = dcal_get_system_version( session, &sys );

		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = sys;
		}
		return ret;
	};

	int get_driver_version( class generic_uint & g ){
		int ret;
		unsigned int driver;

		ret = dcal_get_driver_version( session, &driver );

		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = driver;
		}
		return ret;
	};

	int get_dcas_version( class generic_uint & g ){
		int ret;
		unsigned int dcas;

		ret = dcal_get_dcas_version( session, &dcas );

		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = dcas;
		}
		return ret;
	};

	int get_dcal_version( class generic_uint & g ){
		int ret;
		unsigned int dcal;

		ret = dcal_get_dcal_version( session, &dcal );

		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = dcal;
		}
		return ret;
	};

	int get_firmware_version( class generic_string & g ){
		int ret;
		char firmware[STR_SZ];

		ret = dcal_get_firmware_version( session, firmware, STR_SZ );

		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, firmware, STR_SZ);
		}
		return ret;
	};

	int get_supplicant_version( class generic_string & g ){
		int ret;
		char supplicant[STR_SZ];

		ret = dcal_get_supplicant_version( session, supplicant, STR_SZ );

		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, supplicant, STR_SZ);
		}
		return ret;
	};

	int get_release_version( class generic_string & g ){
		int ret;
		char release[STR_SZ];

		ret = dcal_get_release_version( session, release, STR_SZ );

		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, release, STR_SZ);
		}
		return ret;
	};

	int device_status_pull() { return dcal_device_status_pull(session); };

	int device_status_get_settings(class settings & s) {
		int ret;
		char profilename[NAME_SZ];
		LRD_WF_SSID ssid={0};
		unsigned char mac[MAC_SZ];
		ret = dcal_device_status_get_settings( session, profilename, NAME_SZ,
							&ssid, mac, MAC_SZ);

		if (ret == DCAL_SUCCESS)
		{
			char string_mac[STR_SZ];
			sprintf(string_mac, "%x:%x:%x:%x:%x:%x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

			strncpy(s._profilename, profilename, NAME_SZ);
			memcpy(s._ssid, ssid.val, LRD_WF_MAX_SSID_LEN);
			s.ssid_len = ssid.len;
			strncpy(s._mac, string_mac, STR_SZ);
		}
		return ret;
	}

	int device_status_get_ccx(class ccx & c) {
		int ret;
		unsigned char ap_ip[IP4_SZ];
		char ap_name[NAME_SZ];
		char clientname[NAME_SZ];

		ret = dcal_device_status_get_ccx( session, ap_ip, IP4_SZ, ap_name, NAME_SZ, clientname, NAME_SZ);

		if (ret == DCAL_SUCCESS)
		{
			char string_ap_ip[STR_SZ];

			sprintf(string_ap_ip, "%i.%i.%i.%i", ap_ip[0],ap_ip[1],ap_ip[2],ap_ip[3]);

			strncpy(c._ap_ip, string_ap_ip, STR_SZ);
			strncpy(c._ap_name, ap_name, NAME_SZ);
			strncpy(c._clientname, clientname, NAME_SZ);
		}
		return ret;
	}

	int device_status_get_ipv4( class generic_string & g ) {
		int ret;
		unsigned char ipv4[IP4_SZ];
		ret = dcal_device_status_get_ipv4(session, ipv4, IP4_SZ);
		if (ret == DCAL_SUCCESS)
		{
			char string_ipv4[STR_SZ];
			sprintf(string_ipv4, "%i.%i.%i.%i", ipv4[0],ipv4[1],ipv4[2],ipv4[3]);
			strncpy(g._gen_string, string_ipv4, STR_SZ);
		}
		return ret;
	}

	int device_status_get_ipv6_count( class generic_int & g ) {
		int ret;
		size_t count;
		ret = dcal_device_status_get_ipv6_count(session, &count);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = count;
		}
		return ret;
	}

	int device_status_get_ipv6_string_at_index(unsigned int index, class generic_string & g ) {
		int ret;
		char ipv6[IP6_STR_SZ];
		ret = dcal_device_status_get_ipv6_string_at_index(session, index, ipv6, IP6_STR_SZ);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, ipv6, IP6_STR_SZ);
		}
		return ret;
	}

	int device_status_get_connection(class connection & c) {
		int ret;
		unsigned int cardstate;
		unsigned int channel;
		int rssi;
		unsigned char ap_mac[MAC_SZ];
		ret = dcal_device_status_get_connection( session,
							&cardstate,
							&channel,
							&rssi,
							ap_mac,
							MAC_SZ
							);

		if (ret == DCAL_SUCCESS)
		{
			char string_ap_mac[STR_SZ];

			sprintf(string_ap_mac, "%x:%x:%x:%x:%x:%x", ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);

			c.cardstate = cardstate;
			c.channel = channel;
			c.rssi = rssi;
			strncpy(c._ap_mac, string_ap_mac, STR_SZ);
		}
		return ret;
	}

	int device_status_get_connection_extended(class connection_extended & c) {
		int ret;
		unsigned int bitrate;
		unsigned int txpower;
		unsigned int dtim;
		unsigned int beaconperiod;
		ret =  dcal_device_status_get_connection_extended( session,
							&bitrate,
							&txpower,
							&dtim,
							&beaconperiod);

		if (ret == DCAL_SUCCESS)
		{
			c.bitrate = bitrate;
			c.txpower = txpower;
			c.dtim = dtim;
			c.beaconperiod = beaconperiod;
		}
		return ret;
	}
	// WiFi Management
	int wifi_enable() { return dcal_wifi_enable( session ); }
	int wifi_disable() { return dcal_wifi_disable( session ); }

	// WiFi Global Management
	int wifi_global_create() { return dcal_wifi_global_create( &global ); }
	int wifi_global_pull() { return dcal_wifi_global_pull(session, &global); }
	int wifi_global_close_handle() { return dcal_wifi_global_close_handle( global ); }
	int wifi_global_push() { return dcal_wifi_global_push( session, global ); }

	int wifi_global_set_auth_server( int server_auth ) {
		SERVER_AUTH auth;
		auth = (SERVER_AUTH) server_auth;
		return dcal_wifi_global_set_auth_server(global, auth);
	}

	int wifi_global_get_auth_server( class generic_int & g ) {
		int ret;
		SERVER_AUTH auth;
		ret = dcal_wifi_global_get_auth_server(global, &auth);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) auth;
		}
		return ret;
	}

	int wifi_global_set_achannel_mask( unsigned int channel_set_a ) { return dcal_wifi_global_set_achannel_mask(global, channel_set_a); }
	int wifi_global_get_achannel_mask( class generic_uint & g ) {
		int ret;
		unsigned int channel_set_a;
		ret = dcal_wifi_global_get_achannel_mask(global, &channel_set_a);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = channel_set_a;
		}
		return ret;
	}

	int wifi_global_set_bchannel_mask( unsigned int channel_set_b ) { return dcal_wifi_global_set_bchannel_mask(global, channel_set_b); }
	int wifi_global_get_bchannel_mask( class generic_uint & g ) {
		int ret;
		unsigned int channel_set_b;
		ret = dcal_wifi_global_get_bchannel_mask(global, &channel_set_b);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = channel_set_b;
		}
		return ret;
	}

	int wifi_global_set_auto_profile( bool auto_profile ) { return dcal_wifi_global_set_auto_profile(global, auto_profile); }
	int wifi_global_get_auto_profile( class generic_int & g ) {
		int ret;
		bool auto_profile;
		ret = dcal_wifi_global_get_auto_profile(global, &auto_profile);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) auto_profile;
		}
		return ret;
	}

	int wifi_global_set_beacon_miss( unsigned int beacon_miss ) { return dcal_wifi_global_set_beacon_miss(global, beacon_miss); }
	int wifi_global_get_beacon_miss( class generic_uint & g ) {
		int ret;
		unsigned int beacon_miss;
		ret = dcal_wifi_global_get_beacon_miss(global, &beacon_miss);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = beacon_miss;
		}
		return ret;
	}

	int wifi_global_set_ccx( bool ccx ) { return dcal_wifi_global_set_ccx(global, ccx); }
	int wifi_global_get_ccx( class generic_int & g ) {
		int ret;
		bool ccx;
		ret = dcal_wifi_global_get_ccx(global, &ccx);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) ccx;
		}
		return ret;
	}

	int wifi_global_set_cert_path( char * cert_path ) { return dcal_wifi_global_set_cert_path(global, cert_path); }
	int wifi_global_get_cert_path( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char cert_path[buf_len];
		ret = dcal_wifi_global_get_cert_path(global, cert_path, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			memcpy(g._gen_string, cert_path, buf_len);
		}
		return ret;
	}

	int wifi_global_set_date_check( bool date_check ) { return dcal_wifi_global_set_date_check(global, date_check); }
	int wifi_global_get_date_check( class generic_int & g ) {
		int ret;
		bool date_check;
		ret = dcal_wifi_global_get_date_check(global, &date_check);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) date_check;
		}
		return ret;
	}

	int wifi_global_set_def_adhoc_channel( unsigned int def_adhoc_channel ) { return dcal_wifi_global_set_def_adhoc_channel(global, def_adhoc_channel); }
	int wifi_global_get_def_adhoc_channel( class generic_uint & g ) {
		int ret;
		unsigned int def_adhoc_channel;
		ret = dcal_wifi_global_get_def_adhoc_channel(global, &def_adhoc_channel);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = def_adhoc_channel;
		}
		return ret;
	}

	int wifi_global_set_fips( bool fips ) { return dcal_wifi_global_set_fips(global, fips); }
	int wifi_global_get_fips( class generic_int & g ) {
		int ret;
		bool fips;
		ret = dcal_wifi_global_get_fips(global, &fips);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) fips;
		}
		return ret;
	}

	int wifi_global_set_pmk( int pmk_cache ) {
		DCAL_PMK_CACHING pmk;
		pmk = (DCAL_PMK_CACHING) pmk_cache;
		return dcal_wifi_global_set_pmk(global, pmk);
	}

	int wifi_global_get_pmk( class generic_int & g ) {
		int ret;
		DCAL_PMK_CACHING pmk;
		ret = dcal_wifi_global_get_pmk(global, &pmk);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) pmk;
		}
		return ret;
	}

	int wifi_global_set_probe_delay( unsigned int probe_delay ) { return dcal_wifi_global_set_probe_delay(global, probe_delay); }
	int wifi_global_get_probe_delay( class generic_uint & g ) {
		int ret;
		unsigned int probe_delay;
		ret = dcal_wifi_global_get_probe_delay(global, &probe_delay);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = probe_delay;
		}
		return ret;
	}

	int wifi_global_get_regdomain( class generic_int & g ) {
		int ret;
		REG_DOMAIN regdomain;
		ret = dcal_wifi_global_get_regdomain(global, &regdomain);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) regdomain;
		}
		return ret;
	}

	int wifi_global_set_roam_periodms( unsigned int roam_periodms ) { return dcal_wifi_global_set_roam_periodms(global, roam_periodms); }
	int wifi_global_get_roam_periodms( class generic_uint & g ) {
		int ret;
		unsigned int roam_periodms;
		ret = dcal_wifi_global_get_roam_periodms(global, &roam_periodms);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = roam_periodms;
		}
		return ret;
	}

	int wifi_global_set_roam_trigger( unsigned int roam_trigger ) { return dcal_wifi_global_set_roam_trigger(global, roam_trigger); }
	int wifi_global_get_roam_trigger( class generic_uint & g ) {
		int ret;
		unsigned int roam_trigger;
		ret = dcal_wifi_global_get_roam_trigger(global, &roam_trigger);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = roam_trigger;
		}
		return ret;
	}

	int wifi_global_set_rts( unsigned int rts ) { return dcal_wifi_global_set_rts(global, rts); }
	int wifi_global_get_rts( class generic_uint & g ) {
		int ret;
		unsigned int rts;
		ret = dcal_wifi_global_get_rts(global, &rts);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = rts;
		}
		return ret;
	}

	int wifi_global_set_scan_dfs_time( unsigned int scan_dfs ) { return dcal_wifi_global_set_scan_dfs_time(global, scan_dfs); }
	int wifi_global_get_scan_dfs_time( class generic_uint & g ) {
		int ret;
		unsigned int scan_dfs;
		ret = dcal_wifi_global_get_scan_dfs_time(global, &scan_dfs);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = scan_dfs;
		}
		return ret;
	}

	int wifi_global_set_ttls_inner_method( int ttls_inner ) {
		TTLS_INNER_METHOD ttls_inner_method;
		ttls_inner_method = (TTLS_INNER_METHOD) ttls_inner;
		return dcal_wifi_global_set_ttls_inner_method(global, ttls_inner_method);
	}

	int wifi_global_get_ttls_inner_method( class generic_int & g ) {
		int ret;
		TTLS_INNER_METHOD ttls_inner_method;
		ret = dcal_wifi_global_get_ttls_inner_method(global, &ttls_inner_method);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) ttls_inner_method;
		}
		return ret;
	}

	int wifi_global_set_uapsd( bool uapsd ) { return dcal_wifi_global_set_uapsd(global, uapsd); }
	int wifi_global_get_uapsd( class generic_int & g ) {
		int ret;
		bool uapsd;
		ret = dcal_wifi_global_get_uapsd(global, &uapsd);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) uapsd;
		}
		return ret;
	}

	int wifi_global_set_wmm( bool wmm ) { return dcal_wifi_global_set_wmm(global, wmm); }
	int wifi_global_get_wmm( class generic_int & g ) {
		int ret;
		bool wmm;
		ret = dcal_wifi_global_get_wmm(global, &wmm);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) wmm;
		}
		return ret;
	}

	int wifi_global_set_ignore_null_ssid( bool ignore_null_ssid ) { return dcal_wifi_global_set_ignore_null_ssid(global, ignore_null_ssid); }
	int wifi_global_get_ignore_null_ssid( class generic_int & g ) {
		int ret;
		bool ignore_null_ssid;
		ret = dcal_wifi_global_get_ignore_null_ssid(global, &ignore_null_ssid);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) ignore_null_ssid;
		}
		return ret;
	}

	int wifi_global_set_dfs_channels( int dfs ) {
		DFS_CHANNELS dfs_channels;
		dfs_channels = (DFS_CHANNELS) dfs;
		return dcal_wifi_global_set_dfs_channels(global, dfs_channels);
	}

	int wifi_global_get_dfs_channels( class generic_int & g ) {
		int ret;
		DFS_CHANNELS dfs_channels;
		ret = dcal_wifi_global_get_dfs_channels(global, &dfs_channels);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) dfs_channels;
		}
		return ret;
	}

	void wifi_global_printf() { return dcal_wifi_global_printf(global); }

	// Wifi Scan
	int wifi_pull_scan_list( class generic_int & g ) {
		int ret;
		size_t scan_count;
		ret =  dcal_wifi_pull_scan_list(session, &scan_count);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = scan_count;
		}
		return ret;
	}
	int wifi_get_scan_list_entry_ssid(int index, class profile_SSID & s) {
		int ret;
		LRD_WF_SSID ssid={0};
		ret = dcal_wifi_get_scan_list_entry_ssid( session, index, &ssid );
		if (ret == DCAL_SUCCESS)
		{
			s.len = ssid.len;
			memcpy(s._val, ssid.val, LRD_WF_MAX_SSID_LEN);
		}
		return ret;
	}
	int wifi_get_scan_list_entry_bssid( int index, class generic_string & g) {
		int ret;
		unsigned char bssid[MAC_SZ];
		ret =  dcal_wifi_get_scan_list_entry_bssid(session, index, bssid, MAC_SZ);
		if (ret == DCAL_SUCCESS)
		{
			char string_bssid[STR_SZ];
			sprintf(string_bssid, "%x:%x:%x:%x:%x:%x", bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
			strncpy(g._gen_string, string_bssid, STR_SZ);
		}
		return ret;
	}

	int wifi_get_scan_list_entry_channel( int index, class generic_int & g) {
		int ret;
		int channel;
		ret = dcal_wifi_get_scan_list_entry_channel(session, index, &channel);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = channel;
		}
		return ret;
	}


	int wifi_get_scan_list_entry_rssi( int index, class generic_int & g) {
		int ret;
		int rssi;
		ret = dcal_wifi_get_scan_list_entry_rssi(session, index, &rssi);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = rssi;
		}
		return ret;
	}

	int wifi_get_scan_list_entry_securityMask( int index, class generic_int & g) {
		int ret;
		int securityMask;
		ret = dcal_wifi_get_scan_list_entry_securityMask(session, index, &securityMask);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = securityMask;
		}
		return ret;
	}

	int wifi_get_scan_list_entry_type( int index, class generic_int & g ) {
		int ret;
		LRD_WF_BSSTYPE bssType;
		ret = dcal_wifi_get_scan_list_entry_type(session, index, &bssType);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) bssType;
		}
		return ret;
	}

	// WiFi Profile Management
	int wifi_pull_profile_list( class generic_int & g ) {
		int ret;
		size_t profile_count;
		ret = dcal_wifi_pull_profile_list(session, &profile_count);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = profile_count;
		}
		return ret;
	}
	int wifi_get_profile_list_entry_profilename( int index, class generic_string & g) {
		int ret;
		char profilename[CONFIG_NAME_SZ];
		ret = dcal_wifi_get_profile_list_entry_profilename(session, index, profilename, CONFIG_NAME_SZ);
		if (ret == DCAL_SUCCESS)
		{
			memcpy(g._gen_string, profilename, CONFIG_NAME_SZ);
		}
		return ret;
	}
	int wifi_get_profile_list_entry_autoprofile( int index, class generic_int & g ) {
		int ret;
		bool autoprofile;
		ret = dcal_wifi_get_profile_list_entry_autoprofile(session, index, &autoprofile);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) autoprofile;
		}
		return ret;
	}

	int wifi_get_profile_list_entry_active( int index, class generic_int & g ) {
		int ret;
		bool active;
		ret = dcal_wifi_get_profile_list_entry_active(session, index, &active);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) active;
		}
		return ret;
	}

	int wifi_profile_create() { return dcal_wifi_profile_create( &profile ); }
	int wifi_profile_pull( char * profilename ) { return dcal_wifi_profile_pull(session, &profile, profilename); }
	int wifi_profile_close_handle() { return dcal_wifi_profile_close_handle( profile ); }
	int wifi_profile_push() { return dcal_wifi_profile_push( session, profile ); }
	int wifi_profile_activate_by_name( char * profilename ) { return dcal_wifi_profile_activate_by_name(session, profilename); }
	int wifi_profile_delete_from_device( char * profilename ) { return dcal_wifi_profile_delete_from_device(session, profilename); }
	int wifi_profile_set_profilename( char * profilename ) { return dcal_wifi_profile_set_profilename(profile, profilename); }
	int wifi_profile_get_profilename( class generic_string & g ) {
		int ret;
		char profilename[CONFIG_NAME_SZ];
		ret = dcal_wifi_profile_get_profilename(profile, profilename, CONFIG_NAME_SZ);
		if (ret == DCAL_SUCCESS)
		{
			memcpy(g._gen_string, profilename, CONFIG_NAME_SZ);
		}
		return ret;
	}
	int wifi_profile_set_SSID( char * profilename ) {
		LRD_WF_SSID *ssid;
		strcpy((char*)ssid->val, profilename);
		ssid->len = strlen((char*)ssid->val);
		return dcal_wifi_profile_set_SSID(profile, ssid);
	}

	int wifi_profile_get_SSID( class profile_SSID & s ) {
		int ret;
		LRD_WF_SSID ssid={0};
		ret = dcal_wifi_profile_get_SSID( profile, &ssid );
		if (ret == DCAL_SUCCESS)
		{
			s.len = ssid.len;
			memcpy(s._val, ssid.val, LRD_WF_MAX_SSID_LEN);
		}
		return ret;
	}

	int wifi_profile_set_encrypt_std( int encryption_std ) {
		ENCRYPT_STD estd;
		estd = (ENCRYPT_STD) encryption_std;
		return dcal_wifi_profile_set_encrypt_std(profile, estd);
	}

	int wifi_profile_get_encrypt_std( class generic_int & g ) {
		int ret;
		ENCRYPT_STD encryption_std;
		ret = dcal_wifi_profile_get_encrypt_std(profile, &encryption_std);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) encryption_std;
		}
		return ret;
	}

	int wifi_profile_set_encryption( int encrypt ) {
		ENCRYPTION encryption;
		encryption = (ENCRYPTION) encrypt;
		return dcal_wifi_profile_set_encryption(profile, encryption);
	}

	int wifi_profile_get_encryption( class generic_int & g ) {
		int ret;
		ENCRYPTION encryption;
		ret = dcal_wifi_profile_get_encryption(profile, &encryption);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) encryption;
		}
		return ret;
	}

	int wifi_profile_set_auth( int auth_type ) {
		AUTH auth;
		auth = (AUTH) auth_type;
		return dcal_wifi_profile_set_auth(profile, auth);
	}

	int wifi_profile_get_auth( class generic_int & g ) {
		int ret;
		AUTH auth;
		ret = dcal_wifi_profile_get_auth(profile, &auth);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) auth;
		}
		return ret;
	}

	int wifi_profile_set_eap( int eap_type ) {
		EAPTYPE eap;
		eap = (EAPTYPE) eap_type;
		return dcal_wifi_profile_set_eap(profile, eap);
	}

	int wifi_profile_get_eap( class generic_int & g ) {
		int ret;
		EAPTYPE eap;
		ret = dcal_wifi_profile_get_eap(profile, &eap);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) eap;
		}
		return ret;
	}

	int wifi_profile_set_psk( char * psk ) { return dcal_wifi_profile_set_psk(profile, psk); }
	int wifi_profile_psk_is_set( class generic_int & g ) {
		int ret;
		bool psk;
		ret = dcal_wifi_profile_psk_is_set(profile, &psk);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) psk;
		}
		return ret;
	}

	int wifi_profile_set_user( char * user ) { return dcal_wifi_profile_set_user(profile, user); }
	int wifi_profile_user_is_set( class generic_int & g ) {
		int ret;
		bool user;
		ret = dcal_wifi_profile_user_is_set(profile, &user);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) user;
		}
		return ret;
	}

	int wifi_profile_set_password( char * password ) { return dcal_wifi_profile_set_password(profile, password); }
	int wifi_profile_password_is_set( class generic_int & g ) {
		int ret;
		bool password;
		ret = dcal_wifi_profile_user_is_set(profile, &password);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) password;
		}
		return ret;
	}

	int wifi_profile_set_cacert( char * cacert ) { return dcal_wifi_profile_set_cacert(profile, cacert); }
	int wifi_profile_cacert_is_set( class generic_int & g ) {
		int ret;
		bool cacert;
		ret = dcal_wifi_profile_cacert_is_set(profile, &cacert);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) cacert;
		}
		return ret;
	}

	int wifi_profile_set_pacfile( char * pacfilename ) { return dcal_wifi_profile_set_pacfile(profile, pacfilename); }
	int wifi_profile_pacfile_is_set( class generic_int & g ) {
		int ret;
		bool pacfile;
		ret = dcal_wifi_profile_pacfile_is_set(profile, &pacfile);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) pacfile;
		}
		return ret;
	}

	int wifi_profile_set_pacpassword( char * pacpassword ) { return dcal_wifi_profile_set_pacpassword(profile, pacpassword); }
	int wifi_profile_pacpassword_is_set( class generic_int & g ) {
		int ret;
		bool pacpassword;
		ret = dcal_wifi_profile_pacpassword_is_set(profile, &pacpassword);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) pacpassword;
		}
		return ret;
	}

	int wifi_profile_set_usercert( char * usercert ) { return dcal_wifi_profile_set_usercert(profile, usercert); }
	int wifi_profile_usercert_is_set( class generic_int & g ) {
		int ret;
		bool usercert;
		ret = dcal_wifi_profile_usercert_is_set(profile, &usercert);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) usercert;
		}
		return ret;
	}

	int wifi_profile_set_usercert_password( char * usercert_password ) { return dcal_wifi_profile_set_usercert_password(profile, usercert_password); }
	int wifi_profile_usercert_password_is_set( class generic_int & g ) {
		int ret;
		bool usercert_password;
		ret = dcal_wifi_profile_usercert_password_is_set(profile, &usercert_password);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) usercert_password;
		}
		return ret;
	}

	int wifi_profile_set_wep_key( char * wepkey, int index ) { return dcal_wifi_profile_set_wep_key(profile, wepkey, index); }
	int wifi_profile_wep_key_is_set( class generic_int & g, int wep_index ) {
		int ret;
		bool wep_key;
		int index = (int) wep_index;
		ret = dcal_wifi_profile_wep_key_is_set(profile, &wep_key, index);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) wep_key;
		}
		return ret;
	}

	int wifi_profile_set_wep_txkey( unsigned int txkey) { return dcal_wifi_profile_set_wep_txkey(profile, txkey); }
	int wifi_profile_get_wep_txkey( class generic_uint & g ) {
		int ret;
		unsigned int txkey;
		ret = dcal_wifi_profile_get_wep_txkey(profile, &txkey);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = txkey;
		}
		return ret;
	}

	int wifi_profile_set_clientname( char * clientname ) { return dcal_wifi_profile_set_clientname(profile, clientname); }
	int wifi_profile_get_clientname( class generic_string & g ) {
		int ret;
		char clientname_buffer[CLIENT_NAME_SZ];
		ret = dcal_wifi_profile_get_clientname(profile, clientname_buffer, CLIENT_NAME_SZ);
		if (ret == DCAL_SUCCESS)
		{
			memcpy(g._gen_string, clientname_buffer, CLIENT_NAME_SZ);
		}
		return ret;
	}

	int wifi_profile_set_radiomode( int radio_mode ) {
		RADIOMODE mode;
		mode = (RADIOMODE) radio_mode;
		return dcal_wifi_profile_set_radiomode(profile, mode);
	}

	int wifi_profile_get_radiomode( class generic_int & g ) {
		int ret;
		RADIOMODE mode;
		ret = dcal_wifi_profile_get_radiomode(profile, &mode);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) mode;
		}
		return ret;
	}

	int wifi_profile_set_powersave( int power_save ) {
		POWERSAVE powersave;
		powersave = (POWERSAVE) power_save;
		return dcal_wifi_profile_set_powersave(profile, powersave);
	}

	int wifi_profile_get_powersave( class generic_int & g ) {
		int ret;
		POWERSAVE powersave;
		ret = dcal_wifi_profile_get_powersave(profile, &powersave);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) powersave;
		}
		return ret;
	}

	int wifi_profile_set_psp_delay( unsigned int pspdelay) { return dcal_wifi_profile_set_psp_delay(profile, pspdelay); }
	int wifi_profile_get_psp_delay( class generic_uint & g ) {
		int ret;
		unsigned int pspdelay;
		ret = dcal_wifi_profile_get_psp_delay(profile, &pspdelay);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_uint = pspdelay;
		}
		return ret;
	}

	int wifi_profile_set_txpower( int txpower) { return dcal_wifi_profile_set_txpower(profile, txpower); }
	int wifi_profile_get_txpower( class generic_int & g ) {
		int ret;
		int txpower;
		ret = dcal_wifi_profile_get_txpower(profile, &txpower);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = txpower;
		}
		return ret;
	}

	int wifi_profile_set_bitrate( int bit_rate ) {
		BITRATE bitrate;
		bitrate = (BITRATE) bit_rate;
		return dcal_wifi_profile_set_bitrate(profile, bitrate);
	}

	int wifi_profile_get_bitrate( class generic_int & g ) {
		int ret;
		BITRATE bitrate;
		ret = dcal_wifi_profile_get_bitrate(profile, &bitrate);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) bitrate;
		}
		return ret;
	}

	int wifi_profile_set_autoprofile( bool autoprofile) { return dcal_wifi_profile_set_autoprofile(profile, autoprofile); }
	int wifi_profile_get_autoprofile( class generic_int & g ) {
		int ret;
		bool autoprofile;
		ret = dcal_wifi_profile_get_autoprofile(profile, &autoprofile);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) autoprofile;
		}
		return ret;
	}

	void wifi_profile_printf() { return dcal_wifi_profile_printf(profile); }

	// system controls
	int wifi_restart() { return dcal_wifi_restart(session); }
	int system_restart() { return dcal_system_restart(session); }

	int time_set( time_t tv_sec, suseconds_t tv_usec ){ return dcal_time_set(session, tv_sec, tv_usec); }
	int time_get( class dcal_time & t ){
		int ret;
		struct timeval tv;

		ret =  dcal_time_get(session, &tv.tv_sec, &tv.tv_usec);
		if (ret == DCAL_SUCCESS)
		{
			t.tv_sec = tv.tv_sec;
			t.tv_usec = tv.tv_usec;
		}

		return ret;
	}

	int ntpdate( char * server_name ){ return dcal_ntpdate(session, server_name); }

	// file handling
	int file_push_to_wb( char * local_file_name, char * remote_file_name ) { return dcal_file_push_to_wb(session, local_file_name, remote_file_name); }
	int file_pull_from_wb( char * remote_file_name, char * local_file_name ) { return dcal_file_pull_from_wb(session, remote_file_name, local_file_name); }
	int fw_update( int flags ) { return dcal_fw_update(session, flags); }
	int pull_logs( char * dest_file ) { return dcal_pull_logs(session, dest_file); }
	int process_cli_command_file( char * src_file ) { return dcal_process_cli_command_file(session, src_file); }

	// interface handling
	int interface_create() { return dcal_wifi_interface_create( &interface ); }
	int interface_pull( char * interface_name ) { return dcal_wifi_interface_pull(session, &interface, interface_name); }
	int interface_close_handle() { return dcal_wifi_interface_close_handle( interface ); }
	int interface_push() { return dcal_wifi_interface_push( session, interface ); }
	int interface_delete( char * interface_name ) { return dcal_wifi_interface_delete(session, interface_name); }
	int interface_set_interface_name( char * interface_name ) { return dcal_wifi_interface_set_interface_name(interface, interface_name); }
	int interface_get_ipv4_state( class generic_int & g ) {
		int ret;
		bool state;
		ret = dcal_wifi_interface_get_ipv4_state(interface, &state);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) state;
		}
		return ret;
	}

	int interface_set_method( char * method ) { return dcal_wifi_interface_set_method(interface, method); }
	int interface_get_method( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char method[buf_len];
		ret = dcal_wifi_interface_get_method(interface, method, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, method, buf_len);
		}
		return ret;
	}

	int interface_set_auto_start( bool auto_start ) { return dcal_wifi_interface_set_auto_start(interface, auto_start); }
	int interface_get_auto_start( class generic_int & g ) {
		int ret;
		bool auto_start;
		ret = dcal_wifi_interface_get_auto_start(interface, &auto_start);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) auto_start;
		}
		return ret;
	}

	int interface_set_address( char * address ) { return dcal_wifi_interface_set_address(interface, address); }
	int interface_get_address( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char address[buf_len];
		ret = dcal_wifi_interface_get_address(interface, address, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, address, buf_len);
		}
		return ret;
	}

	int interface_set_netmask( char * netmask ) { return dcal_wifi_interface_set_netmask(interface, netmask); }
	int interface_get_netmask( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char netmask[buf_len];
		ret = dcal_wifi_interface_get_netmask(interface, netmask, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, netmask, buf_len);
		}
		return ret;
	}

	int interface_set_gateway( char * gateway ) { return dcal_wifi_interface_set_gateway(interface, gateway); }
	int interface_get_gateway( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char gateway[buf_len];
		ret = dcal_wifi_interface_get_gateway(interface, gateway, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, gateway, buf_len);
		}
		return ret;
	}

	int interface_set_broadcast_address( char * broadcast ) { return dcal_wifi_interface_set_broadcast_address(interface, broadcast); }
	int interface_get_broadcast_address( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char broadcast[buf_len];
		ret = dcal_wifi_interface_get_broadcast_address(interface, broadcast, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, broadcast, buf_len);
		}
		return ret;
	}

	int interface_set_nameserver( char * nameserver ) { return dcal_wifi_interface_set_nameserver(interface, nameserver); }
	int interface_get_nameserver( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char nameserver[buf_len];
		ret = dcal_wifi_interface_get_nameserver(interface, nameserver, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, nameserver, buf_len);
		}
		return ret;
	}

	int interface_set_state( bool state ) { return dcal_wifi_interface_set_state(interface, state); }
	int interface_set_bridge( bool bridge ) { return dcal_wifi_interface_set_bridge(interface, bridge); }
	int interface_get_bridge( class generic_int & g ) {
		int ret;
		bool bridge;
		ret = dcal_wifi_interface_get_bridge(interface, &bridge);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) bridge;
		}
		return ret;
	}

	int interface_set_ap_mode( bool ap_mode ) { return dcal_wifi_interface_set_ap_mode(interface, ap_mode); }
	int interface_get_ap_mode( class generic_int & g ) {
		int ret;
		bool ap_mode;
		ret = dcal_wifi_interface_get_ap_mode(interface, &ap_mode);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) ap_mode;
		}
		return ret;
	}
	int interface_set_nat( bool nat ) { return dcal_wifi_interface_set_nat(interface, nat); }
	int interface_get_nat( class generic_int & g ) {
		int ret;
		bool nat;
		ret = dcal_wifi_interface_get_nat(interface, &nat);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) nat;
		}
		return ret;
	}

	int interface_clear_property( int prop ) {
		INTERFACE_PROPERTY interface_prop;
		interface_prop = (INTERFACE_PROPERTY) prop;
		return dcal_wifi_interface_clear_property(interface, interface_prop);
	}

	int interface_get_ipv6_state( class generic_int & g ) {
		int ret;
		bool state6;
		ret = dcal_wifi_interface_get_ipv6_state(interface, &state6);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) state6;
		}
		return ret;
	}

	int interface_set_dhcp6( char * dhcp6 ) { return dcal_wifi_interface_set_dhcp6(interface, dhcp6); }
	int interface_get_dhcp6( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char dhcp6[buf_len];
		ret = dcal_wifi_interface_get_dhcp6(interface, dhcp6, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, dhcp6, buf_len);
		}
		return ret;
	}

	int interface_set_method6( char * method6 ) { return dcal_wifi_interface_set_method6(interface, method6); }
	int interface_get_method6( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char method6[buf_len];
		ret = dcal_wifi_interface_get_method6(interface, method6, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, method6, buf_len);
		}
		return ret;
	}

	int interface_set_address6( char * address6 ) { return dcal_wifi_interface_set_address6(interface, address6); }
	int interface_get_address6( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char address6[buf_len];
		ret = dcal_wifi_interface_get_address6(interface, address6, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, address6, buf_len);
		}
		return ret;
	}

	int interface_set_netmask6( char * netmask6 ) { return dcal_wifi_interface_set_netmask6(interface, netmask6); }
	int interface_get_netmask6( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char netmask6[buf_len];
		ret = dcal_wifi_interface_get_netmask6(interface, netmask6, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, netmask6, buf_len);
		}
		return ret;
	}

	int interface_set_gateway6( char * gateway6 ) { return dcal_wifi_interface_set_gateway6(interface, gateway6); }
	int interface_get_gateway6( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char gateway6[buf_len];
		ret = dcal_wifi_interface_get_gateway6(interface, gateway6, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, gateway6, buf_len);
		}
		return ret;
	}

	int interface_set_nameserver6( char * nameserver6 ) { return dcal_wifi_interface_set_nameserver6(interface, nameserver6); }
	int interface_get_nameserver6( class generic_string & g ) {
		int ret;
		size_t buf_len = STR_SZ;
		char nameserver6[buf_len];
		ret = dcal_wifi_interface_get_nameserver6(interface, nameserver6, buf_len);
		if (ret == DCAL_SUCCESS)
		{
			strncpy(g._gen_string, nameserver6, buf_len);
		}
		return ret;
	}

	int interface_set_state6( bool state6 ) { return dcal_wifi_interface_set_state6(interface, state6); }
	int interface_set_nat6( bool nat6 ) { return dcal_wifi_interface_set_nat6(interface, nat6); }
	int interface_get_nat6( class generic_int & g ) {
		int ret;
		bool nat6;
		ret = dcal_wifi_interface_get_nat6(interface, &nat6);
		if (ret == DCAL_SUCCESS)
		{
			g.gen_int = (int) nat6;
		}
		return ret;
	}

	int interface_clear_property6( int prop6 ) {
		INTERFACE_PROPERTY interface_prop6;
		interface_prop6 = (INTERFACE_PROPERTY) prop6;
		return dcal_wifi_interface_clear_property6(interface, interface_prop6);
	}

  private:
	laird_session_handle session;
	laird_profile_handle profile;
	laird_global_handle global;
	laird_interface_handle interface;
};

using namespace boost::python;


BOOST_PYTHON_MODULE(dcal_py)
{
	class_<generic_int>("generic_int")
		.def_readwrite("gen_int", &generic_int::gen_int)
	;

	class_<generic_uint>("generic_uint")
		.def_readwrite("gen_uint", &generic_uint::gen_uint)
	;

	class_<generic_string>("generic_string")
		.def("gen_string", &generic_string::gen_string)
	;

	class_<settings>("settings")
		.def("profilename", &settings::profilename)
		.def("ssid", &settings::ssid)
		.def_readwrite("ssid_len", &settings::ssid_len)
		.def("mac", &settings::mac)
	;

	class_<ccx>("ccx")
		.def("ap_ip", &ccx::ap_ip)
		.def("ap_name", &ccx::ap_name)
		.def("clientname", &ccx::clientname)
	;

	class_<connection>("connection")
		.def_readwrite("cardstate", &connection::cardstate)
		.def_readwrite("channel", &connection::channel)
		.def_readwrite("rssi", &connection::rssi)
		.def("ap_mac", &connection::ap_mac)
	;

	class_<connection_extended>("connection_extended")
		.def_readwrite("bitrate", &connection_extended::bitrate)
		.def_readwrite("txpower", &connection_extended::txpower)
		.def_readwrite("dtim", &connection_extended::dtim)
		.def_readwrite("beaconperiod", &connection_extended::beaconperiod)
	;

	class_<profile_SSID>("profile_SSID")
		.def_readwrite("len", &profile_SSID::len)
		.def("val", &profile_SSID::val)
	;

	class_<dcal_time>("dcal_time")
		.def_readwrite("tv_sec", &dcal_time::tv_sec)
		.def_readwrite("tv_usec", &dcal_time::tv_usec)
	;

	class_<dcal>("dcal")
		// Session management
		.def("session_create", &dcal::session_create)
		.def("host", &dcal::host)
		.def("port", &dcal::port)
		.def("user", &dcal::user)
		.def("pw", &dcal::pw)
		.def("session_open", &dcal::session_open)
		.def("session_close", &dcal::session_close)
		// Device status/info
		.def("get_sdk_version", &dcal::get_sdk_version)
		.def("get_chipset_version", &dcal::get_chipset_version)
		.def("get_system_version", &dcal::get_system_version)
		.def("get_driver_version", &dcal::get_driver_version)
		.def("get_dcas_version", &dcal::get_dcas_version)
		.def("get_dcal_version", &dcal::get_dcal_version)
		.def("get_firmware_version", &dcal::get_firmware_version)
		.def("get_supplicant_version", &dcal::get_supplicant_version)
		.def("get_release_version", &dcal::get_release_version)
		.def("device_status_pull", &dcal::device_status_pull)
		.def("device_status_get_settings", &dcal::device_status_get_settings)
		.def("device_status_get_ccx", &dcal::device_status_get_ccx)
		.def("device_status_get_ipv4", &dcal::device_status_get_ipv4)
		.def("device_status_get_ipv6_count", &dcal::device_status_get_ipv6_count)
		.def("device_status_get_ipv6_string_at_index", &dcal::device_status_get_ipv6_string_at_index)
		.def("device_status_get_connection", &dcal::device_status_get_connection)
		.def("device_status_get_connection_extended", &dcal::device_status_get_connection_extended)
		// WiFi Management
		.def("wifi_enable", &dcal::wifi_enable)
		.def("wifi_disable", &dcal::wifi_disable)
		// WiFi Global Management
		.def("wifi_global_create", &dcal::wifi_global_create)
		.def("wifi_global_pull", &dcal::wifi_global_pull)
		.def("wifi_global_close_handle", &dcal::wifi_global_close_handle)
		.def("wifi_global_push", &dcal::wifi_global_push)
		.def("wifi_global_set_auth_server", &dcal::wifi_global_set_auth_server)
		.def("wifi_global_get_auth_server", &dcal::wifi_global_get_auth_server)
		.def("wifi_global_set_achannel_mask", &dcal::wifi_global_set_achannel_mask)
		.def("wifi_global_get_achannel_mask", &dcal::wifi_global_get_achannel_mask)
		.def("wifi_global_set_bchannel_mask", &dcal::wifi_global_set_bchannel_mask)
		.def("wifi_global_get_bchannel_mask", &dcal::wifi_global_get_bchannel_mask)
		.def("wifi_global_set_auto_profile", &dcal::wifi_global_set_auto_profile)
		.def("wifi_global_get_auto_profile", &dcal::wifi_global_get_auto_profile)
		.def("wifi_global_set_beacon_miss", &dcal::wifi_global_set_beacon_miss)
		.def("wifi_global_get_beacon_miss", &dcal::wifi_global_get_beacon_miss)
		.def("wifi_global_set_ccx", &dcal::wifi_global_set_ccx)
		.def("wifi_global_get_ccx", &dcal::wifi_global_get_ccx)
		.def("wifi_global_set_cert_path", &dcal::wifi_global_set_cert_path)
		.def("wifi_global_get_cert_path", &dcal::wifi_global_get_cert_path)
		.def("wifi_global_set_date_check", &dcal::wifi_global_set_date_check)
		.def("wifi_global_get_date_check", &dcal::wifi_global_get_date_check)
		.def("wifi_global_set_def_adhoc_channel", &dcal::wifi_global_set_def_adhoc_channel)
		.def("wifi_global_get_def_adhoc_channel", &dcal::wifi_global_get_def_adhoc_channel)
		.def("wifi_global_set_fips", &dcal::wifi_global_set_fips)
		.def("wifi_global_get_fips", &dcal::wifi_global_get_fips)
		.def("wifi_global_set_pmk", &dcal::wifi_global_set_pmk)
		.def("wifi_global_get_pmk", &dcal::wifi_global_get_pmk)
		.def("wifi_global_set_probe_delay", &dcal::wifi_global_set_probe_delay)
		.def("wifi_global_get_probe_delay", &dcal::wifi_global_get_probe_delay)
		.def("wifi_global_get_regdomain", &dcal::wifi_global_get_regdomain)
		.def("wifi_global_set_roam_periodms", &dcal::wifi_global_set_roam_periodms)
		.def("wifi_global_get_roam_periodms", &dcal::wifi_global_get_roam_periodms)
		.def("wifi_global_set_roam_trigger", &dcal::wifi_global_set_roam_trigger)
		.def("wifi_global_get_roam_trigger", &dcal::wifi_global_get_roam_trigger)
		.def("wifi_global_set_rts", &dcal::wifi_global_set_rts)
		.def("wifi_global_get_rts", &dcal::wifi_global_get_rts)
		.def("wifi_global_set_scan_dfs_time", &dcal::wifi_global_set_scan_dfs_time)
		.def("wifi_global_get_scan_dfs_time", &dcal::wifi_global_get_scan_dfs_time)
		.def("wifi_global_set_ttls_inner_method", &dcal::wifi_global_set_ttls_inner_method)
		.def("wifi_global_get_ttls_inner_method", &dcal::wifi_global_get_ttls_inner_method)
		.def("wifi_global_set_uapsd", &dcal::wifi_global_set_uapsd)
		.def("wifi_global_get_uapsd", &dcal::wifi_global_get_uapsd)
		.def("wifi_global_set_wmm", &dcal::wifi_global_set_wmm)
		.def("wifi_global_get_wmm", &dcal::wifi_global_get_wmm)
		.def("wifi_global_set_ignore_null_ssid", &dcal::wifi_global_set_ignore_null_ssid)
		.def("wifi_global_get_ignore_null_ssid", &dcal::wifi_global_get_ignore_null_ssid)
		.def("wifi_global_set_dfs_channels", &dcal::wifi_global_set_dfs_channels)
		.def("wifi_global_get_dfs_channels", &dcal::wifi_global_get_dfs_channels)
		.def("wifi_global_printf", &dcal::wifi_global_printf)
		// Wifi Scan
		.def("wifi_pull_scan_list", &dcal::wifi_pull_scan_list)
		.def("wifi_get_scan_list_entry_ssid", &dcal::wifi_get_scan_list_entry_ssid)
		.def("wifi_get_scan_list_entry_bssid", &dcal::wifi_get_scan_list_entry_bssid)
		.def("wifi_get_scan_list_entry_channel", &dcal::wifi_get_scan_list_entry_channel)
		.def("wifi_get_scan_list_entry_rssi", &dcal::wifi_get_scan_list_entry_rssi)
		.def("wifi_get_scan_list_entry_securityMask", &dcal::wifi_get_scan_list_entry_securityMask)
		.def("wifi_get_scan_list_entry_type", &dcal::wifi_get_scan_list_entry_type)
		// Wifi Profile Management
		.def("wifi_pull_profile_list", &dcal::wifi_pull_profile_list)
		.def("wifi_get_profile_list_entry_profilename", &dcal::wifi_get_profile_list_entry_profilename)
		.def("wifi_get_profile_list_entry_autoprofile", &dcal::wifi_get_profile_list_entry_autoprofile)
		.def("wifi_get_profile_list_entry_active", &dcal::wifi_get_profile_list_entry_active)
		.def("wifi_profile_create", &dcal::wifi_profile_create)
		.def("wifi_profile_pull", &dcal::wifi_profile_pull)
		.def("wifi_profile_close_handle", &dcal::wifi_profile_close_handle)
		.def("wifi_profile_push", &dcal::wifi_profile_push)
		.def("wifi_profile_activate_by_name", &dcal::wifi_profile_activate_by_name)
		.def("wifi_profile_delete_from_device", &dcal::wifi_profile_delete_from_device)
		.def("wifi_profile_set_profilename", &dcal::wifi_profile_set_profilename)
		.def("wifi_profile_get_profilename", &dcal::wifi_profile_get_profilename)
		.def("wifi_profile_set_SSID", &dcal::wifi_profile_set_SSID)
		.def("wifi_profile_get_SSID", &dcal::wifi_profile_get_SSID)
		.def("wifi_profile_set_encrypt_std", &dcal::wifi_profile_set_encrypt_std)
		.def("wifi_profile_get_encrypt_std", &dcal::wifi_profile_get_encrypt_std)
		.def("wifi_profile_set_encryption", &dcal::wifi_profile_set_encryption)
		.def("wifi_profile_get_encryption", &dcal::wifi_profile_get_encryption)
		.def("wifi_profile_get_auth", &dcal::wifi_profile_get_auth)
		.def("wifi_profile_set_eap", &dcal::wifi_profile_set_eap)
		.def("wifi_profile_get_eap", &dcal::wifi_profile_get_eap)
		.def("wifi_profile_set_psk", &dcal::wifi_profile_set_psk)
		.def("wifi_profile_psk_is_set", &dcal::wifi_profile_psk_is_set)
		.def("wifi_profile_set_user", &dcal::wifi_profile_set_user)
		.def("wifi_profile_user_is_set", &dcal::wifi_profile_user_is_set)
		.def("wifi_profile_set_password", &dcal::wifi_profile_set_password)
		.def("wifi_profile_password_is_set", &dcal::wifi_profile_password_is_set)
		.def("wifi_profile_set_cacert", &dcal::wifi_profile_set_cacert)
		.def("wifi_profile_cacert_is_set", &dcal::wifi_profile_cacert_is_set)
		.def("wifi_profile_set_pacfile", &dcal::wifi_profile_set_pacfile)
		.def("wifi_profile_pacfile_is_set", &dcal::wifi_profile_pacfile_is_set)
		.def("wifi_profile_set_pacpassword", &dcal::wifi_profile_set_pacpassword)
		.def("wifi_profile_pacpassword_is_set", &dcal::wifi_profile_pacpassword_is_set)
		.def("wifi_profile_set_usercert", &dcal::wifi_profile_set_usercert)
		.def("wifi_profile_usercert_is_set", &dcal::wifi_profile_usercert_is_set)
		.def("wifi_profile_set_usercert_password", &dcal::wifi_profile_set_usercert_password)
		.def("wifi_profile_usercert_password_is_set", &dcal::wifi_profile_usercert_password_is_set)
		.def("wifi_profile_set_wep_key", &dcal::wifi_profile_set_wep_key)
		.def("wifi_profile_wep_key_is_set", &dcal::wifi_profile_wep_key_is_set)
		.def("wifi_profile_set_wep_txkey", &dcal::wifi_profile_set_wep_txkey)
		.def("wifi_profile_get_wep_txkey", &dcal::wifi_profile_get_wep_txkey)
		.def("wifi_profile_set_clientname", &dcal::wifi_profile_set_clientname)
		.def("wifi_profile_get_clientname", &dcal::wifi_profile_get_clientname)
		.def("wifi_profile_set_radiomode", &dcal::wifi_profile_set_radiomode)
		.def("wifi_profile_get_radiomode", &dcal::wifi_profile_get_radiomode)
		.def("wifi_profile_set_powersave", &dcal::wifi_profile_set_powersave)
		.def("wifi_profile_get_powersave", &dcal::wifi_profile_get_powersave)
		.def("wifi_profile_set_psp_delay", &dcal::wifi_profile_set_psp_delay)
		.def("wifi_profile_get_psp_delay", &dcal::wifi_profile_get_psp_delay)
		.def("wifi_profile_set_txpower", &dcal::wifi_profile_set_txpower)
		.def("wifi_profile_get_txpower", &dcal::wifi_profile_get_txpower)
		.def("wifi_profile_set_bitrate", &dcal::wifi_profile_set_bitrate)
		.def("wifi_profile_get_bitrate", &dcal::wifi_profile_get_bitrate)
		.def("wifi_profile_set_autoprofile", &dcal::wifi_profile_set_autoprofile)
		.def("wifi_profile_get_autoprofile", &dcal::wifi_profile_get_autoprofile)
		.def("wifi_profile_printf", &dcal::wifi_profile_printf)
		// System controls
		.def("wifi_restart", &dcal::wifi_restart)
		.def("system_restart", &dcal::system_restart)
		// Time functions
		.def("time_set", &dcal::time_set)
		.def("time_get", &dcal::time_get)
		.def("ntpdate", &dcal::ntpdate)
		// File functions
		.def("file_push_to_wb", &dcal::file_push_to_wb)
		.def("file_pull_from_wb", &dcal::file_pull_from_wb)
		.def("fw_update", &dcal::fw_update)
		.def("pull_logs", &dcal::pull_logs)
		.def("process_cli_command_file", &dcal::process_cli_command_file)
		// Interface functions
		.def("interface_create", &dcal::interface_create)
		.def("interface_pull", &dcal::interface_pull)
		.def("interface_close_handle", &dcal::interface_close_handle)
		.def("interface_push", &dcal::interface_push)
		.def("interface_delete", &dcal::interface_delete)
		.def("interface_set_interface_name", &dcal::interface_set_interface_name)
		.def("interface_get_ipv4_state", &dcal::interface_get_ipv4_state)
		.def("interface_set_method", &dcal::interface_set_method)
		.def("interface_get_method", &dcal::interface_get_method)
		.def("interface_set_auto_start", &dcal::interface_set_auto_start)
		.def("interface_get_auto_start", &dcal::interface_get_auto_start)
		.def("interface_set_address", &dcal::interface_set_address)
		.def("interface_get_address", &dcal::interface_get_address)
		.def("interface_set_netmask", &dcal::interface_set_netmask)
		.def("interface_get_netmask", &dcal::interface_get_netmask)
		.def("interface_set_gateway", &dcal::interface_set_gateway)
		.def("interface_get_gateway", &dcal::interface_get_gateway)
		.def("interface_set_broadcast_address", &dcal::interface_set_broadcast_address)
		.def("interface_get_broadcast_address", &dcal::interface_get_broadcast_address)
		.def("interface_set_nameserver", &dcal::interface_set_nameserver)
		.def("interface_get_nameserver", &dcal::interface_get_nameserver)
		.def("interface_set_state", &dcal::interface_set_state)
		.def("interface_set_bridge", &dcal::interface_set_bridge)
		.def("interface_get_bridge", &dcal::interface_get_bridge)
		.def("interface_set_ap_mode", &dcal::interface_set_ap_mode)
		.def("interface_get_ap_mode", &dcal::interface_get_ap_mode)
		.def("interface_set_nat", &dcal::interface_set_nat)
		.def("interface_get_nat", &dcal::interface_get_nat)
		.def("interface_clear_property", &dcal::interface_clear_property)
		.def("interface_get_ipv6_state", &dcal::interface_get_ipv6_state)
		.def("interface_set_dhcp6", &dcal::interface_set_dhcp6)
		.def("interface_get_dhcp6", &dcal::interface_get_dhcp6)
		.def("interface_set_method6", &dcal::interface_set_method6)
		.def("interface_get_method6", &dcal::interface_get_method6)
		.def("interface_set_address6", &dcal::interface_set_address6)
		.def("interface_get_address6", &dcal::interface_get_address6)
		.def("interface_set_netmask6", &dcal::interface_set_netmask6)
		.def("interface_get_netmask6", &dcal::interface_get_netmask6)
		.def("interface_set_gateway6", &dcal::interface_set_gateway6)
		.def("interface_get_gateway6", &dcal::interface_get_gateway6)
		.def("interface_set_nameserver6", &dcal::interface_set_nameserver6)
		.def("interface_get_nameserver6", &dcal::interface_get_nameserver6)
		.def("interface_set_state6", &dcal::interface_set_state6)
		.def("interface_set_nat6", &dcal::interface_set_nat6)
		.def("interface_get_nat6", &dcal::interface_get_nat6)
		.def("interface_clear_property6", &dcal::interface_clear_property6)
	;
}
