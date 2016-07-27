#include <boost/python.hpp>
#include <iostream>

#include "dcal_api.h"

// First have to "object-ize" our api, because we have handles, but we can't
// easily send those back and forth to python
class sdk_version
{
  public:
	unsigned int sdk;
};

class chipset_version
{
  public:
	int chipset;
};

class system_version
{
  public:
	int sys;
};

class driver_version
{
  public:
	unsigned int driver;
};

class dcas_version
{
  public:
	unsigned int dcas;
};

class dcal_version
{
  public:
	unsigned int dcal;
};

class firmware_version
{
  public:
	char _firmware[STR_SZ];
	boost::python::object firmware() const { return boost::python::object(_firmware); }
};

class supplicant_version
{
  public:
	char _supplicant[STR_SZ];
	boost::python::object supplicant() const { return boost::python::object(_supplicant); }
};

class release_version
{
  public:
	char _release[STR_SZ];
	boost::python::object release() const { return boost::python::object(_release); }
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

class tcp
{
  public:
	char _ipv4[STR_SZ];
	boost::python::object ipv4() const { return boost::python::object(_ipv4); }
	char _ipv6[IP6_STR_SZ];
	boost::python::object ipv6() const { return boost::python::object(_ipv6); }
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

class profile_profilename
{
  public:
	char _profilename[CONFIG_NAME_SZ];
	boost::python::object profilename() const { return boost::python::object(_profilename); }
};

class profile_SSID
{
  public:
	int len;
	char _val[LRD_WF_MAX_SSID_LEN];
	boost::python::object val() const { return boost::python::object(_val); }
};

class profile_encryption_std
{
  public:
	int encryption_std;
};

class profile_encryption
{
  public:
	int encryption;
};

class profile_auth
{
  public:
	int auth;
};

class profile_eap
{
  public:
	int eap;
};

class profile_psk
{
  public:
	int psk;
};

class profile_user
{
  public:
	int user;
};

class profile_password
{
  public:
	int password;
};

class profile_cacert
{
  public:
	int cacert;
};

class profile_pacfile
{
  public:
	int pacfile;
};

class profile_pacpassword
{
  public:
	int pacpassword;
};

class profile_usercert
{
  public:
	int usercert;
};

class profile_usercert_password
{
  public:
	int usercert_password;
};

class profile_wep_key
{
  public:
	int wep_key;
};

class profile_wep_txkey
{
  public:
	unsigned int txkey;
};

class profile_clientname
{
  public:
	char _clientname_buffer[CLIENT_NAME_SZ];
	boost::python::object clientname_buffer() const { return boost::python::object(_clientname_buffer); }
};

class profile_radiomode
{
  public:
	int mode;
};

class profile_powersave
{
  public:
	int powersave;
};

class profile_pspdelay
{
  public:
	unsigned int pspdelay;
};

class profile_txpower
{
  public:
	int txpower;
};

class profile_bitrate
{
  public:
	int bitrate;
};

class profile_autoprofile
{
  public:
	int autoprofile;
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
	int get_sdk_version( class sdk_version & v ){
		int ret;
		unsigned int sdk;

		ret = dcal_get_sdk_version( session, &sdk );

		if (ret == DCAL_SUCCESS)
		{
			v.sdk = sdk;
		}
		return ret;
	};

	int get_chipset_version( class chipset_version & v ){
		int ret;
		RADIOCHIPSET chipset;

		ret = dcal_get_chipset_version( session, &chipset );

		if (ret == DCAL_SUCCESS)
		{
			v.chipset = chipset;
		}
		return ret;
	};

	int get_system_version( class system_version & v ){
		int ret;
		LRD_SYSTEM sys;

		ret = dcal_get_system_version( session, &sys );

		if (ret == DCAL_SUCCESS)
		{
			v.sys = sys;
		}
		return ret;
	};

	int get_driver_version( class driver_version & v ){
		int ret;
		unsigned int driver;

		ret = dcal_get_driver_version( session, &driver );

		if (ret == DCAL_SUCCESS)
		{
			v.driver = driver;
		}
		return ret;
	};

	int get_dcas_version( class dcas_version & v ){
		int ret;
		unsigned int dcas;

		ret = dcal_get_dcas_version( session, &dcas );

		if (ret == DCAL_SUCCESS)
		{
			v.dcas = dcas;
		}
		return ret;
	};

	int get_dcal_version( class dcal_version & v ){
		int ret;
		unsigned int dcal;

		ret = dcal_get_dcal_version( session, &dcal );

		if (ret == DCAL_SUCCESS)
		{
			v.dcal = dcal;
		}
		return ret;
	};

	int get_firmware_version( class firmware_version & v ){
		int ret;
		char firmware[STR_SZ];

		ret = dcal_get_firmware_version( session, firmware );

		if (ret == DCAL_SUCCESS)
		{
			strncpy(v._firmware, firmware, STR_SZ);
		}
		return ret;
	};

	int get_supplicant_version( class supplicant_version & v ){
		int ret;
		char supplicant[STR_SZ];

		ret = dcal_get_supplicant_version( session, supplicant );

		if (ret == DCAL_SUCCESS)
		{
			strncpy(v._supplicant, supplicant, STR_SZ);
		}
		return ret;
	};

	int get_release_version( class release_version & v ){
		int ret;
		char release[STR_SZ];

		ret = dcal_get_supplicant_version( session, release );

		if (ret == DCAL_SUCCESS)
		{
			strncpy(v._release, release, STR_SZ);
		}
		return ret;
	};

	int device_status_pull() { return dcal_device_status_pull(session); };

	int device_status_get_settings(class settings & s) {
		int ret;
		char profilename[NAME_SZ];
		char ssid[SSID_SZ];
		unsigned int ssid_len;
		unsigned char mac[MAC_SZ];
		ret = dcal_device_status_get_settings( session, profilename,
							ssid, &ssid_len,
							mac);

		if (ret == DCAL_SUCCESS)
		{
			char string_mac[STR_SZ];
			sprintf(string_mac, "%x:%x:%x:%x:%x:%x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

			strncpy(s._profilename, profilename, NAME_SZ);
			memcpy(s._ssid, ssid, SSID_SZ);
			s.ssid_len = ssid_len;
			strncpy(s._mac, string_mac, STR_SZ);
		}
		return ret;
	}

	int device_status_get_ccx(class ccx & c) {
		int ret;
		unsigned char ap_ip[IP4_SZ];
		char ap_name[NAME_SZ];
		char clientname[NAME_SZ];

		ret = dcal_device_status_get_ccx( session, ap_ip, ap_name, clientname);

		if (ret == DCAL_SUCCESS)
		{
			char string_ap_ip[IP4_SZ];

			sprintf(string_ap_ip, "%i.%i.%i.%i", ap_ip[0],ap_ip[1],ap_ip[2],ap_ip[3]);

			strncpy(c._ap_ip, string_ap_ip, STR_SZ);
			strncpy(c._ap_name, ap_name, NAME_SZ);
			strncpy(c._clientname, clientname, NAME_SZ);
		}
		return ret;
	}

	int device_status_get_tcp(class tcp & t) {
		int ret;
		unsigned char ipv4[IP4_SZ];
		char ipv6[IP6_STR_SZ];

		ret = dcal_device_status_get_tcp( session, ipv4, ipv6);

		if (ret == DCAL_SUCCESS)
		{
			char string_ipv4[STR_SZ];

			sprintf(string_ipv4, "%i.%i.%i.%i", ipv4[0],ipv4[1],ipv4[2],ipv4[3]);

			strncpy(t._ipv4, string_ipv4, STR_SZ);
			strncpy(t._ipv6, ipv6, IP6_STR_SZ);
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
							ap_mac
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

	// WiFi Profile Management
	int wifi_profile_create() { return dcal_wifi_profile_create( &profile ); }
	int wifi_profile_pull( char * profilename ) { return dcal_wifi_profile_pull(session, &profile, profilename); }
	int wifi_profile_close_handle() { return dcal_wifi_profile_close_handle( profile ); }
	int wifi_profile_push() { return dcal_wifi_profile_push( session, profile ); }
	int wifi_profile_activate_by_name( char * profilename ) { return dcal_wifi_profile_activate_by_name(session, profilename); }
	int wifi_profile_delete_from_device( char * profilename ) { return dcal_wifi_profile_delete_from_device(session, profilename); }
	int wifi_profile_set_profilename( char * profilename ) { return dcal_wifi_profile_set_profilename(profile, profilename); }
	int wifi_profile_get_profilename( class profile_profilename & p ) {
		int ret;
		char profilename[CONFIG_NAME_SZ];
		ret = dcal_wifi_profile_get_profilename(profile, profilename);
		if (ret == DCAL_SUCCESS)
		{
			memcpy(p._profilename, profilename, CONFIG_NAME_SZ);
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

	int wifi_profile_get_encrypt_std( class profile_encryption_std & e ) {
		int ret;
		ENCRYPT_STD encryption_std;
		ret = dcal_wifi_profile_get_encrypt_std(profile, &encryption_std);
		if (ret == DCAL_SUCCESS)
		{
			e.encryption_std = (int) encryption_std;
		}
		return ret;
	}

	int wifi_profile_set_encryption( int encrypt ) {
		ENCRYPTION encryption;
		encryption = (ENCRYPTION) encrypt;
		return dcal_wifi_profile_set_encryption(profile, encryption);
	}

	int wifi_profile_get_encryption( class profile_encryption & e ) {
		int ret;
		ENCRYPTION encryption;
		ret = dcal_wifi_profile_get_encryption(profile, &encryption);
		if (ret == DCAL_SUCCESS)
		{
			e.encryption = (int) encryption;
		}
		return ret;
	}

	int wifi_profile_set_auth( int auth_type ) {
		AUTH auth;
		auth = (AUTH) auth_type;
		return dcal_wifi_profile_set_auth(profile, auth);
	}

	int wifi_profile_get_auth( class profile_auth & a ) {
		int ret;
		AUTH auth;
		ret = dcal_wifi_profile_get_auth(profile, &auth);
		if (ret == DCAL_SUCCESS)
		{
			a.auth = (int) auth;
		}
		return ret;
	}

	int wifi_profile_set_eap( int eap_type ) {
		EAPTYPE eap;
		eap = (EAPTYPE) eap_type;
		return dcal_wifi_profile_set_eap(profile, eap);
	}

	int wifi_profile_get_eap( class profile_eap & e ) {
		int ret;
		EAPTYPE eap;
		ret = dcal_wifi_profile_get_eap(profile, &eap);
		if (ret == DCAL_SUCCESS)
		{
			e.eap = (int) eap;
		}
		return ret;
	}

	int wifi_profile_set_psk( char * psk ) { return dcal_wifi_profile_set_psk(profile, psk); }
	int wifi_profile_psk_is_set( class profile_psk & p ) {
		int ret;
		bool psk;
		ret = dcal_wifi_profile_psk_is_set(profile, &psk);
		if (ret == DCAL_SUCCESS)
		{
			p.psk = (int) psk;
		}
		return ret;
	}

	int wifi_profile_set_user( char * user ) { return dcal_wifi_profile_set_user(profile, user); }
	int wifi_profile_user_is_set( class profile_user & u ) {
		int ret;
		bool user;
		ret = dcal_wifi_profile_user_is_set(profile, &user);
		if (ret == DCAL_SUCCESS)
		{
			u.user = (int) user;
		}
		return ret;
	}

	int wifi_profile_set_password( char * password ) { return dcal_wifi_profile_set_password(profile, password); }
	int wifi_profile_password_is_set( class profile_password & p ) {
		int ret;
		bool password;
		ret = dcal_wifi_profile_user_is_set(profile, &password);
		if (ret == DCAL_SUCCESS)
		{
			p.password = (int) password;
		}
		return ret;
	}

	int wifi_profile_set_cacert( char * cacert ) { return dcal_wifi_profile_set_cacert(profile, cacert); }
	int wifi_profile_cacert_is_set( class profile_cacert & c ) {
		int ret;
		bool cacert;
		ret = dcal_wifi_profile_cacert_is_set(profile, &cacert);
		if (ret == DCAL_SUCCESS)
		{
			c.cacert = (int) cacert;
		}
		return ret;
	}

	int wifi_profile_set_pacfile( char * pacfilename ) { return dcal_wifi_profile_set_pacfile(profile, pacfilename); }
	int wifi_profile_pacfile_is_set( class profile_pacfile & p ) {
		int ret;
		bool pacfile;
		ret = dcal_wifi_profile_pacfile_is_set(profile, &pacfile);
		if (ret == DCAL_SUCCESS)
		{
			p.pacfile = (int) pacfile;
		}
		return ret;
	}

	int wifi_profile_set_pacpassword( char * pacpassword ) { return dcal_wifi_profile_set_pacpassword(profile, pacpassword); }
	int wifi_profile_pacpassword_is_set( class profile_pacpassword & p ) {
		int ret;
		bool pacpassword;
		ret = dcal_wifi_profile_pacpassword_is_set(profile, &pacpassword);
		if (ret == DCAL_SUCCESS)
		{
			p.pacpassword = (int) pacpassword;
		}
		return ret;
	}

	int wifi_profile_set_usercert( char * usercert ) { return dcal_wifi_profile_set_usercert(profile, usercert); }
	int wifi_profile_usercert_is_set( class profile_usercert & u ) {
		int ret;
		bool usercert;
		ret = dcal_wifi_profile_usercert_is_set(profile, &usercert);
		if (ret == DCAL_SUCCESS)
		{
			u.usercert = (int) usercert;
		}
		return ret;
	}

	int wifi_profile_set_usercert_password( char * usercert_password ) { return dcal_wifi_profile_set_usercert_password(profile, usercert_password); }
	int wifi_profile_usercert_password_is_set( class profile_usercert_password & u ) {
		int ret;
		bool usercert_password;
		ret = dcal_wifi_profile_usercert_password_is_set(profile, &usercert_password);
		if (ret == DCAL_SUCCESS)
		{
			u.usercert_password = (int) usercert_password;
		}
		return ret;
	}

	int wifi_profile_set_wep_key( char * wepkey, int index ) { return dcal_wifi_profile_set_wep_key(profile, wepkey, index); }
	int wifi_profile_wep_key_is_set( class profile_wep_key & w, int wep_index ) {
		int ret;
		bool wep_key;
		int index = (int) wep_index;
		ret = dcal_wifi_profile_wep_key_is_set(profile, &wep_key, index);
		if (ret == DCAL_SUCCESS)
		{
			w.wep_key = (int) wep_key;
		}
		return ret;
	}

	int wifi_profile_set_wep_txkey( unsigned int txkey) { return dcal_wifi_profile_set_wep_txkey(profile, txkey); }
	int wifi_profile_get_wep_txkey( class profile_wep_txkey & w ) {
		int ret;
		unsigned int txkey;
		ret = dcal_wifi_profile_get_wep_txkey(profile, &txkey);
		if (ret == DCAL_SUCCESS)
		{
			w.txkey = (int) txkey;
		}
		return ret;
	}

	int wifi_profile_set_clientname( char * clientname ) { return dcal_wifi_profile_set_clientname(profile, clientname); }
	int wifi_profile_get_clientname( class profile_clientname & c ) {
		int ret;
		char clientname_buffer[CLIENT_NAME_SZ];
		ret = dcal_wifi_profile_get_clientname(profile, clientname_buffer);
		if (ret == DCAL_SUCCESS)
		{
			memcpy(c._clientname_buffer, clientname_buffer, CLIENT_NAME_SZ);
		}
		return ret;
	}

	int wifi_profile_set_radiomode( int radio_mode ) {
		RADIOMODE mode;
		mode = (RADIOMODE) radio_mode;
		return dcal_wifi_profile_set_radiomode(profile, mode);
	}

	int wifi_profile_get_radiomode( class profile_radiomode & r ) {
		int ret;
		RADIOMODE mode;
		ret = dcal_wifi_profile_get_radiomode(profile, &mode);
		if (ret == DCAL_SUCCESS)
		{
			r.mode = (int) mode;
		}
		return ret;
	}

	int wifi_profile_set_powersave( int power_save ) {
		POWERSAVE powersave;
		powersave = (POWERSAVE) power_save;
		return dcal_wifi_profile_set_powersave(profile, powersave);
	}

	int wifi_profile_get_powersave( class profile_powersave & p ) {
		int ret;
		POWERSAVE powersave;
		ret = dcal_wifi_profile_get_powersave(profile, &powersave);
		if (ret == DCAL_SUCCESS)
		{
			p.powersave = (int) powersave;
		}
		return ret;
	}

	int wifi_profile_set_psp_delay( unsigned int pspdelay) { return dcal_wifi_profile_set_psp_delay(profile, pspdelay); }
	int wifi_profile_get_psp_delay( class profile_pspdelay & p ) {
		int ret;
		unsigned int pspdelay;
		ret = dcal_wifi_profile_get_psp_delay(profile, &pspdelay);
		if (ret == DCAL_SUCCESS)
		{
			p.pspdelay = pspdelay;
		}
		return ret;
	}

	int wifi_profile_set_txpower( int txpower) { return dcal_wifi_profile_set_txpower(profile, txpower); }
	int wifi_profile_get_txpower( class profile_txpower & t ) {
		int ret;
		int txpower;
		ret = dcal_wifi_profile_get_txpower(profile, &txpower);
		if (ret == DCAL_SUCCESS)
		{
			t.txpower = txpower;
		}
		return ret;
	}

	int wifi_profile_set_bitrate( int bit_rate ) {
		BITRATE bitrate;
		bitrate = (BITRATE) bit_rate;
		return dcal_wifi_profile_set_bitrate(profile, bitrate);
	}

	int wifi_profile_get_bitrate( class profile_bitrate & b ) {
		int ret;
		BITRATE bitrate;
		ret = dcal_wifi_profile_get_bitrate(profile, &bitrate);
		if (ret == DCAL_SUCCESS)
		{
			b.bitrate = (int) bitrate;
		}
		return ret;
	}

	int wifi_profile_set_autoprofile( bool autoprofile) { return dcal_wifi_profile_set_autoprofile(profile, autoprofile); }
	int wifi_profile_get_autoprofile( class profile_autoprofile & a ) {
		int ret;
		bool autoprofile;
		ret = dcal_wifi_profile_get_autoprofile(profile, &autoprofile);
		if (ret == DCAL_SUCCESS)
		{
			a.autoprofile = (int) autoprofile;
		}
		return ret;
	}

	void wifi_profile_printf() { return dcal_wifi_profile_printf(profile); }

	// system controls
	int wifi_restart() { return dcal_wifi_restart(session); }
	int system_restart() { return dcal_system_restart(session); }

  private:
	laird_session_handle session;
	laird_profile_handle profile;
};

using namespace boost::python;


BOOST_PYTHON_MODULE(dcal_py)
{
	class_<sdk_version>("sdk_version")
		.def_readwrite("sdk", &sdk_version::sdk)
	;

	class_<chipset_version>("chipset_version")
		.def_readwrite("chipset", &chipset_version::chipset)
	;

	class_<system_version>("system_version")
		.def_readwrite("sys", &system_version::sys)
	;

	class_<driver_version>("driver_version")
		.def_readwrite("driver", &driver_version::driver)
	;

	class_<dcas_version>("dcas_version")
		.def_readwrite("dcas", &dcas_version::dcas)
	;

	class_<dcal_version>("dcal_version")
		.def_readwrite("dcal", &dcal_version::dcal)
	;

	class_<firmware_version>("firmware_version")
		.def("firmware", &firmware_version::firmware)
	;

	class_<supplicant_version>("supplicant_version")
		.def("supplicant", &supplicant_version::supplicant)
	;

	class_<release_version>("release_version")
		.def("release", &release_version::release)
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

	class_<tcp>("tcp")
		.def("ipv4", &tcp::ipv4)
		.def("ipv6", &tcp::ipv6)
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

	class_<profile_profilename>("profile_profilename")
		.def("profilename", &profile_profilename::profilename)
	;

	class_<profile_SSID>("profile_SSID")
		.def_readwrite("len", &profile_SSID::len)
		.def("val", &profile_SSID::val)
	;

	class_<profile_encryption_std>("profile_encryption_std")
		.def_readwrite("encryption_std", &profile_encryption_std::encryption_std)
	;

	class_<profile_encryption>("profile_encryption")
		.def_readwrite("encryption", &profile_encryption::encryption)
	;

	class_<profile_auth>("profile_auth")
		.def_readwrite("auth", &profile_auth::auth)
	;

	class_<profile_eap>("profile_eap")
		.def_readwrite("eap", &profile_eap::eap)
	;

	class_<profile_psk>("profile_psk")
		.def_readwrite("psk", &profile_psk::psk)
	;

	class_<profile_user>("profile_user")
		.def_readwrite("user", &profile_user::user)
	;

	class_<profile_password>("profile_password")
		.def_readwrite("password", &profile_password::password)
	;

	class_<profile_cacert>("profile_cacert")
		.def_readwrite("cacert", &profile_cacert::cacert)
	;

	class_<profile_pacfile>("profile_pacfile")
		.def_readwrite("pacfile", &profile_pacfile::pacfile)
	;

	class_<profile_pacpassword>("profile_pacpassword")
		.def_readwrite("pacpassword", &profile_pacpassword::pacpassword)
	;

	class_<profile_usercert>("profile_usercert")
		.def_readwrite("usercert", &profile_usercert::usercert)
	;

	class_<profile_usercert_password>("profile_usercert_password")
		.def_readwrite("usercert_password", &profile_usercert_password::usercert_password)
	;

	class_<profile_wep_key>("profile_wep_key")
		.def_readwrite("wep_key", &profile_wep_key::wep_key)
	;

	class_<profile_wep_txkey>("profile_wep_txkey")
		.def_readwrite("txkey", &profile_wep_txkey::txkey)
	;

	class_<profile_clientname>("profile_clientname")
		.def("clientname_buffer", &profile_clientname::clientname_buffer)
	;

	class_<profile_radiomode>("profile_radiomode")
		.def_readwrite("mode", &profile_radiomode::mode)
	;

	class_<profile_powersave>("profile_powersave")
		.def_readwrite("powersave", &profile_powersave::powersave)
	;

	class_<profile_pspdelay>("profile_pspdelay")
		.def_readwrite("pspdelay", &profile_pspdelay::pspdelay)
	;

	class_<profile_txpower>("profile_txpower")
		.def_readwrite("txpower", &profile_txpower::txpower)
	;

	class_<profile_bitrate>("profile_bitrate")
		.def_readwrite("bitrate", &profile_bitrate::bitrate)
	;

	class_<profile_autoprofile>("profile_autoprofile")
		.def_readwrite("autoprofile", &profile_autoprofile::autoprofile)
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
		.def("device_status_get_tcp", &dcal::device_status_get_tcp)
		.def("device_status_get_connection", &dcal::device_status_get_connection)
		.def("device_status_get_connection_extended", &dcal::device_status_get_connection_extended)
		// WiFi Management
		.def("wifi_enable", &dcal::wifi_enable)
		.def("wifi_disable", &dcal::wifi_disable)
		// Wifi Profile Management
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
	;
}
