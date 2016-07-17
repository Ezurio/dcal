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

	// WiFi Profile Management
	int wifi_profile_activate_by_name( char * profilename ) { return dcal_wifi_profile_activate_by_name(session, profilename); }

  private:
	laird_session_handle session;
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
		// Wifi Profile Management
		.def("wifi_profile_activate_by_name", &dcal::wifi_profile_activate_by_name)
	;
}
