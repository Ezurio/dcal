#include <boost/python.hpp>
#include <iostream>

#include "dcal_api.h"

// First have to "object-ize" our api, because we have handles, but we can't
// easily send those back and forth to python
class version
{
  public:
	unsigned int sdk;
	int chipset;
	int sys;
	unsigned int driver;
	unsigned int dcas;
	unsigned int dcal;
	char _firmware[STR_SZ];
	boost::python::object firmware() const { return boost::python::object(_firmware); }
	char _supplicant[STR_SZ];
	boost::python::object supplicant() const { return boost::python::object(_supplicant); }
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
	int version_pull( class version & v )
	{
		int ret;
		unsigned int sdk;
		RADIOCHIPSET chipset;
		LRD_SYSTEM sys;
		unsigned int driver;
		unsigned int dcas;
		unsigned int dcal;
		char firmware[STR_SZ];
		char supplicant[STR_SZ];
		char release[STR_SZ];

		ret = dcal_device_version_pull( session,
						&sdk,
						&chipset,
						&sys,
						&driver,
						&dcas,
						&dcal,
						firmware,
						supplicant,
						release);
		if (ret == DCAL_SUCCESS)
		{
			v.sdk = sdk;
			v.chipset = chipset;
			v.sys = sys;
			v.driver = driver;
			v.dcas = dcas;
			v.dcal = dcal;
			strncpy(v._firmware, firmware, STR_SZ);
			strncpy(v._supplicant, supplicant, STR_SZ);
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
	class_<version>("version")
		.def_readwrite("sdk", &version::sdk)
		.def_readwrite("chipset", &version::chipset)
		.def_readwrite("sys", &version::sys)
		.def_readwrite("driver", &version::driver)
		.def_readwrite("dcas", &version::dcas)
		.def_readwrite("dcal", &version::dcal)
		.def("firmware", &version::firmware)
		.def("supplicant", &version::supplicant)
		.def("release", &version::release)
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
		.def("version_pull", &dcal::version_pull)
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
