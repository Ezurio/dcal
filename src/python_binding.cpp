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

	// WB information
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
	class_<dcal>("dcal")
		.def("session_create", &dcal::session_create)
		.def("host", &dcal::host)
		.def("port", &dcal::port)
		.def("user", &dcal::user)
		.def("pw", &dcal::pw)
		.def("session_open", &dcal::session_open)
		.def("session_close", &dcal::session_close)
		.def("version_pull", &dcal::version_pull)
	;
}
