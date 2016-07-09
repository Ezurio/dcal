#include <boost/python.hpp>

#include "dcal_api.h"

// First have to "object-ize" our api, because we have handles, but we can't
// easily send those back and forth to python

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

  private:
	laird_session_handle session;
};

using namespace boost::python;


BOOST_PYTHON_MODULE(dcal_py)
{
	class_<dcal>("dcal")
		.def("session_create", &dcal::session_create)
		.def("host", &dcal::host)
		.def("port", &dcal::port)
		.def("user", &dcal::user)
		.def("pw", &dcal::pw)
		.def("session_open", &dcal::session_open)
		.def("session_close", &dcal::session_close)
	;
}
