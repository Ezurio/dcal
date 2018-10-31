In addition to the session commands, the app shows how to update the image
with swupdate. swupdate must be installed on the wb50n/som60.

The swupdate() function can take an extended period of time as it waits
for the update to complete before returning the exit code of the swupdate
app.

The API prevents the device from auto-rebooting after the update so if a
reboot is desired, use the system_restart() function.

usage: Parameters for '/usr/bin/swupdate' are to be passed as a string at the end.

./sw_update -p 2222 -u libssh -P libssh "\-b \"2 3 8\" \-e stable,main-a \-d h
ttp://10.1.40.181/wb50n_devel/20171108/wb50n_20171122.swu"

Image wb50n_20171122.swu on the webserver 10.1.40.181 will be downloaded and partitions
belong to main-a will be updated.
