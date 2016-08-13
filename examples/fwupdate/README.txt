In addition to the session commands, the app shows how to update the image
on the wb.  Before calling the fw_update() function, you must first send
the image and fw.txt files to the WB.

The fw_update() function can take an extended period of time as it waits
for the update to complete before returning the exit code of the fw_update
app on the WB.

The API prevents the device from auto-rebooting after the update so if a
reboot is desired, use the system_restart() function.
