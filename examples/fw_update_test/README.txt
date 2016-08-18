In addition to the session commands, the app shows how to send and receive
files to/from the WB.

By default this app sends to the WB.  To switch modes, use the -x g (xfer
get) parameter. -l <filename> is local file -r <filename> is the remote
filename.

Any file sent to the WB is placed in the /tmp subdirectory. Any file can
be pulled from the WB.

If sending a file to the WB, the -r parameter is optional.  If omitted, the
basename of the local filename will be used.

If receiving a file from the WB, the -l parameter is optional.  If omitted,
the basename of the remote filename will be used and the file will be
saved to the current directory on the host.

