#!/bin/bash

# This is a trivial example to show how the Ghidra ExternalProgramLoginModule
# communicates with the external authenticator.
#
# The username and password will be supplied on STDIN separated by a newline.
# No other data will be sent on STDIN.
#
# The external authenticator (this script) needs to exit with 0 (zero) error level
# if the authentication was successful, or a non-zero error level if not successful.
# 

echo "Starting example JAAS external auth script" 1>&2

read NAME
read PASSWORD


if [[ ${NAME} =~ "bad" ]]
then
	echo "Login failed: username has 'bad' in it: $NAME" 1>&2
	exit 100
else
	echo "Login successful" 1>&2
fi


