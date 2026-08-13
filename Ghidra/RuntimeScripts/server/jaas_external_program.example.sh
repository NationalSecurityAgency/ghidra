#!/bin/bash
## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##

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


