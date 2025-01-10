#!/usr/bin/env bash
## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

umask 027

function showUsage() {

	echo "Usage: $0 <mode> <java-type> <name> <max-memory> \"<vmarg-list>\" <app-classname> <app-args>... "
	echo "   <mode>: fg   run as foreground process in current shell"
	echo "		   bg   run as background process in new shell"
	echo "		   debug   run as foreground process in current shell in debug mode (suspend=n)"
	echo "		   debug-suspend   run as foreground process in current shell in debug mode (suspend=y)"
	echo "		   NOTE: for all debug modes environment variable DEBUG_ADDRESS may be set to "
	echo "				 override default debug address of 127.0.0.1:18001"
	echo "   <java-type>: jdk  requires JDK to run"
	echo "				jre  JRE is sufficient to run (JDK works too)"
	echo "   <name>: application name used for naming console window"
	echo "   <max-memory>: maximum memory heap size in MB (e.g., 768M or 2G).  Use empty \"\" if default"
	echo "				 should be used.  This will generally be upto 1/4 of the physical memory available"
	echo "				 to the OS."
	echo "   <vmarg-list>: pass-thru args (e.g.,  \"-Xmx512M -Dmyvar=1 -DanotherVar=2\"). Use"
	echo "				 empty \"\" if vmargs not needed.  Spaces are not supported."
	echo "   <app-classname>: application classname (e.g., ghidra.GhidraRun )"
	echo "   <app-args>...: arguments to be passed to the application"
	echo " "
	echo "   Example:"
	echo "	  \"$0\" debug jdk Ghidra 4G \"\" ghidra.GhidraRun"

	exit 1
}

VMARGS_FROM_CALLER=		 # Passed in from the outer script as one long string, no spaces
VMARGS_FROM_LAUNCH_SH=()	# Defined in this script, added to array
VMARGS_FROM_LAUNCH_PROPS=() # Retrieved from LaunchSupport, added to array

ARGS=()
INDEX=0
WHITESPACE="[[:space:]]"

for AA in "$@"
do
	INDEX=$(expr $INDEX + 1)
	case "$INDEX" in
		1)
			MODE=$AA
			;;
		2)
			if [ "$AA" = "jre" ]; then
				JAVA_TYPE_ARG="-java_home"
			else
				JAVA_TYPE_ARG="-jdk_home"
			fi
			;;
		3)
			APPNAME=$AA
			;;
		4)
			MAXMEM=$AA
			;;
		5)
			if [ "$AA" != "" ]; then
				VMARGS_FROM_CALLER=$AA
			fi
			;;
		6)
			CLASSNAME=$AA
			;;
		*)
			ARGS[${#ARGS[@]}]=$AA
			;;
	esac
done

# Verify that required number of args were provided
if [[ ${INDEX} -lt 6 ]]; then
	echo "Incorrect launch usage - missing argument(s)"
	showUsage
	exit 1
fi

# Sets SUPPORT_DIR to the directory that contains this file (launch.sh)
SUPPORT_DIR="${0%/*}"

# Ensure Ghidra path doesn't contain illegal characters
if [[ "${SUPPORT_DIR}" = *"!"* ]]; then
	echo "Ghidra path cannot contain a \"!\" character."
	exit 1
fi

if [ -f "${SUPPORT_DIR}/launch.properties" ]; then

	# Production Environment
	INSTALL_DIR="${SUPPORT_DIR}/.."
	CPATH="${INSTALL_DIR}/Ghidra/Framework/Utility/lib/Utility.jar"
	LS_CPATH="${SUPPORT_DIR}/LaunchSupport.jar"
	DEBUG_LOG4J="${SUPPORT_DIR}/debug.log4j.xml"
else

	# Development Environment (Eclipse classes or "gradle jar")
	INSTALL_DIR="${SUPPORT_DIR}/../../../.."
	CPATH="${INSTALL_DIR}/Ghidra/Framework/Utility/bin/main"
	LS_CPATH="${INSTALL_DIR}/GhidraBuild/LaunchSupport/bin/main"
	if ! [ -d "${LS_CPATH}" ]; then
		CPATH="${INSTALL_DIR}/Ghidra/Framework/Utility/build/libs/Utility.jar"
		LS_CPATH="${INSTALL_DIR}/GhidraBuild/LaunchSupport/build/libs/LaunchSupport.jar"
		if ! [ -f "${LS_CPATH}" ]; then
			echo "ERROR: Cannot launch from repo because Ghidra has not been compiled with Eclipse or Gradle."
			exit 1
		fi
	fi
	DEBUG_LOG4J="${INSTALL_DIR}/Ghidra/RuntimeScripts/Common/support/debug.log4j.xml"
fi

# Identify java command from either JAVA_HOME or PATH, try PATH first
JAVA_CMD=
if [ -x "$(command -v java)" ] ; then
	JAVA_CMD=java
elif [ -n "${JAVA_HOME}" ] ; then
	JAVA_CMD="${JAVA_HOME}/bin/java"
	if [ ! -x "${JAVA_CMD}" ] ; then
		echo "WARNING: JAVA_HOME environment variable is set to an invalid directory: ${JAVA_HOME}"
		JAVA_CMD=
	fi
fi

if [ "${JAVA_CMD}" == "" ]; then
	echo
	echo "ERROR: The 'java' command could not be found in your PATH or with JAVA_HOME."
	echo "Please refer to the Ghidra Installation Guide's Troubleshooting section."
	exit 1
fi

# Get the JDK that will be used to launch Ghidra
LS_JAVA_HOME="$("${JAVA_CMD}" -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -save)"
if [ ! $? -eq 0 ]; then
	# If fd 0 (stdin) isn't a tty, fail because we can't prompt the user
	if [ ! -t 0 ]; then
		echo
		echo "ERROR: Unable to prompt user for JDK path, no TTY detected."
		echo "Please refer to the Ghidra Installation Guide's Troubleshooting section."
		exit 1
	fi
	
	# No JDK has been setup yet.  Let the user choose one.
	"${JAVA_CMD}" -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -ask
	
	# Now that the user chose one, try again to get the JDK that will be used to launch Ghidra
	LS_JAVA_HOME="$("${JAVA_CMD}" -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -save)"
	if [ ! $? -eq 0 ]; then
		echo
		echo "ERROR: Failed to find a supported JDK."
		echo "Please refer to the Ghidra Installation Guide's Troubleshooting section."
		exit 1
	fi
fi
JAVA_CMD="${LS_JAVA_HOME}/bin/java"

# Get the configurable VM arguments from the launch properties
while IFS=$'\r\n' read -r line; do
	VMARGS_FROM_LAUNCH_PROPS+=("$line")
done < <("${JAVA_CMD}" -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" -vmargs)

# Add extra macOS VM arguments
if [ "$(uname -s)" = "Darwin" ]; then
	VMARGS_FROM_LAUNCH_SH+=("-Xdock:name=${APPNAME}")
fi

# Set Max Heap Size if specified
if [ "${MAXMEM}" != "" ]; then
	VMARGS_FROM_LAUNCH_SH+=("-Xmx${MAXMEM}")
fi

BACKGROUND=false
if [ "${MODE}" = "debug" ] || [ "${MODE}" = "debug-suspend" ]; then
	
	SUSPEND=n
	
	if [ "${DEBUG_ADDRESS}" = "" ]; then
		DEBUG_ADDRESS=127.0.0.1:18001
	fi

	if [ "${MODE}" = "debug-suspend" ]; then
		SUSPEND=y
	fi
	 
	VMARGS_FROM_LAUNCH_SH+=("-Dlog4j.configurationFile=${DEBUG_LOG4J}")
	VMARGS_FROM_LAUNCH_SH+=("-agentlib:jdwp=transport=dt_socket,server=y,suspend=${SUSPEND},address=${DEBUG_ADDRESS}")
	

elif [ "${MODE}" = "fg" ]; then
	:

elif [ "${MODE}" = "bg" ]; then
	BACKGROUND=true

else
	echo "ERROR: Incorrect launch usage - invalid launch mode: ${MODE}"
	exit 1
fi

if [ "${BACKGROUND}" = true ]; then
	"${JAVA_CMD}" "${VMARGS_FROM_LAUNCH_PROPS[@]}" "${VMARGS_FROM_LAUNCH_SH[@]}" ${VMARGS_FROM_CALLER} -showversion -cp "${CPATH}" ghidra.Ghidra ${CLASSNAME} "${ARGS[@]}" &>/dev/null &
	
	# If our process dies immediately, output something so the user knows to run in debug mode.
	# Otherwise they'll never see any error output from background mode.
	# Doing a kill -0 sends a no-op signal, which can be used to see if the process is still alive.
	PID=$!
	sleep 1
	if ! kill -0 ${PID} &>/dev/null; then
		echo "Exited with error.  Run in foreground (fg) mode for more details."
		exit 1
	fi
	exit 0
else
	set -o noglob; "${JAVA_CMD}" "${VMARGS_FROM_LAUNCH_PROPS[@]}" "${VMARGS_FROM_LAUNCH_SH[@]}" ${VMARGS_FROM_CALLER} -showversion -cp "${CPATH}" ghidra.Ghidra ${CLASSNAME} "${ARGS[@]}"
	exit $?
fi

