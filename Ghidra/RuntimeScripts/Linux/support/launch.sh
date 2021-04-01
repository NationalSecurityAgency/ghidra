#!/usr/bin/env bash
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

umask 027

function showUsage() {

	echo "Usage: $0 <mode> <name> <max-memory> \"<vmarg-list>\" <app-classname> <app-args>... "
	echo "   <mode>: fg   run as foreground process in current shell"
	echo "           bg   run as background process in new shell"
	echo "           debug   run as foreground process in current shell in debug mode (suspend=n)"
	echo "           debug-suspend   run as foreground process in current shell in debug mode (suspend=y)"
	echo "           NOTE: for all debug modes environment variable DEBUG_ADDRESS may be set to "
	echo "                 override default debug address of 127.0.0.1:18001"
	echo "   <name>: application name used for naming console window"
	echo "   <max-memory>: maximum memory heap size in MB (e.g., 768M or 2G).  Use empty \"\" if default"
    echo "               should be used.  This will generally be upto 1/4 of the physical memory available"
    echo "               to the OS."
	echo "   <vmarg-list>: pass-thru args (e.g.,  \"-Xmx512M -Dmyvar=1 -DanotherVar=2\") - use"
	echo "               empty \"\" if vmargs not needed"
	echo "   <app-classname>: application classname (e.g., ghidra.GhidraRun )"
	echo "   <app-args>...: arguments to be passed to the application"
	echo " "
	echo "   Example:"
	echo "      $0 debug Ghidra 768M \"\" ghidra.GhidraRun"

	exit 1
}


VMARG_LIST=
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
			APPNAME=$AA
			;;
		3)
			MAXMEM=$AA
			;;
		4)
			if [ "$AA" != "" ]; then
				VMARG_LIST=$AA
			fi
			;;
		5)
			CLASSNAME=$AA
			;;
		*)
			# Preserve quoted arguments
			if [[ $AA =~ $WHITESPACE ]]; then
				AA="\"$AA\""
		    fi
			ARGS[${#ARGS[@]}]=$AA
			;;
	esac
done

# Verify that required number of args were provided
if [[ ${INDEX} -lt 5 ]]; then
	echo "Incorrect launch usage - missing argument(s)"
	showUsage
	exit 1
fi

SUPPORT_DIR="${0%/*}"
if [ -f "${SUPPORT_DIR}/launch.properties" ]; then

	# Production Environment
	INSTALL_DIR="${SUPPORT_DIR}/.."
	CPATH="${INSTALL_DIR}/Ghidra/Framework/Utility/lib/Utility.jar"
	LS_CPATH="${SUPPORT_DIR}/LaunchSupport.jar"
	DEBUG_LOG4J="${SUPPORT_DIR}/debug.log4j.xml"
else

	# Development Environment
	INSTALL_DIR="${SUPPORT_DIR}/../../../.."
	CPATH="${INSTALL_DIR}/Ghidra/Framework/Utility/bin/main"
	LS_CPATH="${INSTALL_DIR}/GhidraBuild/LaunchSupport/bin/main"
	DEBUG_LOG4J="${INSTALL_DIR}/Ghidra/RuntimeScripts/Common/support/debug.log4j.xml"
	if ! [ -d "${LS_CPATH}" ]; then
		echo "Ghidra cannot launch in development mode because Eclipse has not compiled its class files."
		exit 1
	fi
fi

# Make sure some kind of java is on the path.  It's required to run the LaunchSupport program.
if ! [ -x "$(command -v java)" ] ; then
	echo "Java runtime not found.  Please refer to the Ghidra Installation Guide's Troubleshooting section."
	exit 1
fi

# Get the JDK that will be used to launch Ghidra
JAVA_HOME="$(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" -jdk_home -save)"
if [ ! $? -eq 0 ]; then
	# No JDK has been setup yet.  Let the user choose one.
	java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" -jdk_home -ask
	
	# Now that the user chose one, try again to get the JDK that will be used to launch Ghidra
	JAVA_HOME="$(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" -jdk_home -save)"
	if [ ! $? -eq 0 ]; then
		echo
		echo "Failed to find a supported JDK.  Please refer to the Ghidra Installation Guide's Troubleshooting section."
		exit 1
	fi
fi
JAVA_CMD="${JAVA_HOME}/bin/java"

# Get the configurable VM arguments from the launch properties
VMARG_LIST+=" $(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" -vmargs)"

# Add extra macOS VM arguments
if [ "$(uname -s)" = "Darwin" ]; then
	VMARG_LIST+=" -Xdock:name=${APPNAME}"
fi

# Set Max Heap Size if specified
if [ "${MAXMEM}" != "" ]; then
	VMARG_LIST+=" -Xmx${MAXMEM}"
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
	 
	VMARG_LIST+=" -Dlog4j.configuration=\"${DEBUG_LOG4J}\""  
	VMARG_LIST+=" -agentlib:jdwp=transport=dt_socket,server=y,suspend=${SUSPEND},address=${DEBUG_ADDRESS}"
	

elif [ "${MODE}" = "fg" ]; then
	:

elif [ "${MODE}" = "bg" ]; then
	BACKGROUND=true

else
	echo "Incorrect launch usage - invalid launch mode: ${MODE}"
	exit 1
fi

if [ "${BACKGROUND}" = true ]; then
	eval "\"${JAVA_CMD}\" ${VMARG_LIST} -showversion -cp \"${CPATH}\" ghidra.GhidraLauncher ${CLASSNAME} ${ARGS[@]}" &>/dev/null &
	
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
	eval "\"${JAVA_CMD}\" ${VMARG_LIST} -showversion -cp \"${CPATH}\" ghidra.GhidraLauncher ${CLASSNAME} ${ARGS[@]}"
	exit $?
fi

