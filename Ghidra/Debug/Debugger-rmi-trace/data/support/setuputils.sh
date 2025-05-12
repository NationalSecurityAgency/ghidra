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
find-app-properties() {
	local simple="$GHIDRA_HOME/Ghidra/application.properties"
	if [ -f "$simple" ]; then
		echo $simple
		return 0
	fi
	local dev2="$GHIDRA_HOME/ghidra/Ghidra/application.properties"
	if [ -f "$dev2" ]; then
		echo $dev2
		return 0
	fi
	echo >&2 "Cannot find application.properties"
	return 1
}

get-ghidra-version() {
	local app_ver_re='application\.version=(.*)'
	local props=$(find-app-properties)
	local version=$(cat "$props" | while read line; do
		if [[ $line =~ $app_ver_re ]]; then
			echo "${BASH_REMATCH[1]}"
		fi
	done)
	if [ -n "$version" ]; then
		echo "$version"
		return 0
	fi
	echo >&2 "Cannot determine Ghidra version"
	return 1
}

ghidra-module-pypath() {
	installed="$GHIDRA_HOME/Ghidra/$1/pypkg/src"
	if [ -d "$installed" ]; then
		echo $installed
		return 0
	fi
	dev1="$GHIDRA_HOME/Ghidra/$1/build/pypkg/src"
	if [ -d "$dev1" ]; then
		echo $dev1
		return 0
	fi
	dev2="$GHIDRA_HOME/ghidra/Ghidra/$1/build/pypkg/src"
	if [ -d "$dev2" ]; then
		echo $dev2
		return 0
	fi
	echo >&2 "Cannot find Python source for $1. Try gradle assemblePyPackage?"
	return 1
}

ghidra-module-pydist() {
	installed="$GHIDRA_HOME/Ghidra/$1/pypkg/dist"
	if [ -d "$installed" ]; then
		echo $installed
		return 0
	fi
	dev1="$GHIDRA_HOME/Ghidra/$1/build/pypkg/dist"
	if [ -d "$dev1" ]; then
		echo $dev1
		return 0
	fi
	dev2="$GHIDRA_HOME/ghidra/Ghidra/$1/build/pypkg/dist"
	if [ -d "$dev2" ]; then
		echo $dev2
		return 0
	fi
	echo >&2 "Cannot find Python package for $1. Try gradle buildPyPackage?"
	return 1
}

compute-ssh-args() {
	forward=$1
	shift
	local qargs
	printf -v qargs '%q ' "$@"

	sshargs+=("$OPT_SSH_PATH")
	sshargs+=(-t)
	if [ "$forward" == "true" ]; then
		sshargs+=("-R$OPT_REMOTE_PORT:$GHIDRA_TRACE_RMI_ADDR")
	fi
	if [ -n "$OPT_EXTRA_SSH_ARGS" ]; then
		sshargs+=($OPT_EXTRA_SSH_ARGS)
	fi
	sshargs+=("$OPT_HOST")
	sshargs+=("TERM='$TERM' $qargs")
}

check-result-and-prompt-mitigation() {
	exitcode=$1
	msg=$2
	prompt=$3

	if [ "$exitcode" -eq "253" ]; then
		cat << EOF
--------------------------------------------------------------------------------
!!!                       INCORRECT OR INCOMPLETE SETUP                      !!!
--------------------------------------------------------------------------------

EOF
		echo "$msg"
		echo ""
		echo "Select KEEP if you're seeing this in an error dialog."
		echo -n "$prompt [Y/n] "
		read answer
		[ "$answer" == "y" ] || [ "$answer" == "Y" ] || [ "$answer" == "" ]
		return $?
	fi
	return 1
}

mitigate-scp-pymodules() {
	local -a scpargs
	for mod in "$@"; do
		dist=$(ghidra-module-pydist "$mod")
		scpargs+=("$dist"/*)
	done
	scp "${scpargs[@]}" "$OPT_HOST:~/"
}
