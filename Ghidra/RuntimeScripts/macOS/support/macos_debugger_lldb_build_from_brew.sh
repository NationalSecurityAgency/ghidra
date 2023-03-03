#!/usr/bin/env bash
# This script will download lldb from homebrew and
# build the Ghidra JNI bindings for this version of
# lldb. It will then patch your Ghidra distribution
# to use these built libraries.

set -ex

if [ -z "${GHIDRA_INSTALL_DIR}" ]; then
	echo "Please set the GHIDRA_INSTALL_DIR environment variable to your Ghidra install location"
	exit 1
fi

if [ ! -z "${GHIDRA_INSTALL_DIR}" ]; then
	pushd "${GHIDRA_INSTALL_DIR}/Ghidra/Debug/Debugger-swig-lldb"
fi

# Pin to 14, as this is what Ghidra's built in bindings are built against
LLVM_VERSION="14"

# Install llvm and unpack the source code for this version, patched
# with the brew patches
brew install llvm@${LLVM_VERSION}

LLVM_TEMP_DIR=$(mktemp -d)

# Download the source code brew used to build llvm, including
# brew specific patches.
brew unpack --patch --destdir ${LLVM_TEMP_DIR} llvm@${LLVM_VERSION}
export LLVM_HOME="$(echo ${LLVM_TEMP_DIR}/llvm@${LLVM_VERSION}-*)"

# Set the appropriate build variables to link and compile the
# liblldb-java library below.
BREW_LLVM="$(brew --prefix llvm@${LLVM_VERSION})"
export LDFLAGS="-L${BREW_LLVM}/lib/c++ -Wl,-rpath,${BREW_LLVM}/lib/c++,-L${BREW_LLVM}/lib"
export PATH="${BREW_LLVM}/bin:$PATH"
export CPPFLAGS="-I${BREW_LLVM}/include"

export LLVM_BUILD="$(echo ${BREW_LLVM})"

# Build native components
gradle buildNatives

# Build only the library required for our architecture.
# The brew llvm package installs a thinned binary containing
# only the native architecture of your machine.
if [ $(arch) == "arm64" ]; then
	gradle :Debugger-swig-lldb:linkMainMac_arm_64SharedLibrary
	export LIBLLDB_JAVA_DIR=Ghidra/Debug/Debugger-swig-lldb/build/os/mac_arm_64/
else
	gradle :Debugger-swig-lldb:linkMainMac_x86_64SharedLibrary
	export LIBLLDB_JAVA_DIR=Ghidra/Debug/Debugger-swig-lldb/build/os/mac_x86_64/
fi

# Patch the launch.properties with our library location
LAUNCH_PROPERTIES=${GHIDRA_INSTALL_DIR}/support/launch.properties
sed -i '' /llvm/d ${LAUNCH_PROPERTIES}
echo "VMARGS=-Djava.library.path=${GHIDRA_INSTALL_DIR}/${LIBLLDB_JAVA_DIR}:${BREW_LLVM}/lib" >> ${LAUNCH_PROPERTIES}
