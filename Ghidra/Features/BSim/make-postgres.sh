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
#
# This script builds the postgresql server and BSim extension within a
# GHIDRA installation.
#
# The PostgreSQL source distribution file postgresql-15.3.tar.gz must
# be placed in the BSim module directory prior to running this script.
# This file can be downloaded directly from the PostgreSQL website at:
#
#   https://www.postgresql.org/ftp/source/v15.3
#
# Within development environments, this script will first check the
# ghidra.bin repo for this source file.
#
# The postgresql server configuration options below
# (POSTGRES_CONFIG_OPTIONS) may be adjusted if required (e.g., build
# without openssl use, etc.). 
#
# See https://www.postgresql.org/docs/15/install-procedure.html
# for supported postgresql config options.
#
# Additional software may need to be installed in order to perform the 
# postgresql build.  Please refer to the following web page for 
# software dependencies:
#
#   https://www.postgresql.org/docs/current/install-requirements.html
#
# Or for Linux specific package dependencies, see:
#
#   https://wiki.postgresql.org/wiki/Compile_and_Install_from_source_code
#
#

POSTGRES=postgresql-15.3
POSTGRES_GZ=${POSTGRES}.tar.gz
POSTGRES_CONFIG_OPTIONS="--disable-rpath --with-openssl"

DIR=$(cd `dirname $0`; pwd)

POSTGRES_GZ_PATH=${DIR}/../../../../ghidra.bin/Ghidra/Features/BSim/${POSTGRES_GZ}
if [ ! -f "${POSTGRES_GZ_PATH}" ]; then
	POSTGRES_GZ_PATH=${DIR}/${POSTGRES_GZ}
	if [ ! -f "${POSTGRES_GZ_PATH}" ]; then
		echo "Postgres source bundle not found: ${POSTGRES_GZ_PATH}"
		exit -1
	fi
fi

OS=`uname -s`
ARCH=`uname -m`

cd ${DIR}

mkdir -p build > /dev/null

if [ ! -d build/${POSTGRES} ]; then
	# Unpack postgres source distro into build
	echo "Unpacking postgresql source: ${POSTGRES_GZ_PATH}"
	$(cd build; tar -xzf ${POSTGRES_GZ_PATH} )
fi

# Build postgresql

pushd  build/${POSTGRES}

if [ "$OS" = "Darwin" ]; then
	export MACOSX_DEPLOYMENT_TARGET=10.5
	export ARCHFLAGS="-arch x86_64"
	OSDIR=mac_x86_64
elif [ "$ARCH" = "x86_64" ]; then
	OSDIR=linux_x86_64
else
	echo "Unsupported platform: $OS $ARCH"
	exit -1	
fi

# Install within build/os
INSTALL_DIR=${DIR}/build/os/${OSDIR}/postgresql
rm -rf ${INSTALL_DIR} > /dev/null

make distclean

# Configure postgres 

./configure ${POSTGRES_CONFIG_OPTIONS} --prefix=${INSTALL_DIR}
if [ $? != 0 ]; then
	exit $?
fi

make install
if [ $? != 0 ]; then
	exit $?
fi

make -C contrib/pg_prewarm install
if [ $? != 0 ]; then
	exit $?
fi

echo "Completed postgresql build"

# Build lshvector plugin for postgresql

popd

rm -rf build/lshvector > /dev/null
mkdir build/lshvector

echo "Building lshvector plugin..."

cp src/lshvector/* build/lshvector
cp src/lshvector/c/* build/lshvector

cd build/lshvector
make -f Makefile.lshvector install PG_CONFIG=${INSTALL_DIR}/bin/pg_config

if [ $? = 0 ]; then
	echo "Completed build and install of lshvector postgresql plugin"	
	exit 0
fi

exit -1

