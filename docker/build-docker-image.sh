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

#-------------------------------
# Build Docker Image
#-------------------------------

# check if docker is installed
if which docker &> /dev/null; then
    echo "Docker installation found"
else
    echo "Docker installation not found. Please install docker."
    exit 1
fi


SCRIPT_FILE="$(readlink -f "$0" 2>/dev/null || readlink "$0" 2>/dev/null || echo "$0")"
SCRIPT_DIR="${SCRIPT_FILE%/*}"

if [ ! -e $SCRIPT_DIR/../ghidraRun ]; then
	echo "ERROR: This script must be run on a built release of Ghidra."
	exit 1
fi

if [ ! -e $SCRIPT_DIR/../Ghidra/application.properties ]; then
	echo "ERROR: $SCRIPT_DIR/../Ghidra/application.properties does not exist. Dockerized Ghidra needs this file to get tagging information."
	exit 1
fi

# get appropriate tag
source <(sed 's/\.\|\(=.*\)/_\1/g;s/_=/=/' $SCRIPT_DIR/../Ghidra/application.properties) &> /dev/null
VERSION=${application_version}
RELEASE=${application_release_name}
TAG=${VERSION}_${RELEASE}

# build docker image
IMAGE=ghidra/ghidra:$TAG
echo building image $IMAGE
docker build -f $SCRIPT_DIR/../docker/Dockerfile -t $IMAGE $SCRIPT_DIR/.. 2>&1 | tee $SCRIPT_DIR/../docker/docker.log
if [ $? != 0 ]; then
        echo "ERROR: Docker Image Build Failed! See docker/docker.log to identify build error"
        exit 1
fi
echo "Docker Image built ($IMAGE). See docker/README.md for usage instructions."
exit 0

