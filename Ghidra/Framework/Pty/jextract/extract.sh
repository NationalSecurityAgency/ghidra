#!/usr/bin/bash
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
# Run this from this same directory
# After extract, manual edits are required to implement the captureState for errno

~/bin/jextract-25/bin/jextract \
  --output ../src/main/java \
  --target-package org.unix \
  "<fcntl.h>" \
  --include-function open \
  --include-typedef mode_t \
  --include-constant O_RDWR

~/bin/jextract-25/bin/jextract \
  --output ../src/main/java \
  --target-package org.unix.x \
  "<sys/ioctl.h>" \
  --include-function ioctl \
  --include-struct winsize

~/bin/jextract-25/bin/jextract \
  --output ../src/main/java \
  --target-package org.unix \
  "<pty.h>" \
  --include-function openpty

~/bin/jextract-25/bin/jextract \
  --output ../src/main/java \
  --target-package org.unix \
  "<string.h>" \
  --include-function strerror

~/bin/jextract-25/bin/jextract \
  --output ../src/main/java \
  --target-package org.unix \
  "<termios.h>" \
  --include-function tcgetattr \
  --include-function tcsetattr \
  --include-struct termios \
  --include-constant ECHO \
  --include-constant TCSANOW

~/bin/jextract-25/bin/jextract \
  --output ../src/main/java \
  --target-package org.unix \
  "<unistd.h>" \
  --include-function close \
  --include-function dup \
  --include-function dup2 \
  --include-function execv \
  --include-function read \
  --include-function setsid \
  --include-function write
