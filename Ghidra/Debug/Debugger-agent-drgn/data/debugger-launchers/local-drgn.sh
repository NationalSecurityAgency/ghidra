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
#@title drgn
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>drgn</tt></h3>
#@desc   <p>
#@desc     This will attach to a target running on the local machine using <tt>drgn</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group drgn
#@icon icon.debugger
#@help drgn#attach
#@depends Debugger-rmi-trace
#@env OPT_TARGET_PID:int=44068 "PID" "The target's process id"

export OPT_TARGET_KIND="user" 
# sudo -E drgn -p "$OPT_TARGET_PID" ../support/local-drgn.py
# or 'echo 0 > /proc/sys/kernel/yama/ptrace_scope'
drgn -p "$OPT_TARGET_PID" ../support/local-drgn.py

