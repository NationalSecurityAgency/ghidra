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
#@title drgn kernel
#@desc <html><body width="300px">
#@desc   <h3>Launch with <tt>drgn-kernel</tt></h3>
#@desc   <p>
#@desc     This will attach to the local machine's kernel using <tt>drgn</tt>.
#@desc     For setup instructions, press <b>F1</b>.
#@desc   </p>
#@desc </body></html>
#@menu-group drgn
#@icon icon.debugger
#@help drgn#linux_kernel
#@depends Debugger-rmi-trace

export OPT_TARGET_KIND="kernel" 
sudo -E drgn ../support/local-drgn.py

