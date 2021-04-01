#!/usr/bin/env python
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
"""
This script starts a new session on the given TTY

The first parameter is the TTY file name. The remaining parameters
specify the image path and parameters of the session leader process.

A few stack overflow questions, the Linux man pages, and a good
tutorial on TTYs, PTYs, jobs, process groups, and sessions is needed to
understand everything that is going on here. Nevertheless, the
operative lines are commented in the hopes it will help readers find
their way.
"""
from __future__ import print_function

import os
import sys


def main():
    # Parse the arguments
    ptypath = sys.argv[1]
    args = sys.argv[2:]

    try:
        # This tells Linux to make this process the leader of a new session.
        os.setsid()
    except OSError as e:
        # This error occurs if we are already a session leader. Unlikely....
        print("Warning: setsid failed with EPERM")
        if e.errno != 1:
            raise e

    # Open the TTY. On Linux, the first TTY opened since becoming a session
    # leader becomes the session's controlling TTY. Other platforms, e.g., BSD
    # may require an explicit IOCTL.
    fd = os.open(ptypath, os.O_RDWR)

    # Copy stderr to a backup descriptor, in case something goes wrong.
    bk = fd + 1
    os.dup2(2, bk)

    # Copy the TTY fd over all standard streams. This effectively redirects
    # the leader's standard streams to the TTY.
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)

    # At this point, we are the session leader and the named TTY is the
    # controlling PTY.
    # Now, exec the specified image with arguments as the session leader.
    # Recall, this replaces the image of this process.
    try:
        os.execvp(args[0], args)
    except:
        # Something went wrong. Put stderr back, and report the error.
        os.dup2(bk, 2)
        raise


if __name__ == '__main__':
    main()
