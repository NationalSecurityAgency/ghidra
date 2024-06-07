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
from concurrent.futures import ThreadPoolExecutor
import os
import socket
import sys

from ghidratrace import *
from ghidratrace.client import *


REGISTRY = MethodRegistry(ThreadPoolExecutor(max_workers=1))

host = os.getenv("GHIDRA_TRACE_RMI_HOST")
port = int(os.getenv("GHIDRA_TRACE_RMI_PORT"))
c = socket.socket()
c.connect((host, port))
client = Client(
    c, f"python-{sys.version_info.major}.{sys.version_info.minor}", REGISTRY)
print(f"Connected to {client.description} at {host}:{port}")

trace = client.create_trace("noname", os.getenv(
    "OPT_LANG"), os.getenv("OPT_COMP"))
