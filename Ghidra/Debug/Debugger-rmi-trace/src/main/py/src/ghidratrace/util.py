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
from concurrent.futures import Future
import socket
from typing import TypeVar

from google.protobuf import message as _message

M = TypeVar('M', bound=_message.Message)


def send_length(s: socket.socket, value: int) -> None:
    s.sendall(value.to_bytes(4, 'big'))


def send_delimited(s: socket.socket, msg: _message.Message) -> None:
    data = msg.SerializeToString()
    send_length(s, len(data))
    s.sendall(data)


def recv_all(s, size: int) -> bytes:
    buf = b''
    while len(buf) < size:
        part = s.recv(size - len(buf))
        if len(part) == 0:
            return buf
        buf += part
    return buf
    # return s.recv(size, socket.MSG_WAITALL)


def recv_length(s: socket.socket) -> int:
    buf = recv_all(s, 4)
    if len(buf) < 4:
        raise Exception("Socket closed")
    return int.from_bytes(buf, 'big')


def recv_delimited(s: socket.socket, msg: M, dbg_seq: int) -> M:
    size = recv_length(s)
    buf = recv_all(s, size)
    if len(buf) < size:
        raise Exception("Socket closed")
    msg.ParseFromString(buf)
    return msg
