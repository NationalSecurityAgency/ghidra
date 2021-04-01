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
'''
Placeholders for annotations particular to string packet codecs

The string packet codec is not yet ported to Python, so there is no
sense in exporting string-based packet types. However, the test packet
types are annotated with binary and string codecs in mind, so these
annotations must be defined.
'''
from .annot import Annotation


class RegexSeparated(Annotation):

    def __init__(self, exp, tok, optional=True):
        self.exp = exp
        self.optional = optional
        self.tok = tok


class RegexTerminated(Annotation):

    def __init__(self, exp, tok, cond=''):
        self.exp = exp
        self.cond = cond
        self.tok = tok


class SizeRestricted_PadDirection:
    LEFT = 0
    NONE = 1
    RIGHT = 2


class SizeRestricted(Annotation):

    def __init__(self, direction=SizeRestricted_PadDirection.NONE, pad=' ',
                 value=None, min=0, max=None):  # @ReservedAssignment
        self.direction = direction
        self.pad = pad
        self.value = value
        self.min = min
        self.max = max


class WithRadix(Annotation):

    def __init__(self, value):
        self.value = value
