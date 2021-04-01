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
from java.lang import (Object, Enum)


class BitmaskSet(Object):
    def __init__(self, universe, bitmask=0):
        if not issubclass(universe, Enum):
            raise TypeError("BitmaskSet must have an Enum as the universe")
        self.universe = universe
        self.bitmask = bitmask

    def add(self, elem):
        if not isinstance(elem, self.universe):
            raise TypeError("Element must be a member of the universe")
        self.bitmask |= elem.mask

    def discard(self, elem):
        if not isinstance(elem, self.universe):
            return
        self.bitmask &= ~elem.mask

    @classmethod
    def of(cls, universe, *args):
        bs = cls(universe, 0)
        for a in args:
            bs.add(a)
        return bs

    @classmethod
    def validate(cls, val, E):
        if val is None:
            return
        elif not isinstance(val, cls):
            raise TypeError("Value must be a %s. Got %r" % (cls.__name__, val))
        elif not val.universe == E.type():
            raise TypeError("Must be a set of %s. Got %r" %
                            (E.type(), val.universe))

    def __contains__(self, elem):
        if not isinstance(elem, self.universe):
            return False
        else:
            return (self.bitmask & elem.mask) != 0

    def __eq__(self, other):
        if isinstance(other, BitmaskSet):
            return self.universe == other.universe and self.bitmask == self.bitmask
        return self.issubset(other) and other.issubset(self)

    def __iter__(self):
        for elem in self.universe.values:
            if elem in self:
                yield elem

    def __repr__(self):
        return '[%s]' % (', '.join(self))
