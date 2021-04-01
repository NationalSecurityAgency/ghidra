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
Classes corresponding to common Java collection types

These are not ports by any means of the corresponding Java types.
Instead, they just populate the same name space so that exporting need
not map things over. I also use them as convenient places to implement
a common interface.
'''

from java.lang import Object


class Collection(Object):

    @classmethod
    def validate(cls, val, **targs):
        E = cls.resolve_targs(Collection, **targs)['E']
        if not hasattr(val, '__iter__') or not hasattr(val, '__len__'):
            raise ValueError(
                "Value for %s must behave list a collection " +
                "(__iter__ and __len__)")
        for e in val:
            E.validate(e)

    @classmethod
    def subst_targs(cls, E):
        return {}


class List(Collection):

    @classmethod
    def validate(cls, val, **targs):
        E = cls.resolve_targs(List, **targs)['E']
        if not hasattr(val, '__getitem__') or not hasattr(val, '__len__'):
            raise ValueError(
                "Value for %s must behave list a list " +
                "(__getitem__ and __len__)")
        for e in val:
            E.validate(e)

    @classmethod
    def subst_targs(cls, E):
        return dict(E=E)

    @classmethod
    def add_to(cls, l, item):
        l.append(item)


class ArrayList(List):

    @classmethod
    def new(cls):
        return list()
