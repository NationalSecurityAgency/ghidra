
from ghidra.comm.packet import typedesc

import java.lang
import java.util


class PacketTestClasses_TestMessageFullSpecColField_IntList(java.util.ArrayList):

    @classmethod
    def subst_targs(cls):
        return dict(E=typedesc(lambda: java.lang.Integer))
