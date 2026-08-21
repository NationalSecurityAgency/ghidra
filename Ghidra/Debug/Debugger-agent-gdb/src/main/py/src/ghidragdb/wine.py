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
from dataclasses import dataclass
from typing import Dict, List, Optional
import gdb

from . import util
from .commands import install, cmd


@install
class GhidraWinePrefix(gdb.Command):
    """Commands for tracing Wine processes"""

    def __init__(self) -> None:
        super().__init__('ghidra wine', gdb.COMMAND_SUPPORT, prefix=True)


def is_mapped(pe_file: str) -> bool:
    return pe_file in gdb.execute("info proc mappings", to_string=True)


def set_break(command: str) -> gdb.Breakpoint:
    breaks_before = set(gdb.breakpoints())
    gdb.execute(command)
    return (set(gdb.breakpoints()) - breaks_before).pop()


@cmd('ghidra wine run-to-image', '-ghidra-wine-run-to-image',
     gdb.COMMAND_SUPPORT, False)
def ghidra_wine_run_to_image(pe_file: str, *, is_mi: bool, **kwargs) -> None:
    mprot_catchpoint = set_break("""
catch syscall mprotect
commands
silent
end
""".strip())
    while not is_mapped(pe_file):
        gdb.execute("continue")
    mprot_catchpoint.delete()


ORIG_MODULE_INFO_READER = util.MODULE_INFO_READER


@dataclass(frozen=False)
class Range(object):
    min: int
    max: int

    @staticmethod
    def from_region(region: util.Region) -> 'Range':
        return Range(region.start, region.end)

    def expand(self, region: util.Region):
        self.min = min(self.min, region.start)
        self.max = max(self.max, region.end)
        return self


# There are more, but user can monkey patch this
MODULE_SUFFIXES = (".exe", ".dll")


class WineModuleInfoReader(util.ModuleInfoReader):

    def get_modules(self) -> Dict[str, util.Module]:
        modules = ORIG_MODULE_INFO_READER.get_modules()
        ranges = dict()
        for region in util.REGION_INFO_READER.get_regions():
            if not region.objfile in ranges:
                ranges[region.objfile] = Range.from_region(region)
            else:
                ranges[region.objfile].expand(region)
        for k, v in ranges.items():
            if k in modules:
                continue
            if not k.lower().endswith(MODULE_SUFFIXES):
                continue
            modules[k] = util.Module(k, v.min, v.max, {})
        return modules


util.MODULE_INFO_READER = WineModuleInfoReader()
