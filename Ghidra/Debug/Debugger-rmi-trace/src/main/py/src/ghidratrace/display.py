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
from typing import Any, Callable, List, Optional, Sequence, TypeVar, Union
from .client import Address, TraceObject, TraceObjectValue


T = TypeVar('T')


def wait_opt(val: Union[T, Future[T], None]) -> Optional[T]:
    if val is None:
        return None
    if isinstance(val, Future):
        return val.result()
    return val


def wait(val: Union[T, Future[T]]) -> T:
    if isinstance(val, Future):
        return val.result()
    return val


class TableColumn(object):
    def __init__(self, head: str) -> None:
        self.head = head
        self.contents = [head]
        self.is_last = False

    def add_data(self, data: str) -> None:
        self.contents.append(data)

    def finish(self) -> None:
        self.width = max(len(d) for d in self.contents) + 1

    def format_cell(self, i: int) -> str:
        return (self.contents[i] if self.is_last
                else self.contents[i].ljust(self.width))


class Tabular(object):
    def __init__(self, heads: List[str]) -> None:
        self.columns = [TableColumn(h) for h in heads]
        self.columns[-1].is_last = True
        self.num_rows = 1

    def add_row(self, datas: List[str]) -> None:
        for c, d in zip(self.columns, datas):
            c.add_data(d)
        self.num_rows += 1

    def print_table(self, println: Callable[[str], None]) -> None:
        for c in self.columns:
            c.finish()
        for rn in range(self.num_rows):
            println(''.join(c.format_cell(rn) for c in self.columns))


def repr_or_future(val: Union[T, Future[T]]) -> str:
    if isinstance(val, Future):
        if val.done():
            return str(val.result())
        else:
            return "<Future>"
    else:
        return str(val)


def obj_repr(obj: TraceObject) -> str:
    if obj.path is None:
        if obj.id is None:
            return "<ERR: no path nor id>"
        else:
            return f"<id={repr_or_future(obj.id)}>"
    elif isinstance(obj.path, Future):
        if obj.path.done():
            return obj.path.result()
        elif obj.id is None:
            return "<path=<Future>>"
        else:
            return f"<id={repr_or_future(obj.id)}>"
    else:
        return obj.path


def val_repr(value: Any) -> str:
    if isinstance(value, TraceObject):
        return obj_repr(value)
    elif isinstance(value, Address):
        return f'{value.space}:{value.offset:08x}'
    return repr(value)


def print_tabular_values(values: Sequence[TraceObjectValue],
                         println: Callable[[str], None]) -> None:
    table = Tabular(['Parent', 'Key', 'Span', 'Value', 'Type'])
    for v in values:
        table.add_row([obj_repr(v.parent), v.key, str(v.span),
                       val_repr(v.value), str(v.schema)])
    table.print_table(println)
