#!/usr/bin/env python3
# ###
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
import argparse
import subprocess
from dataclasses import dataclass
from pathlib import Path


PIPE_NAMES = ("x0", "x1", "y0", "y1", "y2")
BUILTIN_USEROPS = {
    "tilegx_fence",
    "tilegx_mfspr",
    "tilegx_mtspr",
    "tilegx_finv",
    "tilegx_flush",
    "tilegx_icoh",
    "tilegx_wait",
    "tilegx_trap",
}
REGISTER_NAMES = (
    [f"r{i}" for i in range(53)]
    + ["tp", "sp", "lr", "sn", "idn0", "idn1", "udn0", "udn1", "udn2", "udn3", "zero"]
)
SHADOW_REGISTER_NAMES = [f"{name}_new" for name in REGISTER_NAMES]

# Binutils tilegx_operands[] index -> SLEIGH display/pattern symbol.
OPERANDS = {
    0: "imm8_x0",
    1: "imm8_x1",
    2: "imm8_y0",
    3: "imm8_y1",
    4: "imm16_x0",
    5: "imm16_x1",
    6: "dest_x1",
    7: "srca_x1",
    8: "dest_x0",
    9: "srca_x0",
    10: "dest_y0",
    11: "srca_y0",
    12: "dest_y1",
    13: "srca_y1",
    14: "srca_y2",
    15: "srca_x1",
    16: "srcb_x0",
    17: "srcb_x1",
    18: "srcb_y0",
    19: "srcb_y1",
    20: "broff_x1",
    21: "bfstart_x0",
    22: "bfend_x0",
    23: "dest_x0",
    24: "dest_y0",
    25: "jumpoff_x1",
    26: "srcbdest_y2",
    27: "mf_spr_x1",
    28: "mt_imm14_x1",
    29: "shamt_x0",
    30: "shamt_x1",
    31: "shamt_y0",
    32: "shamt_y1",
    33: "srcbdest_y2",
    34: "dest_imm8_x1",
}

# Register operands need small constructors so register 63 behaves as the
# architectural zero register: reads return zero and writes are discarded.
REGISTER_OPERANDS = {
    6: ("D_x1", "dest_x1", "write"),
    7: ("A_x1", "srca_x1", "read"),
    8: ("D_x0", "dest_x0", "write"),
    9: ("A_x0", "srca_x0", "read"),
    10: ("D_y0", "dest_y0", "write"),
    11: ("A_y0", "srca_y0", "read"),
    12: ("D_y1", "dest_y1", "write"),
    13: ("A_y1", "srca_y1", "read"),
    14: ("A_y2", "srca_y2", "read"),
    15: ("AD_x1", "srca_x1", "readwrite"),
    16: ("B_x0", "srcb_x0", "read"),
    17: ("B_x1", "srcb_x1", "read"),
    18: ("B_y0", "srcb_y0", "read"),
    19: ("B_y1", "srcb_y1", "read"),
    23: ("AD_x0", "dest_x0", "readwrite"),
    24: ("AD_y0", "dest_y0", "readwrite"),
    26: ("D_y2", "srcbdest_y2", "write"),
    33: ("AD_y2", "srcbdest_y2", "readwrite"),
}

FIELDS = {
    "mode": (62, 63, False),
    "imm8_x0": (12, 19, True),
    "imm8_x1": (43, 50, True),
    "imm8_y0": (12, 19, True),
    "imm8_y1": (43, 50, True),
    "imm16_x0": (12, 27, True),
    "imm16_x1": (43, 58, True),
    "dest_x1": (31, 36, False),
    "srca_x1": (37, 42, False),
    "dest_x0": (0, 5, False),
    "srca_x0": (6, 11, False),
    "dest_y0": (0, 5, False),
    "srca_y0": (6, 11, False),
    "dest_y1": (31, 36, False),
    "srca_y1": (37, 42, False),
    "srca_y2": (20, 25, False),
    "srcb_x0": (12, 17, False),
    "srcb_x1": (43, 48, False),
    "srcb_y0": (12, 17, False),
    "srcb_y1": (43, 48, False),
    "bfstart_x0": (18, 23, False),
    "bfend_x0": (12, 17, False),
    "jumpoff_x1": (31, 57, True),
    "srcbdest_y2": (51, 56, False),
    "mf_imm14_x1": (37, 50, False),
    "shamt_x0": (12, 17, False),
    "shamt_x1": (43, 48, False),
    "shamt_y0": (12, 17, False),
    "shamt_y1": (43, 48, False),
    "br_lo": (31, 36, False),
    "br_hi": (43, 53, True),
    "mt_lo": (31, 36, False),
    "mt_hi": (43, 50, False),
    "destimm_lo": (31, 36, False),
    "destimm_hi": (43, 44, True),
}

REGISTER_FIELDS = (
    "dest_x1",
    "srca_x1",
    "dest_x0",
    "srca_x0",
    "dest_y0",
    "srca_y0",
    "dest_y1",
    "srca_y1",
    "srca_y2",
    "srcb_x0",
    "srcb_x1",
    "srcb_y0",
    "srcb_y1",
    "srcbdest_y2",
)


@dataclass(frozen=True)
class Opcode:
    pipe: int
    name: str
    mask: int
    value: int
    operands: tuple[int, ...]


def load_opcodes(dumper: Path) -> list[Opcode]:
    result = subprocess.run([str(dumper)], check=True, capture_output=True, text=True)
    opcodes = []
    seen = set()
    for line in result.stdout.splitlines():
        columns = line.split("\t")
        pipe, name = int(columns[0]), columns[1]
        mask, value = int(columns[2], 16), int(columns[3], 16)
        operand_count = int(columns[4])
        operands = tuple(map(int, columns[5 : 5 + operand_count]))
        key = (pipe, mask, value)
        if key not in seen:
            opcodes.append(Opcode(pipe, name, mask, value, operands))
            seen.add(key)
    return opcodes


def mask_runs(mask: int):
    bit = 0
    while bit < 64:
        if not (mask >> bit) & 1:
            bit += 1
            continue
        low = bit
        while bit + 1 < 64 and (mask >> (bit + 1)) & 1:
            bit += 1
        yield low, bit
        bit += 1


def fixed_term(low: int, high: int, value: int) -> str:
    width = high - low + 1
    return f"m_{low:02d}_{high:02d}=0x{(value >> low) & ((1 << width) - 1):x}"


def patterns_overlap(left: Opcode, right: Opcode) -> bool:
    common = left.mask & right.mask
    return (left.value & common) == (right.value & common)


def prioritize(opcodes: list[Opcode]):
    ordered = []
    exclusions = {}
    for pipe in range(len(PIPE_NAMES)):
        pipe_opcodes = [opcode for opcode in opcodes if opcode.pipe == pipe]
        pipe_opcodes.sort(key=lambda opcode: -bin(opcode.mask).count("1"))
        previous = []
        for opcode in pipe_opcodes:
            opcode_exclusions = []
            for higher_priority in previous:
                if not patterns_overlap(opcode, higher_priority):
                    continue
                extra_mask = higher_priority.mask & ~opcode.mask
                if extra_mask:
                    opcode_exclusions.append((extra_mask, higher_priority.value))
            exclusions[opcode] = opcode_exclusions
            ordered.append(opcode)
            previous.append(opcode)
    return ordered, exclusions


def composite_operands() -> str:
    return "\n".join(
        (
            "broff_x1: reloc is br_hi & br_lo "
            "[ reloc = inst_start + (((br_hi << 6) | br_lo) << 3); ] "
            "{ export *[ram]:8 reloc; }",
            "mf_spr_x1: mf_imm14_x1 is mf_imm14_x1 "
            "{ local value:8 = mf_imm14_x1; export value; }",
            'mt_imm14_x1: mt_hi^":"^mt_lo is mt_hi & mt_lo '
            "{ local value:8 = (mt_hi << 6) | mt_lo; export value; }",
            "dest_imm8_x1: immediate is destimm_hi & destimm_lo "
            "[ immediate = (destimm_hi << 6) | destimm_lo; ] "
            "{ export *[const]:8 immediate; }",
            "jumpoff_target: reloc is jumpoff_x1 "
            "[ reloc = inst_start + (jumpoff_x1 << 3); ] "
            "{ export *[ram]:8 reloc; }",
        )
    )


def register_operand_constructors() -> str:
    lines = []
    for symbol, field, mode in dict.fromkeys(REGISTER_OPERANDS.values()):
        if mode == "read":
            zero_semantics = "export 0:8;"
        else:
            zero_semantics = "local ignored:8 = 0; export ignored;"
        lines.append(
            f"{symbol}: {field} is {field} & {field}_num=0x3f "
            f"{{ {zero_semantics} }}"
        )
        if mode == "read":
            lines.append(
                f"{symbol}: {field} is {field} & {field}_num!=0x3f "
                f"{{ export {field}; }}"
            )
            continue
        initialize = f"{field}_new = {field}; " if mode == "readwrite" else ""
        lines.append(
            f"{symbol}: {field} is {field} & {field}_new & {field}_num!=0x3f "
            f"{{ {initialize}export {field}_new; "
            f"<<COMMIT>> {field} = {field}_new; }}"
        )
    return "\n".join(lines)


def operand_symbol(index: int) -> str:
    if index == 25:
        return "jumpoff_target"
    if index in REGISTER_OPERANDS:
        return REGISTER_OPERANDS[index][0]
    return OPERANDS[index]


def load_size(name: str):
    base = name.removesuffix("_add")
    base = base.replace("ldnt", "ld", 1)
    if base == "ldna":
        base = "ld"
    return {
        "ld": (8, False),
        "ld1s": (1, True),
        "ld1u": (1, False),
        "ld2s": (2, True),
        "ld2u": (2, False),
        "ld4s": (4, True),
        "ld4u": (4, False),
    }.get(base)


def store_size(name: str):
    base = name.removesuffix("_add").replace("stnt", "st", 1)
    return {"st": 8, "st1": 1, "st2": 2, "st4": 4}.get(base)


def saturating_word(dest: str, left: str, right: str, operator: str) -> str:
    return (
        f"local value:8 = sext({left}:4) {operator} sext({right}:4); "
        "if (value s<= 0x7fffffff) goto <high_ok>; value = 0x7fffffff; <high_ok> "
        "if (value s>= 0xffffffff80000000) goto <low_ok>; "
        "value = 0xffffffff80000000; <low_ok> "
        f"{dest} = value;"
    )


def multiply_half(name: str, operands: list[str]) -> str:
    dest, left, right = operands
    suffix = name.removeprefix("mula_").removeprefix("mul_")
    left_half, right_half = suffix.split("_")

    def extend(value: str, half: str) -> str:
        return {
            "lu": f"zext({value}:4)",
            "ls": f"sext({value}:4)",
            "hu": f"({value} >> 32)",
            "hs": f"({value} s>> 32)",
        }[half]

    product = f"({extend(left, left_half)} * {extend(right, right_half)})"
    if name.startswith("mula_"):
        return f"{dest} = {dest} + {product};"
    return f"{dest} = {product};"


def atomic_memory(name: str, operands: list[str]) -> str:
    dest, address, value = operands
    size = 4 if name.endswith("4") else 8
    old = f"local old:{size} = *[ram]:{size} addr; "
    result = f"{dest} = {'sext(old)' if size == 4 else 'old'}; "
    write = f"*[ram]:{size} addr = {value}:{size};"
    prefix = f"local addr:8 = {address}; {old}{result}"

    if name.startswith("cmpexch"):
        compare = "sext(cmpexch_value:4)" if size == 4 else "cmpexch_value"
        return (
            prefix
            + f"if ({dest} != {compare}) goto <done>; {write} <done>"
        )
    if name.startswith("exch"):
        return prefix + write

    operator = {
        "fetchadd": "+",
        "fetchadd4": "+",
        "fetchaddgez": "+",
        "fetchaddgez4": "+",
        "fetchand": "&",
        "fetchand4": "&",
        "fetchor": "|",
        "fetchor4": "|",
    }[name]
    update = f"local updated:{size} = old {operator} {value}:{size}; "
    if name.startswith("fetchaddgez"):
        return (
            prefix
            + update
            + "if (updated s< 0) goto <done>; "
            + f"*[ram]:{size} addr = updated; <done>"
        )
    return prefix + update + f"*[ram]:{size} addr = updated;"


def vector_lanes(
    dest: str,
    left: str,
    right: str,
    lane_bits: int,
    operation: str,
    signed: bool = False,
) -> str:
    lane_bytes = lane_bits // 8
    lane_count = 64 // lane_bits
    pieces = ["local output:8 = 0;"]
    for lane in range(lane_count):
        shift = lane * lane_bits
        pieces.append(f"local shifted_a{lane}:8 = {left} >> {shift};")
        pieces.append(f"local shifted_b{lane}:8 = {right} >> {shift};")
        pieces.append(f"local a{lane}:{lane_bytes} = shifted_a{lane}:{lane_bytes};")
        pieces.append(f"local b{lane}:{lane_bytes} = shifted_b{lane}:{lane_bytes};")
        a = f"a{lane}"
        b = f"b{lane}"
        if operation in {"==", "!=", "<", "<=", "s<", "s<="}:
            pieces.append(
                f"local lane_result{lane}:{lane_bytes} = "
                f"zext({a} {operation} {b});"
            )
        else:
            pieces.append(
                f"local lane_result{lane}:{lane_bytes} = {a} {operation} {b};"
            )
        pieces.append(
            f"output = output | (zext(lane_result{lane}) << {shift});"
        )
    pieces.append(f"{dest} = output;")
    return " ".join(pieces)


def vector_immediate(
    dest: str,
    source: str,
    immediate: str,
    lane_bits: int,
    operation: str,
    signed: bool = False,
) -> str:
    lane_bytes = lane_bits // 8
    lane_count = 64 // lane_bits
    pieces = [
        f"local immediate:{lane_bytes} = {immediate};",
        "local output:8 = 0;",
    ]
    for lane in range(lane_count):
        shift = lane * lane_bits
        pieces.append(f"local shifted_a{lane}:8 = {source} >> {shift};")
        pieces.append(f"local a{lane}:{lane_bytes} = shifted_a{lane}:{lane_bytes};")
        a = f"a{lane}"
        b = "immediate"
        if operation in {"==", "!=", "<", "<=", "s<", "s<="}:
            pieces.append(
                f"local lane_result{lane}:{lane_bytes} = "
                f"zext({a} {operation} {b});"
            )
        else:
            pieces.append(
                f"local lane_result{lane}:{lane_bytes} = {a} {operation} {b};"
            )
        pieces.append(
            f"output = output | (zext(lane_result{lane}) << {shift});"
        )
    pieces.append(f"{dest} = output;")
    return " ".join(pieces)


def vector_interleave(dest: str, left: str, right: str, lane_bits: int, high: bool) -> str:
    lane_count = 64 // lane_bits
    half = lane_count // 2
    start = half if high else 0
    mask = (1 << lane_bits) - 1
    pieces = ["local output:8 = 0;"]
    for lane in range(lane_count):
        source = left if lane & 1 else right
        source_lane = start + lane // 2
        pieces.append(
            f"output = output | ((({source} >> {source_lane * lane_bits}) "
            f"& 0x{mask:x}) << {lane * lane_bits});"
        )
    pieces.append(f"{dest} = output;")
    return " ".join(pieces)


def vector_shift(dest: str, source: str, amount: str, lane_bits: int, operator: str) -> str:
    lane_bytes = lane_bits // 8
    lane_count = 64 // lane_bits
    mask = lane_bits - 1
    pieces = [f"local amount:8 = {amount} & {mask};", "local output:8 = 0;"]
    for lane in range(lane_count):
        shift = lane * lane_bits
        pieces.append(f"local shifted_a{lane}:8 = {source} >> {shift};")
        pieces.append(f"local a{lane}:{lane_bytes} = shifted_a{lane}:{lane_bytes};")
        pieces.append(
            f"local lane_result{lane}:{lane_bytes} = "
            f"a{lane} {operator} amount;"
        )
        pieces.append(
            f"output = output | (zext(lane_result{lane}) << {shift});"
        )
    pieces.append(f"{dest} = output;")
    return " ".join(pieces)


def vector_sad(dest: str, left: str, right: str, lane_bits: int, accumulate: bool) -> str:
    lane_bytes = lane_bits // 8
    lane_count = 64 // lane_bits
    pieces = ["local output:8 = 0;"]
    for lane in range(lane_count):
        shift = lane * lane_bits
        pieces.append(f"local shifted_a{lane}:8 = {left} >> {shift};")
        pieces.append(f"local shifted_b{lane}:8 = {right} >> {shift};")
        pieces.append(f"local a{lane}:{lane_bytes} = shifted_a{lane}:{lane_bytes};")
        pieces.append(f"local b{lane}:{lane_bytes} = shifted_b{lane}:{lane_bytes};")
        pieces.append(f"local au{lane}:8 = zext(a{lane});")
        pieces.append(f"local bu{lane}:8 = zext(b{lane});")
        pieces.append(f"local diff{lane}:8 = au{lane} - bu{lane};")
        pieces.append(
            f"if (au{lane} >= bu{lane}) goto <sad{lane}>; "
            f"diff{lane} = 0 - diff{lane}; <sad{lane}>"
        )
        pieces.append(f"output = output + diff{lane};")
    pieces.append(f"{dest} = {dest} + output;" if accumulate else f"{dest} = output;")
    return " ".join(pieces)


def reverse_bytes(dest: str, source: str) -> str:
    return (
        f"local value:8 = {source}; "
        "value = ((value & 0x00ff00ff00ff00ff) << 8) | "
        "((value >> 8) & 0x00ff00ff00ff00ff); "
        "value = ((value & 0x0000ffff0000ffff) << 16) | "
        "((value >> 16) & 0x0000ffff0000ffff); "
        f"{dest} = (value << 32) | (value >> 32);"
    )


def reverse_bits(dest: str, source: str) -> str:
    return (
        f"local value:8 = {source}; "
        "value = ((value & 0x5555555555555555) << 1) | "
        "((value >> 1) & 0x5555555555555555); "
        "value = ((value & 0x3333333333333333) << 2) | "
        "((value >> 2) & 0x3333333333333333); "
        "value = ((value & 0x0f0f0f0f0f0f0f0f) << 4) | "
        "((value >> 4) & 0x0f0f0f0f0f0f0f0f); "
        "value = ((value & 0x00ff00ff00ff00ff) << 8) | "
        "((value >> 8) & 0x00ff00ff00ff00ff); "
        "value = ((value & 0x0000ffff0000ffff) << 16) | "
        "((value >> 16) & 0x0000ffff0000ffff); "
        f"{dest} = (value << 32) | (value >> 32);"
    )


def shuffle_bytes(dest: str, left: str, selector: str) -> str:
    pieces = [f"local original:8 = {dest};", "local output:8 = 0;"]
    for lane in range(8):
        shift = lane * 8
        pieces.extend(
            (
                f"local shifted_selector{lane}:8 = {selector} >> {shift};",
                f"local selector{lane}:1 = shifted_selector{lane}:1;",
                f"local source{lane}:8 = original;",
                f"if ((selector{lane} & 8) == 0) goto <selected{lane}>;",
                f"source{lane} = {left};",
                f"<selected{lane}>",
                f"local shifted_source{lane}:8 = source{lane} >> "
                f"((selector{lane} & 7) << 3);",
                f"local byte{lane}:1 = shifted_source{lane}:1;",
                f"output = output | (zext(byte{lane}) << {shift});",
            )
        )
    pieces.append(f"{dest} = output;")
    return " ".join(pieces)


def crc32(dest: str, accumulator: str, value: str, bits: int) -> str:
    pieces = [
        f"local crc:4 = {accumulator}:4;",
        f"local input:4 = {value}:4;",
    ]
    for bit in range(bits):
        pieces.extend(
            (
                f"local bit{bit}:4 = (crc ^ input) & 1;",
                "crc = crc >> 1;",
                f"if (bit{bit} == 0) goto <crc{bit}>;",
                "crc = crc ^ 0xedb88320;",
                f"<crc{bit}>",
                "input = input >> 1;",
            )
        )
    pieces.append(f"{dest} = zext(crc);")
    return " ".join(pieces)


def pcode(opcode: Opcode, operands: list[str]) -> str:
    name = opcode.name
    if name in {
        "fnop",
        "nop",
        "info",
        "infol",
        "prefetch",
        "prefetch_l1",
        "prefetch_l1_fault",
        "prefetch_l2",
        "prefetch_l2_fault",
        "prefetch_l3",
        "prefetch_l3_fault",
        "wh64",
    }:
        return ""

    if name == "move":
        return f"{operands[0]} = {operands[1]};"
    if name in {"movei", "moveli"}:
        return f"{operands[0]} = {operands[1]};"
    if name in {"add", "addi", "addli"}:
        return f"{operands[0]} = {operands[1]} + {operands[2]};"
    if name in {"addx", "addxi", "addxli"}:
        return (
            f"local result:4 = {operands[1]}:4 + {operands[2]}:4; "
            f"{operands[0]} = sext(result);"
        )
    if name in {"sub", "and", "or", "xor"}:
        operator = {"sub": "-", "and": "&", "or": "|", "xor": "^"}[name]
        return f"{operands[0]} = {operands[1]} {operator} {operands[2]};"
    if name in {"andi", "ori", "xori"}:
        operator = {"andi": "&", "ori": "|", "xori": "^"}[name]
        return f"{operands[0]} = {operands[1]} {operator} {operands[2]};"
    if name == "nor":
        return f"{operands[0]} = ~({operands[1]} | {operands[2]});"
    if name == "subx":
        return (
            f"local result:4 = {operands[1]}:4 - {operands[2]}:4; "
            f"{operands[0]} = sext(result);"
        )
    if name in {"addxsc", "subxsc"}:
        operator = "+" if name == "addxsc" else "-"
        return saturating_word(*operands, operator)
    if name in {"clz", "ctz", "pcnt"}:
        dest, source = operands
        if name == "clz":
            return f"{dest} = lzcount({source});"
        if name == "pcnt":
            return f"{dest} = popcount({source});"
        return (
            f"local isolated:8 = {source} & (0 - {source}); "
            f"{dest} = popcount(isolated - 1);"
        )
    if name == "revbytes":
        return reverse_bytes(*operands)
    if name == "revbits":
        return reverse_bits(*operands)
    if name.startswith("tblidxb"):
        dest, source = operands
        byte = int(name[-1]) * 8
        return (
            f"{dest} = ({dest} & 0xfffffffffffffc03) | "
            f"((({source} >> {byte}) & 0xff) << 2);"
        )

    comparisons = {
        "cmpeq": "==",
        "cmpeqi": "==",
        "cmpne": "!=",
        "cmples": "s<=",
        "cmplts": "s<",
        "cmpltsi": "s<",
        "cmpleu": "<=",
        "cmpltu": "<",
        "cmpltui": "<",
    }
    if name in comparisons:
        return (
            f"{operands[0]} = zext({operands[1]} "
            f"{comparisons[name]} {operands[2]});"
        )
    if name in {"cmoveqz", "cmovnez"}:
        condition = "!=" if name == "cmoveqz" else "=="
        return (
            f"if ({operands[1]} {condition} 0) goto <done>; "
            f"{operands[0]} = {operands[2]}; <done>"
        )
    if name in {"mnz", "mz"}:
        condition = "!=" if name == "mnz" else "=="
        return (
            f"local mask:8 = sext({operands[1]} {condition} 0); "
            f"{operands[0]} = mask & {operands[2]};"
        )

    if name in {"shl", "shrs", "shru"}:
        operator = {"shl": "<<", "shrs": "s>>", "shru": ">>"}[name]
        return (
            f"{operands[0]} = {operands[1]} {operator} "
            f"({operands[2]} & 0x3f);"
        )
    if name in {"shli", "shrsi", "shrui"}:
        operator = {"shli": "<<", "shrsi": "s>>", "shrui": ">>"}[name]
        return f"{operands[0]} = {operands[1]} {operator} {operands[2]};"
    if name in {"shlx", "shlxi", "shrux", "shruxi"}:
        operator = "<<" if name.startswith("shl") else ">>"
        amount = (
            operands[2]
            if name.endswith("i")
            else f"({operands[2]} & 0x1f)"
        )
        return (
            f"local result:4 = {operands[1]}:4 {operator} {amount}; "
            f"{operands[0]} = sext(result);"
        )
    if name in {"shl1add", "shl2add", "shl3add"}:
        shift = name[3]
        return (
            f"{operands[0]} = ({operands[1]} << {shift}) + {operands[2]};"
        )
    if name in {"shl1addx", "shl2addx", "shl3addx"}:
        shift = name[3]
        return (
            f"local result:4 = ({operands[1]}:4 << {shift}) + "
            f"{operands[2]}:4; {operands[0]} = sext(result);"
        )
    if name == "shl16insli":
        return (
            f"{operands[0]} = ({operands[1]} << 16) | "
            f"({operands[2]} & 0xffff);"
        )
    if name in {"rotl", "rotli"}:
        amount = (
            operands[2]
            if name == "rotli"
            else f"({operands[2]} & 0x3f)"
        )
        return (
            f"local amount:8 = {amount}; "
            f"{operands[0]} = ({operands[1]} << amount) | "
            f"({operands[1]} >> ((64 - amount) & 0x3f));"
        )

    if name in {"bfextu", "bfexts"}:
        dest, source, start, end = operands
        lines = (
            f"local width:8 = (({end} - {start}) & 0x3f) + 1; "
            f"local value:8 = ({source} >> {start}) | "
            f"({source} << ((64 - {start}) & 0x3f)); "
            "local mask:8 = (1 << width) - 1; "
            "value = value & mask; "
        )
        if name == "bfextu":
            return lines + f"{dest} = value;"
        return (
            lines
            + "local shift:8 = 64 - width; "
            + f"{dest} = (value << shift) s>> shift;"
        )
    if name == "bfins":
        dest, source, start, end = operands
        return (
            f"local width:8 = (({end} - {start}) & 0x3f) + 1; "
            "local lowmask:8 = (1 << width) - 1; "
            f"local mask:8 = (lowmask << {start}) | "
            f"(lowmask >> ((64 - {start}) & 0x3f)); "
            f"local value:8 = ({source} << {start}) | "
            f"({source} >> ((64 - {start}) & 0x3f)); "
            f"{dest} = ({dest} & ~mask) | (value & mask);"
        )
    if name == "mm":
        dest, source, start, end = operands
        return (
            f"local width:8 = (({end} - {start}) & 0x3f) + 1; "
            "local lowmask:8 = (1 << width) - 1; "
            f"local mask:8 = (lowmask << {start}) | "
            f"(lowmask >> ((64 - {start}) & 0x3f)); "
            f"{dest} = ({dest} & mask) | ({source} & ~mask);"
        )

    if name in {"mulx", "mulax"}:
        dest, left, right = operands
        addend = f"{dest}:4 + " if name == "mulax" else ""
        return (
            f"local result:4 = {addend}({left}:4 * {right}:4); "
            f"{dest} = sext(result);"
        )
    if name.startswith(("mul_", "mula_")):
        return multiply_half(name, operands)
    if name in {"dblalign2", "dblalign4", "dblalign6"}:
        dest, high, low = operands
        amount = {"dblalign2": 16, "dblalign4": 32, "dblalign6": 48}[name]
        return (
            f"{dest} = ({low} >> {amount}) | ({high} << {64 - amount});"
        )
    if name == "dblalign":
        dest, high, amount_source = operands
        return (
            f"local amount:8 = ({amount_source} & 7) << 3; "
            f"{dest} = ({dest} >> amount) | "
            f"(({high} << (amount ^ 63)) << 1);"
        )
    if name in {
        "cmpexch",
        "cmpexch4",
        "exch",
        "exch4",
        "fetchadd",
        "fetchadd4",
        "fetchaddgez",
        "fetchaddgez4",
        "fetchand",
        "fetchand4",
        "fetchor",
        "fetchor4",
    }:
        return atomic_memory(name, operands)

    if name == "shufflebytes":
        return shuffle_bytes(*operands)
    if name in {"crc32_8", "crc32_32"}:
        return crc32(*operands, 8 if name.endswith("_8") else 32)
    if name in {"v1int_l", "v1int_h", "v2int_l", "v2int_h"}:
        lane_bits = 8 if name.startswith("v1") else 16
        return vector_interleave(*operands, lane_bits, name.endswith("_h"))
    if name == "v4int_h":
        return vector_interleave(*operands, 32, True)
    if name == "v4int_l":
        return (
            f"{operands[0]} = ({operands[1]} << 32) | "
            f"({operands[2]} & 0xffffffff);"
        )
    if name in {"v1addi", "v2addi"}:
        return vector_immediate(*operands, 8 if name.startswith("v1") else 16, "+")
    if name == "v1cmpeq":
        return vector_lanes(*operands, 8, "==")
    if name == "v1cmpeqi":
        return vector_immediate(*operands, 8, "==")
    if name == "v1shrui":
        return vector_shift(*operands, 8, ">>")
    if name in {"v2sadu", "v2sadau"}:
        return vector_sad(*operands, 16, name == "v2sadau")

    size_and_sign = load_size(name)
    if size_and_sign:
        size, signed = size_and_sign
        dest, address = operands[:2]
        extension = "sext" if signed else "zext"
        if size == 8:
            load = f"{dest} = *[ram]:8 addr;"
        else:
            load = f"{dest} = {extension}(*[ram]:{size} addr);"
        result = f"local addr:8 = {address}; {load}"
        if name.endswith("_add"):
            result += f" {address} = addr + {operands[2]};"
        return result

    size = store_size(name)
    if size:
        address, value = operands[:2]
        result = (
            f"local addr:8 = {address}; *[ram]:{size} addr = {value}:{size};"
        )
        if name.endswith("_add"):
            result += f" {address} = addr + {operands[2]};"
        return result

    if name == "j":
        return f"<<FLOW>> goto {operands[0]};"
    if name == "jal":
        return (
            f"lr_new = inst_next; <<COMMIT>> lr = lr_new; "
            f"<<FLOW>> call {operands[0]};"
        )
    if name == "jr":
        return (
            f"branch_target = {operands[0]} & ~7; "
            "<<FLOW>> goto [branch_target];"
        )
    if name == "jrp":
        return (
            f"branch_target = {operands[0]} & ~7; "
            "<<FLOW>> return [branch_target];"
        )
    if name in {"jalr", "jalrp"}:
        return (
            f"lr_new = inst_next; branch_target = {operands[0]} & ~7; "
            "<<COMMIT>> lr = lr_new; <<FLOW>> call [branch_target];"
        )
    if name == "lnk":
        return f"{operands[0]} = inst_next;"

    branches = {
        "beqz": "== 0",
        "beqzt": "== 0",
        "bnez": "!= 0",
        "bnezt": "!= 0",
        "bgez": "s>= 0",
        "bgezt": "s>= 0",
        "bgtz": "s> 0",
        "bgtzt": "s> 0",
        "blez": "s<= 0",
        "blezt": "s<= 0",
        "bltz": "s< 0",
        "bltzt": "s< 0",
    }
    if name in branches:
        return (
            f"branch_taken = {operands[0]} {branches[name]}; "
            f"<<FLOW>> if (branch_taken != 0) goto {operands[1]};"
        )
    if name in {"blbc", "blbct"}:
        return (
            f"branch_taken = ({operands[0]} & 1) == 0; "
            f"<<FLOW>> if (branch_taken != 0) goto {operands[1]};"
        )
    if name in {"blbs", "blbst"}:
        return (
            f"branch_taken = ({operands[0]} & 1) != 0; "
            f"<<FLOW>> if (branch_taken != 0) goto {operands[1]};"
        )

    if name in {"mf", "drain"}:
        return "tilegx_fence();"
    if name == "mfspr":
        dest, spr = operands
        return (
            f"if ({spr} != 0x2780) goto <other_spr>; "
            f"{dest} = cmpexch_value; goto <spr_done>; "
            f"<other_spr> {dest} = tilegx_mfspr({spr}); <spr_done>"
        )
    if name == "mtspr":
        spr, source = operands
        return (
            f"if ({spr} != 0x2780) goto <other_spr>; "
            f"cmpexch_value = {source}; goto <spr_done>; "
            f"<other_spr> tilegx_mtspr({spr}, {source}); <spr_done>"
        )
    if name in {"finv", "flush", "icoh"}:
        return f"tilegx_{name}({operands[0]});"
    if name == "nap":
        return "tilegx_wait();"
    if name == "iret":
        return (
            "local exception_context_spr:8 = 0x2580; "
            "branch_target = tilegx_mfspr(exception_context_spr); "
            "<<FLOW>> return [branch_target];"
        )
    if name in {"raise", "bpt", "ill"}:
        return "local trap_number:8 = 0; tilegx_trap(trap_number);"
    if name.startswith("swint") and name[-1].isdigit():
        return (
            f"local trap_number:8 = {name[-1]}; "
            "tilegx_trap(trap_number);"
        )

    destination_indexes = {6, 8, 10, 12, 23, 24, 26}
    register_arguments = [
        operand
        for index, operand in zip(opcode.operands, operands)
        if index in REGISTER_OPERANDS
    ]
    if opcode.operands and opcode.operands[0] in destination_indexes:
        arguments = ", ".join(register_arguments[1:])
        return f"{operands[0]} = tilegx_{name}({arguments});"
    return f"tilegx_{name}({', '.join(register_arguments)});"


def render(opcodes: list[Opcode]) -> str:
    opcodes, exclusions = prioritize(opcodes)
    semantics = {opcode: pcode(opcode, [operand_symbol(i) for i in opcode.operands])
                 for opcode in opcodes}
    custom_userops = sorted({
        f"tilegx_{opcode.name}"
        for opcode, body in semantics.items()
        if f"tilegx_{opcode.name}(" in body
    } - BUILTIN_USEROPS)
    runs = {run for opcode in opcodes for run in mask_runs(opcode.mask)}
    runs.update(
        run
        for opcode_exclusions in exclusions.values()
        for extra_mask, _ in opcode_exclusions
        for run in mask_runs(extra_mask)
    )
    runs = sorted(runs)
    lines = [
        "# Generated from GNU binutils tilegx-opc.c.",
        "# Common scalar, memory, and control instructions include p-code.",
        "# Complex DSP/system instructions remain explicit user-ops.",
        "define endian=little;",
        "define alignment=8;",
        "",
        "define space ram type=ram_space size=8 default;",
        "define space register type=register_space size=4;",
        "",
        "define register offset=0x0000 size=8 [",
        "    " + " ".join(REGISTER_NAMES[:16]),
        "    " + " ".join(REGISTER_NAMES[16:32]),
        "    " + " ".join(REGISTER_NAMES[32:48]),
        "    " + " ".join(REGISTER_NAMES[48:]),
        "];",
        "define register offset=0x0400 size=8 [",
        "    " + " ".join(SHADOW_REGISTER_NAMES[:16]),
        "    " + " ".join(SHADOW_REGISTER_NAMES[16:32]),
        "    " + " ".join(SHADOW_REGISTER_NAMES[32:48]),
        "    " + " ".join(SHADOW_REGISTER_NAMES[48:]),
        "];",
        "define register offset=0x0200 size=8 pc;",
        "define register offset=0x0208 size=8 cmpexch_value;",
        "define register offset=0x0210 size=8 branch_target;",
        "define register offset=0x0218 size=1 branch_taken;",
        "",
        "define pcodeop tilegx_fence;",
        "define pcodeop tilegx_mfspr;",
        "define pcodeop tilegx_mtspr;",
        "define pcodeop tilegx_finv;",
        "define pcodeop tilegx_flush;",
        "define pcodeop tilegx_icoh;",
        "define pcodeop tilegx_wait;",
        "define pcodeop tilegx_trap;",
    ]
    lines.extend(f"define pcodeop {name};" for name in custom_userops)
    lines.extend([
        "",
        "define token bundle(64)",
        "    bundle_bits=(0,63)",
    ])
    for name, (low, high, signed) in FIELDS.items():
        lines.append(f"    {name}=({low},{high}){' signed' if signed else ''}")
    for name in REGISTER_FIELDS:
        low, high, _ = FIELDS[name]
        lines.append(f"    {name}_num=({low},{high})")
        lines.append(f"    {name}_new=({low},{high})")
    for low, high in runs:
        lines.append(f"    m_{low:02d}_{high:02d}=({low},{high})")
    lines.extend((";", "", f"attach variables [ {' '.join(REGISTER_FIELDS)} ] ["))
    lines.extend(
        "    " + " ".join(REGISTER_NAMES[start : start + 16])
        for start in range(0, len(REGISTER_NAMES), 16)
    )
    lines.extend(
        (
            "];",
            "",
            f"attach variables [ {' '.join(f'{name}_new' for name in REGISTER_FIELDS)} ] [",
        )
    )
    lines.extend(
        "    " + " ".join(SHADOW_REGISTER_NAMES[start : start + 16])
        for start in range(0, len(SHADOW_REGISTER_NAMES), 16)
    )
    lines.extend(
        (
            "];",
            "",
            register_operand_constructors(),
            "",
            composite_operands(),
            "bundle_address: address is epsilon [ address = inst_start; ] "
            "{ export *[ram]:8 address; }",
            "",
        )
    )

    for opcode in opcodes:
        pipe_name = PIPE_NAMES[opcode.pipe]
        operand_names = [operand_symbol(index) for index in opcode.operands]
        display = f'"{opcode.name}"'
        if operand_names:
            display += '^" "^' + '^", "^'.join(operand_names)
        terms = list(dict.fromkeys(operand_names))
        terms.extend(fixed_term(low, high, opcode.value) for low, high in mask_runs(opcode.mask))
        for extra_mask, higher_value in exclusions[opcode]:
            alternatives = [
                fixed_term(low, high, higher_value).replace("=", "!=")
                for low, high in mask_runs(extra_mask)
            ]
            terms.append(f"({' | '.join(alternatives)})")
        lines.append(
            f"{pipe_name}: {display} is {' & '.join(terms)} "
            f"{{ {semantics[opcode]} }}"
        )

    lines.extend(
        (
            "",
            ':"{" x0 ";" x1 "}" is x0 & x1 & bundle_address { '
            "build x0; build x1; crossbuild bundle_address,COMMIT; "
            "crossbuild bundle_address,FLOW; }",
            ':"{" y0 ";" y1 ";" y2 "}" is y0 & y1 & y2 & bundle_address { '
            "build y0; build y1; build y2; crossbuild bundle_address,COMMIT; "
            "crossbuild bundle_address,FLOW; }",
            "",
        )
    )
    return "\n".join(lines)


def decode_names(opcodes: list[Opcode], bundle: int) -> list[str]:
    pipes = (0, 1) if bundle >> 62 == 0 else (2, 3, 4)
    return [
        next(
            opcode.name
            for opcode in opcodes
            if opcode.pipe == pipe and bundle & opcode.mask == opcode.value
        )
        for pipe in pipes
    ]


def self_test(opcodes: list[Opcode]) -> None:
    assert len(opcodes) > 500
    assert decode_names(opcodes, 0x180843CF5107F78C) == ["move", "addi"]
    assert "ld4u" in decode_names(opcodes, 0x9E5E400030BC3000)


def self_test_generated(source: str) -> None:
    assert "D_x1 = zext(*[ram]:4 addr);" in source
    assert "D_x0 = (A_x0 << 32) | (B_x0 & 0xffffffff);" in source
    assert "branch_taken = A_x1 == 0;" in source
    assert "crossbuild bundle_address,COMMIT;" in source
    assert "<<COMMIT>> dest_x0 = dest_x0_new;" in source
    assert ':"{" x0 ";" x1 "}"' in source
    for name in ("fetchadd4", "dblalign", "mul_hu_lu", "v1int_l", "mfspr"):
        constructors = [
            line for line in source.splitlines() if line.startswith(("x0:", "x1:", "y0:"))
            and f'"{name}"' in line
        ]
        assert constructors and all("tilegx_unsupported" not in line for line in constructors)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dumper", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    opcodes = load_opcodes(args.dumper)
    self_test(opcodes)
    source = render(opcodes)
    self_test_generated(source)
    args.output.write_text(source)


if __name__ == "__main__":
    main()
