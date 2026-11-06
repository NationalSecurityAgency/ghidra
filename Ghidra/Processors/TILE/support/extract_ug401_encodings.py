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
"""Extract TILE-Gx instruction encodings from the Tilera ISA manual.

Source document: "TILE-Gx Instruction Set Architecture", Tilera Corporation,
document UG401, release 1.3 (June 2013).

Every instruction page in UG401 carries one "<mnemonic> in <pipe> Bits
Encoding" figure per pipeline the instruction can issue in. Each figure draws a
box per instruction field over a row of bit numbers, writes the fixed binary
value or an operand placeholder in the box, and lists the fields in a legend
("Opcode_X0 - 0x5", "Dest_X0 - Dest"). This script reads those figures together
with each page's Syntax line and Functional Description and writes the plain
text table that generate_tilegx_sleigh.py consumes:

    field  <name> <low bit> <high bit>
    insn   <pipe> <mnemonic> <fixed-bit mask> <fixed-bit value> <operands>

Operands are listed in Syntax order as <field>:<mode>, where mode is r, w or
rw for register operands (taken from the Functional Description) and i for
immediates. A field written as Name[hi:lo] in the manual is one piece of a
split operand; the generator reassembles the pieces from the slice ranges.

Usage: extract_ug401_encodings.py UG401-ISA.pdf tilegx_encodings.txt
Requires pdfplumber.
"""
import argparse
import re

import pdfplumber

# Figure text uses a subset font whose glyph ids are ASCII code points minus 29.
CID = re.compile(r"\(cid:(\d+)\)")
CAPTION = re.compile(r"Figure \d+-\d+: (\S+) in\s*([XY][0-2]) Bits Encoding")
LEGEND = re.compile(r"^(\S+) - (.+)$")
HEX_LABEL = re.compile(r"^(?:Reserved )?0x([0-9A-Fa-f]+)$")
SLICE = re.compile(r"^(.+)\[(\d+):(\d+)\]$")
REGISTER_TOKENS = {"Dest", "SrcA", "SrcB", "Src"}
# UG401 section 2.1.1: mode bits 63:62 are zero for an X bundle. X figures do
# not draw the mode bits, so they are added here.
X_MODE_MASK = 0x3 << 62
# Figures transcribed by hand as (field, legend label, low bit, high bit, box
# text): figures 8-193 and 8-194 are raster images, and figure 3-37 ("addx in
# Y1") reproduces the X1 figure by mistake. The Y1 add/addx/sub/subx group
# shares Opcode_Y1 0x6 (figures 3-36, 3-44 and 3-48 give extensions 0x1, 0x3
# and 0x2), and addx takes the remaining extension 0x0, as it does in Y0.
HAND_TRANSCRIBED = {
    ("addx", "Y1"): [
        ("Opcode_Y1", "0x6", 58, 61, "0110"),
        ("RRROpcodeExtension_Y1", "0x0", 49, 50, "00"),
        ("SrcB_Y1", "SrcB", 43, 48, "s"),
        ("SrcA_Y1", "SrcA", 37, 42, "s"),
        ("Dest_Y1", "Dest", 31, 36, "d"),
    ],
    ("bfexts", "X0"): [
        ("Opcode_X0", "0x3", 28, 30, "011"),
        ("BFOpcodeExtension_X0", "0x4", 24, 27, "0100"),
        ("BFStart_X0", "BFStart", 18, 23, "i"),
        ("BFEnd_X0", "BFEnd", 12, 17, "i"),
        ("SrcA_X0", "SrcA", 6, 11, "s"),
        ("Dest_X0", "Dest", 0, 5, "d"),
    ],
    ("bfextu", "X0"): [
        ("Opcode_X0", "0x3", 28, 30, "011"),
        ("BFOpcodeExtension_X0", "0x5", 24, 27, "0101"),
        ("BFStart_X0", "BFStart", 18, 23, "i"),
        ("BFEnd_X0", "BFEnd", 12, 17, "i"),
        ("SrcA_X0", "SrcA", 6, 11, "s"),
        ("Dest_X0", "Dest", 0, 5, "d"),
    ],
}


def decode(text):
    return CID.sub(lambda match: chr(int(match.group(1)) + 29), text)


def rows(words, tolerance=2.5):
    grouped = []
    for word in sorted(words, key=lambda w: (w["top"], w["x0"])):
        if grouped and abs(grouped[-1][0] - word["top"]) <= tolerance:
            grouped[-1][1].append(word)
        else:
            grouped.append([word["top"], [word]])
    return [(top, sorted(ws, key=lambda w: w["x0"])) for top, ws in grouped]


def row_text(words):
    return re.sub(r"\s+", " ", " ".join(w["text"] for w in words)).strip()


def parse_figure(page_rows, tight_rows, boxes, region_top, region_bottom):
    region = [(top, ws) for top, ws in page_rows if region_top < top < region_bottom]
    # Bit numbers sit close together in the smaller figures, so they come from
    # a word split with a tight gap tolerance.
    bit_row = next(
        (top, ws)
        for top, ws in tight_rows
        if region_top < top < region_bottom
        and sum(bool(re.fullmatch(r"\d{1,2}", w["text"])) for w in ws) >= 8
    )
    bit_centers = {
        (w["x0"] + w["x1"]) / 2: int(w["text"])
        for w in bit_row[1]
        if re.fullmatch(r"\d{1,2}", w["text"])
    }
    numbers = list(bit_centers.values())
    assert numbers == sorted(numbers, reverse=True), numbers
    unique = {}
    for box in boxes:
        if bit_row[0] < box["top"] < bit_row[0] + 30:
            unique[(round(box["x0"]), round(box["x1"]))] = box
    fig_boxes = sorted(unique.values(), key=lambda b: b["x0"])
    assert fig_boxes, "no field boxes under bit row"
    box_top = min(b["top"] for b in fig_boxes) - 2
    box_bottom = max(b["bottom"] for b in fig_boxes) + 2
    right_edge = max(b["x1"] for b in fig_boxes)
    legend = []
    for top, ws in region:
        if top <= bit_row[0] or ws[0]["x0"] < right_edge + 5:
            continue
        match = LEGEND.match(row_text(ws))
        if match:
            legend.append((match.group(1), match.group(2)))
    if len(legend) != len(fig_boxes):
        raise ValueError(f"{len(legend)} legend entries for {len(fig_boxes)} boxes")

    fields = []
    for box, (name, label) in zip(fig_boxes, reversed(legend)):
        bits = sorted(
            bit for cx, bit in bit_centers.items() if box["x0"] < cx < box["x1"]
        )
        assert bits and bits == list(range(bits[0], bits[-1] + 1)), (name, bits)
        text = "".join(
            w["text"]
            for top, ws in region
            for w in ws
            if box_top < (w["top"] + w["bottom"]) / 2 < box_bottom
            and box["x0"] < (w["x0"] + w["x1"]) / 2 < box["x1"]
        )
        fields.append((name, label, bits[0], bits[-1], text))
    return fields


def operand_mode(token, functional_description):
    reads = writes = 0
    for match in re.finditer(r"rf\[" + re.escape(token) + r"\]\s*([-+|&^]?=)?(=?)", functional_description):
        operator, second = match.group(1), match.group(2)
        if operator and not second:
            writes += 1
            if operator != "=":
                reads += 1
        else:
            reads += 1
    if writes and reads:
        return "rw"
    if writes:
        return "w"
    if reads:
        return "r"
    # No register-file access in the description (prefetch hints, probes).
    return "w" if token == "Dest" else "r"


def extract(pdf_path):
    pdf = pdfplumber.open(pdf_path)
    field_bits = {}
    encodings = []
    current = None
    in_description = False
    for page in pdf.pages:
        # A few pages paint their content twice; drop the duplicate glyphs.
        page = page.dedupe_chars()
        words = page.extract_words(extra_attrs=["fontname", "size"])
        for word in words:
            word["text"] = decode(word["text"])
        tight_words = page.extract_words(x_tolerance=1)
        for word in tight_words:
            word["text"] = decode(word["text"])
        boxes = [r for r in page.rects if r.get("stroke") and 9 < r["height"] < 15]
        page_rows = rows(words)
        tight_rows = rows(tight_words)
        last_caption_bottom = 0
        for index, (top, ws) in enumerate(page_rows):
            text = row_text(ws)
            first = ws[0]
            if (
                len(ws) == 1
                and "Bold" in first["fontname"]
                and abs(first["size"] - 11) < 0.5
                and first["x0"] < 80
            ):
                current = {"name": first["text"], "syntax": "", "description": []}
                in_description = False
                continue
            if current is None:
                continue
            if text == "Syntax":
                current["syntax"] = row_text(page_rows[index + 1][1])
                continue
            if text == "Functional Description":
                in_description = True
                continue
            if text.startswith("Valid Pipelines"):
                in_description = False
                continue
            if in_description and "Courier" in first["fontname"]:
                current["description"].append(text)
                continue
            caption = CAPTION.search(text)
            if not caption:
                continue
            name, pipe = caption.group(1), caption.group(2)
            if name != current["name"]:
                raise ValueError(f"figure for {name} under {current['name']} page")
            if (name, pipe) in HAND_TRANSCRIBED:
                fields = HAND_TRANSCRIBED[(name, pipe)]
            else:
                try:
                    fields = parse_figure(page_rows, tight_rows, boxes, last_caption_bottom, top)
                except Exception as error:
                    for row_top, row in page_rows:
                        if last_caption_bottom < row_top < top:
                            print(f"  y={row_top:.0f} {row_text(row)!r}")
                    raise ValueError(f"{name} in {pipe}: {error!r}") from error
            last_caption_bottom = first["bottom"]
            mask = value = 0
            operands_by_label = {}
            fixed_fields = set()
            for field_name, label, low, high, box_text in fields:
                width = high - low + 1
                field_pipe = SLICE.sub(r"\1", field_name).rsplit("_", 1)[-1]
                if field_pipe != pipe and field_name != "Mode":
                    raise ValueError(f"{name} in {pipe}: figure shows {field_name}")
                if re.fullmatch(r"[01]+", box_text):
                    assert len(box_text) == width, (name, pipe, field_name, box_text)
                    hex_label = HEX_LABEL.match(label)
                    assert hex_label and int(hex_label.group(1), 16) == int(box_text, 2), (
                        name, pipe, field_name, label, box_text)
                    fixed_fields.add(SLICE.sub(r"\1", field_name).split("_")[0])
                    # Section 2.1.1 recommends zeros in unused fields but lets
                    # hardware ignore them, so reserved fields stay don't-care.
                    if not label.startswith("Reserved"):
                        mask |= ((1 << width) - 1) << low
                        value |= int(box_text, 2) << low
                    continue
                previous = field_bits.setdefault(field_name, (low, high))
                assert previous == (low, high), (field_name, previous, (low, high))
                operands_by_label.setdefault(label.split("[")[0], []).append(field_name)
            if pipe.startswith("X"):
                mask |= X_MODE_MASK
            description = " ".join(current["description"])
            operands = []
            for token in re.split(r"\s*,\s*", current["syntax"].split(" ", 1)[1]) if " " in current["syntax"] else []:
                if token not in operands_by_label:
                    # The assembler accepts the operand but the figure fixes
                    # its field (the TLS loads take an Imm8 that encodes as 0).
                    assert token in fixed_fields, (name, pipe, token, operands_by_label)
                    continue
                field_names = operands_by_label.pop(token)
                base = {SLICE.sub(r"\1", f) for f in field_names}
                assert len(base) == 1, (name, pipe, token, field_names)
                mode = operand_mode(token, description) if token in REGISTER_TOKENS else "i"
                operands.append(f"{base.pop()}:{mode}")
            assert not operands_by_label, (name, pipe, operands_by_label)
            encodings.append((pipe, name, mask, value, operands))
    return field_bits, encodings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manual")
    parser.add_argument("output")
    args = parser.parse_args()
    field_bits, encodings = extract(args.manual)
    lines = [
        "# TILE-Gx instruction encodings, extracted from the Tilera ISA manual",
        "# (UG401 release 1.3, June 2013) by extract_ug401_encodings.py.",
        "# field <name> <low bit> <high bit>",
        "# insn <pipe> <mnemonic> <fixed-bit mask> <fixed-bit value> <operand>:<mode>...",
    ]
    for name, (low, high) in sorted(field_bits.items(), key=lambda item: (item[1], item[0])):
        lines.append(f"field\t{name}\t{low}\t{high}")
    for pipe, name, mask, value, operands in sorted(encodings):
        lines.append(f"insn\t{pipe}\t{name}\t0x{mask:016x}\t0x{value:016x}\t{' '.join(operands)}")
    with open(args.output, "w") as output:
        output.write("\n".join(lines) + "\n")
    print(f"{len(field_bits)} fields, {len(encodings)} encodings")


if __name__ == "__main__":
    main()
