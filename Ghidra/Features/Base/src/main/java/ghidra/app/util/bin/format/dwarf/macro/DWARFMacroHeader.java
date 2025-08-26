/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.dwarf.macro;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFForm;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroInfoEntry;
import ghidra.program.model.data.LEB128;

/** 
 * Represents a DWARF Macro Header
 */
public class DWARFMacroHeader {

	private static final int OFFSET_SIZE_FLAG_MASK = 0x1;
	private static final int DEBUG_LINE_OFFSET_FLAG_MASK = 0x2;
	private static final int OPCODE_OPERANDS_TABLE_FLAG_MASK = 0x4;

	/**
	 * Reads a {@code DWARFMacroHeader} from a stream.
	 * 
	 * @param reader source of bytes
	 * @param cu {@link DWARFCompilationUnit} that pointed to this macro header
	 * @return macro header, never null
	 * @throws IOException if reading fails
	 */
	public static DWARFMacroHeader readV5(BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException {
		long startOffset = reader.getPointerIndex();
		int version = reader.readNextUnsignedShort();
		if (version != 5) {
			throw new IllegalArgumentException("Unsupported DWARF Macro version: " + version);
		}

		int flags = reader.readNextUnsignedByte();
		int intSize = (flags & OFFSET_SIZE_FLAG_MASK) == OFFSET_SIZE_FLAG_MASK ? 8 : 4;

		DWARFLine line = null;
		long debug_line_offset = -1;
		if ((flags & DEBUG_LINE_OFFSET_FLAG_MASK) != 0) {
			debug_line_offset = reader.readNextUnsignedValue(intSize);
			line = cu.getProgram().getLine(debug_line_offset, cu, false);
		}
		Map<Integer, List<DWARFForm>> opcodeMap = DWARFMacroOpcode.defaultOpcodeOperandMap;
		if ((flags & OPCODE_OPERANDS_TABLE_FLAG_MASK) != 0) {
			opcodeMap = new HashMap<>(opcodeMap);
			readMacroOpcodeTable(reader, opcodeMap);
		}
		return new DWARFMacroHeader(startOffset, version, flags, debug_line_offset, intSize,
			reader.getPointerIndex(), cu, line, opcodeMap);
	}

	private static void readMacroOpcodeTable(BinaryReader reader,
			Map<Integer, List<DWARFForm>> opcodeMap) throws IOException {
		// TODO: needs testing with actual data emitted from toolchain
		int numOpcodes = reader.readNextUnsignedByte();
		for (int i = 0; i < numOpcodes; i++) {
			int opcode = reader.readNextUnsignedByte();
			int numOperands = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			DWARFForm[] operandForms = new DWARFForm[numOperands];
			for (int formIndex = 0; formIndex < numOperands; formIndex++) {
				int formInt = reader.readNextUnsignedByte();
				operandForms[formIndex] = DWARFForm.of(formInt);
			}
			opcodeMap.put(opcode, List.of(operandForms));
		}
	}

	public static List<DWARFMacroInfoEntry> readMacroEntries(BinaryReader reader,
			DWARFMacroHeader macroHeader) throws IOException {
		List<DWARFMacroInfoEntry> results = new ArrayList<>();
		DWARFMacroInfoEntry entry;
		while ((entry = DWARFMacroInfoEntry.read(reader, macroHeader)) != null) {
			results.add(entry);
		}
		return results;
	}

	private long startOffset;
	private int version;
	private int flags;
	private long debug_line_offset;
	private int intSize;
	private long entriesStartOffset;
	private Map<Integer, List<DWARFForm>> opcodeMap;
	private DWARFCompilationUnit cu;
	private DWARFLine line;

	public DWARFMacroHeader(long startOffset, int version, int flags, long debug_line_offset,
			int intSize, long entriesStartOffset, DWARFCompilationUnit cu, DWARFLine line,
			Map<Integer, List<DWARFForm>> opcodeMap) {
		this.startOffset = startOffset;
		this.version = version;
		this.flags = flags;
		this.debug_line_offset = debug_line_offset;
		this.intSize = intSize;
		this.entriesStartOffset = entriesStartOffset;
		this.cu = cu;
		this.line = line;
		this.opcodeMap = opcodeMap;
	}

	public DWARFLine getLine() {
		return line;
	}

	public long getDebug_line_offset() {
		return debug_line_offset;
	}

	public int getIntSize() {
		return intSize;
	}

	public long getEntriesStartOffset() {
		return entriesStartOffset;
	}

	public List<DWARFMacroInfoEntry> getEntries() throws IOException {
		return cu.getProgram().getMacroEntries(this);
	}

	public DWARFCompilationUnit getCompilationUnit() {
		return cu;
	}

	public Map<Integer, List<DWARFForm>> getOpcodeMap() {
		return opcodeMap;
	}

	@Override
	public String toString() {
		return "DWARFMacroHeader: startOffset=0x%x, debug_line_offset=0x%x, intSize=%d"
				.formatted(startOffset, debug_line_offset, intSize);
	}

	//---------------------------------------------------------------------------------------------
	public static final DWARFMacroHeader EMTPY =
		new DWARFMacroHeader(0, 0, 0, 0, 0, 0, null, DWARFLine.empty(), null) {
			@Override
			public List<DWARFMacroInfoEntry> getEntries() throws IOException {
				return List.of();
			}
		};

}
