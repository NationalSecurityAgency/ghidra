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
package ghidra.app.util.bin.format.dwarf4;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.DWARFUtil.LengthResult;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A DWARF "CompilationUnit" is a contiguous block of {@link DebugInfoEntry DIE} records found
 * in a ".debug_info" section of an ELF program.  The compilation unit block starts with a
 * header that has a few important values and flags, and is followed by the DIE records.
 * <p>
 * The first DIE record must be a DW_TAG_compile_unit (see {@link DWARFCompileUnit},
 * and {@link #getCompileUnit()}).
 * <p>
 * DIE records are identified by their byte offset in the ".debug_info" section.
 * <p>
 */
public class DWARFCompilationUnit {

	public static final int DWARF_32 = 32;
	public static final int DWARF_64 = 64;

	/**
	 * Reference to the owning {@link DWARFProgram}.
	 */
	private final DWARFProgram dwarfProgram;

	/**
	 * Offset in the debug_info section of this compUnit's header
	 */
	private final long startOffset;

	/**
	 * Offset in the debug_info section of the end of this compUnit.  (right after
	 * the last DIE record)
	 */
	private final long endOffset;

	/**
	 * Length in bytes of this compUnit header and DIE records.
	 */
	private final long length;

	/**
	 * {@link #DWARF_32} or {@link #DWARF_64}
	 */
	private final int format;

	/**
	 * DWARF ver number, as read from the compunit structure, currently not used but being kept.
	 */
	@SuppressWarnings("unused")
	private final short version;

	/**
	 * Sequential number of this compUnit
	 */
	private final int compUnitNumber;

	/**
	 * Size of pointers that are held in DIEs in this compUnit.
	 */
	private final byte pointerSize;

	/**
	 * Offset in the abbr section of this compUnit's abbreviations.
	 */
	private final long abbreviationOffset;

	/**
	 * Offset in the debug_info section of the first DIE of this compUnit.
	 */
	private final long firstDIEOffset;

	/**
	 * Map of abbrevCode to {@link DWARFAbbreviation} instances.
	 */
	private final Map<Integer, DWARFAbbreviation> codeToAbbreviationMap;

	/**
	 * The contents of the first DIE (that must be a compile unit) in this compUnit.
	 */
	private DWARFCompileUnit compUnit;

	/**
	 * Creates a new {@link DWARFCompilationUnit} by reading a compilationUnit's header data
	 * from the debug_info section and the debug_abbr section and its compileUnit DIE (ie.
	 * the first DIE right after the header).
	 * <p>
	 * Returns {@code NULL} if there was an ignorable error while reading the compilation unit (and
	 * leaves the input stream at the next compilation unit to read), otherwise throws
	 * an IOException if there was an unrecoverable error.
	 * <p>
	 * Also returns {@code NULL} (and leaves the stream at EOF) if the remainder of the stream 
	 * is filled with null bytes. 
	 *
	 * @param dwarfProgram the dwarf program.
	 * @param debugInfoBR the debug info binary reader.
	 * @param debugAbbrBR the debug abbreviation binary reader
	 * @param cuNumber the compilation unit number
	 * @param monitor the current task monitor
	 * @return the read compilation unit, or null if the compilation unit was bad/empty and should 
	 * be ignored
	 * @throws DWARFException if an invalid or unsupported DWARF version is read.
	 * @throws IOException if the length of the compilation unit is invalid.
	 * @throws CancelledException if the task has been canceled.
	 */
	public static DWARFCompilationUnit readCompilationUnit(DWARFProgram dwarfProgram,
			BinaryReader debugInfoBR, BinaryReader debugAbbrBR, int cuNumber, TaskMonitor monitor)
			throws DWARFException, IOException, CancelledException {

		long startOffset = debugInfoBR.getPointerIndex();
		LengthResult lengthInfo =
			DWARFUtil.readLength(debugInfoBR, dwarfProgram.getGhidraProgram());
		if (lengthInfo.length == 0) {
			if (isAllZerosUntilEOF(debugInfoBR)) {
				// hack to handle trailing padding at end of section.  (similar to the check for
				// unexpectedTerminator in readDIEs(), when padding occurs inside the bounds
				// of the compile unit's range after the end of the root DIE's children)
				debugInfoBR.setPointerIndex(debugInfoBR.length());
				return null;
			}
			else {
				throw new DWARFException(
					"Invalid DWARF length 0 at 0x" + Long.toHexString(startOffset));
			}
		}

		long endOffset = debugInfoBR.getPointerIndex() + lengthInfo.length;
		short version = debugInfoBR.readNextShort();
		long abbreviationOffset = DWARFUtil.readOffsetByDWARFformat(debugInfoBR, lengthInfo.format);
		byte pointerSize = debugInfoBR.readNextByte();
		long firstDIEOffset = debugInfoBR.getPointerIndex();

		if (version < 2 || version > 4) {
			throw new DWARFException(
				"Only DWARF version 2, 3, or 4 information is currently supported.");
		}
		if (firstDIEOffset > endOffset) {
			throw new IOException("Invalid length " + (endOffset - startOffset) +
				" for DWARF Compilation Unit at 0x" + Long.toHexString(startOffset));
		}
		else if (firstDIEOffset == endOffset) {
			// silently skip this empty compunit
			return null;
		}

		debugAbbrBR.setPointerIndex(abbreviationOffset);
		Map<Integer, DWARFAbbreviation> abbrMap =
			DWARFAbbreviation.readAbbreviations(debugAbbrBR, dwarfProgram, monitor);

		DWARFCompilationUnit cu = new DWARFCompilationUnit(dwarfProgram, startOffset, endOffset,
			lengthInfo.length, lengthInfo.format, version, abbreviationOffset, pointerSize,
			cuNumber, firstDIEOffset, abbrMap);

		try {
			DebugInfoEntry compileUnitDIE =
				DebugInfoEntry.read(debugInfoBR, cu, dwarfProgram.getAttributeFactory());

			DWARFCompileUnit compUnit =
				DWARFCompileUnit.read(DIEAggregate.createSingle(compileUnitDIE));
			cu.setCompileUnit(compUnit);
			return cu;
		}
		catch (IOException ioe) {
			Msg.error(null,
				"Failed to parse the DW_TAG_compile_unit DIE at the start of compilation unit " +
					cuNumber + " at offset " + startOffset + " (0x" +
					Long.toHexString(startOffset) + "), skipping entire compilation unit",
				ioe);
			debugInfoBR.setPointerIndex(cu.getEndOffset());
			return null;
		}
	}

	private static boolean isAllZerosUntilEOF(BinaryReader reader) throws IOException {
		reader = reader.clone();
		while (reader.getPointerIndex() < reader.length()) {
			if (reader.readNextByte() != 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * This ctor is public only for junit tests.  Do not use directly.
	 * 
	 * @param dwarfProgram {@link DWARFProgram} 
	 * @param startOffset offset in provider where it starts
	 * @param endOffset offset in provider where it ends
	 * @param length how many bytes following the header the DIEs of this unit take
	 * @param format DWARF_32 or DWARF_64
	 * @param version 2, 3, 4
	 * @param abbreviationOffset offset into abbrev section 
	 * @param pointerSize default size of pointers
	 * @param compUnitNumber this compunits ordinal in the file
	 * @param firstDIEOffset start of DIEs in the provider
	 * @param codeToAbbreviationMap map of abbreviation numbers to {@link DWARFAbbreviation} instances
	 */
	public DWARFCompilationUnit(DWARFProgram dwarfProgram, long startOffset, long endOffset,
			long length, int format, short version, long abbreviationOffset, byte pointerSize,
			int compUnitNumber, long firstDIEOffset,
			Map<Integer, DWARFAbbreviation> codeToAbbreviationMap) {
		this.dwarfProgram = dwarfProgram;
		this.startOffset = startOffset;
		this.endOffset = endOffset;
		this.length = length;
		this.format = format;
		this.version = version;
		this.abbreviationOffset = abbreviationOffset;
		this.pointerSize = pointerSize;
		this.compUnitNumber = compUnitNumber;
		this.firstDIEOffset = firstDIEOffset;
		this.codeToAbbreviationMap =
			(codeToAbbreviationMap != null) ? codeToAbbreviationMap : new HashMap<>();
	}

	public DWARFCompileUnit getCompileUnit() {
		return compUnit;
	}

	protected void setCompileUnit(DWARFCompileUnit compUnit) {
		this.compUnit = compUnit;
	}

	public DWARFProgram getProgram() {
		return dwarfProgram;
	}

	/**
	 * An unsigned long (4 bytes in 32-bit or 8 bytes in 64-bit format) representing
	 * the length of the .debug_info contribution for that compilation unit,
	 * not including the length field itself.
	 * @return the length in bytes of the this compilation unit
	 */
	public long getLength() {
		return this.length;
	}

	/**
	 * A 1-byte unsigned integer representing the size
	 * in bytes of an address on the target
	 * architecture. If the system uses segmented addressing, this
	 * value represents the size of the offset portion of an address.
	 * @return the size in bytes of pointers
	 */
	public byte getPointerSize() {
		return this.pointerSize;
	}

	/**
	 * Returns the byte offset to the start of this compilation unit.
	 * @return the byte offset to the start of this compilation unit
	 */
	public long getStartOffset() {
		return this.startOffset;
	}

	/**
	 * Returns the byte offset to the end of this compilation unit.
	 * @return the byte offset to the end of this compilation unit
	 */
	public long getEndOffset() {
		return this.endOffset;
	}

	/**
	 * Returns either DWARF_32 or DWARF_64 depending on the current compilation unit format
	 * @return DWARF_32 or DWARF_64 constant depending on the current compilation unit format
	 */
	public int getFormat() {
		return this.format;
	}

	/**
	 * Returns true if the {@code offset} value is within
	 * this compUnit's start and end position in the debug_info section.
	 * @param offset DIE offset
	 * @return true if within range of this compunit
	 */
	public boolean containsOffset(long offset) {
		return firstDIEOffset <= offset && offset < endOffset;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append("Compilation Unit");
		buffer.append(" [Start:0x" + Long.toHexString(this.startOffset) + "]");
		buffer.append(" [Length:0x" + Long.toHexString(this.length) + "]");
		buffer.append(" [AbbreviationOffset:0x" + Long.toHexString(this.abbreviationOffset) + "]");
		buffer.append(
			" [CompileUnit: " + (compUnit != null ? compUnit.toString() : "not present") + "]");
		return buffer.toString();
	}

	public Map<Integer, DWARFAbbreviation> getCodeToAbbreviationMap() {
		return codeToAbbreviationMap;
	}

	public long getFirstDIEOffset() {
		return firstDIEOffset;
	}

	public int getCompUnitNumber() {
		return compUnitNumber;
	}

	/**
	 * Reads the {@link DebugInfoEntry} records for this compilation unit from the .debug_info
	 * section.
	 * <p>
	 * @param entries List of DIE records that is written to by this method.  This list should
	 * be empty if the caller only wants this CU's records (ie. normal mode), or the list
	 * can be used to accumulate all DIE records (preload all DIE mode).
	 * @param monitor {@link TaskMonitor} to watch for cancelation
	 * @throws IOException if error reading data
	 * @throws DWARFException if error in DWARF structure
	 * @throws CancelledException if user cancels.
	 */
	public void readDIEs(List<DebugInfoEntry> entries, TaskMonitor monitor)
			throws IOException, DWARFException, CancelledException {

		BinaryReader br = dwarfProgram.getDebugInfo();
		br.setPointerIndex(getFirstDIEOffset());

		Deque<DebugInfoEntry> parentStack = new ArrayDeque<>();

		DebugInfoEntry parent = null;
		DebugInfoEntry die;
		DebugInfoEntry unexpectedTerminator = null;
		while ((br.getPointerIndex() < getEndOffset()) &&
			(die = DebugInfoEntry.read(br, this, dwarfProgram.getAttributeFactory())) != null) {

			monitor.checkCanceled();

			if (die.isTerminator()) {
				if (parent == null && parentStack.isEmpty()) {
					unexpectedTerminator = die;
					continue;
				}
				parent = !parentStack.isEmpty() ? parentStack.pop() : null;
				continue;
			}

			if (unexpectedTerminator != null) {
				throw new DWARFException("Unexpected terminator entry at " +
					Long.toHexString(unexpectedTerminator.getOffset()));
			}
			entries.add(die);

			if (parent != null) {
				parent.addChild(die);
				die.setParent(parent);
			}
			else {
				if (die.getOffset() != getFirstDIEOffset()) {
					throw new DWARFException(
						"Unexpected root level DIE at " + Long.toHexString(die.getOffset()));
				}
			}

			if (die.getAbbreviation().hasChildren()) {
				if (parent != null) {
					parentStack.push(parent);
				}
				parent = die;
			}
		}
	}
}
