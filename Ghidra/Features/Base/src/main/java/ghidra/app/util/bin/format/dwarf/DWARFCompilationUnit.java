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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.line.DWARFLine;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A DWARF CompilationUnit is a contiguous block of {@link DebugInfoEntry DIE} records found
 * in a .debug_info section of an program.  The compilation unit block starts with a
 * header that has a few important values and flags, and is followed by the DIE records.
 * <p>
 * The first DIE record must be a DW_TAG_compile_unit.
 * <p>
 * DIE records are identified by their byte offset in the .debug_info section.
 * <p>
 */
public class DWARFCompilationUnit extends DWARFUnitHeader {
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
	 * @param partial already read partial unit header
	 * @param reader .debug_info BinaryReader 
	 * @param abbrReader .debug_abbr BinaryReader
	 * @param monitor the current task monitor
	 * @return the read compilation unit, or null if the compilation unit was bad/empty and should 
	 * be ignored
	 * @throws DWARFException if an invalid or unsupported DWARF version is read.
	 * @throws IOException if the length of the compilation unit is invalid.
	 * @throws CancelledException if the task has been canceled.
	 */
	public static DWARFCompilationUnit readV4(DWARFUnitHeader partial, BinaryReader reader,
			BinaryReader abbrReader, TaskMonitor monitor)
			throws DWARFException, IOException, CancelledException {

		long abbreviationOffset = reader.readNextUnsignedValue(partial.getIntSize());
		byte pointerSize = reader.readNextByte();
		long firstDIEOffset = reader.getPointerIndex();

		if (firstDIEOffset > partial.endOffset) {
			throw new IOException("Invalid length %d for DWARF Compilation Unit at 0x%x"
					.formatted(partial.endOffset - partial.startOffset, partial.startOffset));
		}
		else if (firstDIEOffset == partial.endOffset) {
			// silently skip this empty compunit
			return null;
		}

		abbrReader.setPointerIndex(abbreviationOffset);
		Map<Integer, DWARFAbbreviation> abbrMap =
			DWARFAbbreviation.readAbbreviations(abbrReader, partial.dprog, monitor);

		DWARFCompilationUnit cu =
			new DWARFCompilationUnit(partial, pointerSize, firstDIEOffset, abbrMap);
		return cu;
	}

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
	 * @param partial already read partial unit header
	 * @param reader .debug_info BinaryReader 
	 * @param abbrReader .debug_abbr BinaryReader
	 * @param monitor the current task monitor
	 * @return the read compilation unit, or null if the compilation unit was bad/empty and should 
	 * be ignored
	 * @throws DWARFException if an invalid or unsupported DWARF version is read.
	 * @throws IOException if the length of the compilation unit is invalid.
	 * @throws CancelledException if the task has been canceled.
	 */
	public static DWARFCompilationUnit readV5(DWARFUnitHeader partial, BinaryReader reader,
			BinaryReader abbrReader, TaskMonitor monitor)
			throws DWARFException, IOException, CancelledException {

		byte pointerSize = reader.readNextByte();
		long abbreviationOffset = reader.readNextUnsignedValue(partial.getIntSize());

		long firstDIEOffset = reader.getPointerIndex();

		if (firstDIEOffset > partial.endOffset) {
			throw new IOException("Invalid length %d for DWARF Compilation Unit at 0x%x"
					.formatted(partial.endOffset - partial.startOffset, partial.startOffset));
		}
		else if (firstDIEOffset == partial.endOffset) {
			// silently skip this empty compunit
			return null;
		}

		abbrReader.setPointerIndex(abbreviationOffset);
		Map<Integer, DWARFAbbreviation> abbrMap =
			DWARFAbbreviation.readAbbreviations(abbrReader, partial.dprog, monitor);

		DWARFCompilationUnit cu =
			new DWARFCompilationUnit(partial, pointerSize, firstDIEOffset, abbrMap);
		return cu;
	}

	/**
	 * Size of pointers that are held in DIEs in this compUnit. (from header)
	 */
	private final byte pointerSize;

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
	protected DIEAggregate diea;

	private DWARFLine line;

	private DWARFCompilationUnit(DWARFUnitHeader partial, byte pointerSize, long firstDIEOffset,
			Map<Integer, DWARFAbbreviation> abbrMap) {
		super(partial);

		this.pointerSize = pointerSize;
		this.firstDIEOffset = firstDIEOffset;
		this.codeToAbbreviationMap = (abbrMap != null) ? abbrMap : new HashMap<>();
	}

	/**
	 * This ctor is public only for junit tests.  Do not use directly.
	 * 
	 * @param dwarfProgram {@link DWARFProgram} 
	 * @param startOffset offset in provider where it starts
	 * @param endOffset offset in provider where it ends
	 * @param intSize 4 (DWARF_32) or 8 (DWARF_64)
	 * @param dwarfVersion 2-5 
	 * @param pointerSize default size of pointers
	 * @param unitNumber this compunits ordinal in the file
	 * @param firstDIEOffset start of DIEs in the provider
	 * @param codeToAbbreviationMap map of abbreviation numbers to {@link DWARFAbbreviation} instances
	 */
	public DWARFCompilationUnit(DWARFProgram dwarfProgram, long startOffset, long endOffset,
			int intSize, short dwarfVersion, byte pointerSize, int unitNumber,
			long firstDIEOffset, Map<Integer, DWARFAbbreviation> codeToAbbreviationMap) {
		super(dwarfProgram, startOffset, endOffset, intSize, dwarfVersion, unitNumber);
		this.pointerSize = pointerSize;
		this.firstDIEOffset = firstDIEOffset;
		this.codeToAbbreviationMap =
			(codeToAbbreviationMap != null) ? codeToAbbreviationMap : new HashMap<>();
	}

	/**
	 * Initializes this compunit with the root DIE (first DIE) of the compunit.  This comp unit
	 * isn't usable until this has happened.
	 * 
	 * @param rootDIE {@link DebugInfoEntry}
	 * @throws IOException if error reading data from the DIE
	 */
	public void init(DebugInfoEntry rootDIE) throws IOException {
		diea = DIEAggregate.createSingle(rootDIE);
		line = getProgram().getLine(diea, DW_AT_stmt_list);
	}

	/**
	 * Returns this comp unit's root DIE as a DIE Aggregate.
	 *  
	 * @return the aggregate containing the root element of this comp unit
	 */
	public DIEAggregate getCompUnitDIEA() {
		return diea;
	}

	/**
	 * Returns the size of pointers in this compUnit.
	 * 
	 * @return the size in bytes of pointers
	 */
	public byte getPointerSize() {
		return this.pointerSize;
	}

	public Map<Integer, DWARFAbbreviation> getCodeToAbbreviationMap() {
		return codeToAbbreviationMap;
	}

	public DWARFAbbreviation getAbbreviation(int ac) {
		return codeToAbbreviationMap.get(ac);
	}

	public long getFirstDIEOffset() {
		return firstDIEOffset;
	}

	public DWARFLine getLine() {
		return line;
	}

	/**
	 * Get the filename that produced the compile unit
	 * 
	 * @return the filename that produced the compile unit
	 */
	public String getName() {
		return diea.getString(DW_AT_name, null);
	}

	/**
	 * Get the producer of the compile unit
	 * @return the producer of the compile unit
	 */
	public String getProducer() {
		return diea.getString(DW_AT_producer, null);
	}

	/**
	 * Get the compile directory of the compile unit
	 * @return the compile directory of the compile unit
	 */
	public String getCompileDirectory() {
		return diea.getString(DW_AT_comp_dir, null);
	}

	/**
	 * Get the source language of the compile unit.
	 * <p>
	 * See {@link DWARFSourceLanguage} for values.
	 * 
	 * @return the source language of the compile unit, or -1 if not set
	 */
	public int getLanguage() {
		return (int) diea.getUnsignedLong(DW_AT_language, -1);
	}

	public boolean hasDWO() {
		return diea.hasAttribute(DW_AT_GNU_dwo_id) && diea.hasAttribute(DW_AT_GNU_dwo_name);
	}

	public long getAddrTableBase() {
		return diea.getUnsignedLong(DW_AT_addr_base, 0);
	}

	public long getRangeListsBase() {
		return diea.getUnsignedLong(DW_AT_rnglists_base, 0);
	}

	public long getLocListsBase() {
		return diea.getUnsignedLong(DW_AT_loclists_base, 0);
	}

	public long getStrOffsetsBase() {
		return diea.getUnsignedLong(DW_AT_str_offsets_base, 0);
	}

	/**
	 * Returns the range covered by this CU, as defined by the lo_pc and high_pc attribute values,
	 * defaulting to (0,0] if missing.
	 * 
	 * @return {@link DWARFRange} that this CU covers, never null
	 */
	public DWARFRange getPCRange() {
		return diea.getPCRange();
	}

	@Override
	public String toString() {
		return "DWARFCompilationUnit @%x, ver %d, pointersize: %d\n".formatted(startOffset,
			dwarfVersion, pointerSize) + diea.toString().indent(4);
	}
}
