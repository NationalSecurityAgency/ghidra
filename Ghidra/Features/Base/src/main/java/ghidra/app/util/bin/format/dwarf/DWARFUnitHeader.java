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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The base class for a set of headers that share a common field layout.
 */
public class DWARFUnitHeader {
	/**
	 * Reads the initial fields found in a unit header.
	 * 
	 * @param dprog {@link DWARFProgram}
	 * @param reader {@link BinaryReader} stream
	 * @param abbrReader  {@link BinaryReader} .debug_abbr stream
	 * @param unitNumber ordinal of this item
	 * @param monitor {@link TaskMonitor}
	 * @return a unit header (only comp units for now), or null if at end-of-list
	 * @throws DWARFException if invalid dwarf data
	 * @throws IOException if error reading data
	 * @throws CancelledException if cancelled
	 */
	public static DWARFUnitHeader read(DWARFProgram dprog, BinaryReader reader,
			BinaryReader abbrReader, int unitNumber, TaskMonitor monitor)
			throws DWARFException, IOException, CancelledException {
		// unit_length : dwarf_length
		// version : 2 bytes
		// unit type : 1 byte [ version >= 5 ]

		long startOffset = reader.getPointerIndex();
		DWARFLengthValue lengthInfo = DWARFLengthValue.read(reader, dprog.getDefaultIntSize());
		if (lengthInfo == null) {
			return null;
		}

		long endOffset = reader.getPointerIndex() + lengthInfo.length();
		short version = reader.readNextShort();
		if (version < 2) {
			throw new DWARFException("Unsupported DWARF version [%d]".formatted(version));
		}

		DWARFUnitHeader partial = new DWARFUnitHeader(dprog, startOffset, endOffset,
			lengthInfo.intSize(), version, unitNumber);

		if (2 <= version && version <= 4) {
			return DWARFCompilationUnit.readV4(partial, reader, abbrReader, monitor);
		}
		int unitType = reader.readNextUnsignedByte();
		switch (unitType) {
			case DWARFUnitType.DW_UT_compile:
				return DWARFCompilationUnit.readV5(partial, reader, abbrReader, monitor);
			case DWARFUnitType.DW_UT_type:
			case DWARFUnitType.DW_UT_partial:
			case DWARFUnitType.DW_UT_skeleton:
			case DWARFUnitType.DW_UT_split_compile:
			case DWARFUnitType.DW_UT_split_type:
			default:
				throw new DWARFException("Unsupported unitType %d, %s".formatted(unitType,
					DWARFUtil.toString(DWARFUnitType.class, unitType)));
		}
	}

	/**
	 * Reference to the owning {@link DWARFProgram}.
	 */
	protected final DWARFProgram dprog;

	/**
	 * Offset in the section of this header
	 */
	protected final long startOffset;

	/**
	 * Offset in the section of the end of this header. (exclusive)
	 */
	protected final long endOffset;

	/**
	 * size of integers, 4=int32 or 8=int64
	 */
	protected final int intSize;

	/**
	 * Version number, as read from the header.  Note: Some header types use version numbers that do
	 * not match the general dwarfVersion.
	 */
	protected final short dwarfVersion;

	/**
	 * Sequential number of this unit
	 */
	protected final int unitNumber;

	protected DWARFUnitHeader(DWARFUnitHeader other) {
		this.dprog = other.dprog;
		this.startOffset = other.startOffset;
		this.endOffset = other.endOffset;
		this.intSize = other.intSize;
		this.dwarfVersion = other.dwarfVersion;
		this.unitNumber = other.unitNumber;
	}

	protected DWARFUnitHeader(DWARFProgram dprog, long startOffset, long endOffset, int intSize,
			short version, int unitNumber) {
		this.dprog = dprog;
		this.startOffset = startOffset;
		this.endOffset = endOffset;
		this.intSize = intSize;
		this.dwarfVersion = version;
		this.unitNumber = unitNumber;
	}

	public DWARFProgram getProgram() {
		return dprog;
	}

	public short getDWARFVersion() {
		return dwarfVersion;
	}

	/**
	 * Returns the byte offset to the start of this unit.
	 * @return the byte offset to the start of this unit
	 */
	public long getStartOffset() {
		return this.startOffset;
	}

	/**
	 * Returns the byte offset to the end of this unit.
	 * @return the byte offset to the end of this unit
	 */
	public long getEndOffset() {
		return this.endOffset;
	}

	/**
	 * Returns either 4 (for DWARF_32) or 8 (for DWARF_64) depending on the current unit format
	 * 
	 * @return size of ints in this unit (4 or 8)
	 */
	public int getIntSize() {
		return this.intSize;
	}

	/**
	 * Return the ordinal number of this unit
	 * 
	 * @return ordinal of this unit
	 */
	public int getUnitNumber() {
		return unitNumber;
	}

}
