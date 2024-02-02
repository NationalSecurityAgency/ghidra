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
import ghidra.app.util.bin.format.dwarf4.attribs.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.program.model.data.LEB128;
import ghidra.util.datastruct.IntArrayList;

/**
 * A DWARF Debug Info Entry is a collection of {@link DWARFAttributeValue attributes}
 * in a hierarchical structure (see {@link #getParent()}, {@link #getChildren()}).
 * <p>
 * This class is a lower-level class and {@link DIEAggregate} should be used instead in most
 * cases when examining information from the DWARF system.
 *
 */
public class DebugInfoEntry {

	/**
	 * List of common DWARF attributes that are not used currently in Ghidra.  These attributes values will be
	 * thrown away during reading to save some memory.  There are lots of attributes that Ghidra doesn't
	 * currently use, but they do not appear frequently enough to consume a significant amount of memory.
	 */
	private static final Set<Integer> ATTRIBUTES_TO_SKIP =
		Set.of(DWARFAttribute.DW_AT_sibling, DWARFAttribute.DW_AT_accessibility);

	private final DWARFCompilationUnit compilationUnit;
	private final DWARFAbbreviation abbreviation;
	private final DWARFAttributeValue[] attributes;
	private final long offset;
	private final int dieIndex;

	/**
	 * Read a DIE record.
	 *
	 * @param reader {@link BinaryReader} positioned at the start of a DIE record
	 * @param unit the compunit that contains the DIE
	 * @param dieIndex the index of the DIE
	 * @param attributeFactory the {@link DWARFAttributeFactory} to use to deserialize attribute
	 * values
	 * @return new DIE instance
	 * @throws IOException if error reading data, or bad DWARF
	 */
	public static DebugInfoEntry read(BinaryReader reader, DWARFCompilationUnit unit,
			int dieIndex, DWARFAttributeFactory attributeFactory) throws IOException {
		long offset = reader.getPointerIndex();
		int abbreviationCode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);

		// Check for terminator DIE
		if (abbreviationCode == 0) {
			return new DebugInfoEntry(unit, offset, -1, null);
		}

		DWARFAbbreviation abbreviation = unit.getCodeToAbbreviationMap().get(abbreviationCode);
		if (abbreviation == null) {
			throw new IOException("Abbreviation code " + abbreviationCode +
				" not found in the abbreviation map for compunit " + unit);
		}

		DebugInfoEntry result = new DebugInfoEntry(unit, offset, dieIndex, abbreviation);
		// Read in all of the attribute values based on the attribute specification
		DWARFAttributeSpecification[] attributeSpecs = result.abbreviation.getAttributes();
		for (int i = 0; i < attributeSpecs.length; i++) {
			DWARFAttributeSpecification attributeSpec = attributeSpecs[i];
			result.attributes[i] =
				attributeFactory.read(reader, unit, attributeSpec.getAttributeForm());

			if (ATTRIBUTES_TO_SKIP.contains(attributeSpec.getAttribute())) {
				// throw away the object holding the value and replace it with
				// the static boolean true value object to hold its place in
				// the list.  This saves a little memory
				result.attributes[i] = DWARFBooleanAttribute.TRUE;
			}
		}

		return result;
	}

	/**
	 * Creates a DIE.  Used by 
	 * {@link #read(BinaryReader, DWARFCompilationUnit, DWARFAttributeFactory) static read()} and 
	 * junit tests.
	 * 
	 * @param unit compunit containing the DIE
	 * @param offset offset of the DIE
	 * @param dieIndex index of the DIE
	 * @param abbreviation that defines the schema of this DIE record
	 */
	public DebugInfoEntry(DWARFCompilationUnit unit, long offset, int dieIndex,
			DWARFAbbreviation abbreviation) {
		this.compilationUnit = unit;
		this.offset = offset;
		this.dieIndex = dieIndex;
		this.abbreviation = abbreviation;
		this.attributes = abbreviation != null
				? new DWARFAttributeValue[abbreviation.getAttributeCount()]
				: null;
	}

	/**
	 * Returns the index of this DIE (in the entire dwarf program)
	 * 
	 * @return index of this DIE
	 */
	public int getIndex() {
		return dieIndex;
	}

	/**
	 * Return a list of the child DIE's.
	 * 
	 * @return list of child DIE's
	 */
	public List<DebugInfoEntry> getChildren() {
		return getProgram().getChildrenOf(dieIndex);
	}

	/**
	 * Return a list of children that are of a specific DWARF type.
	 * <p>
	 * @param childTag DIE tag used to filter the child DIEs
	 * @return list of matching child DIE records
	 */
	public List<DebugInfoEntry> getChildren(int childTag) {
		List<DebugInfoEntry> result = new ArrayList<>();
		for (DebugInfoEntry child : getChildren()) {
			if (child.getTag() == childTag) {
				result.add(child);
			}
		}
		return result;
	}

	/**
	 * Get the parent DIE of this DIE.
	 * 
	 * @return the parent DIE, or null if this DIE is the root of the compunit
	 */
	public DebugInfoEntry getParent() {
		return getProgram().getParentOf(dieIndex);
	}

	/**
	 * Get the offset of this DIE from the beginning of the debug_info section.
	 * @return the offset of this DIE from the beginning of the debug_info section
	 */
	public long getOffset() {
		return this.offset;
	}

	/**
	 * Get the DWARFTag value of this DIE.
	 * @return the DWARFTag value of this DIE
	 */
	public int getTag() {
		return (abbreviation != null) ? abbreviation.getTag() : 0;
	}

	public DWARFAttributeValue[] getAttributes() {
		return attributes;
	}

	/**
	 * Check to see if this DIE has the given attribute key.
	 * @param attribute the attribute key
	 * @return true if the DIE contains the attribute and false otherwise
	 */
	public boolean hasAttribute(int attribute) {
		if (abbreviation == null) {
			return false;
		}

		for (DWARFAttributeSpecification as : abbreviation.getAttributes()) {
			if (as.getAttribute() == attribute) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the abbreviation of this DIE.
	 * @return the abbreviation of this DIE
	 */
	public DWARFAbbreviation getAbbreviation() {
		return this.abbreviation;
	}

	/**
	 * Check to see if the DIE is a terminator.
	 * @return true if the DIE is a terminator and false otherwise
	 */
	public boolean isTerminator() {
		return abbreviation == null;
	}

	/**
	 * Returns the ordinal position of this DIE record in its parent's list of children.
	 * 
	 * @return index of ourself in our parent, or -1 if root DIE
	 */
	public int getPositionInParent() {
		DWARFProgram dprog = getProgram();
		int parentIndex = dprog.getParentIndex(dieIndex);
		if (parentIndex < 0) {
			return -1;
		}
		IntArrayList childIndexes = dprog.getDIEChildIndexes(parentIndex);
		for (int i = 0; i < childIndexes.size(); i++) {
			if (childIndexes.get(i) == dieIndex) {
				return i;
			}
		}
		// only way to get here is if our in-memory indexes are corrupt / incorrect
		throw new RuntimeException("DWARF DIE index failure.");
	}

	public DWARFCompilationUnit getCompilationUnit() {
		return compilationUnit;
	}

	public DWARFProgram getProgram() {
		return getCompilationUnit().getProgram();
	}

	public int getDepth() {
		return getProgram().getParentDepth(dieIndex);
	}

	@Override
	public int hashCode() {
		return Objects.hash(compilationUnit, dieIndex, offset);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DebugInfoEntry)) {
			return false;
		}
		DebugInfoEntry other = (DebugInfoEntry) obj;
		return Objects.equals(compilationUnit, other.compilationUnit) &&
			dieIndex == other.dieIndex && offset == other.offset;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		int tag = getTag();
		int abbrNum = abbreviation != null ? abbreviation.getAbbreviationCode() : 0;
		int childCount = getProgram().getDIEChildIndexes(dieIndex).size();

		buffer.append("<%d><%x>: %s [abbrev %d, tag %d, index %d, children %d]\n".formatted(
			getDepth(), offset, DWARFUtil.toString(DWARFTag.class, tag), abbrNum, tag, dieIndex,
			childCount));

		if (isTerminator()) {
			return buffer.toString();
		}

		DWARFAttributeSpecification[] attributeSpecs = abbreviation.getAttributes();
		for (int i = 0; i < attributeSpecs.length; i++) {
			DWARFAttributeSpecification attributeSpec = attributeSpecs[i];
			buffer.append("\t\tAttribute: %s %s %s\n".formatted(
				DWARFUtil.toString(DWARFAttribute.class, attributeSpec.getAttribute()),
				attributes[i], attributeSpec.getAttributeForm().toString()));
		}

		return buffer.toString();
	}

}
