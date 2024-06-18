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
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef;
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

	private final DWARFCompilationUnit compilationUnit;
	private final DWARFAbbreviation abbreviation;
	private final DWARFAttributeValue[] attributes;
	private final int[] attrOffsets;
	private final long offset;
	private final int dieIndex;

	/**
	 * Read a DIE record.
	 *
	 * @param reader {@link BinaryReader} positioned at the start of a DIE record
	 * @param cu the compunit that contains the DIE
	 * @param dieIndex the index of the DIE
	 * @return new DIE instance
	 * @throws IOException if error reading data, or bad DWARF
	 */
	public static DebugInfoEntry read(BinaryReader reader, DWARFCompilationUnit cu, int dieIndex)
			throws IOException {
		long offset = reader.getPointerIndex();
		int ac = reader.readNextUnsignedVarIntExact(LEB128::unsigned);

		// Check for terminator DIE
		if (ac == 0) {
			return new DebugInfoEntry(cu, offset);
		}

		DWARFAbbreviation abbreviation = cu.getAbbreviation(ac);
		if (abbreviation == null) {
			throw new IOException("Abbreviation code %d not found in compunit %d at 0x%x"
					.formatted(ac, cu.getUnitNumber(), cu.getStartOffset()));
		}
		int[] attrOffsets = new int[abbreviation.getAttributeCount()];

		// Read in all of the attribute values based on the attribute specification
		AttrDef[] attributeSpecs = abbreviation.getAttributes();
		int currentAttrOffset = (int) (reader.getPointerIndex() - offset);
		for (int i = 0; i < attributeSpecs.length; i++) {
			attrOffsets[i] = currentAttrOffset;

			AttrDef attributeSpec = attributeSpecs[i];
			DWARFFormContext context = new DWARFFormContext(reader, cu, attributeSpec);
			long attrSize = attributeSpec.getAttributeForm().getSize(context);
			if (attrSize < 0 || attrSize > Integer.MAX_VALUE) {
				throw new IOException("Invalid attribute value size");
			}

			currentAttrOffset += attrSize;

			// manually set stream position because some attributes don't read from the stream to determine size
			reader.setPointerIndex(offset + currentAttrOffset);
		}

		return new DebugInfoEntry(cu, offset, dieIndex, abbreviation, attrOffsets);
	}

	private DebugInfoEntry(DWARFCompilationUnit unit, long offset) {
		this(unit, offset, -1, null, null);
	}

	/**
	 * Creates a DIE.
	 * 
	 * @param cu compunit containing the DIE
	 * @param offset offset of the DIE
	 * @param dieIndex index of the DIE
	 * @param abbreviation that defines the schema of this DIE record
	 * @param attrOffsets offset (from the die offset) of each attribute value 
	 */
	public DebugInfoEntry(DWARFCompilationUnit cu, long offset, int dieIndex,
			DWARFAbbreviation abbreviation, int[] attrOffsets) {
		this.compilationUnit = cu;
		this.offset = offset;
		this.dieIndex = dieIndex;
		this.abbreviation = abbreviation;
		this.attrOffsets = attrOffsets;
		this.attributes = attrOffsets != null ? new DWARFAttributeValue[attrOffsets.length] : null;
	}

	/**
	 * Returns the index of this DIE in the entire dwarf program.
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
	public List<DebugInfoEntry> getChildren(DWARFTag childTag) {
		List<DebugInfoEntry> children = getChildren();
		List<DebugInfoEntry> result = new ArrayList<>(children.size());
		for (DebugInfoEntry child : children) {
			if (child.getTag() == childTag) {
				result.add(child);
			}
		}
		return result;
	}

	/**
	 * Get the parent DIE of this DIE.
	 * 
	 * @return the parent DIE, or null if this DIE is the root of the compilation unit
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
	public DWARFTag getTag() {
		return (abbreviation != null) ? abbreviation.getTag() : null;
	}

	/**
	 * Returns the number of attributes in this DIE.
	 * 
	 * @return number of attribute values in this DIE
	 */
	public int getAttributeCount() {
		return attrOffsets.length;
	}

	/**
	 * Returns the indexed attribute value.
	 * 
	 * @param attribIndex index (0..count)
	 * @return {@link DWARFAttributeValue}
	 * @throws IOException if error reading the value
	 */
	public DWARFAttributeValue getAttributeValue(int attribIndex) throws IOException {
		if (attributes[attribIndex] == null) {
			BinaryReader reader = getProgram().getReaderForCompUnit(compilationUnit)
					.clone(offset + attrOffsets[attribIndex]);
			DWARFFormContext context = new DWARFFormContext(reader, compilationUnit,
				abbreviation.getAttributeAt(attribIndex));
			attributes[attribIndex] = context.def().getAttributeForm().readValue(context);
		}
		return attributes[attribIndex];
	}

	/* for testing */ public void setAttributeValue(int index, DWARFAttributeValue attrVal) {
		attributes[index] = attrVal;
	}

	private DWARFAttributeValue getAttributeValueUnchecked(int attribIndex) {
		try {
			return getAttributeValue(attribIndex);
		}
		catch (IOException e) {
			return null;
		}
	}

	/**
	 * Searches the list of attributes for a specific attribute, by id.
	 * 
	 * @param attributeId {@link DWARFAttribute}
	 * @return {@link DWARFAttributeValue}, or null if not found
	 */
	public DWARFAttributeValue findAttribute(DWARFAttribute attributeId) {
		AttrDef[] attrDefs = abbreviation.getAttributes();
		for (int i = 0; i < attrDefs.length; i++) {
			AttrDef attrDef = attrDefs[i];
			if (attrDef.getAttributeId() == attributeId) {
				return getAttributeValueUnchecked(i);
			}
		}
		return null;
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
		DWARFTag tag = getTag();
		int tagNum = tag != null ? tag.getId() : 0;
		int abbrNum = abbreviation != null ? abbreviation.getAbbreviationCode() : 0;
		int childCount = getProgram().getDIEChildIndexes(dieIndex).size();

		buffer.append("<%d><%x>: %s [abbrev %d, tag %d, index %d, children %d]\n".formatted(
			getDepth(), offset, tag, abbrNum, tagNum, dieIndex, childCount));

		if (isTerminator()) {
			return buffer.toString();
		}

		for (int i = 0; i < attributes.length; i++) {
			buffer.append("\t\t");
			DWARFAttributeValue attribVal = getAttributeValueUnchecked(i);
			buffer.append(attribVal != null ? attribVal.toString(compilationUnit) : "-missing-");
			buffer.append("\n");
		}

		return buffer.toString();
	}

}
