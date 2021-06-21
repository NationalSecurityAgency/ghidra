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
	private final long offset;
	private final DWARFAbbreviation abbreviation;
	private final DWARFAttributeValue[] attributes;
	private long parentOffset = -1;
	private List<DebugInfoEntry> children;

	/**
	 * Read a DIE record.
	 *
	 * @param reader
	 * @param unit
	 * @param attributeFactory
	 * @return
	 * @throws IOException
	 */
	public static DebugInfoEntry read(BinaryReader reader, DWARFCompilationUnit unit,
			DWARFAttributeFactory attributeFactory) throws IOException {
		long offset = reader.getPointerIndex();
		int abbreviationCode = LEB128.readAsUInt32(reader);

		// Check for terminator DIE
		if (abbreviationCode == 0) {
			return new DebugInfoEntry(unit, offset, null);
		}

		DWARFAbbreviation abbreviation = unit.getCodeToAbbreviationMap().get(abbreviationCode);
		if (abbreviation == null) {
			throw new IOException("Abbreviation code " + abbreviationCode +
				" not found in the abbreviation map for compunit " + unit);
		}

		DebugInfoEntry result = new DebugInfoEntry(unit, offset, abbreviation);
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
	 * Creates an empty DIE.  Used by {@link #read(BinaryReader, DWARFCompilationUnit, DWARFAttributeFactory) static read()}
	 * and junit tests.
	 * <p>
	 * @param unit
	 * @param offset
	 * @param abbreviation
	 */
	public DebugInfoEntry(DWARFCompilationUnit unit, long offset, DWARFAbbreviation abbreviation) {
		this.compilationUnit = unit;
		this.offset = offset;
		this.abbreviation = abbreviation;
		this.attributes =
			(abbreviation != null) ? new DWARFAttributeValue[abbreviation.getAttributeCount()]
					: null;
	}

	/**
	 * Add a child DIE to this DIE.
	 * @param child DIE of the child
	 */
	public void addChild(DebugInfoEntry child) {
		if (children == null) {
			children = new ArrayList<>(5);
		}
		this.children.add(child);
	}

	/**
	 * Return a live list of the child DIE's.
	 * @return list of child DIE's
	 */
	public List<DebugInfoEntry> getChildren() {
		return children != null ? children : Collections.EMPTY_LIST;
	}

	/**
	 * Return a list of children that are of a specific DWARF type.
	 * <p>
	 * @param childTag
	 * @return
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
	 * Check to see if this DIE has any child DIE's.
	 * @return true if there are child DIE's and false otherwise
	 */
	public boolean hasChildren() {
		return !this.children.isEmpty();
	}

	/**
	 * Set the parent DIE of this DIE.
	 * @param parent the parent DIE
	 */
	public void setParent(DebugInfoEntry parent) {
		parentOffset = (parent != null) ? parent.getOffset() : -1;
	}

	/**
	 * Get the parent DIE of this DIE.
	 * @return the parent DIE
	 */
	public DebugInfoEntry getParent() {
		return (parentOffset != -1)
				? compilationUnit.getProgram().getEntryAtByteOffsetUnchecked(parentOffset)
				: null;
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

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder(getClass().getSimpleName());
		buffer.append(" - Offset: 0x").append(Long.toHexString(this.offset)).append("\n");
		buffer.append("AbbreviationCode: 0x").append(
			Long.toHexString(abbreviation != null ? abbreviation.getAbbreviationCode() : 0));

		if (isTerminator()) {
			return buffer.toString();
		}

		buffer.append(" ").append(
			DWARFUtil.toString(DWARFTag.class, this.abbreviation.getTag())).append("\n");

		DWARFAttributeSpecification[] attributeSpecs = abbreviation.getAttributes();
		for (int i = 0; i < attributeSpecs.length; i++) {
			DWARFAttributeSpecification attributeSpec = attributeSpecs[i];
			buffer.append("\tAttribute: ");
			buffer.append(DWARFUtil.toString(DWARFAttribute.class, attributeSpec.getAttribute()));
			buffer.append(" ");
			buffer.append(attributes[i]);
			buffer.append(" ");
			buffer.append(attributeSpec.getAttributeForm().toString());
			buffer.append("\n");
		}
		if (children != null && !children.isEmpty()) {
			buffer.append("\tChild count: ").append(children.size()).append("\n");
		}

		return buffer.toString();
	}

	public DWARFCompilationUnit getCompilationUnit() {
		return compilationUnit;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (offset ^ (offset >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof DebugInfoEntry)) {
			return false;
		}
		DebugInfoEntry other = (DebugInfoEntry) obj;
		if (offset != other.offset) {
			return false;
		}
		return true;
	}

}
