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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents the 'schema' for a DWARF DIE record.
 * <p>
 * A raw DWARF DIE record specifies its abbreviation code (pointing to an instance of
 * this class) and the corresponding DWARFAbbreviation instance has the information
 * about how the raw DIE is laid out.
 */
public class DWARFAbbreviation {
	private static final int EOL = 0;
	private final int abbreviationCode;
	private final DWARFTag tag;
	private final int tagId;
	private final boolean hasChildren;
	private final AttrDef[] attributes;

	/**
	 * Reads a {@link DWARFAbbreviation} from the stream.
	 * 
	 * @param reader {@link BinaryReader} stream
	 * @param prog {@link DWARFProgram}
	 * @param monitor {@link TaskMonitor}
	 * @return {@link DWARFAbbreviation}, or null if the stream was at a end-of-list marker
	 * @throws IOException if error reading
	 * @throws CancelledException if canceled
	 */
	public static DWARFAbbreviation read(BinaryReader reader, DWARFProgram prog,
			TaskMonitor monitor) throws IOException, CancelledException {

		int ac = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		if (ac == EOL) {
			return null;
		}
		int tag = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		int hasChildren = reader.readNextByte();

		// Read each attribute specification until EOL marker value
		List<AttrDef> tmpAttrSpecs = new ArrayList<>();
		AttrDef attrSpec;
		while ((attrSpec = AttrDef.read(reader)) != null) {
			monitor.checkCancelled();
			attrSpec = prog.internAttributeSpec(attrSpec);
			tmpAttrSpecs.add(attrSpec);
			warnIfMismatchedForms(attrSpec);
		}
		AttrDef[] attrSpecArray = tmpAttrSpecs.toArray(new AttrDef[tmpAttrSpecs.size()]);

		DWARFAbbreviation result = new DWARFAbbreviation(ac, tag,
			hasChildren == DWARFChildren.DW_CHILDREN_yes, attrSpecArray);

		return result;
	}

	private static void warnIfMismatchedForms(DWARFAttribute.AttrDef attrSpec) {
		DWARFForm form = attrSpec.getAttributeForm();
		DWARFAttribute attribute = attrSpec.getAttributeId();
		if (attribute != null && !form.getFormClasses().isEmpty() &&
			!attribute.getAttributeClass().isEmpty()) {
			EnumSet<DWARFAttributeClass> tmp =
				EnumSet.copyOf(attrSpec.getAttributeForm().getFormClasses());
			tmp.retainAll(attrSpec.getAttributeId().getAttributeClass());
			if (tmp.isEmpty()) {
				Msg.warn(DWARFAbbreviation.class,
					"Mismatched DWARF Attribute and Form: %s".formatted(attrSpec));
			}
		}

	}

	/**
	 * Reads a list of {@link DWARFAbbreviation}, stopping when the end-of-list marker is
	 * encountered.
	 * 
	 * @param reader {@link BinaryReader} .debug_abbr stream
	 * @param prog {@link DWARFProgram}
	 * @param monitor {@link TaskMonitor}
	 * @return map of abbrCode -> abbr instance
	 * @throws IOException if error reading
	 * @throws CancelledException if cancelled
	 */
	public static Map<Integer, DWARFAbbreviation> readAbbreviations(BinaryReader reader,
			DWARFProgram prog, TaskMonitor monitor) throws IOException, CancelledException {
		Map<Integer, DWARFAbbreviation> result = new HashMap<>();

		// Read a list of abbreviations, terminated by a marker value that returns null from read()
		DWARFAbbreviation abbrev = null;
		while ((abbrev = DWARFAbbreviation.read(reader, prog, monitor)) != null) {
			monitor.checkCancelled();
			result.put(abbrev.getAbbreviationCode(), abbrev);
		}

		return result;
	}

	public DWARFAbbreviation(int abbreviationCode, int tagId, boolean hasChildren,
			AttrDef[] attributes) {
		this.abbreviationCode = abbreviationCode;
		this.tagId = tagId;
		this.tag = DWARFTag.of(tagId);
		this.hasChildren = hasChildren;
		this.attributes = attributes;
	}

	@Override
	public String toString() {
		return "%x:%s".formatted(abbreviationCode, getTagName());
	}

	/**
	 * Get the abbreviation code.
	 * @return the abbreviation code
	 */
	public int getAbbreviationCode() {
		return this.abbreviationCode;
	}

	/**
	 * Get the tag value.
	 * @return the tag value
	 */
	public DWARFTag getTag() {
		return this.tag;
	}

	public String getTagName() {
		return tag.name(tagId);
	}

	/**
	 * Checks to see if this abbreviation has any DIE children.
	 * @return true if this abbreviation has DIE children
	 */
	public boolean hasChildren() {
		return this.hasChildren;
	}

	/**
	 * Return a live list of the attributes.
	 * @return list of attributes
	 */
	public AttrDef[] getAttributes() {
		return attributes;
	}

	/**
	 * Return number of attribute values.
	 * 
	 * @return number of attribute values
	 */
	public int getAttributeCount() {
		return attributes.length;
	}

	/**
	 * Get the attribute at the given index.
	 * @param index index of the attribute
	 * @return attribute specification
	 */
	public AttrDef getAttributeAt(int index) {
		return this.attributes[index];
	}

	/**
	 * Get the attribute with the given attribute key.
	 * @param attributeId attribute key
	 * @return attribute specification
	 */
	public AttrDef findAttribute(DWARFAttribute attributeId) {
		for (AttrDef spec : this.attributes) {
			if (spec.getAttributeId() == attributeId) {
				return spec;
			}
		}
		return null;
	}

}
