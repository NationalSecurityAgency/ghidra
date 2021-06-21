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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFChildren;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.*;

/**
 * This class represents the 'schema' for a DWARF DIE record.
 * <p>
 * A raw DWARF DIE record specifies its abbreviation code (pointing to an instance of
 * this class) and the corresponding DWARFAbbreviation instance has the information
 * about how the raw DIE is laid out. 
 */
public class DWARFAbbreviation
{
	private final int abbreviationCode;
	private final int tag;
	private final boolean hasChildren;
	private final DWARFAttributeSpecification[] attributes;

	public static DWARFAbbreviation read(BinaryReader reader, DWARFProgram prog,
			TaskMonitor monitor)
			throws IOException, CancelledException {

		int ac = LEB128.readAsUInt32(reader);
		if (ac == 0) {
			return null;
		}
		int tag = LEB128.readAsUInt32(reader);
		DWARFChildren hasChildren = DWARFChildren.find((int) reader.readNextByte());

		// Read each attribute specification until attribute and its value is 0
		List<DWARFAttributeSpecification> tmpAttrSpecs = new ArrayList<>();
		DWARFAttributeSpecification attr;
		while ((attr = DWARFAttributeSpecification.read(reader)) != null) {
			monitor.checkCanceled();
			tmpAttrSpecs.add(prog.internAttributeSpec(attr));
		}
		DWARFAttributeSpecification[] attrSpecArray =
			tmpAttrSpecs.toArray(new DWARFAttributeSpecification[tmpAttrSpecs.size()]);

		DWARFAbbreviation result = new DWARFAbbreviation(ac, tag,
			hasChildren == DWARFChildren.DW_CHILDREN_yes, attrSpecArray);

		return result;
	}

	public static Map<Integer, DWARFAbbreviation> readAbbreviations(BinaryReader reader,
			DWARFProgram prog, TaskMonitor monitor) throws IOException, CancelledException {
		Map<Integer, DWARFAbbreviation> result = new HashMap<>();

		// Read all abbreviations for this compilation unit and add to a map
		DWARFAbbreviation abbrev = null;
		while ((abbrev = DWARFAbbreviation.read(reader, prog, monitor)) != null) {
			monitor.checkCanceled();
			result.put(abbrev.getAbbreviationCode(), abbrev);
		}

		return result;
	}

	public DWARFAbbreviation(int abbreviationCode, int tag, boolean hasChildren,
			DWARFAttributeSpecification[] attributes) {
		this.abbreviationCode = abbreviationCode;
		this.tag = tag;
		this.hasChildren = hasChildren;
		this.attributes = attributes;
	}

	@Override
	public String toString()
	{
		return Integer.toHexString(getAbbreviationCode()) + ":" +
			DWARFUtil.toString(DWARFTag.class, getTag());
	}

	/**
	 * Get the abbreviation code.
	 * @return the abbreviation code
	 */
	public int getAbbreviationCode()
	{
		return this.abbreviationCode;
	}
	
	/**
	 * Get the tag value.
	 * @return the tag value
	 */
	public int getTag() {
		return this.tag;
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
	public DWARFAttributeSpecification[] getAttributes() {
		return attributes;
	}
	
	public int getAttributeCount() {
		return attributes.length;
	}

	/**
	 * Get the attribute at the given index.
	 * @param index index of the attribute
	 * @return attribute specification
	 */
	public DWARFAttributeSpecification getAttributeAt(int index) {
		return this.attributes[index];
	}
	
	/**
	 * Get the attribute with the given attribute key.
	 * @param attribute attribute key
	 * @return attribute specification
	 */
	public DWARFAttributeSpecification findAttribute(int attribute) {
		for(DWARFAttributeSpecification spec : this.attributes) {
			if(spec.getAttribute() == attribute) {
				return spec;
			}
		}
		return null;
	}
}
