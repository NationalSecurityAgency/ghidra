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

import java.util.*;

import ghidra.app.util.bin.format.dwarf4.attribs.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFForm;

/**
 * Helper class to create mock DebugInfoEntry instances for use during junit tests.
 */
public class DIECreator {
	private static class AttrInfo {
		int attribute;
		DWARFForm form;
		DWARFAttributeValue value;

		public AttrInfo(int attribute, DWARFForm form, DWARFAttributeValue value) {
			this.attribute = attribute;
			this.form = form;
			this.value = value;
		}
	}

	private MockDWARFProgram dwarfProg;
	private int tag;
	private Map<Integer, AttrInfo> attributes = new HashMap<>();
	private DebugInfoEntry parent;

	public DIECreator(MockDWARFProgram dwarfProg, int tag) {
		this.dwarfProg = dwarfProg;
		this.tag = tag;
	}

	public DIECreator addString(int attribute, String value) {
		attributes.put(attribute,
			new AttrInfo(attribute, DWARFForm.DW_FORM_string, new DWARFStringAttribute(value)));
		return this;
	}

	public DIECreator addUInt(int attribute, long value) {
		attributes.put(attribute,
			new AttrInfo(attribute, DWARFForm.DW_FORM_udata, new DWARFNumericAttribute(value)));
		return this;
	}

	public DIECreator addInt(int attribute, long value) {
		attributes.put(attribute,
			new AttrInfo(attribute, DWARFForm.DW_FORM_sdata, new DWARFNumericAttribute(value)));

		return this;
	}

	public DIECreator addRef(int attribute, DebugInfoEntry die) {
		attributes.put(attribute, new AttrInfo(attribute, DWARFForm.DW_FORM_ref8,
			new DWARFNumericAttribute(die.getOffset())));

		return this;
	}

	public DIECreator addRef(int attribute, long offset) {
		attributes.put(attribute,
			new AttrInfo(attribute, DWARFForm.DW_FORM_ref8, new DWARFNumericAttribute(offset)));

		return this;
	}

	public DIECreator addBoolean(int attribute, boolean value) {
		attributes.put(attribute,
			new AttrInfo(attribute, DWARFForm.DW_FORM_flag, new DWARFBooleanAttribute(value)));

		return this;
	}

	public DIECreator addBlock(int attribute, int... intBytes) {
		byte[] bytes = new byte[intBytes.length];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) intBytes[i];
		}
		attributes.put(attribute,
			new AttrInfo(attribute, DWARFForm.DW_FORM_block1, new DWARFBlobAttribute(bytes)));
		return this;
	}

	DWARFAttributeSpecification[] makeAttrSpecArray() {
		DWARFAttributeSpecification[] attrSpecs =
			new DWARFAttributeSpecification[attributes.size()];
		List<AttrInfo> attrInfoList = new ArrayList<>(attributes.values());
		for (int i = 0; i < attrInfoList.size(); i++) {
			AttrInfo attrInfo = attrInfoList.get(i);
			attrSpecs[i] = new DWARFAttributeSpecification(attrInfo.attribute, attrInfo.form);
		}
		return attrSpecs;
	}

	public DIECreator setParent(DebugInfoEntry parent) {
		this.parent = parent;
		return this;
	}

	public DebugInfoEntry createRootDIE() {
		MockDWARFCompilationUnit cu = dwarfProg.getCurrentCompUnit();
		DWARFAbbreviation abbr = cu.createAbbreviation(makeAttrSpecArray(), tag);
		DebugInfoEntry die = dwarfProg.addDIE(abbr, null);

		int attrNum = 0;
		for (AttrInfo attrInfo : attributes.values()) {
			die.getAttributes()[attrNum++] = attrInfo.value;
		}

		return die;
	}

	public DebugInfoEntry create() {
		MockDWARFCompilationUnit cu = dwarfProg.getCurrentCompUnit();
		if (cu == null) {
			cu = dwarfProg.addCompUnit();
		}
		DWARFAbbreviation abbr = cu.createAbbreviation(makeAttrSpecArray(), tag);
		DebugInfoEntry die =
			dwarfProg.addDIE(abbr, parent != null ? parent : cu.getCompileUnitDIE());

		int attrNum = 0;
		for (AttrInfo attrInfo : attributes.values()) {
			die.getAttributes()[attrNum++] = attrInfo.value;
		}

		return die;
	}
}
