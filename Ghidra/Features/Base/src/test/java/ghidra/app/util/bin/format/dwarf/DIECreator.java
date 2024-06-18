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

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;

import java.util.*;

import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef;

/**
 * Helper class to create mock DebugInfoEntry instances for use during junit tests.
 */
public class DIECreator {
	record AttrInfo(DWARFAttribute attribute, AttrDef spec, DWARFAttributeValue value) {}

	private MockDWARFProgram dwarfProg;
	private DWARFTag tag;
	private Map<DWARFAttribute, AttrInfo> attributes = new HashMap<>();
	private DebugInfoEntry parent;

	public DIECreator(MockDWARFProgram dwarfProg, DWARFTag tag) {
		this.dwarfProg = dwarfProg;
		this.tag = tag;
	}

	private void add(AttrDef attrSpec, DWARFAttributeValue attrVal) {
		attributes.put(attrSpec.getAttributeId(),
			new AttrInfo(attrSpec.getAttributeId(), attrSpec, attrVal));
	}

	public DIECreator addString(DWARFAttribute attribute, String value) {
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_string, 0);
		add(attrSpec, new DWARFStringAttribute(value, attrSpec));
		return this;
	}

	public DIECreator addUInt(DWARFAttribute attribute, long value) {
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_udata, 0);
		add(attrSpec, new DWARFNumericAttribute(value, attrSpec));
		return this;
	}

	public DIECreator addInt(DWARFAttribute attribute, long value) {
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_sdata, 0);
		add(attrSpec, new DWARFNumericAttribute(value, attrSpec));
		return this;
	}

	public DIECreator addRef(DWARFAttribute attribute, DebugInfoEntry die) {
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_ref8, 0);
		add(attrSpec, new DWARFNumericAttribute(die.getOffset(), attrSpec));
		return this;
	}

	public DIECreator addRef(DWARFAttribute attribute, long offset) {
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_ref8, 0);
		add(attrSpec, new DWARFNumericAttribute(offset, attrSpec));
		return this;
	}

	public DIECreator addBoolean(DWARFAttribute attribute, boolean value) {
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_flag, 0);
		add(attrSpec, new DWARFBooleanAttribute(value, attrSpec));
		return this;
	}

	public DIECreator addBlock(DWARFAttribute attribute, int... intBytes) {
		byte[] bytes = new byte[intBytes.length];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) intBytes[i];
		}
		AttrDef attrSpec = new AttrDef(attribute, attribute.getId(), DW_FORM_block1, 0);
		add(attrSpec, new DWARFBlobAttribute(bytes, attrSpec));
		return this;
	}

	AttrDef[] makeAttrSpecArray() {
		AttrDef[] attrSpecs = new AttrDef[attributes.size()];
		List<AttrInfo> attrInfoList = new ArrayList<>(attributes.values());
		for (int i = 0; i < attrInfoList.size(); i++) {
			AttrInfo attrInfo = attrInfoList.get(i);
			attrSpecs[i] = attrInfo.spec;
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
			die.setAttributeValue(attrNum++, attrInfo.value);
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
			die.setAttributeValue(attrNum++, attrInfo.value);
		}

		return die;
	}
}
