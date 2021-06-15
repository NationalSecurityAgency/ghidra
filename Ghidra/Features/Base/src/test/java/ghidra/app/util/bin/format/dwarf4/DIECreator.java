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

import org.junit.Assert;

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

	private int tag;
	private Map<Integer, AttrInfo> attributes = new HashMap<>();
	private List<DebugInfoEntry> children = new ArrayList<>();
	private DebugInfoEntry parent;

	public DIECreator(int tag) {
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

	DWARFAbbreviation createAbbreviation(MockDWARFCompilationUnit cu) {
		DWARFAttributeSpecification[] attrSpecs =
			new DWARFAttributeSpecification[attributes.size()];
		ArrayList<AttrInfo> attrInfoList = new ArrayList<>(attributes.values());
		for (int i = 0; i < attrInfoList.size(); i++) {
			AttrInfo attrInfo = attrInfoList.get(i);
			attrSpecs[i] = new DWARFAttributeSpecification(attrInfo.attribute, attrInfo.form);
		}
		DWARFAbbreviation abbr = new DWARFAbbreviation(cu.getCodeToAbbreviationMap().size(), tag,
			!children.isEmpty(), attrSpecs);
		return abbr;
	}

	public DIECreator setParent(DebugInfoEntry parent) {
		this.parent = parent;
		return this;
	}

	public DebugInfoEntry create(MockDWARFCompilationUnit cu) {
		DWARFAbbreviation abbr = createAbbreviation(cu);
		cu.getCodeToAbbreviationMap().put(abbr.getAbbreviationCode(), abbr);
		DebugInfoEntry die =
			new DebugInfoEntry(cu, cu.getStartOffset() + cu.getMockEntryCount(), abbr);

		int attrNum = 0;
		for (AttrInfo attrInfo : attributes.values()) {
			die.getAttributes()[attrNum++] = attrInfo.value;
		}

		for (DebugInfoEntry childDIE : children) {
			Assert.assertTrue(childDIE.getCompilationUnit() == cu);
			die.addChild(childDIE);
		}

		if (parent == null) {
			parent = cu.getCompileUnitDIE();
		}
		if (parent != null) {
			die.setParent(parent);
			Assert.assertTrue(parent.getCompilationUnit() == cu);
			parent.addChild(die);
		}
		cu.addMockEntry(die);

		return die;
	}
}
