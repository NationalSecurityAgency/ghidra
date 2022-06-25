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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.manager.FridaSection;
import agent.frida.model.iface2.FridaModelTargetModuleSection;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;

@TargetObjectSchemaInfo(
	name = "Section",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetModuleSectionImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetModuleSection {

	protected static String keySection(FridaSection section) {
		return PathUtils.makeKey(section.getRangeAddress());
	}

	protected static final String OBJFILE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "objfile";

	protected AddressRange range;

	public FridaModelTargetModuleSectionImpl(FridaModelTargetModuleSectionContainerImpl sections,
			FridaSection section) {
		super(sections.getModel(), sections, keySection(section), section, "Section");

		AddressSpace space = getModel().getAddressSpace("ram");
		Address min = space.getAddress(0L);
		long lval = Long.decode(section.getRangeAddress());
		if (lval != -1) {
			min = space.getAddress(lval);
		} 
		// Ghidra ranges are not inclusive at the end.
		long sz = section.getRangeSize().longValue();
		Address max = min.add(sz);
		range = new AddressRangeImpl(min, max);
		if (range != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				RANGE_ATTRIBUTE_NAME, range //
			), "Initialized");
		}

		changeAttributes(List.of(), List.of(), Map.of( //
			MODULE_ATTRIBUTE_NAME, sections.getParent(), //
			DISPLAY_ATTRIBUTE_NAME, getDescription(2), //
			"Address", min, //
			"File Offset", section.getFileOffset(), //
			"Size", Long.toHexString(sz), //
			"Permissions", section.getProtection() //
		), "Initialized");
	}

	public String getDescription(int level) {
		FridaSection section = (FridaSection) getModelObject();
		String description = section.getRangeAddress();
		if (level > 0) {
			description += " " + section.getProtection();
		}
		if (level > 1) {
			description += " " + Long.toHexString(section.getFileOffset());
		}
		if (level > 2) {
			description += " " + section.getFilePath();
		}
		return description;
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

}
