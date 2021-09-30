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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;

import SWIG.*;
import agent.lldb.model.iface2.LldbModelTargetModuleSection;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(
	name = "Section",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class LldbModelTargetModuleSectionImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModuleSection {

	protected static String keySection(SBSection section) {
		return PathUtils.makeKey(section.GetName());
	}

	protected static final String OBJFILE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "objfile";

	protected AddressRange range;

	public LldbModelTargetModuleSectionImpl(LldbModelTargetModuleSectionContainerImpl sections,
			SBSection section) {
		super(sections.getModel(), sections, keySection(section), section, "Section");

		AddressSpace space = getModel().getAddressSpace("ram");
		Address min = space.getAddress(0L);
		SBTarget currentSession = getManager().getCurrentSession();
		long lval = section.GetLoadAddress(currentSession).longValue();
		if (lval != -1) {
			min = space.getAddress(lval);
		} 
		// Ghidra ranges are not inclusive at the end.
		long sz = section.GetFileByteSize().longValue();
		Address max = min.add(sz);
		range = new AddressRangeImpl(min, max);

		changeAttributes(List.of(), List.of(), Map.of( //
			MODULE_ATTRIBUTE_NAME, sections.getParent(), //
			RANGE_ATTRIBUTE_NAME, range, //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			"Address", min, //
			"File Offset", section.GetFileOffset().toString(16), //
			"Size", Long.toHexString(sz), //
			"Permissions", section.GetPermissions() //
		), "Initialized");
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBSection section = (SBSection) getModelObject();
		section.GetDescription(stream);
		return stream.GetData();
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

}
