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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;

import agent.dbgeng.manager.DbgModuleSection;
import agent.dbgeng.model.iface2.DbgModelTargetModuleSection;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(name = "Section", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetModuleSectionImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetModuleSection {
	protected static final String OBJFILE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "objfile";

	protected AddressRangeImpl range;

	public DbgModelTargetModuleSectionImpl(DbgModelTargetModuleSectionContainerImpl sections,
			DbgModuleSection section) {
		super(sections.getModel(), sections, section.getName(), "Section");
		this.getModel().addModelObject(section, this);

		AddressSpace space = getModel().getAddressSpace("ram");
		Address min = space.getAddress(section.getStart());
		// Ghidra ranges are not inclusive at the end.
		Address max = space.getAddress(section.getStart() + section.getSize() - 1);
		range = new AddressRangeImpl(min, max);

		changeAttributes(List.of(), List.of(), Map.of( //
			MODULE_ATTRIBUTE_NAME, sections.getParent(), //
			RANGE_ATTRIBUTE_NAME, range, //
			DISPLAY_ATTRIBUTE_NAME, section.getName() //
		), "Initialized");
	}

	@TargetAttributeType(name = RANGE_ATTRIBUTE_NAME)
	@Override
	public AddressRange getRange() {
		return range;
	}

}
