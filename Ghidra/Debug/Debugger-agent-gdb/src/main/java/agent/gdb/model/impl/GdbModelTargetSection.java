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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;

import agent.gdb.manager.GdbModuleSection;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSection;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(
	name = "Section",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetSection extends
		DefaultTargetObject<TargetObject, GdbModelTargetSectionContainer> implements TargetSection {

	public static final String VISIBLE_RANGE_ATTRIBUTE_NAME = "range";

	protected static String indexSection(GdbModuleSection section) {
		return section.getName();
	}

	protected static String keySection(GdbModuleSection section) {
		return PathUtils.makeKey(indexSection(section));
	}

	protected final GdbModelImpl impl;
	protected final GdbModuleSection section;

	protected final GdbModelTargetModule module;
	protected final AddressRange range;

	public GdbModelTargetSection(GdbModelTargetSectionContainer sections,
			GdbModelTargetModule module, GdbModuleSection section) {
		super(sections.impl, sections, keySection(section), "Section");
		this.impl = sections.impl;
		this.section = section;
		impl.addModelObject(section, this);

		this.module = module;
		this.range = doGetRange();
		this.changeAttributes(List.of(), List.of(), Map.of(
			MODULE_ATTRIBUTE_NAME, module,
			RANGE_ATTRIBUTE_NAME, range,
			VISIBLE_RANGE_ATTRIBUTE_NAME, range,
			DISPLAY_ATTRIBUTE_NAME, section.getName()),
			"Initialized");
	}

	@Override
	public GdbModelTargetModule getModule() {
		return module;
	}

	protected AddressRange doGetRange() {
		if (section.getVmaStart() == section.getVmaEnd()) {
			return null; // zero-length range
		}
		Address min = impl.space.getAddress(section.getVmaStart());
		// Ghidra ranges are inclusive at the end. GDB's are not.
		Address max = impl.space.getAddress(section.getVmaEnd() - 1);
		return new AddressRangeImpl(min, max);
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	@TargetAttributeType(name = VISIBLE_RANGE_ATTRIBUTE_NAME)
	public AddressRange getVisibleRange() {
		return range;
	}

	@Override
	public String getDisplay() {
		return section.getName();
	}
}
