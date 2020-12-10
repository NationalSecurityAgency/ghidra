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
package ghidra.dbg.sctl.client;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressRange;

public class SctlTargetSection extends DefaultTargetObject<TargetObject, TargetObject>
		implements TargetSection<SctlTargetSection> {

	protected static String keySection(String name) {
		return PathUtils.makeKey(indexSection(name));
	}

	protected static String indexSection(String name) {
		return name;
	}

	protected final SctlClient client;

	protected final SctlTargetModule module;
	protected final AddressRange range;

	public SctlTargetSection(SctlTargetSectionContainer sections, SctlTargetModule module,
			String name, AddressRange range) {
		super(sections.client, sections, keySection(name), "Section");
		this.client = sections.client;

		this.module = module;
		this.range = range;

		changeAttributes(List.of(), Map.of( //
			MODULE_ATTRIBUTE_NAME, module, //
			RANGE_ATTRIBUTE_NAME, range //
		), "Initialized");
	}

	@Override
	public TypedTargetObjectRef<? extends TargetModule<?>> getModule() {
		return module;
	}

	@Override
	public AddressRange getRange() {
		return range;
	}
}
