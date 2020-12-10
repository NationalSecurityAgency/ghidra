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

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

public class SctlTargetSectionContainer
		extends DefaultTargetObject<SctlTargetSection, SctlTargetModule> {

	protected final SctlClient client;

	public SctlTargetSectionContainer(SctlTargetModule module) {
		super(module.client, module, "Sections", "SectionContainer");
		this.client = module.client;
	}

	protected void add(String name, Address start, long length) {
		if (length == 0) {
			Msg.trace(this, "Ignoring 0-length section: " + name);
			return;
		}

		AddressRange range;
		try {
			range = new AddressRangeImpl(start, length);
		}
		catch (AddressOverflowException e) {
			throw new IllegalArgumentException(e);
		}
		SctlTargetSection section = new SctlTargetSection(this, parent, name, range);
		changeElements(List.of(), List.of(section), "Fetched");
	}
}
