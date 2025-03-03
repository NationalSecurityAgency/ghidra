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
package ghidra.app.plugin.core.debug.gui.modules;

import db.Transaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class SectionRow {
	private final TraceSection section;

	public SectionRow(TraceSection section) {
		this.section = section;
	}

	public TraceModule getModule() {
		return section.getModule();
	}

	public TraceSection getSection() {
		return section;
	}

	public void setName(String name) {
		try (Transaction tx = section.getTrace().openTransaction("Rename section")) {
			section.setName(0, name);
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Rename Section",
				"Section name is already taken by another in the same module");
		}
	}

	public String getName() {
		return section.getName(0);
	}

	public String getModuleName() {
		return section.getModule().getName(0);
	}

	public AddressRange getRange() {
		return section.getRange(0);
	}

	public Address getStart() {
		return section.getStart(0);
	}

	public Address getEnd() {
		return section.getEnd(0);
	}

	public long getLength() {
		return section.getRange(0).getLength();
	}
}
