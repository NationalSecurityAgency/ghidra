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
package ghidra.app.plugin.core.debug.gui.memory;

import db.Transaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.memory.TraceMemoryRegion;

public class RegionRow {
	private final TraceMemoryRegion region;

	public RegionRow(TraceMemoryRegion region) {
		this.region = region;
	}

	public TraceMemoryRegion getRegion() {
		return region;
	}

	public void setName(String name) {
		try (Transaction tx = region.getTrace().openTransaction("Rename region")) {
			region.setName(0, name);
		}
	}

	public String getName() {
		return region.getName(0);
	}

	public AddressRange getRange() {
		return region.getRange(0);
	}

	public Address getMaxAddress() {
		return region.getMaxAddress(0);
	}

	public Address getMinAddress() {
		return region.getMinAddress(0);
	}

	public long getLength() {
		return region.getLength(0);
	}

	public void setRead(boolean read) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region read flag")) {
			region.setRead(0, read);
		}
	}

	public boolean isRead() {
		return region.isRead(0);
	}

	public void setWrite(boolean write) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region write flag")) {
			region.setWrite(0, write);
		}
	}

	public boolean isWrite() {
		return region.isWrite(0);
	}

	public void setExecute(boolean execute) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region execute flag")) {
			region.setExecute(0, execute);
		}
	}

	public boolean isExecute() {
		return region.isExecute(0);
	}

	public void setVolatile(boolean vol) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region volatile flag")) {
			region.setVolatile(0, vol);
		}
	}

	public boolean isVolatile() {
		return region.isVolatile(0);
	}
}
