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
import ghidra.trace.model.Lifespan;
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
			region.setName(name);
		}
	}

	public String getName() {
		return region.getName();
	}

	public Lifespan getLifespan() {
		return region.getLifespan();
	}

	public long getCreatedSnap() {
		return region.getCreationSnap();
	}

	public String getDestroyedSnap() {
		long snap = region.getDestructionSnap();
		return snap == Long.MAX_VALUE ? "" : Long.toString(snap);
	}

	public AddressRange getRange() {
		return region.getRange();
	}

	public Address getMaxAddress() {
		return region.getMaxAddress();
	}

	public Address getMinAddress() {
		return region.getMinAddress();
	}

	public long getLength() {
		return region.getLength();
	}

	public void setRead(boolean read) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region read flag")) {
			region.setRead(read);
		}
	}

	public boolean isRead() {
		return region.isRead();
	}

	public void setWrite(boolean write) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region write flag")) {
			region.setWrite(write);
		}
	}

	public boolean isWrite() {
		return region.isWrite();
	}

	public void setExecute(boolean execute) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region execute flag")) {
			region.setExecute(execute);
		}
	}

	public boolean isExecute() {
		return region.isExecute();
	}

	public void setVolatile(boolean vol) {
		try (Transaction tx =
			region.getTrace().openTransaction("Toggle region volatile flag")) {
			region.setVolatile(vol);
		}
	}

	public boolean isVolatile() {
		return region.isVolatile();
	}
}
