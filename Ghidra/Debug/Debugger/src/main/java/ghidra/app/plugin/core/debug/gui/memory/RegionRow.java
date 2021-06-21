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

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.database.UndoableTransaction;

public class RegionRow {
	private final TraceMemoryRegion region;

	public RegionRow(TraceMemoryRegion region) {
		this.region = region;
	}

	public TraceMemoryRegion getRegion() {
		return region;
	}

	public void setName(String name) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(region.getTrace(), "Renamed region", true)) {
			region.setName(name);
			tid.commit();
		}
	}

	public String getName() {
		return region.getName();
	}

	public Range<Long> getLifespan() {
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
		try (UndoableTransaction tid =
			UndoableTransaction.start(region.getTrace(), "Toggle region read flag", true)) {
			region.setRead(read);
		}
	}

	public boolean isRead() {
		return region.isRead();
	}

	public void setWrite(boolean write) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(region.getTrace(), "Toggle region write flag", true)) {
			region.setWrite(write);
		}
	}

	public boolean isWrite() {
		return region.isWrite();
	}

	public void setExecute(boolean execute) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(region.getTrace(), "Toggle region execute flag", true)) {
			region.setExecute(execute);
		}
	}

	public boolean isExecute() {
		return region.isExecute();
	}

	public void setVolatile(boolean vol) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(region.getTrace(), "Toggle region volatile flag", true)) {
			region.setVolatile(vol);
		}
	}

	public boolean isVolatile() {
		return region.isVolatile();
	}
}
