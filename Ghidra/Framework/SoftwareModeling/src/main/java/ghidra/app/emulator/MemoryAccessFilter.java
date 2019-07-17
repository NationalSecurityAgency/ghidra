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
package ghidra.app.emulator;

import ghidra.program.model.address.AddressSpace;

public abstract class MemoryAccessFilter {

	private MemoryAccessFilter prevFilter;
	private MemoryAccessFilter nextFilter;
	
	protected Emulator emu;
	
	private boolean filterOnExecutionOnly = true;
	
	final void filterRead(AddressSpace spc, long off, int size, byte [] values) {
		if (filterOnExecutionOnly() && !emu.isExecuting()) return; // do not filter idle queries
		processRead(spc, off, size, values);
		if (nextFilter != null) {
			nextFilter.filterRead(spc, off, size, values);
		}
	}
	
	protected abstract void processRead(AddressSpace spc, long off, int size, byte[] values);

	final void filterWrite(AddressSpace spc, long off, int size, byte [] values) {
		if (filterOnExecutionOnly() && !emu.isExecuting()) return; // do not filter idle queries
		processWrite(spc, off, size, values);
		if (nextFilter != null) {
			nextFilter.filterWrite(spc, off, size, values);
		}
	}

	protected abstract void processWrite(AddressSpace spc, long off, int size, byte[] values);

	final void addFilter(Emulator emu) {
		this.emu = emu;
		nextFilter = emu.getFilteredMemState().setFilter(this);
		if (nextFilter != null) {
			nextFilter.prevFilter = this;
		}
	}
	
	/**
	 * Dispose this filter which will cause it to be removed from the memory state.
	 * If overriden, be sure to invoke super.dispose().
	 */
	public void dispose() {
		if (nextFilter != null) {
			nextFilter.prevFilter = prevFilter;
		}
		if (prevFilter != null) {
			prevFilter.nextFilter = nextFilter;
		}
		else {
			emu.getFilteredMemState().setFilter(nextFilter);
		}
	}

	public boolean filterOnExecutionOnly() {
		return filterOnExecutionOnly;
	}

	public void setFilterOnExecutionOnly(boolean filterOnExecutionOnly) {
		this.filterOnExecutionOnly = filterOnExecutionOnly;
	}
	
//	public void compare(String id);
//	public void clear();
//	public void updateFlags(String id);

}
