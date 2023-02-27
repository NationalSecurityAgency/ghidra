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

import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

class FilteredMemoryState extends MemoryState {

	private MemoryAccessFilter filter;
	private boolean filterEnabled = true; // used to prevent filtering filter queries

	FilteredMemoryState(Language lang) {
		super(lang);
	}

	@Override
	public int getChunk(byte[] res, AddressSpace spc, long off, int size,
			boolean stopOnUnintialized) {
		int readLen = super.getChunk(res, spc, off, size, stopOnUnintialized);
		if (filterEnabled && filter != null) {
			filterEnabled = false;
			try {
				filter.filterRead(spc, off, readLen, res);
			}
			finally {
				filterEnabled = true;
			}
		}
		return readLen;
	}

	@Override
	public void setChunk(byte[] res, AddressSpace spc, long off, int size) {
		super.setChunk(res, spc, off, size);
		if (filterEnabled && filter != null) {
			filterEnabled = false;
			try {
				filter.filterWrite(spc, off, size, res);
			}
			finally {
				filterEnabled = true;
			}
		}
	}

	MemoryAccessFilter setFilter(MemoryAccessFilter filter) {
		MemoryAccessFilter oldFilter = this.filter;
		this.filter = filter;
		return oldFilter;
	}
}
