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
package ghidra.app.emulator.state;

import ghidra.pcode.memstate.MemoryBank;
import ghidra.pcode.memstate.MemoryPageOverlay;
import ghidra.program.model.address.AddressSpace;

public class FilteredMemoryPageOverlay extends MemoryPageOverlay {

	private boolean writeBack;

	public FilteredMemoryPageOverlay(AddressSpace spc, MemoryBank ul, boolean writeBack) {
		super(spc, ul, ul.getMemoryFaultHandler());
		this.writeBack = writeBack;
	}

	@Override
	public void setChunk(long offset, int size, byte[] val) {
		super.setChunk(offset, size, val);
		if (writeBack) {
			underlie.setChunk(offset, size, val);
		}
	}

}
