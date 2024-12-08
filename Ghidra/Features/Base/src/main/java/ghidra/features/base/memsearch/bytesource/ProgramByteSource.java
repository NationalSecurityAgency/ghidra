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
package ghidra.features.base.memsearch.bytesource;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * {@link AddressableByteSource} implementation for a Ghidra {@link Program}
 */
public class ProgramByteSource implements AddressableByteSource {

	private Memory memory;

	public ProgramByteSource(Program program) {
		memory = program.getMemory();
	}

	@Override
	public int getBytes(Address address, byte[] bytes, int length) {
		try {
			return memory.getBytes(address, bytes, 0, length);
		}
		catch (MemoryAccessException e) {
			return 0;
		}
	}

	@Override
	public List<SearchRegion> getSearchableRegions() {
		return ProgramSearchRegion.ALL;
	}

	@Override
	public void invalidate() {
		// nothing to do in the static case
	}

}
