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
package ghidra.pcode.memstate;

import generic.stl.ComparableMapSTL;
import generic.stl.MapSTL;
import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.address.AddressSpace;

public class UniqueMemoryBank extends MemoryBank {

	protected MapSTL<Long, byte[]> map = new ComparableMapSTL<Long, byte[]>();

	public UniqueMemoryBank(AddressSpace spc, boolean isBigEndian) {
		super(spc, isBigEndian, 0, null);
	}

	@Override
	protected MemoryPage getPage(long addr) {
		throw new UnsupportedOperationException("UniqueMemoryBank does not support paging");
	}

	@Override
	protected void setPage(long addr, byte[] val, int skip, int size, int bufOffset) {
		throw new UnsupportedOperationException("UniqueMemoryBank does not support paging");
	}

	@Override
	protected void setPageInitialized(long addr, boolean initialized, int skip, int size,
			int bufOffset) {
		throw new UnsupportedOperationException("UniqueMemoryBank does not support paging");
	}

	@Override
	public int getChunk(long addrOffset, int size, byte[] res, boolean ignoreFault) {
		byte[] value = map.get(addrOffset);
		if (value == null) {
			throw new LowlevelError("Unique value read before written: 0x" +
					Long.toHexString(addrOffset));
		}
		if (value.length != size) {
			throw new LowlevelError("Unique value size mismatch: 0x" + Long.toHexString(addrOffset));
		}
		System.arraycopy(value, 0, res, 0, size);
		return size;
	}

	@Override
	public void setChunk(long offset, int size, byte[] val) {
		byte[] value = new byte[size];
		System.arraycopy(val, 0, value, 0, size);
		map.put(offset, value);
	}

	/**
	 * Clear unique storage at the start of an instruction
	 */
	public void clear() {
		map.clear();
	}

}
