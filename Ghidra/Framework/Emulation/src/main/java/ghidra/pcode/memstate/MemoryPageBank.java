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

import generic.stl.*;
import ghidra.program.model.address.AddressSpace;

public class MemoryPageBank extends MemoryBank {

	protected MapSTL<Long, MemoryPage> page = new ComparableMapSTL<>();

	public MemoryPageBank(AddressSpace spc, boolean isBigEndian, int ps,
			MemoryFaultHandler faultHandler) {
		super(spc, isBigEndian, ps, faultHandler);
	}

	@Override
	protected MemoryPage getPage(long addr) {
		IteratorSTL<Pair<Long, MemoryPage>> iter;
		iter = page.find(addr);
		if (iter.equals(page.end())) {
			int size = getPageSize();
			MemoryPage pageptr = new MemoryPage(size);
			page.add(addr, pageptr);
			pageptr.setUninitialized();
			return pageptr;
		}
		return (iter.get()).second;
	}

	@Override
	protected void setPage(long addr, byte[] val, int skip, int size, int bufOffset) {
		if (size == getPageSize() && bufOffset == 0) {
			page.put(addr, new MemoryPage(val));
			return;
		}
		MemoryPage pageptr = getPage(addr);
		System.arraycopy(val, bufOffset, pageptr.data, skip, size);
		pageptr.setInitialized(skip, size);
	}

	@Override
	protected void setPageInitialized(long addr, boolean initialized, int skip, int size,
			int bufOffset) {

		MemoryPage pageptr;
		IteratorSTL<Pair<Long, MemoryPage>> iter;
		iter = page.find(addr);
		if (iter.equals(page.end())) {
			if (!initialized) {
				return;
			}
			int pagesize = getPageSize();
			pageptr = new MemoryPage(pagesize);
			page.add(addr, pageptr);
		}
		else {
			pageptr = (iter.get()).second;

		}
		if (size == getPageSize() && bufOffset == 0) {
			if (initialized) {
				pageptr.setInitialized();
			}
			else {
				pageptr.setUninitialized();
			}
		}
		else if (initialized) {
			pageptr.setInitialized(skip, size);
		}
		else {
			pageptr.setUninitialized(skip, size);
		}

	}

}
