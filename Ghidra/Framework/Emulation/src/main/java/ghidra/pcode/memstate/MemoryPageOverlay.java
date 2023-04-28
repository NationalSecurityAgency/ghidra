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

import generic.stl.IteratorSTL;
import generic.stl.Pair;
import ghidra.program.model.address.AddressSpace;

/// \brief Memory bank that overlays some other memory bank, using a "copy on write" behavior.
///
/// Pages are copied from the underlying object only when there is
/// a write. The underlying access routines are overridden to make optimal use
/// of this page implementation.  The underlying memory bank can be a \b null pointer
/// in which case, this memory bank behaves as if it were initially filled with zeros.
public class MemoryPageOverlay extends MemoryPageBank {
	
	protected MemoryBank underlie;		// underlying memory object
	
	/// A page overlay memory bank needs all the parameters for a generic memory bank
	/// and it needs to know the underlying memory bank being overlayed.
	/// \param spc is the address space associated with the memory bank
	/// \param ul is the underlying MemoryBank
	public MemoryPageOverlay(AddressSpace spc, MemoryBank ul, MemoryFaultHandler faultHandler) {
		super(spc,ul.isBigEndian(),ul.getPageSize(),faultHandler);
		underlie = ul;
	}

	@Override
	protected MemoryPage getPage(long addr) {
		IteratorSTL<Pair<Long, MemoryPage>> iter;
		iter = page.find(addr);
		if (iter.equals(page.end())) {
			MemoryPage pageptr;
			if (underlie == null) {
				int size = getPageSize();
				pageptr = new MemoryPage(size);
				for(int i=0;i<size;++i) {
					pageptr.data[i] = 0;
				}
				pageptr.setUninitialized();
				return pageptr;
			}
			// defer to underlie memory bank
			pageptr = underlie.getPage(addr);
			page.add(addr, pageptr);
			return pageptr;
		}
		return (iter.get()).second;
	}

}
