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
package ghidra.app.emulator.memory;

import ghidra.pcode.memstate.*;
import ghidra.program.model.address.AddressSpace;

/// A kind of MemoryBank which retrieves its data from an underlying LoadImage
///
/// Any bytes requested on the bank which lie in the LoadImage are retrieved from
/// the LoadImage.  Other addresses in the space are filled in with zero.
/// This bank cannot be written to.
public class MemoryImage extends MemoryBank {

	private MemoryLoadImage loader; // The underlying LoadImage

	/// A MemoryImage needs everything a basic memory bank needs and is needs to know
	/// the underlying LoadImage object to forward read requests to.
	/// \param spc is the address space associated with the memory bank
	/// \param ws is the number of bytes in the preferred wordsize (must be power of 2)
	/// \param ps is the number of bytes in a page (must be power of 2)
	/// \param ld is the underlying LoadImage
	public MemoryImage(AddressSpace spc, boolean isBigEndian, int ps, MemoryLoadImage ld,
			MemoryFaultHandler faultHandler) {
		super(spc, isBigEndian, ps, faultHandler);
		loader = ld;
	}

	/// Retrieve an aligned page from the bank.  First an attempt is made to retrieve the
	/// page from the LoadImage, which may do its own zero filling.  If the attempt fails, the
	/// page is entirely filled in with zeros.
	@Override
	public MemoryPage getPage(long addr) {
		MemoryPage page = new MemoryPage(getPageSize());
		// Assume that -addr- is page aligned
		AddressSpace spc = getSpace();
		byte[] maskUpdate =
			loader.loadFill(page.data, getPageSize(), spc.getAddress(addr), 0, true);
		page.setInitialized(0, getPageSize(), maskUpdate);
		return page;
	}

	@Override
	protected void setPage(long addr, byte[] val, int skip, int size, int bufOffset) {
		AddressSpace spc = getSpace();
		loader.writeBack(val, size, spc.getAddress(addr), bufOffset);
	}

	@Override
	protected void setPageInitialized(long addr, boolean initialized, int skip, int size,
			int bufOffset) {
		// unsupported
	}

}
