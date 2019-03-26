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

import ghidra.program.model.address.AddressSpace;

public abstract class MemoryBank {

	private final int pagesize; ///< Number of bytes in an aligned page access
	private final AddressSpace space; ///< The address space associated with this memory
	private final boolean isBigEndian;
	private final int initializedMaskSize; // number of bytes required for uninitialized mask

	protected final MemoryFaultHandler faultHandler;

	/**
	 * A MemoryBank must be associated with a specific address space, have a preferred or natural
	 * pagesize.  The pagesize must be a power of 2.
	 * @param spc is the associated address space
	 * @param isBigEndian memory endianess
	 * @param ps ps is the number of bytes in a page (must be a power of 2)
	 * @param faultHandler memory fault handler
	 */
	public MemoryBank(AddressSpace spc, boolean isBigEndian, int ps, MemoryFaultHandler faultHandler) {
		space = spc;
		pagesize = ps;
		this.isBigEndian = isBigEndian;
		this.faultHandler = faultHandler;
		initializedMaskSize = (ps + 7) / 8;
	}

	/**
	 * @return memory fault handler (may be null)
	 */
	public MemoryFaultHandler getMemoryFaultHandler() {
		return faultHandler;
	}

	/**
	 * @return true if memory bank is big endian
	 */
	public boolean isBigEndian() {
		return isBigEndian;
	}

	/**
	 * A MemoryBank is instantiated with a \e natural page size. Requests for large chunks of data
	 * may be broken down into units of this size.
	 * @return the number of bytes in a page.
	 */
	public int getPageSize() {
		return pagesize;
	}

	/**
	 * @return the size of a page initialized mask in bytes.  Each bit within the
	 * mask corresponds to a data byte within a page.
	 */
	public int getInitializedMaskSize() {
		return initializedMaskSize;
	}

	/**
	 * @return the AddressSpace associated with this bank.
	 */
	public AddressSpace getSpace() {
		return space;
	}

	/// This routine only retrieves data from a single \e page in the memory bank. Bytes need not
	/// be retrieved from the exact start of a page, but all bytes must come from \e one page.
	/// A page is a fixed number of bytes, and the address of a page is always aligned based
	/// on that number of bytes.  This routine may be overridden for a page based implementation
	/// of the MemoryBank.  The default implementation retrieves the page as aligned words
	/// using the find method.
	/// \param addr is the \e aligned offset of the desired page
	/// \param res is a pointer to where fetched data should be written
	/// \param skip is the offset \e into \e the \e page to get the bytes from
	/// \param size is the number of bytes to retrieve
	/// \param ignoreFault if true ignore fault and return 
	//protected abstract void getPage(long addr,MemoryPage res,int skip,int size, int bufOffset);

	protected abstract MemoryPage getPage(long addr);

	/// This routine writes data only to a single \e page of the memory bank. Bytes need not be
	/// written to the exact start of the page, but all bytes must be written to only one page
	/// when using this routine. A page is a
	/// fixed number of bytes, and the address of a page is always aligned based on this size.
	/// This routine may be overridden for a page based implementation of the MemoryBank. The
	/// default implementation writes the page as a sequence of aligned words, using the
	/// insert method.
	/// \param addr is the \e aligned offset of the desired page
	/// \param val is a pointer to the bytes to be written into the page
	/// \param skip is the offset \e into \e the \e page where bytes will be written
	/// \param size is the number of bytes to be written
	/// \param bufOffset the offset in val from which to get the bytes
	protected abstract void setPage(long addr, byte[] val, int skip, int size, int bufOffset);

	/// This routine marks a range within a single \e page of the memory bank as initialized or 
	/// uninitialized. A page is a
	/// fixed number of bytes, and the address of a page is always aligned based on this size.
	/// This routine may be overridden for a page based implementation of the MemoryBank. The
	/// default implementation writes the page as a sequence of aligned words, using the
	/// insert method.
	/// \param addr is the \e aligned offset of the desired page
	/// \param initialized true if range should be marked as initialized, false if uninitialized
	/// \param skip is the offset \e into \e the \e page where bytes will be written
	/// \param size is the number of bytes to be written
	/// \param bufOffset the offset in val from which to get the bytes
	protected abstract void setPageInitialized(long addr, boolean initialized, int skip, int size,
			int bufOffset);

	/// This the most general method for writing a sequence of bytes into the memory bank.
	/// The initial offset and page writes will be wrapped within the address space.
	/// \param offset is the start of the byte range to be written.  This offset will be wrapped
	/// within the space 
	/// \param size is the number of bytes to write
	/// \param val is a pointer to the sequence of bytes to be written into the bank
	public void setChunk(long offset, int size, byte[] val) {
		int cursize;
		int count;
		long pagemask = (pagesize - 1);
		long offalign;
		int skip;
		int bufOffset = 0;

		count = 0;
		while (count < size) {
			cursize = pagesize;
			offset = space.truncateOffset(offset);
			offalign = offset & ~pagemask;
			skip = 0;
			if (offalign != offset) {
				skip = (int) (offset - offalign);
				cursize -= skip;
			}
			if (size - count < cursize)
				cursize = size - count;
			setPage(offalign, val, skip, cursize, bufOffset);
			count += cursize;
			offset += cursize;
			bufOffset += cursize;
		}
	}

	/// This method allows ranges of bytes to marked as initialized or not.
	/// There is no restriction on the offset to write to or the number of bytes to be written,
	/// except that the range must be contained in the address space.
	/// \param offset is the start of the byte range to be written
	/// \param size is the number of bytes to write
	/// \param initialized indicates if the range should be marked as initialized or not
	public void setInitialized(long offset, int size, boolean initialized) {
		int cursize;
		int count;
		long pagemask = (pagesize - 1);
		long offalign;
		int skip;
		int bufOffset = 0;

		count = 0;
		while (count < size) {
			cursize = pagesize;
			offalign = offset & ~pagemask;
			skip = 0;
			if (offalign != offset) {
				skip = (int) (offset - offalign);
				cursize -= skip;
			}
			if (size - count < cursize)
				cursize = size - count;
			setPageInitialized(offalign, initialized, skip, cursize, bufOffset);
			count += cursize;
			offset += cursize;
			bufOffset += cursize;
		}
	}

	/// This is the most general method for reading a sequence of bytes from the memory bank.
	/// There is no restriction on the offset or the number of bytes to read, except that the
	/// range must be contained in the address space.
	/// \param offset is the start of the byte range to read
	/// \param size is the number of bytes to read
	/// \param res is a pointer to where the retrieved bytes should be stored
	/// \param stopOnUnintialized if true a partial read is permitted and returned size may be 
	///        smaller than size requested if uninitialized data is encountered.
	/// \return number of bytes actually read
	public int getChunk(long addrOffset, int size, byte[] res, boolean stopOnUnintialized) {
		int cursize, count;
		long pagemask = (pagesize - 1);
		long offalign;
		int skip;
		int bufOffset = 0;

		addrOffset = space.truncateOffset(addrOffset);

		count = 0;
		while (count < size) {
			cursize = pagesize;
			offalign = addrOffset & ~pagemask;
			skip = 0;
			if (offalign != addrOffset) {
				skip = (int) (addrOffset - offalign);
				cursize -= skip;
			}
			if (size - count < cursize)
				cursize = size - count;

			MemoryPage page = getPage(offalign);

			// Read initialized data which is available
			int initializedByteCount = page.getInitializedByteCount(skip, cursize);
			System.arraycopy(page.data, skip, res, bufOffset, initializedByteCount);
			count += initializedByteCount;

			long nextAddrOffset = space.truncateOffset(addrOffset + initializedByteCount);
			addrOffset += initializedByteCount;
			bufOffset += initializedByteCount;
			cursize -= initializedByteCount;

			if (cursize != 0) {
				// Handle incomplete read from current page 
				skip += initializedByteCount;
				if (faultHandler.uninitializedRead(getSpace().getAddress(offalign + skip), cursize,
					page.data, skip)) {
					page.setInitialized(skip, cursize);
				}
				else if (stopOnUnintialized) {
					return count;
				}
				System.arraycopy(page.data, skip, res, bufOffset, cursize);
				count += cursize;

				nextAddrOffset = space.truncateOffset(nextAddrOffset + cursize);
				addrOffset += cursize;
				bufOffset += cursize;
			}

			// stop if wrapped midway
			if (addrOffset < 0) {
				if (nextAddrOffset > 0) {
					break;
				}
			}
			else if (nextAddrOffset < addrOffset) {
				break;
			}
		}
		return count;
	}

	/// This is a static convenience routine for decoding a value from a sequence of bytes depending
	/// on the desired endianness
	/// \param ptr is the pointer to the bytes to decode
	/// \param size is the number of bytes
	/// \param bigendian is \b true if the bytes are encoded in big endian form
	/// \return the decoded value
	public static long constructValue(byte[] ptr, int offset, int size, boolean bigendian) {
		long res = 0;

		if (bigendian) {
			for (int i = 0; i < size; ++i) {
				res <<= 8;
				res |= ptr[i + offset] & 0xffL;
			}
		}
		else {
			for (int i = size - 1; i >= 0; --i) {
				res <<= 8;
				res |= ptr[i + offset] & 0xffL;
			}
		}
		return res;
	}

	/// This is a static convenience routine for encoding bytes from a given value, depending on
	/// the desired endianness
	/// \param ptr is a pointer to the location to write the encoded bytes
	/// \param val is the value to be encoded
	/// \param size is the number of bytes to encode
	/// \param bigendian is \b true if a big endian encoding is desired
	public static void deconstructValue(byte[] ptr, int offset, long val, int size,
			boolean bigendian) {
		if (bigendian) {
			for (int i = size - 1; i >= 0; --i) {
				ptr[i + offset] = (byte) (val & 0xff);
				val >>= 8;
			}
		}
		else {
			for (int i = 0; i < size; ++i) {
				ptr[i + offset] = (byte) (val & 0xff);
				val >>= 8;
			}
		}
	}

}
