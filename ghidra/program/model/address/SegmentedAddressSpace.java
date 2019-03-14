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
package ghidra.program.model.address;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.NumericUtilities;

/**
 * Address Space for dealing with Intel 20 bit segmented addresses.
 */
public class SegmentedAddressSpace extends GenericAddressSpace {

	private final static int SIZE = 21;

	//private final static int SEGMENT_OFFSET_MASK = 0xffff;
	//final static long MASK = (1L << SIZE) - 1;

	/**
	 * Constructs a new Segmented AddressSpace.
	 * 
	 * @param name
	 *            the name of the space
	 * @param unique
	 *            the unique id for the space.
	 */
	public SegmentedAddressSpace(String name, int unique) {
		super(name, SIZE, TYPE_RAM, unique);
		maxOffset = 0x10FFEF;
		spaceSize = maxOffset + 1;
		maxAddress = getUncheckedAddress(maxOffset);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#getAddress(java.lang.String)
	 */
	@Override
	public Address getAddress(String addrString) throws AddressFormatException {
		return getAddress(addrString, true);
	}

	@Override
	public Address getAddress(String addrString, boolean caseSensitive)
			throws AddressFormatException {

		int colonPos = addrString.indexOf(':');

		if (colonPos >= 0) {
			String addrSpaceStr = addrString.substring(0, colonPos);
			String offStr = addrString.substring(colonPos + 1);
			if (StringUtils.equals(getName(), addrSpaceStr)) {
				colonPos = offStr.indexOf(':');
				if (colonPos >= 0) {
					String segString = offStr.substring(0, colonPos);
					offStr = offStr.substring(colonPos + 1);
					return parseSegmented(segString, offStr);
				}
				return parseNonSegmented(offStr);
			}
			return parseSegmented(addrSpaceStr, offStr);
		}

		return parseNonSegmented(addrString);

	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#subtract(ghidra.program.model.address.Address,
	 *      long)
	 */
	@Override
	public Address subtract(Address addr, long displacement) {

		if (displacement < 0) {
			return add(addr, -displacement);
		}

		testAddressSpace(addr);
		if (displacement > spaceSize) {
			throw new AddressOutOfBoundsException(
				"Address Overflow in subtract: " + addr + " + " + displacement);
		}
		long off = addr.getOffset() - displacement;
		if (off >= 0) {
			SegmentedAddress saddr = (SegmentedAddress) addr;
			return new SegmentedAddress(this, off).normalize(saddr.getSegment());
		}
		throw new AddressOutOfBoundsException(
			"Address Overflow in subtract: " + addr + " + " + displacement);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#subtractWrap(ghidra.program.model.address.Address,
	 *      long)
	 */
	/*
	@Override
	public Address subtractWrap(Address addr, long displacement) {
	
		testAddressSpace(addr);
		SegmentedAddress saddr = (SegmentedAddress) addr;
	
		int segOffset = (int) ((saddr.getSegmentOffset() - displacement) & SEGMENT_OFFSET_MASK);
		return new SegmentedAddress(this, saddr.getSegment(), segOffset);
	}
	*/

	/**
	 * @see ghidra.program.model.address.AbstractAddressSpace#subtractWrapSpace(ghidra.program.model.address.Address, long)
	 */
	/*
	@Override
	public Address subtractWrapSpace(Address addr, long displacement) {
		testAddressSpace(addr);
		return new SegmentedAddress(this, (addr.getOffset() - displacement) & MASK);
	}
	*/

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#subtractNoWrap(ghidra.program.model.address.Address,
	 *      long)
	 */
	/*
	@Override
	public Address subtractNoWrap(Address addr, long displacement) throws AddressOverflowException {
	
		testAddressSpace(addr);
		SegmentedAddress saddr = (SegmentedAddress) addr;
	
		long off = addr.getOffset() - displacement;
		if ((off & MASK) != off) {
			throw new AddressOverflowException();
		}
	
		return new SegmentedAddress(this, off).normalize(saddr.getSegment());
	
	}
	*/

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#add(ghidra.program.model.address.Address,
	 *      long)
	 */
	@Override
	public Address add(Address addr, long displacement) {

		if (displacement < 0) {
			return subtract(addr, -displacement);
		}

		testAddressSpace(addr);
		if (displacement > spaceSize) {
			throw new AddressOutOfBoundsException(
				"Address Overflow in add: " + addr + " + " + displacement);
		}
		long off = addr.getOffset() + displacement;
		//if ((off & MASK) == off) {
		if (off >= 0 && off <= maxOffset) {
			SegmentedAddress saddr = (SegmentedAddress) addr;
			return new SegmentedAddress(this, off).normalize(saddr.getSegment());
		}
		throw new AddressOutOfBoundsException(
			"Address Overflow in add: " + addr + " + " + displacement);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#addWrap(ghidra.program.model.address.Address,
	 *      long)
	 */
	/*
	@Override
	public Address addWrap(Address addr, long displacement) {
		testAddressSpace(addr);
		SegmentedAddress saddr = (SegmentedAddress) addr;
	
		int segOffset = (int) ((saddr.getSegmentOffset() + displacement) & SEGMENT_OFFSET_MASK);
		return new SegmentedAddress(this, saddr.getSegment(), segOffset);
	}
	*/

	/**
	 * @see ghidra.program.model.address.AddressSpace#addWrapSpace(ghidra.program.model.address.Address,
	 *      long)
	 */
	/*
	@Override
	public Address addWrapSpace(Address addr, long displacement) {
		testAddressSpace(addr);
		return new SegmentedAddress(this, (addr.getOffset() + displacement) & MASK);
	}
	*/

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#addNoWrap(ghidra.program.model.address.Address,
	 *      long)
	 */
	/*
	@Override
	public Address addNoWrap(Address addr, long displacement) throws AddressOverflowException {
	
		SegmentedAddress saddr = (SegmentedAddress) addr;
		testAddressSpace(addr);
	
		long off = addr.getOffset() + displacement;
		if ((off & MASK) != off) {
			throw new AddressOverflowException();
		}
	
		return new SegmentedAddress(this, off).normalize(saddr.getSegment());
	}
	*/

	private long parseString(String addr) {
		if (addr.startsWith("0x") || addr.startsWith("0X")) {
			return NumericUtilities.parseHexLong(addr.substring(2));
		}
		return NumericUtilities.parseHexLong(addr);

	}

	private SegmentedAddress parseNonSegmented(String offStr) throws AddressFormatException {

		try {
			long off = (int) parseString(offStr);
			if (off < 0 || off > 0xfffff) {
				throw new AddressFormatException("Offset is outside the range 0 to 0xfffff");
			}
			return new SegmentedAddress(this, off);

		}
		catch (NumberFormatException e) {
			throw new AddressFormatException("Cannot parse (" + offStr + ") as a number.");
		}
	}

	private SegmentedAddress parseSegmented(String segStr, String offStr)
			throws AddressFormatException {
		int seg = -1;
		try {
			seg = (int) parseString(segStr);
		}
		catch (NumberFormatException e) {
			return null;
		}
		if (seg < 0 || seg > 0xffff) {
			throw new AddressFormatException("Segment is outside the range 0 to 0xffff");
		}

		try {
			int off = (int) parseString(offStr);
			if (off < 0 || off > 0xffff) {
				throw new AddressFormatException("Offset is outside the range 0 to 0xffff");
			}
			return new SegmentedAddress(this, seg, off);
		}
		catch (AddressOutOfBoundsException e) {
			throw new AddressFormatException(e.getMessage());
		}
		catch (NumberFormatException e) {
			throw new AddressFormatException("Cannot parse (" + offStr + ") as a number.");
		}
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getAddress(long)
	 */
	@Override
	public SegmentedAddress getAddress(long byteOffset) {
		return new SegmentedAddress(this, byteOffset);
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getAddressInThisSpaceOnly(long)
	 */
	@Override
	public SegmentedAddress getAddressInThisSpaceOnly(long byteOffset) {
		return new SegmentedAddress(this, byteOffset);
	}

	/**
	 * @see ghidra.program.model.address.AbstractAddressSpace#getUncheckedAddress(long)
	 */
	@Override
	protected SegmentedAddress getUncheckedAddress(long byteOffset) {
		return new SegmentedAddress(byteOffset, this);
	}

	/**
	 * Generates a segmented address with the given segment, offset, and overlay id.
	 * @param segment        the segment
	 * @param segmentOffset  the offset in the segment
	 * @return SegmentedAddress the newly created segmented address.
	 */
	public SegmentedAddress getAddress(int segment, int segmentOffset) {
		if (segmentOffset > 0xffff) {
			throw new AddressOutOfBoundsException("Offset is too large.");
		}
		if ((segment << 4) + segmentOffset > maxOffset) {
			throw new AddressOutOfBoundsException("Segmented address is too large.");
		}
		return new SegmentedAddress(this, segment, segmentOffset);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#getPhysicalSpace()
	 */
	@Override
	public SegmentedAddressSpace getPhysicalSpace() {
		return this;
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getPointerSize()
	 */
	@Override
	public int getPointerSize() {
		return 2;
	}
}
