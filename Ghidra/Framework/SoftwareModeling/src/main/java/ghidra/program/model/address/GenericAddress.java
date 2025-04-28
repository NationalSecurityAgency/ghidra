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

import java.math.BigInteger;

import ghidra.util.NumericUtilities;

/**
 * Generic implementation of the Address interface.  Consists of an
 * Address Space, an offset, and a namespace id.
 */
public class GenericAddress implements Address {
	private static final int MAXIMUM_DIGITS = 16;

	private static final int MINIMUM_DIGITS = 8;

	protected static final String zeros = "0000000000000000";

	protected AddressSpace addrSpace;
	protected long offset;

	/**
	 * Constructs a new Generic address with the given offset within the given address space.
	 * Offset is not validated against address space.
	 * @param offset the offset within the space for the new address
	 * @param addrSpace The Address space of the new address
	 */
	GenericAddress(long offset, AddressSpace addrSpace) {
		this.addrSpace = addrSpace;
		this.offset = offset;
	}

	/**
	 * Constructs a new Generic address with the given offset within the given address space
	 * @param addrSpace The Address space of the new address
	 * @param offset the offset within the space for the new address
	 * @throws AddressOutOfBoundsException if the offset is less than 0 or greater
	 * than the max offset allowed for this space.
	 */
	GenericAddress(AddressSpace addrSpace, long offset) {
		this.offset = addrSpace.makeValidOffset(offset);
		this.addrSpace = addrSpace;
	}

	@Override
	public Address getAddress(String addrString) throws AddressFormatException {
		return addrSpace.getAddress(addrString);
	}

	@Override
	public Address getNewAddress(long byteOffset) {
		return addrSpace.getAddress(byteOffset);
	}

	@Override
	public Address getNewAddress(long addrOffset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException {
		return addrSpace.getAddress(addrOffset, isAddressableWordOffset);
	}

	@Override
	public Address getNewTruncatedAddress(long addrOffset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException {
		return addrSpace.getTruncatedAddress(addrOffset, isAddressableWordOffset);
	}

	@Override
	public long getOffset() {
		return offset;
	}

	@Override
	public long getAddressableWordOffset() {
		return addrSpace.getAddressableWordOffset(offset);
	}

	@Override
	public long getUnsignedOffset() {
		// TODO: Validity of offset within space is not verified
		if (offset >= 0 || !addrSpace.hasSignedOffset()) {
			return offset;
		}
		long spaceSize = 0;
		int size = addrSpace.getSize();
		if (size != 64) {
			spaceSize = ((long) addrSpace.getAddressableUnitSize()) << size; // (spaceSize=0 for 64-bit space)
		}
		return spaceSize + offset;
	}

	@Override
	public AddressSpace getAddressSpace() {
		return addrSpace;
	}

	@Override
	public int getSize() {
		return addrSpace.getSize();
	}

	@Override
	public long subtract(Address addr) {
		return addrSpace.subtract(this, addr);
	}

	@Override
	public Address subtractWrap(long displacement) {
		if (displacement == 0)
			return this;
		return addrSpace.subtractWrap(this, displacement);
	}

	@Override
	public Address subtractWrapSpace(long displacement) {
		if (displacement == 0)
			return this;
		return addrSpace.subtractWrapSpace(this, displacement);
	}

	@Override
	public Address subtractNoWrap(long displacement) throws AddressOverflowException {
		if (displacement == 0)
			return this;
		return addrSpace.subtractNoWrap(this, displacement);
	}

	@Override
	public Address subtract(long displacement) {
		if (displacement == 0)
			return this;
		return addrSpace.subtract(this, displacement);
	}

	@Override
	public Address addWrap(long displacement) {
		if (displacement == 0)
			return this;
		return addrSpace.addWrap(this, displacement);
	}

	@Override
	public Address addWrapSpace(long displacement) {
		if (displacement == 0)
			return this;
		return addrSpace.addWrapSpace(this, displacement);
	}

	@Override
	public Address addNoWrap(long displacement) throws AddressOverflowException {
		if (displacement == 0)
			return this;
		return addrSpace.addNoWrap(this, displacement);
	}

	@Override
	public Address addNoWrap(BigInteger displacement) throws AddressOverflowException {
		if (displacement.equals(BigInteger.ZERO)) {
			return this;
		}
		return addrSpace.addNoWrap(this, displacement);
	}

	@Override
	public Address add(long displacement) {
		if (displacement == 0)
			return this;
		return addrSpace.add(this, displacement);
	}

	@Override
	public boolean isSuccessor(Address addr) {
		return addrSpace.isSuccessor(this, addr);
	}

	@Override
	public int compareTo(Address a) {
		int comp = addrSpace.compareTo(a.getAddressSpace());
		if (comp != 0) {
			return comp;
		}
		long otherOffset = a.getOffset();
		if (addrSpace.hasSignedOffset()) {
			return Long.compare(offset, otherOffset);
		}
		return Long.compareUnsigned(offset, otherOffset);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof GenericAddress addr)) {
			return false;
		}
		return offset == addr.offset && addrSpace.equals(addr.getAddressSpace());
	}

	@Override
	public int hashCode() {
		int hash1 = addrSpace.hashCode();
		int hash3 = (int) (offset >> 32) ^ (int) offset;
		return (hash1 << 16) ^ hash3;
	}

	@Override
	public String toString() {
		return toString(addrSpace.showSpaceName(), MINIMUM_DIGITS);
	}

	@Override
	public String toString(String prefix) {
		boolean showSpace = prefix.length() == 0 && addrSpace.showSpaceName();
		return prefix + toString(showSpace, MINIMUM_DIGITS);
	}

	@Override
	public String toString(boolean showAddressSpace) {
		return toString(showAddressSpace, MINIMUM_DIGITS);
	}

	@Override
	public String toString(boolean showAddressSpace, boolean pad) {
		return toString(showAddressSpace, pad ? MAXIMUM_DIGITS : MINIMUM_DIGITS);
	}

	@Override
	public String toString(boolean showAddressSpace, int minNumDigits) {

		boolean stackFormat = false;
		StringBuilder buf = new StringBuilder();
		if (addrSpace.isStackSpace()) {
			stackFormat = true;
			buf.append("Stack[");
			minNumDigits = 1;
		}
		else if (showAddressSpace) {
			buf.append(addrSpace.toString());
		}

		int unitSize = addrSpace.isStackSpace() ? 1 : addrSpace.getAddressableUnitSize();
		int maxDigitsSizeForSpace = ((addrSpace.getSize() - 1) / 4) + 1;
//		if (unitSize > 1) {
//			maxDigitsSizeForSpace /= 2;	//addressSpaces with unitsize > 1, have twice the bitSize that they 
//										// should to account for bits for the mod part.
//		}

		int padSize = Math.min(minNumDigits, maxDigitsSizeForSpace);

		long displayOffset = offset;
		if (stackFormat) {
			if (displayOffset < 0) {
				buf.append("-");
				displayOffset = -displayOffset;
			}
			buf.append("0x");
		}
		long mod = 0;
		if (unitSize > 1) {
			mod = displayOffset % unitSize;
			displayOffset = addrSpace.getAddressableWordOffset(displayOffset);
		}

		String addressString = Long.toHexString(displayOffset);
		int numHexDigits = addressString.length();
		int numZerosToPad = Math.max(padSize - numHexDigits, 0);
		for (int i = 0; i < numZerosToPad; i++) {
			buf.append('0');
		}
		buf.append(addressString);
		if (mod != 0) {
			buf.append('.');
			buf.append(mod);
		}
		if (stackFormat) {
			buf.append("]");
		}
		return buf.toString();
	}

	@Override
	public boolean hasSameAddressSpace(Address addr) {
		return addrSpace.equals(addr.getAddressSpace());
	}

	@Override
	public Address next() {
		if (addrSpace.getMaxAddress().getOffset() == offset) {
			return null;
		}
		return addrSpace.addWrap(this, 1);
	}

	@Override
	public Address previous() {
		if (addrSpace.getMinAddress().getOffset() == offset) {
			return null;
		}
		return addrSpace.subtractWrap(this, 1);
	}

	@Override
	public Address getPhysicalAddress() {
		AddressSpace physical = addrSpace.getPhysicalSpace();
		if (physical == addrSpace) {
			return this;
		}
		if (physical != null) {
			return new GenericAddress(physical, offset);
		}
		return null;
	}

	@Override
	public int getPointerSize() {
		return addrSpace.getPointerSize();
	}

	@Override
	public boolean isMemoryAddress() {
		return addrSpace.isMemorySpace();
	}

	@Override
	public boolean isLoadedMemoryAddress() {
		return addrSpace.isLoadedMemorySpace();
	}

	@Override
	public boolean isNonLoadedMemoryAddress() {
		return addrSpace.isNonLoadedMemorySpace();
	}

	@Override
	public boolean isHashAddress() {
		return addrSpace.isHashSpace();
	}

	@Override
	public boolean isStackAddress() {
		return addrSpace.isStackSpace();
	}

	@Override
	public boolean isUniqueAddress() {
		return addrSpace.isUniqueSpace();
	}

	@Override
	public boolean isConstantAddress() {
		return addrSpace.isConstantSpace();
	}

	@Override
	public boolean isVariableAddress() {
		return addrSpace.isVariableSpace();
	}

	@Override
	public boolean isRegisterAddress() {
		return addrSpace.isRegisterSpace();
	}

	@Override
	public boolean isExternalAddress() {
		return addrSpace.isExternalSpace();
	}

	@Override
	public BigInteger getOffsetAsBigInteger() {
		return NumericUtilities.unsignedLongToBigInteger(offset);
	}
}
