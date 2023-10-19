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

import java.util.Objects;

public abstract class OverlayAddressSpace extends AbstractAddressSpace {
	public static final String OV_SEPARATER = ":";

	private final AddressSpace baseSpace;

	private final String orderedKey;

	/**
	 * Construction an overlay address space instance.
	 * @param baseSpace base overlayed address space
	 * @param unique unique index/sequence number
	 * @param orderedKey unique ordered key which should generally match overlay name unless 
	 * already used (e.g., on a renamed overlay space).  This associated value should not be
	 * changed for a given address factory instance.
	 */
	public OverlayAddressSpace(AddressSpace baseSpace, int unique, String orderedKey) {
		super(baseSpace.getSize(), baseSpace.getAddressableUnitSize(), baseSpace.getType(), unique);
		this.orderedKey = orderedKey;
		this.baseSpace = baseSpace;
		this.setShowSpaceName(true);
	}

	/**
	 * Get the ordered key assigned to this overlay address space instance  This value is used
	 * when performing {@link #equals(Object)} and {@link AddressSpace#compareTo(AddressSpace)}
	 * operations.  
	 * <p>
	 * If this value does not have its optimal value (i.e., same as address space name), the 
	 * associated {@link AddressFactory} should report a 
	 * {@link AddressFactory#hasStaleOverlayCondition() stale overlay condition}.
	 * @return instance ordered key
	 */
	public String getOrderedKey() {
		return orderedKey;
	}

	@Override
	int computeHashCode() {
		return Objects.hash(orderedKey, baseSpace);
	}

	@Override
	public Address getAddress(String addrString, boolean caseSensitive)
			throws AddressFormatException {
		addrString = addrString.replaceAll("::", Address.SEPARATOR);
		return super.getAddress(addrString, caseSensitive);
	}

	@Override
	public long subtract(Address addr1, Address addr2) {
		AddressSpace space1 = addr1.getAddressSpace();
		AddressSpace space2 = addr2.getAddressSpace();
		if (space1.equals(this)) {
			space1 = baseSpace;
		}
		if (space2.equals(this)) {
			space2 = baseSpace;
		}
		if (!space1.equals(space2)) {
			throw new IllegalArgumentException("Address are in different spaces " +
				addr1.getAddressSpace().getName() + " != " + addr2.getAddressSpace().getName());
		}
		return addr1.getOffset() - addr2.getOffset();
	}

	@Override
	public boolean isOverlaySpace() {
		return true;
	}

	/**
	 * Get the overlayed (i.e., underlying) base space associated with this overlay space.
	 * @return overlayed base space.
	 */
	public AddressSpace getOverlayedSpace() {
		return baseSpace;
	}

	@Override
	public AddressSpace getPhysicalSpace() {
		return baseSpace.getPhysicalSpace();
	}

	@Override
	public boolean hasMappedRegisters() {
		return baseSpace.hasMappedRegisters();
	}

	/**
	 * Determine if the specified offset is contained within a defined region of this overlay space.
	 * @param offset unsigned address offset
	 * @return true if contained within defined region otherwise false
	 */
	public abstract boolean contains(long offset);

	/**
	 * Get the {@link AddressSet} which corresponds to overlayed physical region which 
	 * corresponds to the defined overlay regions within the overlay (i.e., overlay blocks).
	 * @return defined regions within the overlay.  All addresses are overlay addresses.
	 */
	public abstract AddressSetView getOverlayAddressSet();

	@Override
	public Address getAddressInThisSpaceOnly(long offset) {
		return new GenericAddress(offset, this);
	}

	@Override
	public Address getAddress(long offset) {
		if (contains(offset)) {
			return new GenericAddress(this, offset);
		}
		return baseSpace.getAddress(offset);
	}

	@Override
	protected Address getUncheckedAddress(long offset) {
		return new GenericAddress(offset, this);
	}

	@Override
	public Address getOverlayAddress(Address addr) {
		if (getOverlayedSpace().equals(addr.getAddressSpace())) {
			if (contains(addr.getOffset())) {
				return new GenericAddress(this, addr.getOffset());
			}
		}
		return addr;
	}

	/**
	 * If the given address is outside the overlay block, then the address is tranlated to an
	 * address in the base space with the same offset, otherwise (if the address exists in the
	 * overlay block), it is returned
	 * 
	 * @param addr the address to translate to the base space if it is outside the overlay block
	 * @return either the given address if it is contained in the overlay memory block or an address
	 *         in the base space with the same offset as the given address.
	 */
	public Address translateAddress(Address addr) {
		return translateAddress(addr, false);
	}

	/**
	 * Tranlated an overlay-space address (addr, which may exceed the bounds of the overlay space)
	 * to an address in the base space with the same offset. If forceTranslation is false and addr
	 * is contained within the overlay-space the original addr is returned.
	 * 
	 * @param addr the address to translate to the base space
	 * @param forceTranslation if true addr will be translated even if addr falls within the bounds
	 *            of this overlay-space.
	 * @return either the given address if it is contained in the overlay memory block or an address
	 *         in the base space with the same offset as the given address.
	 */
	public Address translateAddress(Address addr, boolean forceTranslation) {
		if (addr == null) {
			return null;
		}
		if (!forceTranslation && contains(addr.getOffset())) {
			return addr;
		}
		return new GenericAddress(baseSpace, addr.getOffset());
	}

	/**
	 * @return the ID of the address space underlying this space
	 */
	public int getBaseSpaceID() {
		return baseSpace.getSpaceID();
	}

	@Override
	public String toString() {
		return super.toString() + OV_SEPARATER;
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		if (hashCode() != obj.hashCode()) {
			return false;
		}

		OverlayAddressSpace s = (OverlayAddressSpace) obj;
		if (!s.orderedKey.equals(orderedKey)) {
			return false;
		}

		if (getType() != s.getType() || getSize() != s.getSize()) {
			return false;
		}

		return s.getOverlayedSpace().equals(baseSpace);
	}

	/**
	 * Compare this overlay to the spacified overlay.
	 * @param overlay other overlay to be checked for eqauality
	 * @return see {@link Comparable#compareTo(Object)}
	 */
	int compareOverlay(OverlayAddressSpace overlay) {
		if (overlay == this) {
			return 0;
		}
		int rc = baseSpace.compareTo(overlay.baseSpace);
		if (rc != 0) {
			return rc;
		}
		int c = getType() - overlay.getType();
		if (c == 0) {
			c = orderedKey.compareTo(overlay.orderedKey);
		}
		return c;
	}

}
