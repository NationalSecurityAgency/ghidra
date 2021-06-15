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

public class OverlayAddressSpace extends AbstractAddressSpace {
    public static final String OV_SEPARATER = ":";

	private AddressSpace originalSpace;

	private long databaseKey;

	public OverlayAddressSpace(String name, AddressSpace originalSpace, int unique, 
			long minOffset, long maxOffset) {
		super(name, originalSpace.getSize(), originalSpace.getAddressableUnitSize(),
					originalSpace.getType(), unique);
		
		this.originalSpace = originalSpace;
		this.setShowSpaceName(true);

		//KEEP THIS CODE
		//it also validates the min and max offset
		this.minOffset = minOffset;
		this.maxOffset = maxOffset;
		minAddress = new GenericAddress(this, minOffset);
		maxAddress = new GenericAddress(this, maxOffset);
	}
	
	//	public Address addNoWrap(Address addr, long displacement) throws AddressOverflowException {
//		addr = super.addNoWrap(addr, displacement);
//		
//		return translateAddress(addr);
//	}
//
//	public Address addWrap(Address addr, long displacement) {
//		addr = super.addWrap(addr, displacement);
//		
//		return translateAddress(addr);
//	}
//
//	public Address getAddress(long offset, long namespaceID) {
//		return translateAddress(super.getAddress(offset, namespaceID));
//	}
//
//	public Address getAddress(long offset) {
//		return translateAddress(super.getAddress(offset));
//	}
//
	@Override
    public Address getAddress(String addrString) throws AddressFormatException {
		addrString = addrString.replaceAll("::", ":");

		int firstColonPos = addrString.indexOf(":");
		int lastColonPos = addrString.lastIndexOf(":");

		if (firstColonPos != lastColonPos) {
			String middleName = addrString.substring(firstColonPos+1, lastColonPos);
			if (middleName.equals(originalSpace.getName())) {
				addrString = addrString.substring(0, firstColonPos)+addrString.substring(lastColonPos);
			}
		}
		return super.getAddress(addrString);
//		return translateAddress(super.getAddress(addrString));
		
	}

//	public Address next(Address addr) {
//		addr = super.next(addr);
//		if (addr != null && contains(addr.getOffset())) {
//			return addr;
//		}
//		return null;
//	}
//
//	public Address previous(Address addr) {
//		addr = super.previous(addr);
//		if (addr != null && contains(addr.getOffset())) {
//			return addr;
//		}
//		return null;
//	}

	@Override
    public long subtract(Address addr1, Address addr2) {
		AddressSpace space1 = addr1.getAddressSpace();
		AddressSpace space2 = addr2.getAddressSpace();
		if (space1.equals(this)) {
			space1 = originalSpace;
		}
		if (space2.equals(this)) {
			space2 = originalSpace;
		}
		if (!space1.equals(space2)) {
			throw new IllegalArgumentException("Address are in different spaces " +
						              addr1.getAddressSpace().getName() + " != " + addr2.getAddressSpace().getName());
		}
		return addr1.getOffset()-addr2.getOffset();
	}

//	public Address subtractNoWrap(Address addr, long displacement) throws AddressOverflowException {
//		return translateAddress(super.subtractNoWrap(addr, displacement));
//	}
//
//	public Address subtractWrap(Address addr, long displacement) {
//		return translateAddress(super.subtractWrap(addr, displacement));
//	}
	
	@Override
    public boolean isOverlaySpace() {
		return originalSpace != null;
	}
	
	public AddressSpace getOverlayedSpace() {
		return originalSpace;
	}

	@Override
    public AddressSpace getPhysicalSpace() {
		return originalSpace.getPhysicalSpace();
	}

	@Override
    public boolean hasMappedRegisters() {
		return originalSpace.hasMappedRegisters();
	}
	
	public long getMinOffset() {
		return minOffset;
	}
	public long getMaxOffset() {
		return maxOffset;
	}
	
	public boolean contains(long offset) { 
		return (offset >= minOffset && offset <= maxOffset);
	}
	
	@Override
    public Address getAddressInThisSpaceOnly(long offset) {
		return new GenericAddress(offset, this);
	}
	
	@Override
    public Address getAddress(long offset) {
		if (contains(offset)) {
			return new GenericAddress(this, offset);
		}
		return originalSpace.getAddress(offset);
	}
	
	@Override
    protected Address getUncheckedAddress(long offset) {
		return new GenericAddress(offset, this);
	}
	
	@Override
    public Address getOverlayAddress(Address addr) {
		if (getOverlayedSpace().equals(addr.getAddressSpace()))
		{
			if (contains(addr.getOffset())) {
				return new GenericAddress(this, addr.getOffset());
			}
		}
		return addr;
	}

	/**
	 * If the given address is outside the overlay block, then the address is tranlated to an
	 * address in the base space with the same offset, otherwise (if the address exists in the overlay
	 * block), it is returned
	 * @param addr the address to translate to the base space if it is outside the overlay block
	 * @return either the given address if it is contained in the overlay memory block or an address
	 * in the base space with the same offset as the given address.
	 */
	public Address translateAddress(Address addr) {
		return translateAddress(addr, false);
	}
	/**
	 * Tranlated an overlay-space address (addr, which may exceed the bounds of the overlay space) 
	 * to an address in the base space with the same offset.
	 * If forceTranslation is false and addr is contained within the overlay-space 
	 * the original addr is returned.
	 * @param addr the address to translate to the base space
	 * @param forceTranslation if true addr will be translated even if addr falls within the 
	 * bounds of this overlay-space.
	 * @return either the given address if it is contained in the overlay memory block or an address
	 * in the base space with the same offset as the given address.
	 */
	public Address translateAddress(Address addr, boolean forceTranslation) {
		if (addr == null) {
			return null;
		}
		if (!forceTranslation && contains(addr.getOffset())) {
			return addr;
		}
		return new GenericAddress(originalSpace, addr.getOffset());
	}
	
	/**
	 * @return the ID of the address space underlying this space
	 */
    public int getBaseSpaceID() {
		return originalSpace.getSpaceID();
	}
	
	@Override
    public String toString() {
		return super.toString()+OV_SEPARATER;
	}
	public void setName(String newName) {
		name = newName;
	}

	public void setDatabaseKey(long key) {
		databaseKey = key;
	}
	public long getDatabaseKey() {
		return databaseKey;
	}
	
	@Override
    public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof OverlayAddressSpace)) {
			return false;
		}
		OverlayAddressSpace s = (OverlayAddressSpace)obj;
		
        return	originalSpace.equals(s.originalSpace) &&
        	name.equals(s.name) &&
        	minOffset == s.minOffset &&
        	maxOffset == s.maxOffset;	
	}
}
