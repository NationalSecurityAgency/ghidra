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
package ghidra.util.table.field;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;

/**
 * <code>AddressBasedLocation</code> provides the ability to render and compare
 * addresses (e.g., location table column). This may be necessary when working a
 * mixture of address types (e.g., memory, stack, register, variable, external)
 * with the need to render in a meaningful way. Generally, only memory addresses
 * are meaningful to a user when rendered as a simple address (e.g.,
 * ram:00123456). While most address types are handled, VARIABLE addresses will
 * only render as "&lt;VARIABLE&gt;". As such, this implementation should be
 * extended if VARIABLE addresses will be encountered.
 */
public class AddressBasedLocation implements Comparable<AddressBasedLocation> {

	private final Address address;
	private Class<? extends Reference> referenceClass; // affects sort order
	private final String stringRepresentation;

	/**
	 * Construct a null location which generally corresponds to a unknown/bad
	 * address
	 */
	public AddressBasedLocation() {
		this(null, "<NULL>");
	}

	/**
	 * Construction a location. The memory block name will never be included in
	 * string representation.
	 * 
	 * @param program program to which address belongs
	 * @param address address object (VARIABLE addresses should be avoided)
	 */
	public AddressBasedLocation(Program program, Address address) {
		this(address, buildStringRepresentation(program, address, null, ShowBlockName.NEVER));
	}

	/**
	 * Construct a location which corresponds to a reference TO address. String
	 * representation includes support for Offset References and allows control
	 * over inclusion of memory block name with memory addresses.
	 * 
	 * @param program program to which address belongs
	 * @param reference program reference (e.g., memory, stack, register, external)
	 * @param showBlockName ShowBlockName option for controlling inclusion of memory block 
	 * name with address rendering
	 */
	public AddressBasedLocation(Program program, Reference reference, ShowBlockName showBlockName) {
		this(reference.getToAddress(),
			buildStringRepresentation(program, reference.getToAddress(), reference, showBlockName));
		referenceClass = reference.getClass();
	}

	/**
	 * Construct a location with a specific address and representation
	 * 
	 * @param address address object
	 * @param representation address/location string representation
	 */
	protected AddressBasedLocation(Address address, String representation) {
		this.address = address;
		stringRepresentation = representation;
	}

	public Address getAddress() {
		return address;
	}

	/**
	 * @return true if location corresponds to memory address
	 */
	public boolean isMemoryLocation() {
		return address != null && address.isMemoryAddress();
	}

	private static String buildStringRepresentation(Program program, Address address,
			Reference reference, ShowBlockName showBlockName) {
		if (address == null) {
			return "<NULL>";
		}
		if (address.getAddressSpace().getType() == AddressSpace.TYPE_NONE) {
			return ""; // NO_ADDRESS or EXT_FROM_ADDRESS not rendered
		}
		if (address.isExternalAddress()) {
			return getExternalAddressRepresentation(program, address);
		}
		if (address.isVariableAddress()) {
			return getVariableAddressRepresentation();
		}
		if (address.isStackAddress()) {
			return getStackAddressRepresentation(address);
		}
		if (address.isConstantAddress()) {
			return getConstantAddressRepresentation(address);
		}
		if (isRegisterAddress(program, address)) {
			return getRegisterAddressRepresentation(program, address);
		}

		// Handle all other spaces (e.g., memory, other, overlays, hash, etc.)
		String addrStr;
		if (reference != null && reference.isOffsetReference()) {
			OffsetReference offsetRef = (OffsetReference) reference;
			long offset = offsetRef.getOffset();
			boolean neg = (offset < 0);
			Address baseAddr = offsetRef.getBaseAddress();
			addrStr = baseAddr.toString() + (neg ? "-" : "+") + "0x" +
				Long.toHexString(neg ? -offset : offset);
		}
		else if (reference != null && reference.isShiftedReference()) {
			// TODO: unsure of rendering which has never really been addressed
			// TODO: shifted references have never addressed concerns related to
			// addressable unit size
			ShiftedReference shiftedRef = (ShiftedReference) reference;
			StringBuilder buf = new StringBuilder();
			buf.append(address.toString());
			buf.append("(0x");
			buf.append(Long.toHexString(shiftedRef.getValue()));
			buf.append("<<");
			buf.append(Long.toString(shiftedRef.getShift()));
			buf.append(")");
			addrStr = buf.toString();
		}
		else {
			addrStr = address.toString();
		}

		if (showBlockName != ShowBlockName.NEVER) {
			Memory mem = program.getMemory();
			MemoryBlock toBlock = mem.getBlock(address);
			if (toBlock != null && showBlockName == ShowBlockName.NON_LOCAL && reference != null &&
				toBlock.equals(mem.getBlock(reference.getFromAddress()))) {
				toBlock = null;
			}
			if (toBlock != null) {
				addrStr = toBlock.getName() + "::" + addrStr;
			}
		}

		return addrStr;
	}

	private static boolean isRegisterAddress(Program program, Address address) {

		if (!address.isRegisterAddress()) {
			return false;
		}

		Register register = program.getRegister(address);
		return register != null;
	}

	private static String getExternalAddressRepresentation(Program program, Address address) {
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol == null) {
			return "External[ BAD ]";
		}
		ExternalLocation extLoc = program.getExternalManager().getExternalLocation(symbol);
		Address extAddr = extLoc.getAddress();
		if (extAddr != null) {
			return "External[" + extAddr.toString() + "]";
		}
		return "External[ ? ]";
	}

	private static String getRegisterAddressRepresentation(Program program, Address address) {
		Register register = program.getRegister(address);
		String regName = register.getName();
		return "Register[" + regName + "]";
	}

	private static String getStackAddressRepresentation(Address address) {
		int offset = (int) address.getOffset();
		boolean neg = (offset < 0);
		return "Stack[" + (neg ? "-" : "+") + "0x" + Integer.toHexString(neg ? -offset : offset) +
			"]";
	}

	private static String getConstantAddressRepresentation(Address address) {
		int offset = (int) address.getOffset();
		boolean neg = (offset < 0);
		return "Constant[" + (neg ? "-" : "+") + "0x" +
			Integer.toHexString(neg ? -offset : offset) + "]";
	}

	private static String getVariableAddressRepresentation() {
		return "<VARIABLE>"; // unable to translate to VariableStorage without
							// symbol
	}

	/**
	 * Determine if location corresponds to a reference destination
	 * 
	 * @return true if location corresponds to a reference destination
	 */
	public boolean isReferenceDestination() {
		return referenceClass != null;
	}

	/**
	 * Determine if location corresponds to a shifted memory reference destination
	 * @return true if location corresponds to a shifted memory reference destination
	 */
	public boolean isShiftedAddress() {
		return referenceClass != null && ShiftedReference.class.isAssignableFrom(referenceClass);
	}

	/**
	 * Determine if location corresponds to a shifted memory reference
	 * destination
	 * @return true if location corresponds to a shifted memory reference destination
	 */
	public boolean isOffsetAddress() {
		return referenceClass != null && OffsetReference.class.isAssignableFrom(referenceClass);
	}

	@Override
	public String toString() {
		return stringRepresentation;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AddressBasedLocation)) {
			return false;
		}
		AddressBasedLocation otherLocation = (AddressBasedLocation) obj;
		if (SystemUtilities.isEqual(address, otherLocation.address)) {
			return stringRepresentation.equals(otherLocation.stringRepresentation);
		}
		return false;
	}

	@Override
	public int hashCode() {
		int hashCode = address != null ? address.hashCode() : 0;
		hashCode ^= stringRepresentation.hashCode();
		return hashCode;
	}

	/**
	 * Compare this location's address with another location's given that they
	 * are both within the same address space.
	 * @param otherLocation other location object
	 * @return comparison value
	 * @see #compareTo(AddressBasedLocation)
	 */
	private int compareAddressSameSpace(AddressBasedLocation otherLocation) {

		if (address.isExternalAddress() || address.isVariableAddress() ||
			address.isRegisterAddress()) {
			// These address types have meaningless address offsets
			return stringRepresentation.compareTo(otherLocation.stringRepresentation);
		}

		// for most space types use space specific sort of address when space is the same
		int rc = address.compareTo(otherLocation.address);

		if (rc == 0) {
			// For the same memory offset, after normal addresses and memory references
			// are ShiftedReferences followed by OffsetReferences
			if (isShiftedAddress()) {
				if (otherLocation.isOffsetAddress()) {
					rc = -1;
				}
				else if (otherLocation.isShiftedAddress()) {
					rc = stringRepresentation.compareTo(otherLocation.stringRepresentation);
				}
				else {
					rc = 1;
				}
			}
			else if (isOffsetAddress()) {
				if (!otherLocation.isOffsetAddress()) {
					rc = 1;
				}
			}
			else if (otherLocation.isOffsetAddress() || otherLocation.isShiftedAddress()) {
				rc = -1;
			}
		}
		return rc;
	}

	@Override
	public int compareTo(AddressBasedLocation otherLocation) {

		Address otherAddress = otherLocation.address;

		// handle possible presence of null address
		if (address == null) {
			if (otherAddress == null) {
				return 0;
			}
			return -1;
		}
		if (otherAddress == null) {
			return 1;
		}

		AddressSpace mySpace = address.getAddressSpace();
		AddressSpace otherSpace = otherAddress.getAddressSpace();

		// compare on address space name first
		int rc = mySpace.getName().compareTo(otherSpace.getName());
		if (rc != 0) {
			return rc;
		}

		return compareAddressSameSpace(otherLocation);
	}

}
