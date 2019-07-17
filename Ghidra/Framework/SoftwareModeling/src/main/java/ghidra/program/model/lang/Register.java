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
package ghidra.program.model.lang;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * Class to represent a processor register.  To sort of handle bit registers, a
 * special addressing convention is used.  First the upper bit is set.  Second, the
 * next 3 bits are used to specify what bit position within a byte that this register
 * bit exists at.  Finally, the rest of the address is the address of the byte where
 * the register bit lives.
 */
public class Register implements java.io.Serializable, Comparable<Register> {

	private static final List<String> EMPTY_COLLECTION = new ArrayList<>();

	private final static long serialVersionUID = 1;
	public final static int TYPE_NONE = 0; // nothing special
	public final static int TYPE_FP = 1; // frame pointer
	public final static int TYPE_SP = 2; // stack pointer
	public final static int TYPE_PC = 4; // program counter
	public final static int TYPE_CONTEXT = 8; // processor state
	public final static int TYPE_ZERO = 16; // Register is always zero
	public final static int TYPE_HIDDEN = 32; // Register should not be exposed to users.
	public final static int TYPE_DOES_NOT_FOLLOW_FLOW = 64; // Register value should NOT follow disassembly flow

	/** Register can be used in SIMD operations **/
	public final static int TYPE_VECTOR = 128;

	private String name;
	private String description; // description of the register
	private Address address; // smallest address containing bits for this register
	private int numBytes;
	private int leastSigBit;
	private int bitLength;
	private int typeFlags; // type of register
	private boolean bigEndian;

	private List<Register> childRegisters = new ArrayList<>();
	private Set<String> aliases = new HashSet<>();
	private byte[] baseMask; // contains a mask for accessing bits in the base register
	private int leastSigBitInBaseRegister = 0;
	private Register parent;
	private Register baseRegister;
	private String group;

	/**Set of valid lane sizes**/
	private TreeSet<Integer> laneSizes;

	/**
	 * Constructs a new Register object.
	 *
	 * @param name the name of this Register.
	 * @param description the description of this Register
	 * @param address the address in register space of this register
	 * @param numBytes the size (in bytes) of this register
	 * @param bigEndian true if the most significant bytes are associated with the lowest register
	 * addresses, and false if the least significant bytes are associated with the lowest register 
	 * addresses. 
	 * @param typeFlags the type(s) of this Register  (TYPE_NONE, TYPE_FP, TYPE_SP, 
	 * 	TYPE_PC, TYPE_CONTEXT, TYPE_ZERO);)
	 */
	public Register(String name, String description, Address address, int numBytes,
			boolean bigEndian, int typeFlags) {
		this(name, description, address, numBytes, 0, numBytes * 8, bigEndian, typeFlags);
	}

	public Register(Register register) {
		this(register.name, register.description, register.address, register.numBytes,
			register.leastSigBit, register.bitLength, register.bigEndian, register.typeFlags);
	}

	public Register(String name, String description, Address address, int numBytes,
			int leastSignificantBit, int bitLength, boolean bigEndian, int typeFlags) {

		this.name = name;
		this.description = description;
		this.address = address;
		this.leastSigBit = leastSignificantBit;
		this.numBytes = numBytes;
		this.typeFlags = typeFlags;
		this.bigEndian = bigEndian;
		this.bitLength = bitLength;

		int leastSigByte = leastSignificantBit / 8;
		int mostSigByte = (leastSignificantBit + bitLength - 1) / 8;
		int extraLowerBytes = leastSigByte;
		int extraHighBytes = numBytes - mostSigByte - 1;

		if (bigEndian) {
			if (extraLowerBytes > 0) {
				this.numBytes = numBytes - extraLowerBytes;
				this.leastSigBit -= extraLowerBytes * 8;
			}
			if (extraHighBytes > 0) {
				this.address = address.add(extraHighBytes);
				this.numBytes -= extraHighBytes;
			}
		}
		else {
			if (extraLowerBytes > 0) {
				this.address = address.add(extraLowerBytes);
				this.numBytes -= extraLowerBytes;
				this.leastSigBit -= extraLowerBytes * 8;
			}
			if (extraHighBytes > 0) {
				this.numBytes -= extraHighBytes;
			}
		}
	}

	/**
	 * Add register alias
	 * @param aliasReg
	 */
	void addAlias(String alias) {
		if (name.equals(alias)) {
			return;
		}
		if (aliases == null) {
			aliases = new HashSet<>();
		}
		aliases.add(alias);
	}

	/**
	 * Remove register alias
	 * @param alias
	 */
	void removeAlias(String alias) {
		if (aliases != null) {
			aliases.remove(alias);
		}
	}

	/**
	 * Return register aliases.
	 * NOTE: This is generally only supported for
	 * context register fields.
	 * @return register aliases or null
	 */
	public Iterable<String> getAliases() {
		if (aliases == null) {
			return EMPTY_COLLECTION;
		}
		return aliases;
	}

	/**
	 * Gets the name of this Register.
	 *
	 * @return the name of this Register.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the description of the Register.
	 *
	 * @return the description of the register
	 */
	public String getDescription() {
		return description;
	}

	public boolean isBigEndian() {
		return bigEndian;
	}

	/**
	 * Gets the total number of bits for this Register.
	 *
	 * @return the total number of bits for this Register.
	 */
	public int getBitLength() {
		return bitLength;
	}

	/**
	 * Returns the minimum number of bytes required to store a value for this Register.
	 */
	public int getMinimumByteSize() {
		return (bitLength + 7) / 8;
	}

	/**
	 * Returns the offset into the register space for this register
	 */
	public int getOffset() {
		return (int) address.getOffset();
	}

	/**
	 * Returns the bit offset from the register address for this register.
	 * @return the bit offset from the register address for this register.
	 */
	public int getLeastSignificantBit() {
		return leastSigBit;
	}

	/**
	 * Returns true if this is the default frame pointer register
	 */
	public boolean isDefaultFramePointer() {
		return (typeFlags & TYPE_FP) != 0;
	}

	/**
	 * Returns true for a register whose context value should
	 * follow the disassembly flow.
	 */
	public boolean followsFlow() {
		return (typeFlags & TYPE_DOES_NOT_FOLLOW_FLOW) == 0;
	}

	/**
	 * Returns true if this is a hidden register.
	 */
	public boolean isHidden() {
		return (typeFlags & TYPE_HIDDEN) != 0;
	}

	/**
	 * Returns true if this is the program counter register
	 */
	public boolean isProgramCounter() {
		return (typeFlags & TYPE_PC) != 0;
	}

	/**
	 * Returns true if this is a processor state register
	 */
	public boolean isProcessorContext() {
		return (typeFlags & TYPE_CONTEXT) != 0;
	}

	/**
	 * Returns true for a register that is always zero
	 */
	public boolean isZero() {
		return (typeFlags & TYPE_ZERO) != 0;
	}

	/**
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return name;
	}

	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}

		if (o == null || Register.class != o.getClass()) {
			return false;
		}

		Register rd = (Register) o;
		return rd.name.equals(name) && rd.bitLength == bitLength && rd.address.equals(address) &&
			rd.leastSigBit == leastSigBit;

	}

	/**
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return (int) address.getOffset();
	}

	/**
	 * Returns the register address space
	 */
	public AddressSpace getAddressSpace() {
		return address.getAddressSpace();
	}

	/**
	 * 
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Register other) {
		int result;
		if (getBaseRegister().equals(other.getBaseRegister())) {
			result = leastSigBitInBaseRegister - other.leastSigBitInBaseRegister;
		}
		else {
			result = address.compareTo(other.address);
		}
		if (result == 0) {
			result = bitLength - other.bitLength;
		}
		return result;
	}

	/**
	 * Returns the address of the register.
	 */
	public Address getAddress() {
		return address;
	}

	public Register getParentRegister() {
		return parent;
	}

	/**
	 * Returns list of children registers sorted by
	 * lest-significant bit-offset within this register.
	 */
	public List<Register> getChildRegisters() {
		return new ArrayList<>(childRegisters);
	}

	public Register getBaseRegister() {
		if (baseRegister != null) {
			return baseRegister;
		}
		return this;
	}

	public int getLeastSignificatBitInBaseRegister() {
		return leastSigBitInBaseRegister;
	}

	void setParent(Register parent) {
		this.parent = parent;
		updateBaseRegisterInfo();
		for (Register child : childRegisters) {
			child.updateBaseRegisterInfo();
		}
	}

	private void updateBaseRegisterInfo() {
		baseRegister = parent.getBaseRegister();
		baseMask = null;
		int baseStartAddr = baseRegister.getOffset();
		int baseEndAddr = baseStartAddr + baseRegister.numBytes;
		int myStartAddr = getOffset();
		int myEndAddr = myStartAddr + numBytes;

		if (bigEndian) {
			int bytesAfterMe = baseEndAddr - myEndAddr;
			leastSigBitInBaseRegister = leastSigBit + bytesAfterMe * 8;
		}
		else {
			int bytesBeforeMe = myStartAddr - baseStartAddr;
			leastSigBitInBaseRegister = leastSigBit + bytesBeforeMe * 8;
		}

		for (Register child : childRegisters) {
			child.updateBaseRegisterInfo();
		}
	}

	void setChildRegisters(Register[] childRegisters) {
		for (Register register : childRegisters) {
			if (register.isProcessorContext()) {
				typeFlags |= TYPE_CONTEXT; // if my child is context, then so am I
			}
			register.setParent(this);
		}
		this.childRegisters = Arrays.asList(childRegisters);
		Collections.sort(this.childRegisters);
	}

	public int getTypeFlags() {
		return typeFlags;
	}

	/**
	 * Returns the mask that indicates which bits in the base register apply to this register.
	 * @return the mask that indicates which bits in the base register apply to this register
	 */
	public byte[] getBaseMask() {
		if (baseMask == null) {
			synchronized (this) {
				Register base = getBaseRegister();
				int byteLength = (base.getBitLength() + 7) / 8;
				byte[] newBaseMask = new byte[byteLength];
				int endBit = leastSigBitInBaseRegister + bitLength - 1;
				for (int i = leastSigBitInBaseRegister; i <= endBit; i++) {
					setBit(newBaseMask, i);
				}
				baseMask = newBaseMask;
			}
		}
		return baseMask;
	}

	private void setBit(byte[] byteMask, int bit) {
		int byteNum = byteMask.length - (bit / 8) - 1;
		int bitNum = bit % 8;
		byteMask[byteNum] |= (1 << bitNum);
	}

	void setFlag(int flag) {
		typeFlags |= flag;
	}

	public boolean hasChildren() {
		return childRegisters.size() != 0;
	}

	void setGroup(String group) {
		this.group = group;
	}

	public String getGroup() {
		return group;
	}

	public boolean isBaseRegister() {
		return baseRegister == null;
	}

	/**
	 * Determines if reg is contained within this register.
	 * Method does not work for bit registers (e.g., context-bits)
	 * @param reg another register
	 * @return true if reg equals this register or is contained
	 * within it. 
	 */
	public boolean contains(Register reg) {
		if (equals(reg)) {
			return true;
		}
		for (Register child : childRegisters) {
			if (child.contains(reg)) {
				return true;
			}
		}
		return false;
	}

	void rename(String newName) {
		if (aliases != null) {
			aliases.remove(newName);
		}
		this.name = newName;
	}

	/**
	 * Returns true if this is a vector register
	 * @return true precisely when {@code this} is a full vector register (i.e., a register that can be
	 * used as input or output for a SIMD operation).
	 */
	public boolean isVectorRegister() {
		return (typeFlags & TYPE_VECTOR) != 0;
	}

	/**
	 * Determines whether {@code laneSizeInBytes} is a valid lane size for this register.
	 * @param laneSizeInBytes lane size to check, measured in bytes
	 * @return true precisely when {@code this} is a vector register and {@code laneSizeInBytes} is a valid lane size.
	 */
	public boolean isValidLaneSize(int laneSizeInBytes) {
		if (!isVectorRegister()) {
			return false;
		}
		if (laneSizes == null) {
			return false;
		}
		return laneSizes.contains(laneSizeInBytes);
	}

	/**
	 * Returns the sorted array of lane sizes for this register, measured in bytes.
	 * @return array of lane sizes, or {@code null} if {@code this} is not a vector register or no lane sizes have been set.
	 */
	public int[] getLaneSizes() {
		if (laneSizes == null) {
			return null;
		}
		int[] sizes = new int[laneSizes.size()];
		int index = 0;
		for (int size : laneSizes) {
			sizes[index++] = size;
		}
		return sizes;
	}

	/**
	 * Adds a lane size.
	 * @param laneSizeInBytes lane size to add
	 * @throws UnsupportedOperationException if register is unable to support the definition of 
	 * lanes.
	 * @throws IllegalArgumentException if {@code laneSizeInBytes} is invalid
	 */
	void addLaneSize(int laneSizeInBytes) {
		if ((8 * numBytes) != bitLength) {
			throw new UnsupportedOperationException(
				"Register " + getName() + " does not support lanes");
		}
		if (laneSizeInBytes <= 0 || laneSizeInBytes >= numBytes ||
			(numBytes % laneSizeInBytes) != 0) {
			throw new IllegalArgumentException(
				"Invalid lane size: " + laneSizeInBytes + " for register " + getName());
		}
		if (laneSizes == null) {
			laneSizes = new TreeSet<>();
		}
		typeFlags |= TYPE_VECTOR;
		laneSizes.add(laneSizeInBytes);
	}

}
