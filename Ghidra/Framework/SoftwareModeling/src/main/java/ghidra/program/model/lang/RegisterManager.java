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

import ghidra.program.model.address.*;

public class RegisterManager {

	private List<Register> registers;
	private Map<String, Register> registerNameMap = new HashMap<String, Register>(); // include aliases and case-variations
	
	private List<String> registerNames; // alphabetical sorted list, excludes aliases
	private List<Register> contextRegisters;
	private Register contextBaseRegister;
	
	private Map<RegisterSizeKey, Register> sizeMap = new HashMap<RegisterSizeKey, Register>();
	private Map<Address, List<Register>> registerAddressMap =
		new HashMap<Address, List<Register>>();

	/**List of vector registers, sorted first by size and then by offset**/
	private List<Register> sortedVectorRegisters;

	class RegisterSizeKey {
		Address address;
		int size;

		public RegisterSizeKey(Address addr, int size) {
			address = getGlobalAddress(addr);
			this.size = size < 0 ? 0 : size;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (obj == this) {
				return true;
			}
			if (obj.getClass() != getClass()) {
				return false;
			}
			RegisterSizeKey other = (RegisterSizeKey) obj;
			return other.address.equals(address) && other.size == size;
		}

		@Override
		public int hashCode() {
			return address.hashCode() << 8 + size;
		}

		@Override
		public String toString() {
			return "{" + address.toString() + ", size = " + size + "}";
		}
	}

	private static Comparator<Register> registerSizeComparator = new Comparator<Register>() {
		@Override
		public int compare(Register r1, Register r2) {
			// Used for sorting largest to smallest
			return r2.getBitLength() - r1.getBitLength();
		}
	};

	/**
	 * Construct RegisterManager
	 * @param registers all defined registers with appropriate parent-child relationships
	 * properly established.
	 * @param registerNameMap a complete name-to-register map including all register aliases
	 * and alternate spellings (e.g., case-variations)
	 */
	RegisterManager(List<Register> registers, Map<String, Register> registerNameMap) {
		this.registers = Collections.unmodifiableList(registers);
		this.registerNameMap = Collections.unmodifiableMap(registerNameMap);
		initialize();
	}

	private void initialize() {
		List<String> registerNameList = new ArrayList<String>();
		List<Register> contextRegisterList = new ArrayList<Register>();
		ArrayList<Register> registerListSortedBySize = new ArrayList<>(registers); // copy for sorting
		Collections.sort(registerListSortedBySize, registerSizeComparator);
		for (Register reg : registerListSortedBySize) {
			String regName = reg.getName();
			registerNameList.add(regName);
			if (reg.isProcessorContext()) {
				contextRegisterList.add(reg);
				if (reg.isBaseRegister()) {
					contextBaseRegister = reg;
				}
			}

			Address addr = reg.getAddress();
			List<Register> list = registerAddressMap.get(addr);
			if (list == null) {
				list = new ArrayList<Register>();
				registerAddressMap.put(addr, list);
			}
			list.add(reg);
			if (reg.isProcessorContext()) {
				continue;
			}

			if (reg.isBigEndian()) {
				populateSizeMapBigEndian(reg);
			}
			else {
				populateSizeMapLittleEndian(reg);
			}
		}
		// handle the register size 0 case;
		Collections.reverse(registerListSortedBySize);
		for (Register register : registerListSortedBySize) {
			sizeMap.put(new RegisterSizeKey(register.getAddress(), 0), register);
		}
		contextRegisters = Collections.unmodifiableList(contextRegisterList);
		Collections.sort(registerNameList);
		registerNames = Collections.unmodifiableList(registerNameList);
	}

	private void populateSizeMapBigEndian(Register reg) {
		int regSize = reg.getMinimumByteSize();
		for (int i = 1; i <= regSize; i++) {
			Address address = reg.getAddress().add(regSize - i);
			sizeMap.put(new RegisterSizeKey(address, i), reg);
		}
	}

	private void populateSizeMapLittleEndian(Register reg) {
		int regSize = reg.getMinimumByteSize();
		for (int i = 1; i <= regSize; i++) {
			sizeMap.put(new RegisterSizeKey(reg.getAddress(), i), reg);
		}
	}

	/**
	 * Get context base-register
	 * @return context base register or null if one has not been defined by the language.
	 */
	public Register getContextBaseRegister() {
		return contextBaseRegister;
	}

	/**
	 * Get unsorted unmodifiable list of all processor context registers (include base context register and children)
	 * @return all processor context registers
	 */
	public List<Register> getContextRegisters() {
		return contextRegisters;
	}

	/**
	 * Get an alphabetical sorted unmodifiable list of original register names 
	 * (including context registers).  Names correspond to orignal register
	 * name and not aliases which may be defined.
	 * 
	 * @return alphabetical sorted unmodifiable list of original register names.
	 */
	public List<String> getRegisterNames() {
		return registerNames;
	}

	/**
	 * Returns the largest register located at the specified address
	 * @param addr register address
	 * @return register or null if not found
	 */
	public Register getRegister(Address addr) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isRegisterSpace() || space.hasMappedRegisters()) {
			return sizeMap.get(new RegisterSizeKey(addr, 0));
		}
		return null;
	}

	/**
	 * Returns all registers located at the specified address
	 * 
	 * @param addr register address
	 * @return array of registers found (may be empty)
	 */
	public Register[] getRegisters(Address addr) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isRegisterSpace() || space.hasMappedRegisters()) {
			List<Register> list = registerAddressMap.get(getGlobalAddress(addr));
			if (list != null) {
				Register[] regs = new Register[list.size()];
				list.toArray(regs);
				return regs;
			}
		}
		return new Register[0];
	}

	private Address getGlobalAddress(Address addr) {
		if (addr instanceof OldGenericNamespaceAddress) {
			return ((OldGenericNamespaceAddress) addr).getGlobalAddress();
		}
		return addr;
	}

	/**
	 * Get register by address and size
	 * @param addr register address
	 * @param size register size
	 * @return register or null if not found
	 */
	public Register getRegister(Address addr, int size) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isRegisterSpace() || space.hasMappedRegisters()) {
			return sizeMap.get(new RegisterSizeKey(addr, size));
		}
		return null;
	}

	/**
	 * Get register by name.  A semi-case-insensitive lookup is performed.
	 * The specified name must match either the case-sensitive name or
	 * be entirely lowercase or uppercase.
	 * @param name register name
	 * @return register or null if not found
	 */
	public Register getRegister(String name) {
		return registerNameMap.get(name);
	}

	/**
	 * Get all registers as an unsorted unmodifiable list.
	 * @return unmodifiable list of all registers defined
	 */
	public List<Register> getRegisters() {
		return registers;
	}

	/**
	 * Get an unmodifiable list of all vector registers indentified by the processor specification
	 * in sorted order based upon address and size.  
	 * @return all vector registers as unmodifiable list
	 */
	public List<Register> getSortedVectorRegisters() {
		if (sortedVectorRegisters == null) {
			ArrayList<Register> list = new ArrayList<Register>();
			for (Register reg : registers) {
				if (reg.isVectorRegister()) {
					list.add(reg);
				}
			}
			Collections.sort(list, RegisterManager::compareVectorRegisters);
			sortedVectorRegisters = Collections.unmodifiableList(list);
		}
		return sortedVectorRegisters;
	}

	/**
	 * Compares two vector registers, first by size (descending) and then by offset (ascending).
	 * @param reg1 vector register
	 * @param reg2 vector register
	 * @return result of comparison
	 */
	private static int compareVectorRegisters(Register reg1, Register reg2) {
		if (!(reg1.isVectorRegister() && reg2.isVectorRegister())) {
			throw new IllegalArgumentException("compareVectorRegisters can only be applied to vector registers!");
		}
		//want registers sorted in descending order of size
		int sizeComp = Integer.compare(reg2.getBitLength(), reg1.getBitLength());
		if (sizeComp != 0) {
			return sizeComp;
		}
		//want registers sorted in ascending order of offset
		return Integer.compare(reg1.getOffset(), reg2.getOffset());
	}

}
