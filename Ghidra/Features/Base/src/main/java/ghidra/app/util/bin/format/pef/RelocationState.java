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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

/**
 * This class maintains the running state while
 * applying relocations.
 * <p>
 * <b><code>relocAddress</code></b>
 * Holds an address within the section where the relocations
 * are to be performed. The initial value is the base address
 * of the section to be relocated.
 * <p>
 * <b><code>importIndex</code></b>
 * Holds a symbol index, which is used to access an
 * imported symbol's address. This address can then
 * be used for relocations. The initial value is 0.
 * <p>
 * <b><code>sectionC</code></b>
 * Holds the memory address of an instantiated section
 * within the PEF container, this variable is used by relocation
 * instructions that relocate section addresses. The initial 
 * value is the memory address of section 0 (if that section
 * is present and instantiated), otherwise it is 0.
 * <p>
 * <b><code>sectionD</code></b>
 * Holds the memory address of an instantiated section
 * within the PEF container, this variable is used by relocation
 * instructions that relocate section addresses. The initial 
 * value is the memory address of section 1 (if that section
 * is present and instantiated), otherwise it is 0.
 */
public class RelocationState {
	private ContainerHeader header;
	private LoaderRelocationHeader relocationHeader;
	private ImportStateCache importState;
	private int importIndex = 0;
	private Address relocationAddress;
	private Address sectionC;
	private Address sectionD;
	private Program program;
	private Memory memory;
	private MemoryBlock[] blocks;

	/**
	 * Constructs a new relocation state
	 * @param header the PEF container header
	 * @param relocationHeader the specific relocation header for this state
	 * @param program the program being relocated
	 * @param importState the current import state
	 */
	public RelocationState(ContainerHeader header, LoaderRelocationHeader relocationHeader,
			Program program, ImportStateCache importState) {
		this.header = header;
		this.relocationHeader = relocationHeader;
		this.program = program;
		this.memory = program.getMemory();
		this.importState = importState;

		relocationAddress = getSectionToBeRelocated();
		sectionC = initializeSectionC();
		sectionD = initializeSectionD();
	}

	public void dispose() {
	}

	/**
	 * Increments the import index by one.
	 */
	public void incrementImportIndex() {
		++importIndex;
	}

	/**
	 * Increments the relocation address by the given addend
	 * @param addend the amount to increment the relocation address
	 */
	public void incrementRelocationAddress(int addend) {
		relocationAddress = relocationAddress.add(addend);
	}

	/**
	 * Sets the relocation address.
	 * @param relocationAddress the new relocation address
	 */
	public void setRelocationAddress(Address relocationAddress) {
		this.relocationAddress = relocationAddress;
	}

	/**
	 * Set the sectionC variable to given address.
	 * @param sectionC the new sectionC address
	 */
	public void setSectionC(Address sectionC) {
		this.sectionC = sectionC;
	}

	/**
	 * Set the sectionD variable to given address.
	 * @param sectionD the new sectionD address
	 */
	public void setSectionD(Address sectionD) {
		this.sectionD = sectionD;
	}

	/**
	 * Returns the current import index.
	 * @return the current import index
	 */
	public int getImportIndex() {
		return importIndex;
	}

	/**
	 * Sets the import index.
	 * @param importIndex the new import index value
	 */
	public void setImportIndex(int importIndex) {
		this.importIndex = importIndex;
	}

	/**
	 * Returns the current relocation address.
	 * @return the current relocation address
	 */
	public Address getRelocationAddress() {
		return relocationAddress;
	}

	/**
	 * Returns the current sectionC address.
	 * @return the current sectionC address
	 */
	public Address getSectionC() {
		return sectionC;
	}

	/**
	 * Returns the current sectionD address.
	 * @return the current sectionD address
	 */
	public Address getSectionD() {
		return sectionD;
	}

	private Address initializeSectionC() {
		SectionHeader section = header.getSections().get(0);
		if (section.getSectionKind().isInstantiated()) {
			MemoryBlock sectionBlock = importState.getMemoryBlockForSection(section);
			return sectionBlock.getStart();
		}
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
	}

	/**
	 * Adds the fixup address to the contents stored at address,
	 * then creates a pointer at address.
	 * @param address the address to fixup
	 * @param fixupAddress the value to use in fixup
	 * @param log message log for recording errors
	 */
	public void fixupMemory(Address address, Address fixupAddress, MessageLog log) {
		relocateMemoryAt(address, (int) fixupAddress.getOffset(), log);
		try {
			program.getListing().createData(address, new PointerDataType(), 4);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	/**
	 * Increments the integer in memory at the specified address
	 * @param address the address to increment
	 * @param addend the value to add
	 * @param log a message log
	 */
	public void relocateMemoryAt(Address address, int addend, MessageLog log) {
		MemoryBlock block = getBlockContaining(address);
		if (block == null || !block.isInitialized()) {
			return;
		}
		try {
			int value = memory.getInt(address);

			byte[] bytes = new byte[4];
			memory.getBytes(address, bytes);
			long[] values = new long[] { addend };

			// TODO does PEF have symbol names?
			String symbolName = null;
			program.getRelocationTable().add(address, -1, values, bytes, symbolName);

			value += addend;
			memory.setInt(address, value);
		}
		catch (MemoryAccessException e) {
			log.appendMsg("Unable to perform change memory at " + address);
		}
	}

	private MemoryBlock getBlockContaining(Address address) {
		if (blocks == null) {
			blocks = program.getMemory().getBlocks();
		}
		for (MemoryBlock block : blocks) {
			if (block.contains(address)) {
				return block;
			}
		}
		return null;
	}

	private Address initializeSectionD() {
		SectionHeader section = header.getSections().get(1);
		if (section.getSectionKind().isInstantiated()) {
			MemoryBlock sectionBlock = importState.getMemoryBlockForSection(section);
			return sectionBlock.getStart();
		}
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
	}

	/**
	 * Returns the base address of the section to be relocated.
	 * @return the base address of the section to be relocated
	 */
	public Address getSectionToBeRelocated() {
		int sectionIndex = relocationHeader.getSectionIndex();
		SectionHeader section = header.getSections().get(sectionIndex);
		MemoryBlock sectionBlock = importState.getMemoryBlockForSection(section);
		return sectionBlock.getStart();
	}
}
