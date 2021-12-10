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
package ghidra.app.util.bin.format.elf.extend;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>ElfLoadAdapter</code> provides the base ELF load adapter implementation 
 * which may be extended to facilitate target specific behavior.
 */
public class ElfLoadAdapter {

	/**
	 * Add all extension specific Dynamic table entry types (e.g., DT_ prefix).
	 * This method will add all those statically defined ElfDynamicType fields
	 * within this class.
	 * @param dynamicTypeMap map to which ElfDynamicType definitions should be added
	 */
	public final void addDynamicTypes(Map<Integer, ElfDynamicType> dynamicTypeMap) {

		for (Field field : getClass().getDeclaredFields()) {
			String name = null;
			try {
				if (Modifier.isStatic(field.getModifiers()) &&
					field.getType().equals(ElfDynamicType.class)) {
					ElfDynamicType type = (ElfDynamicType) field.get(this);
					name = type.name;
					ElfDynamicType.addDynamicType(type, dynamicTypeMap);
				}
			}
			catch (DuplicateNameException e) {
				Msg.error(this,
					"Invalid ElfDynamicType(" + name + ") defined by " + getClass().getName(), e);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertException(e);
			}
		}
	}

	/**
	 * Add all extension specific Program Header types (e.g., PT_ prefix).
	 * This method will add all those statically defined ElfProgramHeaderType fields
	 * within this class.
	 * @param programHeaderTypeMap map to which ElfProgramHeaderType definitions should be added
	 */
	public final void addProgramHeaderTypes(
			Map<Integer, ElfProgramHeaderType> programHeaderTypeMap) {

		for (Field field : getClass().getDeclaredFields()) {
			String name = null;
			try {
				if (Modifier.isStatic(field.getModifiers()) &&
					field.getType().equals(ElfProgramHeaderType.class)) {
					ElfProgramHeaderType type = (ElfProgramHeaderType) field.get(this);
					name = type.name;
					ElfProgramHeaderType.addProgramHeaderType(type, programHeaderTypeMap);
				}
			}
			catch (DuplicateNameException e) {
				Msg.error(this,
					"Invalid ElfProgramHeaderType(" + name + ") defined by " + getClass().getName(),
					e);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertException(e);
			}
		}
	}

	/**
	 * Add all extension specific Section Header types (e.g., SHT_ prefix).
	 * This method will add all those statically defined ElfSectionHeaderType fields
	 * within this class.
	 * @param sectionHeaderTypeMap map to which ElfSectionHeaderType definitions should be added
	 */
	public final void addSectionHeaderTypes(
			HashMap<Integer, ElfSectionHeaderType> sectionHeaderTypeMap) {

		for (Field field : getClass().getDeclaredFields()) {
			String name = null;
			try {
				if (Modifier.isStatic(field.getModifiers()) &&
					field.getType().equals(ElfSectionHeaderType.class)) {
					ElfSectionHeaderType type = (ElfSectionHeaderType) field.get(this);
					name = type.name;
					ElfSectionHeaderType.addSectionHeaderType(type, sectionHeaderTypeMap);
				}
			}
			catch (DuplicateNameException e) {
				Msg.error(this,
					"Invalid ElfSectionHeaderType(" + name + ") defined by " + getClass().getName(),
					e);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				throw new AssertException(e);
			}
		}
	}

	/**
	 * Get the preferred load address space for an allocated program segment.
	 * The OTHER space is reserved and should not be returned by this method.
	 * This method may only return a physical address space and not an overlay 
	 * address space.
	 * @param elfLoadHelper load helper object
	 * @param elfProgramHeader elf program segment header
	 * @return preferred load address space
	 */
	public AddressSpace getPreferredSegmentAddressSpace(ElfLoadHelper elfLoadHelper,
			ElfProgramHeader elfProgramHeader) {

		Program program = elfLoadHelper.getProgram();
		if (elfProgramHeader.isExecute()) {
			return program.getAddressFactory().getDefaultAddressSpace();
		}
		// segment is not marked execute, use the data space by default
		return program.getLanguage().getDefaultDataSpace();
	}

	/**
	 * Get the preferred load address for a program segment.
	 * This method may only return a physical address and not an overlay 
	 * address.
	 * @param elfLoadHelper load helper object
	 * @param elfProgramHeader elf program segment header
	 * @return preferred load address
	 */
	public Address getPreferredSegmentAddress(ElfLoadHelper elfLoadHelper,
			ElfProgramHeader elfProgramHeader) {

		Program program = elfLoadHelper.getProgram();

		AddressSpace space = getPreferredSegmentAddressSpace(elfLoadHelper, elfProgramHeader);

		long addrWordOffset = elfProgramHeader.getVirtualAddress();

		if (space == program.getAddressFactory().getDefaultAddressSpace()) {
			addrWordOffset += elfLoadHelper.getImageBaseWordAdjustmentOffset();
		}

		return space.getTruncatedAddress(addrWordOffset, true);
	}

	/**
	 * Get the default alignment within the default address space.
	 * @param elfLoadHelper helper object
	 * @return default alignment within the default address space.
	 */
	public int getDefaultAlignment(ElfLoadHelper elfLoadHelper) {
		Program program = elfLoadHelper.getProgram();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		int unitSize = space.getAddressableUnitSize();
		if (unitSize != 1) {
			return unitSize;
		}
		return elfLoadHelper.getElfHeader().is64Bit() ? 8 : 4;
	}

	/**
	 * Get the preferred load address space for an allocated section.   The OTHER space
	 * is reserved and should not be returned by this method.
	 * This method may only return a physical address space and not an overlay 
	 * address space.
	 * @param elfLoadHelper load helper object
	 * @param elfSectionHeader elf section header
	 * @return preferred load address space
	 */
	public AddressSpace getPreferredSectionAddressSpace(ElfLoadHelper elfLoadHelper,
			ElfSectionHeader elfSectionHeader) {
		Program program = elfLoadHelper.getProgram();
		if (elfSectionHeader.isExecutable()) {
			return program.getAddressFactory().getDefaultAddressSpace();
		}
		// segment is not marked execute, use the data space by default
		return program.getLanguage().getDefaultDataSpace();
	}

	/**
	 * Get the preferred load address for an allocated program section.  
	 * This method may only return a physical address and not an overlay 
	 * address.
	 * @param elfLoadHelper load helper object
	 * @param elfSectionHeader elf program section header
	 * @return preferred load address
	 */
	public Address getPreferredSectionAddress(ElfLoadHelper elfLoadHelper,
			ElfSectionHeader elfSectionHeader) {
		Program program = elfLoadHelper.getProgram();

		AddressSpace space = getPreferredSectionAddressSpace(elfLoadHelper, elfSectionHeader);

		long addrWordOffset = elfSectionHeader.getAddress();

		if (space == program.getAddressFactory().getDefaultAddressSpace()) {
			addrWordOffset += elfLoadHelper.getImageBaseWordAdjustmentOffset();
		}

		return space.getTruncatedAddress(addrWordOffset, true);
	}

	/**
	 * Check if this extension can handle the specified elf header.  If this method returns 
	 * true, this extension will be used to obtain extended types definitions and to perform
	 * additional load processing.
	 * @param elf elf header
	 * @return true if this extension should be used when loading the elf image which
	 * corresponds to the specified header.
	 */
	public boolean canHandle(ElfHeader elf) {
		return false;
	}

	/**
	 * Check if this extension can handle the specified elf image.  This method can provide
	 * a more accurate check based upon the actual language utilized.  While the ELF header
	 * may have stipulated a specific processor via the machine-id, a completely different
	 * and incompatible language may have been used.
	 * @param elfLoadHelper elf header
	 * @return true if this extension can properly support the ELF header and the 
	 * current program/language.
	 */
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return false;
	}

	/**
	 * Return the data type naming suffix which should be used when creating types derived 
	 * from data supplied by this extension.
	 * @return type naming suffix or null
	 */
	public String getDataTypeSuffix() {
		return null;
	}

	/**
	 * Perform any required offset adjustment to account for differences between offset 
	 * values contained within ELF headers and the language modeling of the 
	 * associated address space.
	 * <br>
	 * WARNING: This is an experimental method and is not yet fully supported.
	 * <br>
	 * NOTE: This has currently been utilized for symbol address offset adjustment only.
	 * @param elfOffset memory offset from ELF header
	 * @param space associated address space
	 * @return offset appropriate for use in space (does not account for image base alterations)
	 */
	public long getAdjustedMemoryOffset(long elfOffset, AddressSpace space) {
		return elfOffset;
	}

	/**
	 * Perform extension specific processing of Elf image during program load.
	 * The following loading steps will have already been completed:
	 * <pre>
	 * 1. default processing of all program headers and section headers
	 * 2. memory resolution and loading of all program headers and section headers
	 * 3. Markup completed of Elf header, program headers, section headers, dynamic table,
	 *    string tables, and symbol tables.
	 * </pre>
	 * Markup and application of relocation tables will NOT have been done yet. 
	 * @param elfLoadHelper load helper object
	 * @param monitor
	 * @throws CancelledException
	 */
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		// do nothing extra by default
	}

	/**
	 * Perform extension specific processing of Elf GOT/PLT tables and any other 
	 * related function relocation mechanism (e.g., function descriptors, etc) after
	 * normal REL/RELA relocation fix-ups have been applied.
	 * @param elfLoadHelper load helper object
	 * @param monitor
	 * @throws CancelledException
	 */
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		// The legacy GOT/PLT processing is performed by default
		ElfDefaultGotPltMarkup gotPltMarkup = new ElfDefaultGotPltMarkup(elfLoadHelper);
		gotPltMarkup.process(monitor);
	}

	/**
	 * Prior to the ELF loader creating a function this method will be invoked to permit an 
	 * extension to adjust the address and/or apply context to the intended location.
	 * @param elfLoadHelper load helper object
	 * @param functionAddress function address
	 * @return adjusted function address (required)
	 */
	public Address creatingFunction(ElfLoadHelper elfLoadHelper, Address functionAddress) {
		return functionAddress;
	}

	/**
	 * This method allows an extension to override the default address calculation for loading
	 * a symbol.  This is generally only neccessary when symbol requires handling of processor-specific 
	 * flags or section index.  This method should return null when default symbol processing 
	 * is sufficient. {@link Address#NO_ADDRESS} should be returned if the symbol is external
	 * and is not handled by default processing.
	 * @param elfLoadHelper load helper object
	 * @param elfSymbol elf symbol
	 * @return symbol memory address or null to defer to default implementation
	 * @throws NoValueException if error logged and address calculation failed
	 */
	public Address calculateSymbolAddress(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol)
			throws NoValueException {
		return null;
	}

	/**
	 * During symbol processing this method will be invoked to permit an extension to
	 * adjust the address and/or apply context to the intended symbol location.
	 * @param elfLoadHelper load helper object
	 * @param elfSymbol elf symbol
	 * @param address program memory address where symbol will be created
	 * @param isExternal true if symbol treated as external to the program and has been
	 * assigned a fake memory address in the EXTERNAL memory block.
	 * @return adjusted symbol address or null if extension will handle applying the elfSymbol
	 * to the program (must also invoke {@link ElfLoadHelper#setElfSymbolAddress(ElfSymbol, Address)},
	 * or symbol should not be applied. 
	 */
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {
		return address;
	}

	/**
	 * Get the write permission for the specified segment.
	 * @param segment program header object
	 * @return true if write enabled, else false or null to use standard Elf program header
	 * flags to make the determination.
	 */
	public Boolean isSegmentWritable(ElfProgramHeader segment) {
		return (segment.getFlags() & ElfProgramHeaderConstants.PF_W) != 0;
	}

	/**
	 * Get the read permission for the specified segment.
	 * @param segment program header object
	 * @return true if read enabled, else false or null to use standard Elf program header
	 * flags to make the determination.
	 */
	public Boolean isSegmentReadable(ElfProgramHeader segment) {
		return (segment.getFlags() & ElfProgramHeaderConstants.PF_R) != 0;
	}

	/**
	 * Get the execute permission for the specified segment.
	 * @param segment program header object
	 * @return true if execute enabled, else false or null to use standard Elf program header
	 * flags to make the determination.
	 */
	public Boolean isSegmentExecutable(ElfProgramHeader segment) {
		return (segment.getFlags() & ElfProgramHeaderConstants.PF_X) != 0;
	}

	/**
	 * Get the write permission for the specified section.
	 * @param section section header object
	 * @return true if write enabled, else false or null to use standard Elf section
	 * flags to make the determination.
	 */
	public Boolean isSectionWritable(ElfSectionHeader section) {
		return (section.getFlags() & ElfSectionHeaderConstants.SHF_WRITE) != 0;
	}

	/**
	 * Get the execute permission for the specified section (i.e., instructions permitted).
	 * @param section section header object
	 * @return true if execute enabled, else false or null to use standard Elf section
	 * flags to make the determination.
	 */
	public Boolean isSectionExecutable(ElfSectionHeader section) {
		return (section.getFlags() & ElfSectionHeaderConstants.SHF_EXECINSTR) != 0;
	}

	/**
	 * Determine if the specified section is "allocated" within memory.
	 * @param section section header object
	 * @return true if section should be allocated, else false or null to use standard Elf section
	 * flags to make the determination.
	 */
	public Boolean isSectionAllocated(ElfSectionHeader section) {
		return (section.getFlags() & ElfSectionHeaderConstants.SHF_ALLOC) != 0;
	}

	/**
	 * Return the memory bytes to be loaded from the underlying file for the specified program header.
	 * The returned value will be consistent with any byte filtering which may be required.
	 * @param elfProgramHeader
	 * @return preferred memory block size in bytes which corresponds to the specified program header
	 */
	public long getAdjustedLoadSize(ElfProgramHeader elfProgramHeader) {
		return elfProgramHeader.getFileSize();
	}

	/**
	 * Return the memory segment size in bytes for the specified program header.
	 * The returned value will be consistent with any byte filtering which may be required.
	 * @param elfProgramHeader
	 * @return preferred memory block size in bytes which corresponds to the specified program header
	 */
	public long getAdjustedMemorySize(ElfProgramHeader elfProgramHeader) {
		return elfProgramHeader.getMemorySize();
	}

	/**
	 * Get the dynamic memory block allocation alignment as addressable units
	 * within the default memory space.
	 * @return dynamic memory block allocation alignment.
	 */
	public int getLinkageBlockAlignment() {
		return 0x1000; // 4K alignment
	}

	/**
	 * Get the preferred free range size for the EXTERNAL memory block as addressable units
	 * within the default memory space.
	 * @return minimum free range size for EXTERNAL memory block as addressable units
	 */
	public int getPreferredExternalBlockSize() {
		return 0x20000; // 128K
	}

	/**
	 * Get reserve size of the EXTERNAL memory block as addressable units
	 * within the default memory space.  This size represents the largest 
	 * expansion size to the block which could occur during relocation
	 * processing.
	 * @return reserve size of the EXTERNAL memory block as addressable units
	 */
	public int getExternalBlockReserveSize() {
		return 0x10000; // 64K
	}

	/**
	 * Return the memory section size in bytes for the specified section header.
	 * The returned value will be consistent with any byte filtering which may be required.
	 * @param section the section header
	 * @return preferred memory block size in bytes which corresponds to the specified section header
	 */
	public long getAdjustedSize(ElfSectionHeader section) {
		return section.getSize();
	}

	/**
	 * Return filtered InputStream for loading a memory block (includes non-loaded OTHER blocks).
	 * NOTE: If this method is overriden, the {@link #hasFilteredLoadInputStream(ElfLoadHelper, MemoryLoadable, Address)}
	 * must also be overriden in a consistent fashion.
	 * @param elfLoadHelper
	 * @param loadable Corresponding ElfSectionHeader or ElfProgramHeader for the memory block to be created.
	 * @param start memory load address
	 * @param dataLength the in-memory data length in bytes (actual bytes read from dataInput may be more)
	 * @param dataInput the source input stream
	 * @return filtered input stream or original input stream
	 */
	public InputStream getFilteredLoadInputStream(ElfLoadHelper elfLoadHelper,
			MemoryLoadable loadable, Address start, long dataLength, InputStream dataInput) {
		return dataInput;
	}

	/**
	 * Determine if the use of {@link #getFilteredLoadInputStream(ElfLoadHelper, MemoryLoadable, Address, long, InputStream)} 
	 * is required when loading a memory block.  If a filtered input stream is required this will prevent the use of a direct 
	 * mapping to file bytes.
	 * @param elfLoadHelper 
	 * @param loadable Corresponding ElfSectionHeader or ElfProgramHeader for the memory block to be loaded.
	 * @param start memory load address
	 * @return true if the use of a filtered input stream is required
	 */
	public boolean hasFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, MemoryLoadable loadable,
			Address start) {
		return false;
	}

	/**
	 * Get the ElfRelocation class which should be used to properly parse
	 * the relocation tables.
	 * @param elfHeader ELF header object (for header field access only)
	 * @return ElfRelocation class or null for default behavior
	 */
	public Class<? extends ElfRelocation> getRelocationClass(ElfHeader elfHeader) {
		return null;
	}

}
