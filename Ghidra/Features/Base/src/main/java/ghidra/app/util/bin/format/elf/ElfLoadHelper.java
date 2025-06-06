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
package ghidra.app.util.bin.format.elf;

import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoaderOptionsFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;

/**
 * <code>ElfLoadHelper</code> exposes loader methods useful to ElfExtension 
 * implementations.
 */
public interface ElfLoadHelper {

	/**
	 * Get program object
	 * @return program object
	 */
	Program getProgram();

	/**
	 * Get an import processing option value
	 * @param <T> class of option value (e.g., String, Boolean, etc.)
	 * @param optionName option name
	 * @param defaultValue default option value which also establishes expected value type
	 * @return option value
	 */
	<T> T getOption(String optionName, T defaultValue);

	/**
	 * Get ELF Header object
	 * @return ELF Header object
	 */
	ElfHeader getElfHeader();

	/**
	 * Get the message log
	 * @return message log
	 */
	MessageLog getLog();

	/**
	 * Output loader log message
	 * @param msg text message
	 */
	void log(String msg);

	/**
	 * Output loader log message.
	 * @param t exception/throwable error
	 */
	void log(Throwable t);

	/**
	 * Mark this location as code in the CodeMap.
	 * The analyzers will pick this up and disassemble the code.
	 * @param address code memory address to be marked
	 */
	void markAsCode(Address address);

	/**
	 * Create a one-byte function, so that when the code is analyzed,
	 * it will be disassembled, and the function created with the correct body.
	 * @param name name of function or null for default (or label already applied)
	 * @param address address of function
	 * @param isEntry mark function as entry point if true
	 * @return new or existing function.
	 */
	Function createOneByteFunction(String name, Address address, boolean isEntry);

	/**
	 * Create an external function within the UNKNOWN space and a corresponding thunk at 
	 * the internalFunctionAddr.  If the functionAddr and/or indirectPointerAddr has a symbol with
	 * {@code <name>} it will be removed so as not to replicate the external function name.
	 * @param name external function name
	 * @param functionAddr location of thunk function (memory address only)
	 * @param indirectPointerAddr if not null a pointer to functionAddr will be written (size of pointer
	 * based 32 or 64 bits based upon ELF size).  Memory must exist and will be converted to initialized
	 * if needed.
	 * @return thunk function or null if failure occurred
	 */
	Function createExternalFunctionLinkage(String name, Address functionAddr,
			Address indirectPointerAddr);

	/**
	 * Create an undefined data item to reserve the location as data, without specifying the type.
	 * If {@link ElfLoaderOptionsFactory#applyUndefinedSymbolData(java.util.List)} returns false
	 * data will not be applied and null will be returned.
	 * 
	 * @param address  location of undefined data to create
	 * @param length  size of the undefined data item
	 * @return {@link Data} which was created or null if conflict occurs or disabled by option
	 */
	Data createUndefinedData(Address address, int length);

	/**
	 * Create a data item using the specified data type
	 * @param address  location of undefined data to create
	 * @param dt data type
	 * @return {@link Data} which was created or null if conflict occurs
	 */
	Data createData(Address address, DataType dt);

	/**
	 * Add specified elfSymbol to the loader symbol map after its program address has been assigned
	 * @param elfSymbol elf symbol
	 * @param address program address (may be null if not applicable)
	 */
	void setElfSymbolAddress(ElfSymbol elfSymbol, Address address);

	/**
	 * Get the memory address of a previously resolved symbol
	 * @param elfSymbol elf symbol
	 * @return memory address or null if unknown
	 */
	Address getElfSymbolAddress(ElfSymbol elfSymbol);

	/**
	 * Create the specified label symbol within the program.
	 * @param addr program address
	 * @param name symbol/label name
	 * @param isPrimary true if is symbol should be made primary (certain name patterns excluded)
	 * @param pinAbsolute true if address is absolute and should not change 
	 * @param namespace symbol namespace (should generally be null for global namespace)
	 * @return program symbol
	 * @throws InvalidInputException if an invalid name is specified
	 */
	Symbol createSymbol(Address addr, String name, boolean isPrimary, boolean pinAbsolute,
			Namespace namespace) throws InvalidInputException;

	/**
	 * Find the program address at which a specified offset within a section or segment was loaded/resolved.
	 * @param section a segment or section header which was loaded to memory
	 * @param byteOffsetWithinSection offset within section
	 * @return resolved load address or null if not loaded
	 */
	Address findLoadAddress(MemoryLoadable section, long byteOffsetWithinSection);

	/**
	 * Get the program address for an addressableWordOffset within the default address space.  
	 * This method is responsible for applying any program image base change imposed during 
	 * the import (see {@link #getImageBaseWordAdjustmentOffset()}.
	 * @param addressableWordOffset absolute word offset.  The offset should already include
	 * default image base and pre-link adjustment (see {@link ElfHeader#adjustAddressForPrelink(long)}).  
	 * @return memory address in default code space
	 */
	Address getDefaultAddress(long addressableWordOffset);

	/**
	 * Get the program image base offset adjustment.  The value returned reflects the
	 * actual program image base minus the default image base (see {@link ElfHeader#getImageBase()}.
	 * This will generally be zero (0), unless the program image base differs from the
	 * default.  It may be necessary to add this value to any pre-linked address values
	 * such as those contained with the dynamic table. (Applies to default address space only)
	 * @return image base adjustment value
	 */
	public long getImageBaseWordAdjustmentOffset();

	/**
	 * Returns the appropriate .got (Global Offset Table) section address using the
	 * DT_PLTGOT value defined in the .dynamic section.
	 * If the dynamic value is not defined, the symbol offset for _GLOBAL_OFFSET_TABLE_
	 * will be used, otherwise null will be returned.  See {@link ElfConstants#GOT_SYMBOL_NAME}.
	 * @return the .got section address offset
	 */
	public Long getGOTValue();

	/**
	 * <p>Get a free aligned address range within the program's memory block structure to facilitate 
	 * dynamic memory block allocation requirements to support relocation processing (e.g., fake EXTERNAL memory block,
	 * generated GOT for object modules, etc.).  The range returned for the EXTERNAL memory block may be very large
	 * but only that portion used should be committed the program's memory map.  The EXTERNAL memory block
	 * must be committed to the memory map prior to any subsequent invocations of this method</p>
	 * <p>
	 * NOTES: Additional support may be required for spaces with odd word sizes,
	 * small 16-bit default memory space, or when shared memory regions exist.
	 * </p>
	 * @param alignment required byte alignment of allocated range
	 * @param size size of requested allocation (size &lt;= 0 reserved for EXTERNAL block)
	 * @param purpose brief descriptive purpose of range.
	 * @return address range or null if no unallocated range found
	 */
	public AddressRange allocateLinkageBlock(int alignment, int size, String purpose);

	/**
	 * <p>Get the original memory value at the specified address if a relocation was applied at the
	 * specified address (not containing).  Current memory value will be returned if no relocation
	 * has been applied at specified address.  The value size is either 8-bytes if {@link ElfHeader#is64Bit()},
	 * otherwise it will be 4-bytes.  This is primarily intended to inspect original bytes within 
	 * the GOT which may have had relocations applied to them.
	 * @param addr memory address
	 * @param signExtend if true sign-extend to long, else treat as unsigned
	 * @return original bytes value
	 * @throws MemoryAccessException if memory read fails
	 */
	public long getOriginalValue(Address addr, boolean signExtend)
			throws MemoryAccessException;

	/**
	 * Add an artificial relocation table entry if none previously existed for the specified address.
	 * This is intended to record original file bytes when forced modifications have been
	 * performed during the ELF import processing.  A relocation type of 0 and a status of 
	 * {@link Status#APPLIED_OTHER} will be applied to the relocation entry.  
	 * NOTE: The number of recorded original FileBytes currently ignores the specified length.
	 * However, the length is still used to verify that the intended modification region
	 * does not intersect another relocation.
	 * @param address relocation address
	 * @param length number of bytes affected
	 * @return true if recorded successfully, or false if conflict with existing relocation 
	 * entry and memory addressing error occurs
	 */
	public boolean addArtificialRelocTableEntry(Address address, int length);

}
