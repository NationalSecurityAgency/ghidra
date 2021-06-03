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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
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
	 * @param address
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
	 * Create an undefined data item to reserve the location as data, without specifying the type
	 * @param address  location of undefined data to create
	 * @param length  size of the undefined data item
	 */
	Data createUndefinedData(Address address, int length);

	/**
	 * Create a data item using the specified data type
	 * @param address  location of undefined data to create
	 * @param dt data type
	 * @return data or null if not successful
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
	 * @throws InvalidInputException
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
	 * will be used, otherwise null will be returned.
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

}
