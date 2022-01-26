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
package ghidra.app.plugin.exceptionhandlers.gcc;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Organizational class to record vital data used by a DwarfEHDecoder.
 */
public class DwarfDecodeContext {

	private final Program program;
	private final Address addr;
	private final MemoryBlock ehBlock;
	private final Address functionEntryPoint;

	private Object decodedValue;
	private int encodedLength;
	private MemBuffer buffer;

	/**
	 * Constructs a Dwarf decode context.
	 * @param program the program containing the encoded data 
	 * @param readAddr the address of the encoded data 
	 */
	public DwarfDecodeContext(Program program, Address readAddr) {
		this(program, readAddr, null, null);
	}

	/**
	 * Constructs a Dwarf decode context.
	 * @param program the program containing the encoded data 
	 * @param readAddr the address of the encoded data 
	 * @param ehBlock the exception handling memory block
	 */
	public DwarfDecodeContext(Program program, Address readAddr, MemoryBlock ehBlock) {
		this(program, readAddr, ehBlock, null);
	}

	/**
	 * Constructs a Dwarf decode context.
	 * @param program the program containing the encoded data 
	 * @param readAddr the address of the encoded data 
	 * @param entryPoint the associated function's entry point
	 */
	public DwarfDecodeContext(Program program, Address readAddr, Address entryPoint) {
		this(program, readAddr, null, entryPoint);
	}

	/**
	 * Constructs a Dwarf decode context.
	 * @param program the program containing the encoded data 
	 * @param readAddr the address of the encoded data 
	 * @param function the associated function
	 */
	public DwarfDecodeContext(Program program, Address readAddr, Function function) {
		this(program, readAddr, null, function.getEntryPoint());
	}

	/**
	 * Constructs a Dwarf decode context.
	 * @param program the program containing the encoded data 
	 * @param readAddr the address of the encoded data 
	 * @param ehBlock the exception handling memory block
	 * @param entryPoint the associated function's entry point
	 */
	public DwarfDecodeContext(Program program, Address readAddr, MemoryBlock ehBlock,
			Address entryPoint) {

		if (program == null) {
			throw new NullPointerException("DwarfDecodeContext requires a program");
		}
		if (readAddr == null) {
			throw new NullPointerException("DwarfDecodeContext requires an address");
		}

		this.program = program;
		this.addr = readAddr;
		this.ehBlock = ehBlock;
		this.functionEntryPoint = entryPoint;

	}

	/**
	 * Constructs a Dwarf decode context.
	 * @param buffer the memory buffer which provides the program and address of the encoded data 
	 * @param length the length of the encoded data
	 */
	public DwarfDecodeContext(MemBuffer buffer, int length) {
		this(buffer, length, null, null);
	}

	/**
	 * Constructs a Dwarf decode context.
	 * @param buf the memory buffer which provides the program and address of the encoded data 
	 * @param length the length of the encoded data
	 * @param ehBlock the exception handling memory block
	 * @param entryPoint the function entry point
	 */
	public DwarfDecodeContext(MemBuffer buf, int length, MemoryBlock ehBlock, Address entryPoint) {
		this.buffer = buf;
		this.program = buffer.getMemory().getProgram();
		this.addr = buffer.getAddress();
		this.ehBlock = ehBlock;
		this.functionEntryPoint = entryPoint;
	}

	/**
	 * Gets the program containing the encoded data.
	 * @return the program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Gets the min address of the encoded data.
	 * @return the address
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Set the value and value-length after decode
	 * @param value The integer-value having been decoded
	 * @param encodedLength The length of the encoded integer-value
	 */

	public void setDecodedValue(Object value, int encodedLength) {
		this.decodedValue = value;
		this.encodedLength = encodedLength;
	}

	/**
	 * Gets the decoded value that is at the address.
	 * @return the decoded value
	 */
	public Object getDecodedValue() {
		return decodedValue;
	}

	/**
	 * Gets the length of the encoded data that is at the address.
	 * @return the encoded data's length
	 */
	public int getEncodedLength() {
		return encodedLength;
	}

	/**
	 * Gets the exception handling memory block with this dwarf encoded data.
	 * @return the memory block
	 */
	public MemoryBlock getEhBlock() {
		return ehBlock;
	}

	/**
	 * Gets the associated function's entry point.
	 * @return the entry point address
	 */
	public Address getFunctionEntryPoint() {
		return functionEntryPoint;
	}
}
