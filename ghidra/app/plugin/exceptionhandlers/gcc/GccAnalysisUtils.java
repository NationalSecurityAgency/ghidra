/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.plugin.exceptionhandlers.gcc.datatype.SignedLeb128DataType;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.UnsignedLeb128DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;

/**
 * Utility methods for use by the gcc exception handling analysis.
 */
public class GccAnalysisUtils {

	/**
	 * Reads a byte from the program's memory at the indicated address.
	 * @param program the program containing the byte to read
	 * @param addr the address to start reading
	 * @return the byte
	 * @throws MemoryAccessException if the byte can't be read.
	 */
	public static byte readByte(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getByte(addr);
	}

	/**
	 * Reads a word from the program's memory starting at the indicated address.
	 * @param program the program containing the bytes to read
	 * @param addr the address to start reading
	 * @return the word
	 * @throws MemoryAccessException if 2 bytes can't be read.
	 */
	public static int readWord(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getShort(addr);
	}

	/**
	 * Reads a double word from the program's memory starting at the indicated address.
	 * @param program the program containing the bytes to read
	 * @param addr the address to start reading
	 * @return the double word
	 * @throws MemoryAccessException if 4 bytes can't be read.
	 */
	public static long readDWord(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getInt(addr);
	}

	/**
	 * Reads a quad word from the program's memory starting at the indicated address.
	 * @param program the program containing the bytes to read
	 * @param addr the address to start reading
	 * @return the quad word
	 * @throws MemoryAccessException if 8 bytes can't be read.
	 */
	public static long readQWord(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getLong(addr);
	}

	/**
	 * Reads buffer.length number of bytes from the program's memory starting at the indicated address.
	 * @param program the program containing the bytes to read
	 * @param addr the address to start reading
	 * @param buffer the array to save the bytes that were read.
	 * @throws MemoryAccessException if the expected number of bytes can't be read.
	 */
	public static void readBytes(Program program, Address addr, byte[] buffer) throws MemoryAccessException {
		program.getMemory().getBytes(addr, buffer);
	}

	/**
	 * Reads an unsigned little endian base 128 integer from memory.
	 * @param program the program with memory to be read.
	 * @param addr the address in memory to begin reading the unsigned LEB128.
	 * @return the unsigned LEB128 integer.
	 */
	public static long readULEB128(Program program, Address addr) {
		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		Scalar scalar = (Scalar) uleb.getValue(buf, uleb.getDefaultSettings(), uleb.getLength(buf, -1));
		return scalar.getUnsignedValue();
	}

	/**
	 * Gets the size of an unsigned little endian base 128 integer.
	 * @param program the program with memory to be read.
	 * @param addr the address in memory to begin reading the unsigned LEB128.
	 * @return the length of the unsigned LEB128 integer.
	 */
	public static int getULEB128Length(Program program, Address addr) {
		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		return uleb.getLength(buf, -1);
	}

	/**
	 * Reads an signed little endian base 128 integer from memory.
	 * @param program the program with memory to be read.
	 * @param addr the address in memory to begin reading the signed LEB128.
	 * @return the signed LEB128 integer.
	 */
	public static long readSLEB128(Program program, Address addr) {
		SignedLeb128DataType sleb = SignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		Scalar scalar = (Scalar) sleb.getValue(buf, sleb.getDefaultSettings(), sleb.getLength(buf, -1));
		return scalar.getUnsignedValue();
	}

	/**
	 * Gets the size of a signed little endian base 128 integer.
	 * @param program the program with memory to be read.
	 * @param addr the address in memory to begin reading the signed LEB128.
	 * @return the length of the signed LEB128 integer.
	 */
	public static int getSLEB128Length(Program program, Address addr) {
		SignedLeb128DataType sleb = SignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		return sleb.getLength(buf, -1);
	}

}
