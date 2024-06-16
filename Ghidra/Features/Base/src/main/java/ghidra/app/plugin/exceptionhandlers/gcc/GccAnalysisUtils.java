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

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

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
	public static void readBytes(Program program, Address addr, byte[] buffer)
			throws MemoryAccessException {
		program.getMemory().getBytes(addr, buffer);
	}

	/**
	 * Reads an unsigned little endian base 128 integer from memory.
	 * 
	 * @param program the program with memory to be read.
	 * @param addr the address in memory to begin reading the unsigned LEB128.
	 * @return {@link LEB128Info} (value + metadata)
	 */
	public static LEB128Info readULEB128Info(Program program, Address addr)
			throws MemoryAccessException {
		LEB128Info uleb128 = readLEB128Info(program, addr, false);
		return uleb128;
	}

	/**
	 * Reads an signed little endian base 128 integer from memory.
	 * 
	 * @param program the program with memory to be read.
	 * @param addr the address in memory to begin reading the signed LEB128.
	 * @return {@link LEB128Info} (value + metadata)
	 */
	public static LEB128Info readSLEB128Info(Program program, Address addr)
			throws MemoryAccessException {
		LEB128Info sleb128 = readLEB128Info(program, addr, true);
		return sleb128;
	}

	private static LEB128Info readLEB128Info(Program program, Address addr, boolean isSigned)
			throws MemoryAccessException {
		try (MemoryByteProvider mbp =
			new MemoryByteProvider(program.getMemory(), addr.getAddressSpace())) {
			BinaryReader br = new BinaryReader(mbp, !program.getMemory().isBigEndian());
			br.setPointerIndex(addr.getOffset());

			return LEB128Info.readValue(br, isSigned);
		}
		catch (IOException e) {
			throw new MemoryAccessException("Error reading LEB128 value at " + addr.toString(), e);
		}
	}

}
