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

import ghidra.app.plugin.exceptionhandlers.gcc.datatype.SignedLeb128DataType;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.UnsignedLeb128DataType;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.AddressTranslationException;

/**
 * Extended by each of the various Dwarf exception handling decoders. Provides basic types and 
 * methods for maintaining and retrieving information specific to that decoder.
 */
abstract class AbstractDwarfEHDecoder implements DwarfEHDecoder {

	protected static ByteDataType BYTE_DATA_TYPE = ByteDataType.dataType;
	protected static WordDataType WORD_DATA_TYPE = WordDataType.dataType;
	protected static DWordDataType DWORD_DATA_TYPE = DWordDataType.dataType;
	protected static QWordDataType QWORD_DATA_TYPE = QWordDataType.dataType;

	protected static SignedLeb128DataType SLEB_DATA_TYPE = SignedLeb128DataType.dataType;
	protected static UnsignedLeb128DataType ULEB_DATA_TYPE = UnsignedLeb128DataType.dataType;

	protected DwarfEHDataApplicationMode appMode = DwarfEHDataApplicationMode.DW_EH_PE_absptr;

	protected boolean isIndirect = false;

	@Override
	public void setApplicationMode(DwarfEHDataApplicationMode mode) {
		if (mode == null) {
			mode = DwarfEHDataApplicationMode.DW_EH_PE_absptr;
		}
		appMode = mode;
	}

	@Override
	public void setIndirect(boolean isIndirect) {
		this.isIndirect = isIndirect;
	}

	@Override
	public DwarfEHDataApplicationMode getDataApplicationMode() {
		return appMode;
	}

	@Override
	public String toString() {
		String repr = getDataFormat() + " | " + getDataApplicationMode();
		if (isIndirect) {
			repr += " | " + DwarfEHDataApplicationMode.DW_EH_PE_indirect;
		}
		return repr;
	}

	/**
	 * Reads a pointer-size value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @return The value of the pointer reference
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected long ptrval(Program program, Address addr) throws MemoryAccessException {
		switch (addr.getPointerSize()) {
			case 2:
				return readWord(program, addr);
			case 4:
				return readDWord(program, addr);
			case 8:
				long base = readDWord(program, addr);
				// long ex = readDWord(program, addr.add(4));
				// if (ex == 0) {
				// return (ex << 32) + base;
				// }
				return base;

			default:
				throw new AddressTranslationException("Don't know how to make a " +
					addr.getPointerSize() + "-byte pointer");
		}
	}

	/**
	 * Reads a <code>ptrSize</code> integer value at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @param ptrSize the size of the pointer to be read.
	 * @return The value of the pointer reference
	 * @throws MemoryAccessException if the data can't be read
	 */

	protected long ptrval(MemBuffer buf, int ptrSize) throws MemoryAccessException {
		switch (ptrSize) {
			case 2:
				return readWord(buf);
			case 4:
				return readDWord(buf);
			case 8:
				return readQWord(buf);
			default:
				throw new AddressTranslationException("Don't know how to make a " + ptrSize +
					"-byte pointer");
		}
	}

	/**
	 * Reads an 8-bit value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @return The value of the byte
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readByte(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getByte(addr);
	}

	/**
	 * Reads an 8-bit value from <code>program</code> at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @param length Unused
	 * @return The value of the byte
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readByte(MemBuffer buf, int length) throws MemoryAccessException {
		return buf.getByte(0);
	}

	/**
	 * Reads a 16-bit value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @return The value of the word
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readWord(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getShort(addr);
	}

	/**
	 * Reads a 16-bit value at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @return The value of the word
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readWord(MemBuffer buf) throws MemoryAccessException {
		return buf.getShort(0);
	}

	/**
	 * Reads a 32-bit value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @return The value of the dword
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readDWord(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getInt(addr);
	}

	/**
	 * Reads a 32-bit value at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @return The value of the dword
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readDWord(MemBuffer buf) throws MemoryAccessException {
		return buf.getInt(0);
	}

	/**
	 * Reads a 64-bit value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @return The value of the qword
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readQWord(Program program, Address addr) throws MemoryAccessException {
		return program.getMemory().getLong(addr);
	}

	/**
	 * Reads a 64-bit value at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @return The value of the qword
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static long readQWord(MemBuffer buf) throws MemoryAccessException {
		return buf.getLong(0);
	}

	/**
	 * Reads bytes from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @param buffer Destination buffer to read into
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static void readBytes(Program program, Address addr, byte[] buffer)
			throws MemoryAccessException {
		program.getMemory().getBytes(addr, buffer);
	}

	/**
	 * Reads bytes at the address of <code>buf</code> into <code>buffer</code> up to the length of 
	 * <code>buffer</code>. 
	 * @param buf Buffer to read from
	 * @param buffer Destination buffer to read into
	 * @return the number of bytes read into the buffer
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected static int readBytes(MemBuffer buf, byte[] buffer) throws MemoryAccessException {
		return buf.getBytes(buffer, 0);
	}

	/**
	 * Reads an unsigned LEB128-encoded value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected long read_leb128(Program program, Address addr) throws MemoryAccessException {
		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		Scalar scalar =
			(Scalar) uleb.getValue(buf, uleb.getDefaultSettings(), uleb.getLength(buf, -1));
		return scalar.getUnsignedValue();

	}

	/**
	 * Reads an unsigned LEB128-encoded value from <code>program</code> at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @param length Unused
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected long read_leb128(MemBuffer buf, int length) throws MemoryAccessException {

		UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;

		Scalar scalar =
			(Scalar) uleb.getValue(buf, uleb.getDefaultSettings(), uleb.getLength(buf, -1));
		return scalar.getUnsignedValue();

	}

	/**
	 * Reads a signed LEB128-encoded value from <code>program</code> at <code>addr</code>
	 * @param program Program to read from
	 * @param addr Address to read from
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected long read_sleb128(Program program, Address addr) throws MemoryAccessException {

		SignedLeb128DataType sleb = SignedLeb128DataType.dataType;

		MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
		Scalar scalar =
			(Scalar) sleb.getValue(buf, sleb.getDefaultSettings(), sleb.getLength(buf, -1));
		return scalar.getSignedValue();
	}

	/**
	 * Reads a signed LEB128-encoded value from <code>program</code> at the address of <code>buf</code>
	 * @param buf Buffer to read from
	 * @param length Number of bytes to read
	 * @param buffer Destination buffer to read into
	 * @throws MemoryAccessException if the data can't be read
	 */
	protected long read_sleb128(MemBuffer buf, int length) throws MemoryAccessException {

		SignedLeb128DataType sleb = SignedLeb128DataType.dataType;

		Scalar scalar =
			(Scalar) sleb.getValue(buf, sleb.getDefaultSettings(), sleb.getLength(buf, -1));
		return scalar.getSignedValue();
	}

	/**
	 * Get the DWARF-encoded address value as stored by the context
	 * @param context Stores program location and decode parameters
	 * @return the address
	 * @throws MemoryAccessException if the data can't be read
	 */
	@Override
	public Address decodeAddress(DwarfDecodeContext context) throws MemoryAccessException {
		Program prog = context.getProgram();
		AddressFactory addrFactory = prog.getAddressFactory();
		AddressSpace ram = addrFactory.getDefaultAddressSpace();

		long offset = decode(context);

		return addrFactory.getAddress(ram.getSpaceID(), offset);
	}

	/**
	 * Get the DWARF-encoded integer value as stored by the context
	 * @param context Stores program location and decode parameters
	 * @return the integer value
	 * @throws MemoryAccessException if the data can't be read
	 */
	@Override
	public final long decode(DwarfDecodeContext context) throws MemoryAccessException {

		long val = doDecode(context);

		return resolveRelativeOffset(val, context);

	}

	private long resolveRelativeOffset(long val, DwarfDecodeContext context)
			throws MemoryAccessException {
		Program prog = context.getProgram();
		Address addr = context.getAddress();

		AddressSpace ram = prog.getAddressFactory().getDefaultAddressSpace();

		if ((val == 0 || val == addr.getOffset()) && isIndirect) {
			// if val is 0 don't dereference a null pointer
			// if val is unchanged, don't enter a dereference-loop via ptrVal() below
			return val;
		}

		switch (appMode) {
			case DW_EH_PE_absptr:
				// just pass this through
				break;

			case DW_EH_PE_aligned:

				break;

			case DW_EH_PE_datarel:
				val = context.getEhBlock().getStart().add(val).getOffset();
				break;

			case DW_EH_PE_funcrel:
				val = context.getFunctionEntryPoint().add(val).getOffset();
				break;

			case DW_EH_PE_pcrel:
				val = addr.add(val).getOffset();
				break;

			case DW_EH_PE_texrel:
				MemoryBlock txt = prog.getMemory().getBlock(".text");

				val = txt.getStart().add(val).getOffset();
				break;

			default:
				break;

		}

		if (isIndirect) {
			Address toDeref = prog.getAddressFactory().getAddress(ram.getSpaceID(), val);
			val = ptrval(prog, toDeref);
		}

		return val;
	}

	/**
	 * Decode an integer value according to parameters stored in the <code>context</code> object.
	 * @param context Stores program location and decode parameters
	 * @return the integer value
	 * @throws MemoryAccessException if the data can't be read
	 */
	public abstract long doDecode(DwarfDecodeContext context) throws MemoryAccessException;

}
