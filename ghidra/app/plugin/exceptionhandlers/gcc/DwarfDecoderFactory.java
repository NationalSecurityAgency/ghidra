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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.exceptionhandlers.gcc.datatype.SignedLeb128DataType;
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.UnsignedLeb128DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;

/**
 * Generate instances of DwarfEHDecoder suitable for various pointer-encodings.
 */
public class DwarfDecoderFactory {

	private static final Map<DwarfEHDataDecodeFormat, DwarfEHDecoder> decoderMap = new HashMap<>();
	static {
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_absptr, new DW_EH_PE_absptr_Decoder());
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_uleb128, new DW_EH_PE_uleb128_Decoder());

		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_udata2, new DW_EH_PE_udata2_Decoder());
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_udata4, new DW_EH_PE_udata4_Decoder());
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_udata8, new DW_EH_PE_udata8_Decoder());

		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_signed, new DW_EH_PE_signed_Decoder());
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_sleb128, new DW_EH_PE_sleb128_Decoder());

		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_sdata2, new DW_EH_PE_sdata2_Decoder());
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_sdata4, new DW_EH_PE_sdata4_Decoder());
		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_sdata8, new DW_EH_PE_sdata8_Decoder());

		decoderMap.put(DwarfEHDataDecodeFormat.DW_EH_PE_omit, new DW_EH_PE_omit_Decoder());
	}

	/** 
	 * Get the appropriate decoder for the given decode format and application mode  
	 * @param decodeFormat the exception handling data decoding format
	 * @param appFormat the desired application mode
	 * @param isIndirect flag indicating whether or not the data is an indirect reference
	 * @return the decoder or null
	 */
	public static DwarfEHDecoder getDecoder(DwarfEHDataDecodeFormat decodeFormat,
			DwarfEHDataApplicationMode appFormat, boolean isIndirect) {

		DwarfEHDecoder decoder = decoderMap.get(decodeFormat);
		if (decoder == null) {
			return null;
		}

		decoder.setApplicationMode(appFormat);

		decoder.setIndirect(isIndirect);

		return decoder;
	}

	/**
	 * Get the appropriate decoder for the given 8-bit mode; mode is parsed into
	 * decode format, application mode, and indirection flag.
	 * @see #getDecoder(DwarfEHDataDecodeFormat, DwarfEHDataApplicationMode, boolean)
	 * @param mode a byte that indicates an encoding
	 * @return the decoder for the indicated mode of encoding
	 */
	public static DwarfEHDecoder getDecoder(int mode) {

		int format = mode & 0x0F;
		int appl = mode & 0x70;
		boolean isIndirect = (mode & 0x80) == 0x80;

		if ((mode & 0xFF) == 0xFF) {
			DwarfEHDecoder decoder = decoderMap.get(DwarfEHDataDecodeFormat.DW_EH_PE_omit);
			decoder.setApplicationMode(DwarfEHDataApplicationMode.DW_EH_PE_omit);
			return decoder;
		}

		DwarfEHDataDecodeFormat style = DwarfEHDataDecodeFormat.valueOf(format);
		DwarfEHDataApplicationMode mod = DwarfEHDataApplicationMode.valueOf(appl);

		return getDecoder(style, mod, isIndirect);
	}

	private static abstract class AbstractSignedDwarEHfDecoder extends AbstractDwarfEHDecoder {

		@Override
		public boolean isSigned() {
			return true;
		}
	}

	private static abstract class AbstractUnsignedDwarfEHDecoder extends AbstractDwarfEHDecoder {

		@Override
		public boolean isSigned() {
			return false;
		}
	}

	static final class DW_EH_PE_absptr_Decoder extends AbstractUnsignedDwarfEHDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_absptr;
		}

		@Override
		public int getDecodeSize(Program program) {
			AddressSpace defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
			Address maxAddress = defaultAddressSpace.getMaxAddress();
			int pointerSize = maxAddress.getPointerSize();
			switch (pointerSize) {
				case 3:
					return 4; // 3 uses 4 bytes

				case 5:
				case 6:
				case 7:
					return 8; // 5 thru 7 use 8 bytes

				default:
					return pointerSize;
			}
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {

			Program program = context.getProgram();
			Address addr = context.getAddress();

			MemoryBufferImpl memBuf = new MemoryBufferImpl(program.getMemory(), addr);

			int decodeSize = getDecodeSize(program);
			long offset = ptrval(memBuf, decodeSize);

			context.setDecodedValue(offset, decodeSize);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			int ptrSize = getDecodeSize(program);
			switch (ptrSize) {
				case 2:
					return WORD_DATA_TYPE;
				case 4:
					return DWORD_DATA_TYPE;
				case 8:
					return QWORD_DATA_TYPE;
			}
			throw new IllegalStateException("Don't have a type for " + ptrSize + "-byte pointers");
		}
	}

	static final class DW_EH_PE_omit_Decoder extends AbstractUnsignedDwarfEHDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_omit;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 0;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {

			context.setDecodedValue(null, 0);

			return 0;
		}

		@Override
		public DataType getDataType(Program program) {
			return new VoidDataType();
		}
	}

	static final class DW_EH_PE_uleb128_Decoder extends AbstractUnsignedDwarfEHDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_uleb128;
		}

		@Override
		public int getDecodeSize(Program program) {
			return -1;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
			UnsignedLeb128DataType uleb = UnsignedLeb128DataType.dataType;

			int numAvailBytes = uleb.getLength(buf, -1);

			Scalar scalar = (Scalar) uleb.getValue(buf, uleb.getDefaultSettings(), numAvailBytes);
			long offset = scalar.getUnsignedValue();
			int readLen = uleb.getLength(buf, numAvailBytes);

			context.setDecodedValue(offset, readLen);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return ULEB_DATA_TYPE;
		}

	}

	static final class DW_EH_PE_udata2_Decoder extends AbstractUnsignedDwarfEHDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_udata2;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 2;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			long offset = readWord(program, addr);

			context.setDecodedValue(offset, 2);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return WORD_DATA_TYPE;
		}
	}

	static final class DW_EH_PE_udata4_Decoder extends AbstractUnsignedDwarfEHDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_udata4;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 4;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			long offset = readDWord(program, addr);

			context.setDecodedValue(offset, 4);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return DWORD_DATA_TYPE;
		}
	}

	static final class DW_EH_PE_udata8_Decoder extends AbstractUnsignedDwarfEHDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_udata8;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 8;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			long offset = readQWord(program, addr);

			context.setDecodedValue(offset, 8);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return QWORD_DATA_TYPE;
		}
	}

	static final class DW_EH_PE_signed_Decoder extends AbstractSignedDwarEHfDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_signed;
		}

		@Override
		public int getDecodeSize(Program program) {
			return -1;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			throw new MemoryAccessException(
				"Don't know now to decode DW_EH_PE_signed-encoded values");
		}

		@Override
		public DataType getDataType(Program program) {
			return new VoidDataType();
		}
	}

	static final class DW_EH_PE_sleb128_Decoder extends AbstractSignedDwarEHfDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_sleb128;
		}

		@Override
		public int getDecodeSize(Program program) {
			return -1;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), addr);
			SignedLeb128DataType sleb = SignedLeb128DataType.dataType;

			int numAvailBytes = sleb.getLength(buf, -1);

			Scalar scalar = (Scalar) sleb.getValue(buf, sleb.getDefaultSettings(), numAvailBytes);
			long offset = scalar.getSignedValue();
			int readLen = sleb.getLength(buf, numAvailBytes);

			context.setDecodedValue(offset, readLen);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return SLEB_DATA_TYPE;
		}
	}

	static final class DW_EH_PE_sdata2_Decoder extends AbstractSignedDwarEHfDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_sdata2;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 2;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			long offset = readWord(program, addr);

			context.setDecodedValue(offset, 2);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return WORD_DATA_TYPE;
		}
	}

	static final class DW_EH_PE_sdata4_Decoder extends AbstractSignedDwarEHfDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_sdata4;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 4;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			long offset = readDWord(program, addr);

			context.setDecodedValue(offset, 4);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return DWORD_DATA_TYPE;
		}
	}

	static final class DW_EH_PE_sdata8_Decoder extends AbstractSignedDwarEHfDecoder {

		@Override
		public DwarfEHDataDecodeFormat getDataFormat() {
			return DwarfEHDataDecodeFormat.DW_EH_PE_sdata8;
		}

		@Override
		public int getDecodeSize(Program program) {
			return 8;
		}

		@Override
		public long doDecode(DwarfDecodeContext context) throws MemoryAccessException {
			Program program = context.getProgram();
			Address addr = context.getAddress();

			long offset = readQWord(program, addr);

			context.setDecodedValue(offset, 8);

			return offset;
		}

		@Override
		public DataType getDataType(Program program) {
			return QWORD_DATA_TYPE;
		}
	}
}
