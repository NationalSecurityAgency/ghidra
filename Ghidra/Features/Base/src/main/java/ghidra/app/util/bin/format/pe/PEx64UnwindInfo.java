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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.ImageRuntimeFunctionEntries._IMAGE_RUNTIME_FUNCTION_ENTRY;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

// TODO: If public visibility is required improved member protection is needed
class PEx64UnwindInfo implements StructConverter {

	final static int UNW_FLAG_NHANDLER = 0x0;
	final static int UNW_FLAG_EHANDLER = 0x1;
	final static int UNW_FLAG_UHANDLER = 0x2;
	final static int UNW_FLAG_CHAININFO = 0x4;

	private final static int UNWIND_INFO_VERSION_MASK = 0x07;
	private final static int UNWIND_INFO_FLAGS_MASK = 0x1F;
	private final static int UNWIND_INFO_FLAGS_SHIFT = 0x03;
	private final static int UNWIND_INFO_FRAME_REGISTER_MASK = 0x0F;
	private final static int UNWIND_INFO_FRAME_OFFSET_SHIFT = 0x04;
	private final static int UNWIND_INFO_OPCODE_MASK = 0x0F;
	private final static int UNWIND_INFO_OPCODE_INFO_SHIFT = 0x04;
	private final static int UNWIND_INFO_OPCODE_INFO_MASK = 0x0F;

	byte version;
	byte flags;
	int sizeOfProlog;
	int countOfUnwindCodes;
	byte frameRegister;
	byte frameOffset;
	UNWIND_CODE[] unwindCodes;
	int exceptionHandlerFunction;
	_IMAGE_RUNTIME_FUNCTION_ENTRY unwindHandlerChainInfo;

	long startOffset;

	public PEx64UnwindInfo(long offset) {
		startOffset = offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return PEx64UnwindInfoDataType.INSTANCE;
	}

	public boolean hasExceptionHandler() {
		return (flags & UNW_FLAG_EHANDLER) == UNW_FLAG_EHANDLER;
	}

	public boolean hasUnwindHandler() {
		return (flags & UNW_FLAG_UHANDLER) == UNW_FLAG_UHANDLER;
	}

	public boolean hasChainedUnwindInfo() {
		return (flags & UNW_FLAG_CHAININFO) == UNW_FLAG_CHAININFO;
	}

	// FIXME: change name to conform to Java naming standards
	public static enum UNWIND_CODE_OPCODE {
		UWOP_PUSH_NONVOL(0x00),
		UWOP_ALLOC_LARGE(0x01),
		UWOP_ALLOC_SMALL(0x02),
		UWOP_SET_FPREG(0x03),
		UWOP_SAVE_NONVOL(0x04),
		UWOP_SAVE_NONVOL_FAR(0x05),
		UWOP_SAVE_XMM(0x06),
		UWOP_SAVE_XMM_FAR(0x07),
		UWOP_SAVE_XMM128(0x08),
		UWOP_SAVE_XMM128_FAR(0x09),
		UWOP_PUSH_MACHFRAME(0x0A);

		public final int id;

		UNWIND_CODE_OPCODE(int value) {
			id = value;
		}

		public int id() {
			return id;
		}

		public static UNWIND_CODE_OPCODE fromInt(int id) {
			UNWIND_CODE_OPCODE[] values = UNWIND_CODE_OPCODE.values();
			for (UNWIND_CODE_OPCODE value : values) {
				if (value.id == id) {
					return value;
				}
			}
			return null;
		}
	}

	// FIXME: change name to conform to Java naming standards
//	public static enum UNWIND_INFO_REGISTER {
//		RAX(0x00),
//		RCX(0x01),
//		RDX(0x02),
//		RBX(0x03),
//		RSP(0x04),
//		RBP(0x05),
//		RSI(0x06),
//		RDI(0x07),
//		R8(0x08),
//		R9(0x09),
//		R10(0x0A),
//		R11(0x0B),
//		R12(0x0C),
//		R13(0x0D),
//		R14(0x0E),
//		R15(0x0F);
//
//		public final int id;
//
//		UNWIND_INFO_REGISTER(int value) {
//			id = value;
//		}
//
//		public int id() {
//			return id;
//		}
//
//		public static UNWIND_INFO_REGISTER fromInt(int id) {
//			UNWIND_INFO_REGISTER[] values = UNWIND_INFO_REGISTER.values();
//			for (UNWIND_INFO_REGISTER value : values) {
//				if (value.id == id) {
//					return value;
//				}
//			}
//			return null;
//		}
//	}

	// FIXME: change name to conform to Java naming standards
	// TODO: If public visibility is required improved member protection is needed
	static class UNWIND_CODE {
		byte offsetInProlog;
		UNWIND_CODE_OPCODE opCode;
		byte opInfo; // encoding varies based upon opCode
	}

	static PEx64UnwindInfo readUnwindInfo(FactoryBundledWithBinaryReader reader,
			long offset, NTHeader ntHeader) throws IOException {
		long origIndex = reader.getPointerIndex();

		long pointer = ntHeader.rvaToPointer(offset);
		PEx64UnwindInfo unwindInfo = new PEx64UnwindInfo(pointer);

		if (pointer < 0) {
			return unwindInfo;
		}

		reader.setPointerIndex(pointer);
		byte splitByte = reader.readNextByte();
		unwindInfo.version = (byte) (splitByte & UNWIND_INFO_VERSION_MASK);
		unwindInfo.flags = (byte) ((splitByte >> UNWIND_INFO_FLAGS_SHIFT) & UNWIND_INFO_FLAGS_MASK);

		unwindInfo.sizeOfProlog = reader.readNextUnsignedByte();
		unwindInfo.countOfUnwindCodes = reader.readNextUnsignedByte();

		splitByte = reader.readNextByte();
		unwindInfo.frameRegister = (byte) (splitByte & UNWIND_INFO_FRAME_REGISTER_MASK);
		unwindInfo.frameOffset = (byte) (splitByte >> UNWIND_INFO_FRAME_OFFSET_SHIFT);

		unwindInfo.unwindCodes = new UNWIND_CODE[unwindInfo.countOfUnwindCodes];
		for (int i = 0; i < unwindInfo.countOfUnwindCodes; i++) {
			UNWIND_CODE code = new UNWIND_CODE();
			code.offsetInProlog = reader.readNextByte();

			int opCodeData = reader.readNextUnsignedByte();
			code.opCode = UNWIND_CODE_OPCODE.fromInt((opCodeData & UNWIND_INFO_OPCODE_MASK));
			code.opInfo = (byte) ((opCodeData >> UNWIND_INFO_OPCODE_INFO_SHIFT) &
				UNWIND_INFO_OPCODE_INFO_MASK);
//			code.opInfoRegister =
//				UNWIND_CODE_OPINFO_REGISTER.fromInt(opCodeData >> UNWIND_INFO_OPCODE_INFO_SHIFT);

			unwindInfo.unwindCodes[i] = code;
		}

		// You can have an exception handler or you can have chained exception handling info only.
		if (unwindInfo.hasExceptionHandler() || unwindInfo.hasUnwindHandler()) {
			unwindInfo.exceptionHandlerFunction = reader.readNextInt();
		}
		else if (unwindInfo.hasChainedUnwindInfo()) {
			unwindInfo.unwindHandlerChainInfo =
				new _IMAGE_RUNTIME_FUNCTION_ENTRY();
			unwindInfo.unwindHandlerChainInfo.beginAddress = reader.readNextInt();
			unwindInfo.unwindHandlerChainInfo.endAddress = reader.readNextInt();
			unwindInfo.unwindHandlerChainInfo.unwindInfoAddressOrData = reader.readNextInt();

			// Follow the chain to the referenced UNWIND_INFO structure until we
			// get to the end
			unwindInfo.unwindHandlerChainInfo.unwindInfo = readUnwindInfo(reader,
				unwindInfo.unwindHandlerChainInfo.unwindInfoAddressOrData, ntHeader);
		}

		reader.setPointerIndex(origIndex);

		return unwindInfo;
	}

}
