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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
 *  DWORD BeginAddress;
 *  DWORD EndAddress;
 *  union {
 *    DWORD UnwindInfoAddress;
 *    DWORD UnwindData;
 *  } DUMMYUNIONNAME;
 * } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;
 *
 * #define UNW_FLAG_NHANDLER 0x0
 * #define UNW_FLAG_EHANDLER 0x1
 * #define UNW_FLAG_UHANDLER 0x2
 * #define UNW_FLAG_CHAININFO 0x4
 *
 * typedef struct _UNWIND_INFO {
 *     UCHAR Version : 3;
 *     UCHAR Flags : 5;
 *     UCHAR SizeOfProlog;
 *     UCHAR CountOfUnwindCodes;
 *     UCHAR FrameRegister : 4;
 *     UCHAR FrameOffset : 4;
 *     UNWIND_CODE UnwindCode[1];
 *
 * //
 * // The unwind codes are followed by an optional DWORD aligned field that
 * // contains the exception handler address or the address of chained unwind
 * // information. If an exception handler address is specified, then it is
 * // followed by the language specified exception handler data.
 * //
 * //  union {
 * //      ULONG ExceptionHandler;
 * //      ULONG FunctionEntry;
 * //  };
 * //
 * //  ULONG ExceptionData[];
 * //
 * } UNWIND_INFO, *PUNWIND_INFO;
 */
public class ImageRuntimeFunctionEntries {
	private final static int UNWIND_INFO_VERSION_BITMASK = 0x07;
	private final static int UNWIND_INFO_FLAGS_SHIFT = 0x03;
	private final static int UNWIND_INFO_FRAME_REGISTER_MASK = 0x0F;
	private final static int UNWIND_INFO_FRAME_OFFSET_SHIFT = 0x04;
	private final static int UNWIND_INFO_OPCODE_MASK = 0x0F;
	private final static int UNWIND_INFO_OPCODE_INFO_SHIFT = 0x04;
	private final static int UNWIND_INFO_SIZE = 0x0C;

	List<_IMAGE_RUNTIME_FUNCTION_ENTRY> functionEntries = new ArrayList<>();

	static ImageRuntimeFunctionEntries createImageRuntimeFunctionEntries(
			FactoryBundledWithBinaryReader reader, long index, NTHeader ntHeader)
			throws IOException {
		ImageRuntimeFunctionEntries imageRuntimeFunctionEntriesSection =
			(ImageRuntimeFunctionEntries) reader.getFactory()
					.create(ImageRuntimeFunctionEntries.class);
		imageRuntimeFunctionEntriesSection.initImageRuntimeFunctionEntries(reader, index, ntHeader);
		return imageRuntimeFunctionEntriesSection;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ImageRuntimeFunctionEntries() {
	}

	private void initImageRuntimeFunctionEntries(FactoryBundledWithBinaryReader reader, long index,
			NTHeader ntHeader) throws IOException {

		int entryCount = 0;

		// Find the exception handler data section. This is an unbounded array of
		// RUNTIME_INFO structures one after another and there's no count field
		// to tell us how many there are, so get the maximum number there could be
		// based on the size of the section.
		FileHeader fh = ntHeader.getFileHeader();
		for (SectionHeader section : fh.getSectionHeaders()) {
			if (section.getName().contentEquals(".pdata")) {
				entryCount = section.getSizeOfRawData() / UNWIND_INFO_SIZE;
				break;
			}
		}

		if (entryCount == 0) {
			return;
		}

		long origIndex = reader.getPointerIndex();

		reader.setPointerIndex(index);

		for (int i = 0; i < entryCount; i++) {
			_IMAGE_RUNTIME_FUNCTION_ENTRY entry = new _IMAGE_RUNTIME_FUNCTION_ENTRY();
			entry.beginAddress = reader.readNextUnsignedInt();
			entry.endAddress = reader.readNextUnsignedInt();
			entry.unwindInfoAddressOrData = reader.readNextUnsignedInt();

			// When the size of the section is bigger than the number of structures
			// the structure data fields will all be null, signaling the end of the
			// array of structures. Break out here.
			if (entry.beginAddress == 0 && entry.endAddress == 0 &&
				entry.unwindInfoAddressOrData == 0) {
				break;
			}

			// Read and process the UNWIND_INFO structures the RUNTIME_INFO
			// structures point to
			entry.unwindInfo = readUnwindInfo(reader, entry.unwindInfoAddressOrData, ntHeader);

			functionEntries.add(entry);
		}

		reader.setPointerIndex(origIndex);
	}

	private UNWIND_INFO readUnwindInfo(FactoryBundledWithBinaryReader reader, long offset,
			NTHeader ntHeader) throws IOException {
		long origIndex = reader.getPointerIndex();

		long pointer = ntHeader.rvaToPointer(offset);
		UNWIND_INFO unwindInfo = new UNWIND_INFO(pointer);

		if (pointer < 0) {
			return unwindInfo;
		}

		reader.setPointerIndex(pointer);
		byte splitByte = reader.readNextByte();
		unwindInfo.version = (byte) (splitByte & UNWIND_INFO_VERSION_BITMASK);
		unwindInfo.flags = (byte) (splitByte >> UNWIND_INFO_FLAGS_SHIFT);

		unwindInfo.sizeOfProlog = reader.readNextByte();
		unwindInfo.countOfUnwindCodes = reader.readNextByte();

		splitByte = reader.readNextByte();
		unwindInfo.frameRegister = (byte) (splitByte & UNWIND_INFO_FRAME_REGISTER_MASK);
		unwindInfo.frameOffset = (byte) (splitByte >> UNWIND_INFO_FRAME_OFFSET_SHIFT);

		unwindInfo.unwindCodes = new UNWIND_CODE[unwindInfo.countOfUnwindCodes];
		for (int i = 0; i < unwindInfo.countOfUnwindCodes; i++) {
			UNWIND_CODE code = new UNWIND_CODE();
			code.offsetInProlog = reader.readNextByte();

			int opCodeData = reader.readNextUnsignedByte();
			code.opCode = UNWIND_CODE_OPCODE.fromInt((opCodeData & UNWIND_INFO_OPCODE_MASK));
			code.opInfoRegister =
				UNWIND_CODE_OPINFO_REGISTER.fromInt(opCodeData >> UNWIND_INFO_OPCODE_INFO_SHIFT);

			unwindInfo.unwindCodes[i] = code;
		}

		// You can have an exception handler and/or an unwind handler, or you
		// can have chained exception handling info only.
		if (unwindInfo.hasExceptionHandler() || unwindInfo.hasUnwindHandler()) {
			if (unwindInfo.hasExceptionHandler()) {
				unwindInfo.exceptionHandlerFunction = reader.readNextInt();
			}
			if (unwindInfo.hasUnwindHandler()) {
				unwindInfo.unwindHandlerFunction = reader.readNextInt();
			}
		}
		else if (unwindInfo.hasChainedUnwindInfo()) {
			unwindInfo.unwindHandlerChainInfo = new _IMAGE_RUNTIME_FUNCTION_ENTRY();
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

	public List<_IMAGE_RUNTIME_FUNCTION_ENTRY> getRuntimeFunctionEntries() {
		return functionEntries;
	}

	public class _IMAGE_RUNTIME_FUNCTION_ENTRY {
		public long beginAddress;
		public long endAddress;
		public long unwindInfoAddressOrData;
		public UNWIND_INFO unwindInfo;
	}

	public enum UNWIND_CODE_OPCODE {
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

		private final int id;

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

	public enum UNWIND_CODE_OPINFO_REGISTER {
		UNWIND_OPINFO_REGISTER_RAX(0x00),
		UNWIND_OPINFO_REGISTER_RCX(0x01),
		UNWIND_OPINFO_REGISTER_RDX(0x02),
		UNWIND_OPINFO_REGISTER_RBX(0x03),
		UNWIND_OPINFO_REGISTER_RSP(0x04),
		UNWIND_OPINFO_REGISTER_RBP(0x05),
		UNWIND_OPINFO_REGISTER_RSI(0x06),
		UNWIND_OPINFO_REGISTER_RDI(0x07),
		UNWIND_OPINFO_REGISTER_R8(0x08),
		UNWIND_OPINFO_REGISTER_R9(0x09),
		UNWIND_OPINFO_REGISTER_R10(0x0A),
		UNWIND_OPINFO_REGISTER_R11(0x0B),
		UNWIND_OPINFO_REGISTER_R12(0x0C),
		UNWIND_OPINFO_REGISTER_R13(0x0D),
		UNWIND_OPINFO_REGISTER_R14(0x0E),
		UNWIND_OPINFO_REGISTER_R15(0x0F);

		private final int id;

		UNWIND_CODE_OPINFO_REGISTER(int value) {
			id = value;
		}

		public int id() {
			return id;
		}

		public static UNWIND_CODE_OPINFO_REGISTER fromInt(int id) {
			UNWIND_CODE_OPINFO_REGISTER[] values = UNWIND_CODE_OPINFO_REGISTER.values();
			for (UNWIND_CODE_OPINFO_REGISTER value : values) {
				if (value.id == id) {
					return value;
				}
			}
			return null;
		}
	}

	public class UNWIND_CODE {
		public byte offsetInProlog;
		public UNWIND_CODE_OPCODE opCode;
		public UNWIND_CODE_OPINFO_REGISTER opInfoRegister;
	}

	public class UNWIND_INFO implements StructConverter {
		private static final String NAME = "UNWIND_INFO";

		private final static int UNW_FLAG_NHANDLER = 0x0;
		private final static int UNW_FLAG_EHANDLER = 0x1;
		private final static int UNW_FLAG_UHANDLER = 0x2;
		private final static int UNW_FLAG_CHAININFO = 0x4;

		private final static int UNWIND_VERSION_FIELD_LENGTH = 0x03;
		private final static int UNWIND_FLAGS_FIELD_LENGTH = 0x05;
		private final static int UNWIND_FRAME_REGISTER_LENGTH = 0x04;
		private final static int UNWIND_OP_FIELD_LENGTH = 0x04;

		byte version;
		byte flags;
		byte sizeOfProlog;
		byte countOfUnwindCodes;
		byte frameRegister;
		byte frameOffset;
		UNWIND_CODE[] unwindCodes;
		int exceptionHandlerFunction;
		int unwindHandlerFunction;
		_IMAGE_RUNTIME_FUNCTION_ENTRY unwindHandlerChainInfo;

		long startOffset;

		public UNWIND_INFO(long offset) {
			startOffset = offset;
		}

		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			StructureDataType struct = new StructureDataType(NAME + "_" + startOffset, 0);
			try {
				StructureDataType vf = new StructureDataType("VersionFlags", 0);
				vf.insertBitField(0, 1, 0, BYTE, UNWIND_VERSION_FIELD_LENGTH, "Version", null);
				vf.insertBitField(0, 1, UNWIND_VERSION_FIELD_LENGTH, defineFlagsField(),
					UNWIND_FLAGS_FIELD_LENGTH, "Flags", null);

				struct.add(vf, "Version + Flags", null);
			}
			catch (InvalidDataTypeException e) {
				struct.add(BYTE, "Version + Flags", null);
			}

			struct.add(BYTE, "SizeOfProlog", null);
			struct.add(BYTE, "CountOfUnwindCodes", null);

			try {
				StructureDataType fr = new StructureDataType("FrameRegisterAndOffset", 0);
				fr.insertBitField(0, 1, 0, BYTE, UNWIND_FRAME_REGISTER_LENGTH, "FrameRegister",
					null);
				fr.insertBitField(0, 1, UNWIND_FRAME_REGISTER_LENGTH, BYTE,
					UNWIND_FRAME_REGISTER_LENGTH, "FrameOffset", null);
				struct.add(fr, "FrameRegister + FrameOffset", null);
			}
			catch (InvalidDataTypeException e) {
				struct.add(BYTE, "FrameRegister + FrameOffset", null);
			}

			for (int i = 0; i < countOfUnwindCodes; i++) {
				StructureDataType unwindCode = new StructureDataType("UnwindCode", 0);
				unwindCode.add(BYTE, "OffsetInProlog", null);

				StructureDataType unwindCodeInfo = new StructureDataType("UnwindCodeInfo", 0);
				try {
					if (unwindCodes[i].opCode != null) {
						unwindCodeInfo.insertBitField(0, 1, 0, defineUnwindOpCodeField(),
							UNWIND_OP_FIELD_LENGTH, "UnwindOpCode", null);
					}
					else {
						unwindCodeInfo.insertBitField(0, 1, 0, BYTE, UNWIND_OP_FIELD_LENGTH,
							"UnwindOpCode", null);
					}

					if (unwindCodes[i].opInfoRegister != null) {
						unwindCodeInfo.insertBitField(0, 1, UNWIND_OP_FIELD_LENGTH,
							defineUnwindCodeRegisterField(), UNWIND_OP_FIELD_LENGTH, "OpInfo",
							null);
					}
					else {
						unwindCodeInfo.insertBitField(0, 1, UNWIND_OP_FIELD_LENGTH, BYTE,
							UNWIND_OP_FIELD_LENGTH, "OpInfo", null);
					}
				}
				catch (InvalidDataTypeException e) {
				}
				unwindCode.add(unwindCodeInfo, "UnwindCodeInfo", null);

				struct.add(unwindCode, "UnwindCode", null);
			}

			if (hasExceptionHandler() || hasUnwindHandler()) {
				if (hasExceptionHandler()) {
					struct.add(IBO32, "ExceptionHandler", null);
				}
				if (hasUnwindHandler()) {
					struct.add(IBO32, "UnwindHandler", null);
				}
			}
			else {
				if (hasChainedUnwindInfo()) {
					struct.add(IBO32, "FunctionStartAddress", null);
					struct.add(IBO32, "FunctionEndAddress", null);
					struct.add(IBO32, "FunctionUnwindInfoAddress", null);
				}
			}

			return struct;
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

		private EnumDataType defineFlagsField() {
			EnumDataType flagsField = new EnumDataType("Flags", 5);
			flagsField.add("UNW_FLAG_NHANDLER", UNW_FLAG_NHANDLER);
			flagsField.add("UNW_FLAG_EHANDLER", UNW_FLAG_EHANDLER);
			flagsField.add("UNW_FLAG_UHANDLER", UNW_FLAG_UHANDLER);
			flagsField.add("UNW_FLAG_CHAININFO", UNW_FLAG_CHAININFO);

			return flagsField;
		}

		private EnumDataType defineUnwindOpCodeField() {
			EnumDataType unwindOpCodeField = new EnumDataType("UNWIND_CODE_OPCODE", 4);
			unwindOpCodeField.add("UWOP_PUSH_NONVOL", UNWIND_CODE_OPCODE.UWOP_PUSH_NONVOL.id);
			unwindOpCodeField.add("UWOP_ALLOC_LARGE", UNWIND_CODE_OPCODE.UWOP_ALLOC_LARGE.id);
			unwindOpCodeField.add("UWOP_ALLOC_SMALL", UNWIND_CODE_OPCODE.UWOP_ALLOC_SMALL.id);
			unwindOpCodeField.add("UWOP_SET_FPREG", UNWIND_CODE_OPCODE.UWOP_SET_FPREG.id);
			unwindOpCodeField.add("UWOP_SAVE_NONVOL", UNWIND_CODE_OPCODE.UWOP_SAVE_NONVOL.id);
			unwindOpCodeField.add("UWOP_SAVE_NONVOL_FAR",
				UNWIND_CODE_OPCODE.UWOP_SAVE_NONVOL_FAR.id);
			unwindOpCodeField.add("UWOP_SAVE_XMM", UNWIND_CODE_OPCODE.UWOP_SAVE_XMM.id);
			unwindOpCodeField.add("UWOP_SAVE_XMM_FAR", UNWIND_CODE_OPCODE.UWOP_SAVE_XMM_FAR.id);
			unwindOpCodeField.add("UWOP_SAVE_XMM128", UNWIND_CODE_OPCODE.UWOP_SAVE_XMM128.id);
			unwindOpCodeField.add("UWOP_SAVE_XMM128_FAR",
				UNWIND_CODE_OPCODE.UWOP_SAVE_XMM128_FAR.id);
			unwindOpCodeField.add("UWOP_PUSH_MACHFRAME", UNWIND_CODE_OPCODE.UWOP_PUSH_MACHFRAME.id);

			return unwindOpCodeField;
		}

		private EnumDataType defineUnwindCodeRegisterField() {
			EnumDataType unwindCodeRegisterField =
				new EnumDataType("UNWIND_CODE_OPINFO_REGISTER", 4);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RAX",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RAX.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RCX",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RCX.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RDX",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RDX.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RBX",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RBX.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RSP",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RSP.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RBP",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RBP.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RSI",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RSI.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_RDI",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_RDI.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R8",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R8.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R9",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R9.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R10",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R10.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R11",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R11.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R12",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R12.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R13",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R13.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R14",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R14.id);
			unwindCodeRegisterField.add("UNWIND_OPINFO_REGISTER_R15",
				UNWIND_CODE_OPINFO_REGISTER.UNWIND_OPINFO_REGISTER_R15.id);

			return unwindCodeRegisterField;
		}
	}
}
