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

import ghidra.app.util.bin.format.pe.PEx64UnwindInfo.UNWIND_CODE_OPCODE;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.AssertException;

public class PEx64UnwindInfoDataType extends DynamicDataType {
	
	public static final PEx64UnwindInfoDataType INSTANCE = new PEx64UnwindInfoDataType();

	private final static int UNWIND_VERSION_FIELD_LENGTH = 0x03;
	private final static int UNWIND_FLAGS_FIELD_LENGTH = 0x05;
	private final static int UNWIND_FRAME_REGISTER_LENGTH = 0x04;
	private final static int UNWIND_FRAME_OFFSET_LENGTH = 0x04;
	private final static int UNWIND_OP_FIELD_LENGTH = 0x04;
	private final static int UNWIND_OP_INFO_FIELD_LENGTH = 0x04;

	private final static DataType BYTE = ByteDataType.dataType;
	private final static DataType IBO32 = new ImageBaseOffset32DataType();

	public PEx64UnwindInfoDataType() {
		this(null);
	}
	
	public PEx64UnwindInfoDataType(DataTypeManager dtm) {
		super("PEx64_UnwindInfo", dtm);
	}
	
	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PEx64UnwindInfoDataType(dtm);
	}

	@Override
	public String getDescription() {
		return "Dynamic structure for PE x86-64 Exception UNWIND_INFO";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "UNWIND_INFO";
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "UNWIND_INFO";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null; // TODO: Should we return filled-out structure?  Caching?
	}

	private Structure getStructure(MemBuffer buf) {

		StructureDataType struct;
		try {
			byte flags = (byte) (buf.getByte(0) >> UNWIND_VERSION_FIELD_LENGTH);

			struct = new StructureDataType("UNWIND_INFO", 0, dataMgr);
			struct.setPackingEnabled(true);
			try {
				struct.addBitField(BYTE, UNWIND_VERSION_FIELD_LENGTH, "Version", null);
				struct.addBitField(defineUnwindInfoFlags(), UNWIND_FLAGS_FIELD_LENGTH, "Flags",
					null);
				struct.add(BYTE, "SizeOfProlog", null);
				struct.add(BYTE, "CountOfUnwindCodes", null);
				struct.addBitField(BYTE, UNWIND_FRAME_REGISTER_LENGTH, "FrameRegister", null);
				struct.addBitField(BYTE, UNWIND_FRAME_OFFSET_LENGTH, "FrameOffset", null);

				int countOfUnwindCodes = buf.getByte(2);
				if (countOfUnwindCodes > 0) {
					ArrayDataType unwindInfoArray =
						new ArrayDataType(defineUnwindCodeStructure(), countOfUnwindCodes, -1);
					struct.add(unwindInfoArray, "UnwindCodes", null);
				}
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e); // should never happen with byte bit-fields
			}

			if (hasExceptionHandler(flags) || hasUnwindHandler(flags)) {
				struct.add(IBO32, "ExceptionHandler", null);
				if (hasUnwindHandler(flags)) {
					// NOTE: Dynamic structure does not reflect flex-array
					struct.setFlexibleArrayComponent(UnsignedLongDataType.dataType, "ExceptionData",
						null);
				}
			}
			else if (hasChainedUnwindInfo(flags)) {
				struct.add(IBO32, "FunctionStartAddress", null);
				struct.add(IBO32, "FunctionEndAddress", null);
				struct.add(IBO32, "FunctionUnwindInfoAddress", null);
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}

		return struct;
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Structure struct = getStructure(buf);
		if (struct == null) {
			return null;
		}
		DataTypeComponent[] components = struct.getComponents();
		if (struct.hasFlexibleArrayComponent()) {
			DataTypeComponent[] newArray = new DataTypeComponent[components.length + 1];
			System.arraycopy(components, 0, newArray, 0, components.length);
			newArray[components.length] = struct.getFlexibleArrayComponent();
			components = newArray;
		}
		return components;
	}

	private boolean hasExceptionHandler(int flags) {
		return (flags & PEx64UnwindInfo.UNW_FLAG_EHANDLER) == PEx64UnwindInfo.UNW_FLAG_EHANDLER;
	}

	private boolean hasUnwindHandler(int flags) {
		return (flags & PEx64UnwindInfo.UNW_FLAG_UHANDLER) == PEx64UnwindInfo.UNW_FLAG_UHANDLER;
	}

	private boolean hasChainedUnwindInfo(int flags) {
		return (flags & PEx64UnwindInfo.UNW_FLAG_CHAININFO) == PEx64UnwindInfo.UNW_FLAG_CHAININFO;
	}

	private Structure defineUnwindCodeStructure() {
		StructureDataType unwindCode = new StructureDataType("UnwindCode", 0, dataMgr);
		unwindCode.setPackingEnabled(true);
		try {
			unwindCode.add(BYTE, "OffsetInProlog", null);
			unwindCode.addBitField(defineUnwindOpCodeEnum(), UNWIND_OP_FIELD_LENGTH, "UnwindOpCode",
				null);
			// UnwindOpInfo encoding varies with UnwindOpCode
			unwindCode.addBitField(BYTE, UNWIND_OP_INFO_FIELD_LENGTH, "UnwindOpInfo", null);
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // should never happen with byte bit-fields
		}
		return unwindCode;
	}

	private static EnumDataType unwindInfoFlagsEnum;

	private EnumDataType defineUnwindInfoFlags() {
		if (unwindInfoFlagsEnum == null) {
			unwindInfoFlagsEnum = new EnumDataType("UNW_FLAGS", 1);
			unwindInfoFlagsEnum.add("UNW_FLAG_NHANDLER", PEx64UnwindInfo.UNW_FLAG_NHANDLER);
			unwindInfoFlagsEnum.add("UNW_FLAG_EHANDLER", PEx64UnwindInfo.UNW_FLAG_EHANDLER);
			unwindInfoFlagsEnum.add("UNW_FLAG_UHANDLER", PEx64UnwindInfo.UNW_FLAG_UHANDLER);
			unwindInfoFlagsEnum.add("UNW_FLAG_CHAININFO", PEx64UnwindInfo.UNW_FLAG_CHAININFO);
		}
		return unwindInfoFlagsEnum;
	}

	private static EnumDataType unwindCodeOpcodeEnum;

	private static synchronized EnumDataType defineUnwindOpCodeEnum() {
		if (unwindCodeOpcodeEnum == null) {
			unwindCodeOpcodeEnum = new EnumDataType("UNWIND_CODE_OPCODE", 1);
			for (UNWIND_CODE_OPCODE value : UNWIND_CODE_OPCODE.values()) {
				unwindCodeOpcodeEnum.add(value.name(), value.id);
			}
		}
		return unwindCodeOpcodeEnum;
	}

//	private static EnumDataType unwindRegisterEnum;
//
//	private static EnumDataType defineUnwindRegisterEnum() {
//		if (unwindRegisterEnum == null) {
//			unwindRegisterEnum = new EnumDataType("UNWIND_CODE_OPINFO_REGISTER", 1);
//			for (UNWIND_INFO_REGISTER value : UNWIND_INFO_REGISTER.values()) {
//				unwindRegisterEnum.add(value.name(), value.id);
//			}
//		}
//		return unwindRegisterEnum;
//	}

}
