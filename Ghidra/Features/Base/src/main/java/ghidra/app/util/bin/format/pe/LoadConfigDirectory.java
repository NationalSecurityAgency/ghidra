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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.Conv;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the <code>IMAGE_LOAD_CONFIG_DIRECTORY</code>
 * data structure which is defined in <b><code>winnt.h</code></b>.
 */
public class LoadConfigDirectory implements StructConverter {
	public final static String NAME32 = "IMAGE_LOAD_CONFIG_DIRECTORY32";
	public final static String NAME64 = "IMAGE_LOAD_CONFIG_DIRECTORY64";

	private int size;
	private int timeDateStamp;
	private short majorVersion;
	private short minorVersion;
	private int globalFlagsClear;
	private int globalFlagsSet;
	private int criticalSectionDefaultTimeout;
	private long deCommitFreeBlockThreshold;
	private long deCommitTotalFreeThreshold;
	private long lockPrefixTable;
	private long maximumAllocationSize;
	private long virtualMemoryThreshold;
	private long processAffinityMask;
	private int processHeapFlags;
	private short csdVersion;
	private short dependentLoadFlags;
	private long editList;
	private long securityCookie;
	private long seHandlerTable;
	private long seHandlerCount;
	private long guardCfcCheckFunctionPointer;
	private long guardCfDispatchFunctionPointer;
	private long guardCfFunctionTable;
	private long guardCfFunctionCount;
	private GuardFlags guardFlags;
	private CodeIntegrity codeIntegrity;
	private long guardAddressTakenIatEntryTable;
	private long guardAddressTakenIatEntryCount;
	private long guardLongJumpTargetTable;
	private long guardLongJumpTargetCount;
	private long dynamicValueRelocTable;
	private long chpeMetadataPointer;
	private long guardRfFailureRoutine;
	private long guardRfFailureRoutineFunctionPointer;
	private int dynamicValueRelocTableOffset;
	private short dynamicValueRelocTableSection;
	private short reserved1;
	private long guardRfVerifyStackPointerFunctionPointer;
	private int hotPatchTableOffset;
	private int reserved2;
	private long reserved3;

	private boolean is64bit;

	static LoadConfigDirectory createLoadConfigDirectory(FactoryBundledWithBinaryReader reader,
			int index, OptionalHeader oh) throws IOException {
		LoadConfigDirectory loadConfigDirectory =
			(LoadConfigDirectory) reader.getFactory().create(LoadConfigDirectory.class);
		loadConfigDirectory.initLoadConfigDirectory(reader, index, oh);
		return loadConfigDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public LoadConfigDirectory() {
	}

	private void initLoadConfigDirectory(FactoryBundledWithBinaryReader reader, int index,
			OptionalHeader oh) throws IOException {
		is64bit = oh.is64bit();

		long oldIndex = reader.getPointerIndex();
		reader.setPointerIndex(index);

		// Read original fields
		size = reader.readNextInt();
		timeDateStamp = reader.readNextInt();
		majorVersion = reader.readNextShort();
		minorVersion = reader.readNextShort();
		globalFlagsClear = reader.readNextInt();
		globalFlagsSet = reader.readNextInt();
		criticalSectionDefaultTimeout = reader.readNextInt();
		deCommitFreeBlockThreshold = readPointer(reader);
		deCommitTotalFreeThreshold = readPointer(reader);
		lockPrefixTable = readPointer(reader);
		maximumAllocationSize = readPointer(reader);
		virtualMemoryThreshold = readPointer(reader);
		if (is64bit) {
			processAffinityMask = readPointer(reader);
			processHeapFlags = reader.readNextInt();
		}
		else {
			processHeapFlags = reader.readNextInt();
			processAffinityMask = readPointer(reader);
		}
		csdVersion = reader.readNextShort();
		dependentLoadFlags = reader.readNextShort();
		editList = readPointer(reader);

		// If the structure size indicates there are more fields, we are dealing with
		// a newer version of the structure.  Each size check represents a new version
		// of the structure.
		if (reader.getPointerIndex() - index < size) {
			securityCookie = readPointer(reader);
			seHandlerTable = readPointer(reader);
			seHandlerCount = readPointer(reader);
		}
		if (reader.getPointerIndex() - index < size) {
			guardCfcCheckFunctionPointer = readPointer(reader);
			guardCfDispatchFunctionPointer = readPointer(reader);
			guardCfFunctionTable = readPointer(reader);
			guardCfFunctionCount = readPointer(reader);
			guardFlags = new GuardFlags(reader.readNextInt());
		}
		if (reader.getPointerIndex() - index < size) {
			codeIntegrity = new CodeIntegrity(reader);
		}
		if (reader.getPointerIndex() - index < size) {
			guardAddressTakenIatEntryTable = readPointer(reader);
			guardAddressTakenIatEntryCount = readPointer(reader);
			guardLongJumpTargetTable = readPointer(reader);
			guardLongJumpTargetCount = readPointer(reader);
		}
		if (reader.getPointerIndex() - index < size) {
			dynamicValueRelocTable = readPointer(reader);
			chpeMetadataPointer = readPointer(reader);
		}
		if (reader.getPointerIndex() - index < size) {
			guardRfFailureRoutine = readPointer(reader);
			guardRfFailureRoutineFunctionPointer = readPointer(reader);
			dynamicValueRelocTableOffset = reader.readNextInt();
			dynamicValueRelocTableSection = reader.readNextShort();
			reserved1 = reader.readNextShort();
		}
		if (reader.getPointerIndex() - index < size) {
			guardRfVerifyStackPointerFunctionPointer = readPointer(reader);
			hotPatchTableOffset = reader.readNextInt();
		}
		if (reader.getPointerIndex() - index < size) {
			reserved2 = reader.readNextInt();
			reserved3 = readPointer(reader);
		}

		reader.setPointerIndex(oldIndex);
	}

	/**
	 * Returns the size (in bytes) of this structure.
	 *
	 * @return the size (in bytes) of this structure
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Returns the critical section default time-out value.
	 *
	 * @return the critical section default time-out value
	 */
	public int getCriticalSectionDefaultTimeout() {
		return criticalSectionDefaultTimeout;
	}

	/**
	 * Gets the safe exception handler table.
	 *
	 * @return the safe exception handler table.
	 */
	public long getSeHandlerTable() {
		return seHandlerTable;
	}

	/**
	 * Gets the safe exception handler table count.
	 *
	 * @return the safe exception handler table count.
	 */
	public long getSeHandlerCount() {
		return seHandlerCount;
	}

	/**
	 * Gets the ControlFlowGuard {@link GuardFlags}.
	 * 
	 * @return The ControlFlowGuard {@link GuardFlags}.
	 */
	public GuardFlags getCfgGuardFlags() {
		return guardFlags;
	}

	/**
	 * Gets the ControlFlowGuard check function pointer address.
	 * 
	 * @return The ControlFlowGuard check function pointer address.  
	 *   Could be 0 if ControlFlowGuard is not being used.
	 */
	public long getCfgCheckFunctionPointer() {
		return guardCfcCheckFunctionPointer;
	}

	/**
	 * Gets the ControlFlowGuard dispatch function pointer address.
	 * 
	 * @return The ControlFlowGuard dispatch function pointer address.  
	 *   Could be 0 if ControlFlowGuard is not being used.
	 */
	public long getCfgDispatchFunctionPointer() {
		return guardCfDispatchFunctionPointer;
	}

	/**
	 * Gets the ControlFlowGuard function table pointer address.
	 * 
	 * @return The ControlFlowGuard function table function pointer address.  
	 *   Could be 0 if ControlFlowGuard is not being used.
	 */
	public long getCfgFunctionTablePointer() {
		return guardCfFunctionTable;
	}

	/**
	 * Gets the ControlFlowGuard function count.
	 * 
	 * @return The ControlFlowGuard function count.  Could be 0 if ControlFlowGuard is 
	 *   not being used.
	 */
	public long getCfgFunctionCount() {
		return guardCfFunctionCount;
	}

	/**
	 * Gets the ControlFlowGuard IAT table pointer address.
	 * 
	 * @return The ControlFlowGuard IAT table function pointer address. Could be 0 if ControlFlowGuard is not being used
	 */
	public long getGuardAddressIatTableTablePointer() {
		return guardAddressTakenIatEntryTable;
	}

	/**
	 * Gets the ControlFlowGuard IAT entries count.
	 * 
	 * @return The ControlFlowGuard IAT entries count.  Could be 0 if ControlFlowGuard is not being used
	 */
	public long getGuardAddressIatTableCount() {
		return guardAddressTakenIatEntryCount;
	}

	/**
	 * Gets the ReturnFlowGuard failure routine address.
	 * 
	 * @return The ReturnFlowGuard failure routine address.
	 *   Could be 0 if ReturnFlowGuard is not being used.
	 */
	public long getRfgFailureRoutine() {
		return guardRfFailureRoutine;
	}

	/**
	 * Gets the ReturnFlowGuard failure routine function pointer address.
	 * 
	 * @return The ReturnFlowGuard failure routine function pointer address.
	 *   Could be 0 if ReturnFlowGuard is not being used.
	 */
	public long getRfgFailureRoutineFunctionPointer() {
		return guardRfFailureRoutineFunctionPointer;
	}

	/**
	 * Gets the ReturnFlowGuard verify stack pointer function pointer address.
	 * 
	 * @return The ReturnFlowGuard verify stack pointer function pointer address.
	 *   Could be 0 if ReturnFlowGuard is not being used.
	 */
	public long getRfgVerifyStackPointerFunctionPointer() {
		return guardRfVerifyStackPointerFunctionPointer;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(is64bit ? NAME64 : NAME32, 0);

		DataType counter = is64bit ? QWORD : DWORD;
		DataType ptr = is64bit ? new Pointer64DataType() : new Pointer32DataType();

		// Add original fields
		struct.add(DWORD, "Size", null);
		struct.add(DWORD, "TimeDateStamp", null);
		struct.add(WORD, "MajorVersion", null);
		struct.add(WORD, "MinorVersion", null);
		struct.add(DWORD, "GlobalFlagsClear", null);
		struct.add(DWORD, "GlobalFlagsSet", null);
		struct.add(DWORD, "CriticalSectionDefaultTimeout", null);
		struct.add(counter, "DeCommitFreeBlockThreshold", null);
		struct.add(counter, "DeCommitTotalFreeThreshold", null);
		struct.add(ptr, "LockPrefixTable", null);
		struct.add(counter, "MaximumAllocationSize", null);
		struct.add(counter, "VirtualMemoryThreshold", null);
		if (is64bit) {
			struct.add(counter, "ProcessAffinityMask", null);
			struct.add(DWORD, "ProcessHeapFlags", null);
		}
		else {
			struct.add(DWORD, "ProcessHeapFlags", null);
			struct.add(counter, "ProcessAffinityMask", null);
		}
		struct.add(WORD, "CsdVersion", null);
		struct.add(WORD, "DependentLoadFlags", null);
		struct.add(ptr, "EditList", null);

		// If the structure size indicates there are more fields, we are dealing with
		// a newer version of the structure.  Each size check represents a new version
		// of the structure.
		if (struct.getLength() < size) {
			struct.add(ptr, "SecurityCookie", null);
			struct.add(ptr, "SEHandlerTable", null);
			struct.add(counter, "SEHandlerCount", null);
		}
		if (struct.getLength() < size) {
			struct.add(ptr, "GuardCFCCheckFunctionPointer", null);
			struct.add(ptr, "GuardCFDispatchFunctionPointer", null);
			struct.add(ptr, "GuardCFFunctionTable", null);
			struct.add(counter, "GuardCFFunctionCount", null);
			struct.add(guardFlags.toDataType(), "GuardFlags", null);
		}
		if (struct.getLength() < size) {
			struct.add(codeIntegrity.toDataType(), "CodeIntegrity", null);
		}
		if (struct.getLength() < size) {
			struct.add(ptr, "GuardAddressTakenIatEntryTable", null);
			struct.add(counter, "GuardAddressTakenIatEntryCount", null);
			struct.add(ptr, "GuardLongJumpTargetTable", null);
			struct.add(counter, "GuardLongJumpTargetCount", null);
		}
		if (struct.getLength() < size) {
			struct.add(ptr, "DynamicValueRelocTable", null);
			struct.add(ptr, "CHPEMetadataPointer", null);
		}
		if (struct.getLength() < size) {
			struct.add(ptr, "GuardRFFailureRoutine", null);
			struct.add(ptr, "GuardRFFailureRoutineFunctionPointer", null);
			struct.add(DWORD, "DynamicValueRelocTableOffset", null);
			struct.add(WORD, "DynamicValueRelocTableSection", null);
			struct.add(WORD, "Reserved1", null);
		}
		if (struct.getLength() < size) {
			struct.add(ptr, "GuardRFVerifyStackPointerFunctionPointer", null);
			struct.add(DWORD, "HotPatchTableOffset", null);
		}
		if (struct.getLength() < size) {
			struct.add(DWORD, "Reserved2", null);
			struct.add(counter, "Reserved3", null);
		}

		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	private long readPointer(BinaryReader reader) throws IOException {
		if (is64bit) {
			return reader.readNextLong();
		}
		return reader.readNextInt() & Conv.INT_MASK;
	}

	/**
	 * Control Flow Guard flags.
	 */
	static class GuardFlags implements StructConverter {

		public final static String NAME = "IMAGE_GUARD_FLAGS";

		private int flags;

		public GuardFlags(int flags) {
			this.flags = flags;
		}

		public int getFlags() {
			return flags;
		}

		@Override
		public DataType toDataType() throws DuplicateNameException {
			EnumDataType enumDt = new EnumDataType(NAME, 4);
			enumDt.add("IMAGE_GUARD_CF_INSTRUMENTED", 0x00000100L);
			enumDt.add("IMAGE_GUARD_CFW_INSTRUMENTED", 0x00000200L);
			enumDt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", 0x00000400L);
			enumDt.add("IMAGE_GUARD_SECURITY_COOKIE_UNUSED", 0x00000800L);
			enumDt.add("IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", 0x00001000L);
			enumDt.add("IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION", 0x00002000L);
			enumDt.add("IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", 0x00004000L);
			enumDt.add("IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION", 0x00008000L);
			enumDt.add("IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", 0x00010000L);
			enumDt.add("IMAGE_GUARD_RF_INSTRUMENTED", 0x00020000L);
			enumDt.add("IMAGE_GUARD_RF_ENABLE", 0x00040000L);
			enumDt.add("IMAGE_GUARD_RF_STRICT", 0x00080000L);
			enumDt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1", 0x10000000L);
			enumDt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2", 0x20000000L);
			enumDt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4", 0x40000000L);
			enumDt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8", 0x80000000L);

			enumDt.setCategoryPath(new CategoryPath("/PE"));
			return enumDt;
		}
	}

	/**
	 * Not sure yet what this is used for.
	 */
	static class CodeIntegrity implements StructConverter {

		public final static String NAME = "IMAGE_LOAD_CONFIG_CODE_INTEGRITY";

		private short flags;
		private short catalog;
		private int catalogOffset;
		private int reserved;

		public CodeIntegrity(BinaryReader reader) throws IOException {
			flags = reader.readNextShort();
			catalog = reader.readNextShort();
			catalogOffset = reader.readNextInt();
			reserved = reader.readNextInt();
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("flags=0x" + Integer.toHexString(Conv.shortToInt(flags)));
			sb.append(", catalog=0x" + Integer.toHexString(Conv.shortToInt(catalog)));
			sb.append(", catalogOffset=0x" + Integer.toHexString(catalogOffset));
			sb.append(", reserved=0x" + Integer.toHexString(reserved));
			return sb.toString();
		}

		@Override
		public DataType toDataType() throws DuplicateNameException {
			StructureDataType struct = new StructureDataType(NAME, 0);
			struct.add(WORD, "Flags", null);
			struct.add(WORD, "Catalog", null);
			struct.add(DWORD, "CatalogOffset", null);
			struct.add(DWORD, "Reserved", null);

			struct.setCategoryPath(new CategoryPath("/PE"));
			return struct;
		}
	}
}
