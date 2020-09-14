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
package ghidra.test.processors.support;

import java.util.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.util.PseudoDisassembler;
import ghidra.docking.settings.SettingsImpl;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.utils.Utils;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>PCodeTestAbstractControlBlock</code> data is models the general capabilities
 * of the TestInfo data structure which is used for different puposes as handled
 * by extensions of this class.
 */
public abstract class PCodeTestAbstractControlBlock {

	static final int SIZEOF_U4 = 4;

	private final Disassembler disassembler;

	protected final Program program;
	protected final AddressSpace codeSpace;
	protected final AddressSpace dataSpace;

	protected final int pointerSize;

	protected final Address infoStructAddr;
	protected final Structure infoProgramStruct;

	private List<FunctionInfo> functions = new ArrayList<>();
	private HashMap<String, FunctionInfo> functionMap = new HashMap<>();

	/**
	 * Construct test control block instance for the specified program.  
	 * @param program program containing control block structure
	 * @param infoStructAddr program address where structure resides
	 * @param infoStruct appropriate Info structure definition which will have array 
	 * of FunctionInfo immediately following.
	 */
	PCodeTestAbstractControlBlock(Program program, Address infoStructAddr, Structure infoStruct) {
		this.program = program;
		this.pointerSize = program.getDataTypeManager().getDataOrganization().getPointerSize();
		this.infoStructAddr = infoStructAddr;
		this.infoProgramStruct = (Structure) infoStruct.clone(program.getDataTypeManager());

		codeSpace = program.getAddressFactory().getDefaultAddressSpace();
		dataSpace = program.getLanguage().getDefaultDataSpace();

		disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, m -> {
			/* ignore */ });
	}

	public Address getInfoStructureAddress() {
		return infoStructAddr;
	}

	public FunctionInfo getFunctionInfo(String functionName) {
		return functionMap.get(functionName);
	}

	public FunctionInfo getFunctionInfo(int functionIndex) {
		return functions.get(functionIndex);
	}

	public int getNumberFunctions() {
		return functions.size();
	}

	/**
	 * Force an existing reference to refer to the code space.  Pointers
	 * created in the data space refer to the data space by default, this method
	 * is used to change these pointers in the data space to refer to 
	 * code.
	 * @param addr location with data space which contains code reference
	 */
	void forceCodePointer(Address addr) {
		if (codeSpace == dataSpace) {
			return;
		}
		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.getPrimaryReferenceFrom(addr, 0);
		if (ref == null) {
			return;
		}
		Address toAddr = ref.getToAddress();
		if (!toAddr.getAddressSpace().equals(codeSpace)) {
			toAddr = codeSpace.getAddress(toAddr.getAddressableWordOffset(), true);
			Reference newRef =
				refMgr.addMemoryReference(addr, toAddr, RefType.DATA, SourceType.ANALYSIS, 0);
			refMgr.setPrimary(newRef, true);
			refMgr.delete(ref);
		}
	}

	static byte[] getCharArrayBytes(Program program, String string) {
		DataOrganization dataOrganization = program.getDataTypeManager().getDataOrganization();
		int charSize = dataOrganization.getCharSize();
		byte[] strBytes = string.getBytes();
		if (charSize == 1) {
			return strBytes;
		}

		// generate aligned byte array
		int len = charSize * strBytes.length;
		byte[] bytes = new byte[len];
		boolean bigEndian = program.getMemory().isBigEndian();
		int index = 0;
		int pad = charSize - 1;
		for (byte strByte : strBytes) {
			if (bigEndian) {
				index += pad;
			}
			bytes[index++] = strByte;
			if (!bigEndian) {
				index += pad;
			}
		}
		return bytes;
	}

	private Address readPointer(MemBuffer buffer, int bufferOffset, AddressSpace addrSpace,
			boolean updateReference) {
		byte[] bytes = new byte[pointerSize];
		buffer.getBytes(bytes, bufferOffset);
		long offset = Utils.bytesToLong(bytes, pointerSize, buffer.isBigEndian()) *
			addrSpace.getAddressableUnitSize();
		Address addr = addrSpace.getAddress(offset);
		if (updateReference) {
			ReferenceManager refMgr = program.getReferenceManager();
			Address fromAddr = buffer.getAddress().add(bufferOffset);
			Reference ref = refMgr.getPrimaryReferenceFrom(fromAddr, 0);
			if (ref != null && !ref.getToAddress().equals(addr)) {
				refMgr.delete(ref);
				ref = null;
			}
			if (ref == null) {
				refMgr.addMemoryReference(fromAddr, addr, RefType.DATA, SourceType.USER_DEFINED, 0);
			}
		}
		return addr;
	}

	/**
	 * Check for a Data pointer at the specified address and return the referenced
	 * address.
	 * @param addr address of stored pointer
	 * @return pointer referenced address or null if no pointer found
	 */
	protected Address readDefinedDataPointer(Address addr) {
		Data data = program.getListing().getDefinedDataAt(addr);
		if (data == null || !(data.getDataType() instanceof Pointer)) {
			return null;
		}
		return (Address) data.getValue();
	}

	protected Address readCodePointer(MemBuffer buffer, int bufferOffset, boolean updateReference) throws MemoryAccessException {
		Address codePtr = readPointer(buffer, bufferOffset, codeSpace, updateReference);

		// treat null pointer as special case - just return it
		if (codePtr.getOffset() == 0) {
			return codePtr;
		}

		// shift the pointer if code pointers are stored in memory shifted.
		int ptrShift = program.getDataTypeManager().getDataOrganization().getPointerShift();
		if (ptrShift != 0) {
			codePtr = codePtr.getNewAddress(codePtr.getOffset() << ptrShift);
		}

		// Check for potential procedure descriptor indirection (e.g., PPC64 .opd)
		// in which case a function pointer may refer to a procedure descriptor
		// record (we assume here that the first entry has been marked-up by the importer
		// and corresponds to the true function address

		Address ptr = readDefinedDataPointer(codePtr);
		if (ptr != null) {
			// use stored pointer from procedure descriptor table
			codePtr = ptr;
		}
		else {
			// if pointer refers to simple jump/thunk - follow it
			Address addr = PseudoDisassembler.getNormalizedDisassemblyAddress(program, codePtr);
			InstructionBlock codeBlock = disassembler.pseudoDisassembleBlock(addr, null, 1);
			if (codeBlock == null || codeBlock.isEmpty() || codeBlock.hasInstructionError()) {
				throw new MemoryAccessException(
					"Code pointer " + codePtr.toString(true) + " does not refer to valid code");
			}
			// TODO: may need to handle more complex thunks
			Instruction instr = codeBlock.getInstructionAt(addr);
			FlowType flowType = instr.getFlowType();
			if (flowType.isJump()) {
				Address[] flows = instr.getFlows();
				if (flows.length == 1) {
					codePtr = flows[0];
				}
			}
		}

		return codePtr;
	}

	protected Address readDataPointer(MemBuffer buffer, int bufferOffset, boolean updateReference) {
		return readPointer(buffer, bufferOffset, dataSpace, updateReference);
	}

	protected Address readPointer(int controlBlockOffset) throws MemoryAccessException {
		Address addr = infoStructAddr.add(controlBlockOffset);
		byte[] bytes = new byte[pointerSize];
		Memory memory = program.getMemory();
		if (memory.getBytes(addr, bytes) != pointerSize) {
			throw new MemoryAccessException(
				"Failed to read program memory: " + pointerSize + " bytes at " + addr);
		}
		long offset = Utils.bytesToLong(bytes, pointerSize, memory.isBigEndian());
		return infoStructAddr.getNewAddress(offset);
	}

//	protected void applyPointerData(Program program, Address addr) {
//		Pointer dt = new PointerDataType(program.getDataTypeManager());
//		if (dt.getLength() != pointerSize) {
//			switch (pointerSize) {
//				case 2:
//					dt = new Pointer16DataType();
//					break;
//				case 3:
//					dt = new Pointer24DataType();
//					break;
//				case 4:
//					dt = new Pointer32DataType();
//					break;
//				case 5:
//					dt = new Pointer40DataType();
//					break;
//				case 6:
//					dt = new Pointer48DataType();
//					break;
//				case 7:
//					dt = new Pointer56DataType();
//					break;
//				case 8:
//					dt = new Pointer64DataType();
//					break;
//				default:
//					return;
//			}
//		}
//		try {
//			program.getListing().createData(addr, dt);
//		}
//		catch (CodeUnitInsertionException e) {
//			// ignore
//		}
//		catch (DataTypeConflictException e) {
//			// ignore
//		}
//	}

	protected void applyU4Data(Address addr) {
		try {
			program.getListing().createData(addr, DWordDataType.dataType);
		}
		catch (CodeUnitInsertionException e) {
			// ignore
		}
		catch (DataTypeConflictException e) {
			// ignore
		}
	}

	protected int getStructureComponent(Structure testInfoStruct, String fieldName) {
		for (DataTypeComponent component : testInfoStruct.getDefinedComponents()) {
			if (fieldName.equals(component.getFieldName())) {
				return component.getOffset();
			}
		}
		throw new RuntimeException(fieldName + " field not found within " +
			testInfoStruct.getName() + " structure definition at " + infoStructAddr.toString(true));
	}

	protected void readControlBlock(boolean applyStruct)
			throws InvalidControlBlockException, CodeUnitInsertionException {

		if (applyStruct) {
			DataUtilities.createData(program, infoStructAddr, infoProgramStruct, -1, false,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}

		TerminatedStringDataType stringType =
			new TerminatedStringDataType(program.getDataTypeManager());

		Structure functionInfoStruct =
			(Structure) infoProgramStruct.getDataTypeManager().getDataType(CategoryPath.ROOT,
				"FunctionInfo");
		if (functionInfoStruct == null) {
			throw new AssertException("FunctionInfo structure not yet resolved");
		}

		int nameOffset = getStructureComponent(functionInfoStruct, "name");
		int funcOffset = getStructureComponent(functionInfoStruct, "func");
		int numTestOffset = getStructureComponent(functionInfoStruct, "numTest");

		try {

			DumbMemBufferImpl memBuffer =
				new DumbMemBufferImpl(program.getMemory(), infoStructAddr);
			int functionArrayPtrOffset =
				getStructureComponent(infoProgramStruct, "funcInfoArrayPtr");
			Address functionInfoAddress =
				readDataPointer(memBuffer, functionArrayPtrOffset, applyStruct);

			Msg.info(this, "Loading FunctionInfo array at " + functionInfoAddress);

			while (true) {
				// Read function table
				memBuffer.setPosition(functionInfoAddress);

				if (applyStruct) {
					DataUtilities.createData(program, functionInfoAddress, functionInfoStruct, -1,
						false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
					forceCodePointer(functionInfoAddress.add(funcOffset));
				}

				Address funcNamePtr = readDataPointer(memBuffer, nameOffset, applyStruct);
				Address funcPtr = readCodePointer(memBuffer, funcOffset, applyStruct);
				int numTest = memBuffer.getInt(numTestOffset);

				if (funcNamePtr.getOffset() == 0) {
					break;
				}

				memBuffer.setPosition(funcNamePtr);
				String functionName =
					(String) stringType.getValue(memBuffer, SettingsImpl.NO_SETTINGS, 0);

				if (funcPtr.getOffset() != 0) {
					MemoryBlock block = program.getMemory().getBlock(funcPtr);
					if (block == null || !block.isInitialized()) {
						throw new InvalidControlBlockException(
							infoProgramStruct.getName() + " @ " + infoStructAddr.toString(true) +
								" has invalid pointer offset for function: " + functionName +
								" -> " + funcPtr);
					}
				}

				if (funcPtr.getOffset() != 0) {
					FunctionInfo info = new FunctionInfo(functionName, funcPtr, numTest);
					functions.add(info);
					functionMap.put(functionName, info);
				}

				functionInfoAddress = functionInfoAddress.add(functionInfoStruct.getLength());

			}

		}
		catch (MemoryAccessException e) {
			throw new InvalidControlBlockException(
				infoProgramStruct.getName() + " program read error", e);
		}

	}

	protected String emuReadString(EmulatorHelper emu, Address strPtrAddr) {

		DataOrganization dataOrganization =
			emu.getProgram().getDataTypeManager().getDataOrganization();
		int charSize = dataOrganization.getCharSize();
		boolean isBigEndian = emu.getProgram().getMemory().isBigEndian();

		MemoryState memState = emu.getEmulator().getMemState();
		long offset = strPtrAddr.getOffset();
		if (isBigEndian) {
			offset += (charSize - 1);
		}
		char[] buffer = new char[128];
		int index = 0;
		while (index < buffer.length) {
			buffer[index] =
				(char) (memState.getValue(strPtrAddr.getAddressSpace(), offset, 1) & 0xff);
			if (buffer[index] == 0) {
				break;
			}
			offset += charSize;
			++index;
		}
		return new String(buffer, 0, index);
	}

	protected long emuRead(EmulatorHelper emu, Address addr, int size) {
		if (size < 1 || size > 8) {
			throw new IllegalArgumentException("Unsupported EMU read size: " + size);
		}
		MemoryState memState = emu.getEmulator().getMemState();
		return memState.getValue(addr.getAddressSpace(), addr.getOffset(), size);
	}

	protected void emuWrite(EmulatorHelper emu, Address addr, int size, long value) {
		if (size < 1 || size > 8) {
			throw new IllegalArgumentException("Unsupported EMU read size: " + size);
		}
		MemoryState memState = emu.getEmulator().getMemState();
		memState.setValue(addr.getAddressSpace(), addr.getOffset(), size, value);
	}

	protected Address getMirroredDataAddress(EmulatorTestRunner emuTestRunner, Address addr) {
		AddressSpace defaultDataSpace =
			emuTestRunner.getProgram().getLanguage().getDefaultDataSpace();
		if (defaultDataSpace != null && !addr.getAddressSpace().equals(defaultDataSpace)) {
			addr = defaultDataSpace.getAddress(addr.getOffset());
		}
		return addr;
	}

	static Address findBytes(Memory memory, AddressSetView set, byte[] bytes) {
		for (AddressRange range : set.getAddressRanges()) {
			Address addr = memory.findBytes(range.getMinAddress(), range.getMaxAddress(), bytes,
				null, true, TaskMonitor.DUMMY);
			if (addr != null) {
				// ignore overlay blocks which may have been created by the importer
				if (addr.getAddressSpace().isOverlaySpace()) {
					continue;
				}
				return addr;
			}
		}
		return null;
	}

	static class InvalidControlBlockException extends Exception {

		private static final long serialVersionUID = 9137869694955008327L;

		public InvalidControlBlockException(String msg) {
			super(msg);
		}

		public InvalidControlBlockException(String msg, Throwable cause) {
			super(msg, cause);
		}
	}

	public static class FunctionInfo implements Comparable<FunctionInfo> {

		public final String functionName;
		public final Address functionAddr;
		public final int numberOfAsserts;

		FunctionInfo(String functionName, Address functionAddr, int numberOfAsserts) {
			this.functionName = functionName;
			this.functionAddr = functionAddr;
			this.numberOfAsserts = numberOfAsserts;
		}

		@Override
		public int compareTo(FunctionInfo other) {
			return functionName.compareTo(other.functionName);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof FunctionInfo)) {
				return false;
			}
			FunctionInfo other = (FunctionInfo) obj;
			return functionName.equals(other.functionName) &
				functionAddr.equals(other.functionAddr);
		}

		@Override
		public int hashCode() {
			return functionAddr.hashCode();
		}

		@Override
		public String toString() {
			return functionName + "@" + functionAddr.toString(true);
		}
	}
}
