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
package ghidra.app.util.bin.format.elf.extend;

import java.math.BigInteger;

import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class PowerPC_ElfExtension extends ElfExtension {

	// Label prefix to be applied to the blrl instruction found within the .got
	// and the name of the call-fixup to be applied if it has been defined by
	// the compiler spec
	public static String GOT_THUNK_NAME = "get_pc_thunk_lr";

	private static int BLRL_INSTRUCTION = 0x4e800021;

	// Elf Dynamic Type Extensions
	public static final ElfDynamicType DT_PPC_GOT = new ElfDynamicType(0x70000000, "DT_PPC_GOT",
		"Specify the value of _GLOBAL_OFFSET_TABLE_", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_PPC_OPT = new ElfDynamicType(0x70000001, "DT_PPC_OPT",
		"Specify that tls descriptors should be optimized", ElfDynamicValueType.VALUE);

	// Program header (segment) flags
	private static final int PF_PPC_VLE = 0x10000000;

	// Section header flags
	private static final int SHF_PPC_VLE = 0x10000000;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_PPC && elf.is32Bit();
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"PowerPC".equals(language.getProcessor().toString()) &&
			language.getLanguageDescription().getSize() == 32;
	}

	@Override
	public String getDataTypeSuffix() {
		return "_PPC";
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		if (!canHandle(elfLoadHelper)) {
			return;
		}

		processPpcVleSections(elfLoadHelper, monitor);
	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		processDynamicPpcGotEntry(elfLoadHelper);

		super.processGotPlt(elfLoadHelper, monitor);

		// check for blrl instruction at end of got sections
		markupGotBLRL(elfLoadHelper, monitor);
	}

	private void processDynamicPpcGotEntry(ElfLoadHelper elfLoadHelper) {

		ElfHeader elfHeader = elfLoadHelper.getElfHeader();

		// Presence of DT_PPC_GOT signals old ABI
		ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(DT_PPC_GOT)) {
			return;
		}

		try {
			Address gotAddr =
				elfLoadHelper.getDefaultAddress(dynamicTable.getDynamicValue(DT_PPC_GOT));

			Program program = elfLoadHelper.getProgram();
			Memory memory = program.getMemory();
			try {
				// Update first got entry normally updated by link editor to refer to dynamic table
				int dynamicOffset =
					memory.getInt(gotAddr) + (int) elfLoadHelper.getImageBaseWordAdjustmentOffset();
				memory.setInt(gotAddr, dynamicOffset);
			}
			catch (MemoryAccessException e) {
				elfLoadHelper.log(e);
			}
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * Determine if program's cspec has defined the get_pc_thunk_lr call-fixup
	 * @param program
	 * @return true if get_pc_thunk_lr call-fixup is defined
	 */
	private boolean gotThunkCallFixupExists(Program program) {
		for (String fixupName : program.getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames()) {
			if (GOT_THUNK_NAME.equals(fixupName)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Identify presence of blrl instruction within .got section with execute permission.
	 * The instruction will be disassembled and transformed into a get_pc_thunk_lr function
	 * with an applied call-fixup.
	 * @param elfLoadHelper
	 * @param monitor
	 * @throws CancelledException
	 */
	private void markupGotBLRL(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		boolean applyCallFixup = gotThunkCallFixupExists(program);

		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);

		MemoryBlock[] blocks = memory.getBlocks();

		for (MemoryBlock block : blocks) {
			monitor.checkCanceled();

			MemoryBlock gotBlock = block;

			if (!gotBlock.getName().startsWith(ElfSectionHeaderConstants.dot_got) ||
				!gotBlock.isExecute()) {
				continue;
			}

			Address blrlAddr = findBLRL(gotBlock, memory.isBigEndian());
			if (blrlAddr == null) {
				continue;
			}

			listing.clearCodeUnits(blrlAddr, gotBlock.getEnd(), false);

			Address blrlEndAddr = blrlAddr.add(3);
			AddressSet range = new AddressSet(blrlAddr, blrlEndAddr);

			disassembler.disassemble(blrlAddr, range);

			try {
				Instruction blrlInstr = listing.getInstructionAt(blrlAddr);
				if (blrlInstr == null) {
					elfLoadHelper.log(
						"Failed to generate blrl instruction within " + gotBlock.getName());
					continue;
				}

				blrlInstr.setFlowOverride(FlowOverride.RETURN);

				Function f = listing.createFunction(GOT_THUNK_NAME + gotBlock.getName(), blrlAddr,
					range, SourceType.IMPORTED);
				if (applyCallFixup) {
					f.setCallFixup(GOT_THUNK_NAME);
				}

			}
			catch (InvalidInputException | OverlappingFunctionException e) {
				// should not happen
			}

		}
	}

	/**
	 * Check for trailing BLRL instruction at end of GOT block.
	 * Searching from the end of the .got any non-zero entry will
	 * cause the search to end within that .got
	 * @param block
	 * @param bigEndian
	 * @return address of BLRL bytes or null if not found
	 */
	private Address findBLRL(MemoryBlock block, boolean bigEndian) {

		DataConverter conv =
			bigEndian ? BigEndianDataConverter.INSTANCE : LittleEndianDataConverter.INSTANCE;

		Address start = block.getStart();
		Address addr = block.getEnd();
		byte[] bytes = new byte[4];

		addr = addr.getNewAddress(addr.getOffset() & ~0x3);
		try {
			while (addr.compareTo(start) > 0) {
				if (block.getBytes(addr, bytes) == 4) {
					int val = conv.getInt(bytes);
					if (val == BLRL_INSTRUCTION) {
						return addr;
					}
					if (val != 0) {
						return null;
					}
				}
				addr = addr.subtractNoWrap(4);
			}
		}
		catch (MemoryAccessException | AddressOverflowException e) {
			// ignore
		}
		return null;
	}

	/**
	 * Identify PowerPC VLE sections and set the 'vle' context bit to enable
	 * proper code disassembly.
	 * @param elfLoadHelper Elf load helper object
	 * @param monitor task monitor
	 * @throws CancelledException
	 */
	private void processPpcVleSections(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		// TODO: Check language ID for VLE ":VLE"

		Program program = elfLoadHelper.getProgram();
		LanguageID langID = program.getLanguageID();
		if (langID.toString().indexOf(":VLE") < 0) {
			return; // non VLE variant
		}

		Register vleContextReg = program.getRegister("vle");
		if (vleContextReg == null || !vleContextReg.isProcessorContext()) {
			elfLoadHelper.log("ERROR: failed to locate 'vle' context register field");
			return;
		}

		monitor.setMessage("Checking for VLE sections...");

		RegisterValue enableVLE = new RegisterValue(vleContextReg, BigInteger.ONE);

		ElfHeader elf = elfLoadHelper.getElfHeader();
		if (elf.e_shnum() != 0) {
			// Rely on section headers if present
			for (ElfSectionHeader section : elf.getSections(
				ElfSectionHeaderConstants.SHT_PROGBITS)) {
				monitor.checkCanceled();
				if ((section.getFlags() & SHF_PPC_VLE) == 0) {
					continue;
				}
				enableVLE(section, enableVLE, elfLoadHelper);
			}
		}
		else {
			for (ElfProgramHeader segment : elf.getProgramHeaders(
				ElfProgramHeaderConstants.PT_LOAD)) {
				monitor.checkCanceled();
				if ((segment.getFlags() & PF_PPC_VLE) == 0) {
					continue;
				}
				enableVLE(segment, enableVLE, elfLoadHelper);
			}
		}
	}

	private void enableVLE(MemoryLoadable header, RegisterValue enableVLE,
			ElfLoadHelper elfLoadHelper) {
		Address loadAddress = elfLoadHelper.findLoadAddress(header, 0);
		if (loadAddress == null) {
			elfLoadHelper.log("Failed to locate VLE load section/segment");
			return;
		}
		Program program = elfLoadHelper.getProgram();
		MemoryBlock block = program.getMemory().getBlock(loadAddress);
		if (block != null) {
			elfLoadHelper.log("Marked block " + block.getName() + " as VLE");
			try {
				program.getProgramContext().setRegisterValue(block.getStart(), block.getEnd(),
					enableVLE);
			}
			catch (ContextChangeException e) {
				elfLoadHelper.log(
					"ERROR: failed to set 'vle' context due to conflict: " + e.getMessage());
			}
		}
	}

}
