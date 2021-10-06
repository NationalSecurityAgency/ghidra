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
/*
 * OperandReferenceAnalyzer.java
 * 
 * Created on Aug 5, 2003
 */
package ghidra.app.plugin.core.analysis;

import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class ScalarOperandAnalyzer extends AbstractAnalyzer {
	private static final String DESCRIPTION =
		"Analyzes scalar operands for references to valid addresses.";
	private final static String NAME = "Scalar Operand References";

	// Maximum difference between an instruction location and its target.
//	private final static long MaxTargetDifference = 1000;

	private final static String OPTION_NAME_RELOCATION_GUIDE = "Relocation Table Guide";

	private static final String OPTION_DESCRIPTION_RELOCATION_GUIDE =
		"Select this check box to use relocation table entries to guide pointer analysis.";

	private final static boolean OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED = true;

	private boolean relocationGuideEnabled = OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED;

	private static final int MAX_NEG_ENTRIES = 32;

	private int alignment = 4;

	private TaskMonitor monitor;

	public ScalarOperandAnalyzer() {
		this(NAME, DESCRIPTION);
	}

	public ScalarOperandAnalyzer(String name, String description) {
		super(name, description, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before().before());
	}

	protected boolean isELF(Program program) {
		return ElfLoader.ELF_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return !isELF(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor taskMonitor,
			MessageLog log) {
		int count = 0;

		monitor = taskMonitor;
		try {
			monitor.initialize(set.getNumAddresses());
			// Iterate over all new instructions
			//   Evaluate each operand
			//
			Listing listing = program.getListing();

			InstructionIterator iter = listing.getInstructions(set, true);
			while (iter.hasNext() && !monitor.isCancelled()) {
				Instruction instr = iter.next();
				monitor.setProgress(++count);
				checkOperands(program, instr);
			}
		}
		finally {
			monitor = null; // get rid of the reference to it
		}

		return true;
	}

	void checkOperands(Program program, Instruction instr) {
		// Check for scalar operands that are a valid address
		//
		for (int i = 0; i < instr.getNumOperands(); i++) {
			Object objs[] = instr.getOpObjects(i);
			for (int j = 0; j < objs.length; j++) {
				if (!(objs[j] instanceof Scalar)) {
					continue;
				}
				Scalar scalar = (Scalar) objs[j];

				//if a relocation exists, then this is a valid address
				boolean found = false;
				for (int r = 0; r < instr.getLength(); ++r) {
					Address addr = instr.getMinAddress().add(r);
					RelocationTable relocTable = program.getRelocationTable();
					Relocation reloc = relocTable.getRelocation(addr);
					if (reloc != null) {
						try {
							switch (scalar.bitLength()) {
								case 8:
									if (program.getMemory().getByte(addr) == scalar
											.getSignedValue()) {
										found = true;
									}
									break;
								case 16:
									if (program.getMemory().getShort(addr) == scalar
											.getSignedValue()) {
										found = true;
									}
									break;
								case 32:
									if (program.getMemory().getInt(addr) == scalar
											.getSignedValue()) {
										found = true;
									}
									break;
								case 64:
									if (program.getMemory().getLong(addr) == scalar
											.getSignedValue()) {
										found = true;
									}
									break;
							}
						}
						catch (MemoryAccessException e) {
							// don't care, squelch it.
						}
					}
				}

				if (!found) {
					// don't do any addresses that could be numbers, even if they are in the
					//   address space.
					long value = scalar.getUnsignedValue();
					if (value < 4096 || value == 0xffff || value == 0xff00 || value == 0xffffff ||
						value == 0xff0000 || value == 0xff00ff || value == 0xffffffff ||
						value == 0xffffff00 || value == 0xffff0000 || value == 0xff000000) {
						continue;
					}
				}

				// check the address in this space first
				if (addReference(program, instr, i, instr.getMinAddress().getAddressSpace(),
					scalar)) {
					continue;
				}

				// then check all spaces
				AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
				for (int as = 0; as < spaces.length; as++) {
					if (addReference(program, instr, i, spaces[as], scalar)) {
						break;
					}
				}
			}
		}
	}

	/**
	 * Check if the address is in the Relocation table.
	 * This only counts for relocatable programs.  Every address should be in the relocation table.
	 * @param target location to check
	 * @return
	 */
	private boolean isValidRelocationAddress(Program program, Address target) {
		// If the program is relocatable, and this address is not one of the relocations
		//   can't be a pointer
		RelocationTable relocationTable = program.getRelocationTable();
		if (relocationTable.isRelocatable()) {
			// if it is relocatable, then there should be no pointers in memory, other than relacatable ones
			if (relocationTable.getSize() > 0 && relocationTable.getRelocation(target) == null) {
				return false;
			}
		}
		return true;
	}

	boolean addReference(Program program, Instruction instr, int opIndex, AddressSpace space,
			Scalar scalar) {
		Address addr = null;
		if (space.isOverlaySpace()) {   // don't do this into overlay spaces.
			return false;
		}
		try {
			addr = space.getAddress(scalar.getUnsignedValue(), true);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}

		// if the reference is not in memory or to a well known location, then don't create it
		// because we are not sure it is correct
		if (!program.getMemory().contains(addr)) {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
			if (symbol == null || symbol.getSource() == SourceType.DEFAULT) {
				return false;
			}
		}

		//check that the target does not fall inside a defined function
		if (checkOffcutFuncRef(program, addr)) {
			Object objs[] = instr.getOpObjects(opIndex);
			checkForJumpTable(program, instr, opIndex, objs, addr);
			return false;
		}

		// if the operand already has a reference, don't make a new one!  Someone less speculative
		//   probably knew better!
		if (instr.getOperandReferences(opIndex).length != 0) {
			return false;
		}

		//program.getReferenceManager().addMemReference(instr.getMinAddress(), addr, RefType.DATA, false, opIndex);
		instr.addOperandReference(opIndex, addr,
			RefTypeFactory.getDefaultMemoryRefType(instr, opIndex, addr, false),
			SourceType.ANALYSIS);

		return true;
	}

	void checkForJumpTable(Program program, Instruction refInstr, int opIndex, Object opObjects[],
			Address addr) {
		Instruction instr = program.getListing().getInstructionContaining(addr);

		if (instr == null) {
			return;
		}

		FlowType ftype = instr.getFlowType();
		if (!(ftype.isJump() && ftype.isComputed())) {
			return;
		}

		// figure out the multiple away
		long entryLen = 0;
		for (int i = 0; i < opObjects.length; i++) {
			if (opObjects[i] instanceof Scalar) {
				Scalar sc = (Scalar) opObjects[i];
				long value = sc.getUnsignedValue();
				if (value == 4 || value == 2 || value == 8) {
					entryLen = value;
					break;
				}
			}
		}
		if (entryLen == 0) {
			return;
		}

		// look for a positive offset 1 away
		Address offAddr;
		try {
			offAddr = addr.addNoWrap(entryLen);
		}
		catch (AddressOverflowException e) {
			return;
		}
		// if there is an instruction at the offset
		if (program.getListing().getInstructionContaining(offAddr) != null) {
			return;
		}
		AddressTable table =
			AddressTable.getEntry(program, offAddr, monitor, false, 3, alignment, 0,
				AddressTable.MINIMUM_SAFE_ADDRESS, relocationGuideEnabled);
		if (table != null) {
			// add in an offcut reference
			program.getReferenceManager()
					.addOffsetMemReference(refInstr.getMinAddress(), offAddr,
						-entryLen, RefType.DATA, SourceType.ANALYSIS, opIndex);
			return;
		}

		// look for a negative offset table
		AddressTable lastGoodTable = null;
		int i;
		for (i = 0; i < MAX_NEG_ENTRIES; i++) {
			Address negAddr = null;
			try {
				negAddr = addr.subtractNoWrap((entryLen + 3) * entryLen);
			}
			catch (AddressOverflowException e) {
				break;
			}

			// if there is an instruction at the offset
			if (program.getListing().getInstructionContaining(negAddr) != null) {
				return;
			}

			AddressTable negTable =
				AddressTable.getEntry(program, negAddr, monitor, false, 3, alignment, 0,
					AddressTable.MINIMUM_SAFE_ADDRESS, relocationGuideEnabled);
			if (negTable != null) {
				lastGoodTable = negTable;
			}
		}
		if (i == MAX_NEG_ENTRIES) {
			return;
		}

		if (lastGoodTable != null) {
			offAddr = lastGoodTable.getTopAddress();

			// add in an offcut reference
			program.getReferenceManager()
					.addOffsetMemReference(instr.getMinAddress(), offAddr,
						(i + 3) * entryLen, RefType.DATA, SourceType.ANALYSIS, opIndex);
			return;
		}
	}

	/** Check if an address that is a possible reference falls within a
	 *    defined function, pointing at a symbol
	 * 
	 * @param program
	 * @param addr
	 */
	boolean checkOffcutFuncRef(Program program, Address addr) {
		Instruction instr = program.getListing().getInstructionContaining(addr);
		// no instruction, not offcut
		if (instr == null) {
			return false;
		}
		// in the middle of an instruction, offcut
		if (!instr.getMinAddress().equals(addr)) {
			return true;
		}
		// in the middle of a function body, offcut
		Function func = program.getFunctionManager().getFunctionContaining(addr);
		if (func != null) {
			if (!func.getEntryPoint().equals(addr)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		if (isELF(program)) {
			return false;
		}
		return getDefaultEnablement2(program);
	}

	protected boolean getDefaultEnablement2(Program program) {
		// don't do risc processors, their addresses don't appear directly in code
		Language language = program.getLanguage();
		if (language.getPropertyAsBoolean(
			GhidraLanguagePropertyKeys.ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE, false)) {
			return false;
		}

		// don't analyze programs starting at 0
		Address min = program.getMinAddress();
		if (min == null || min.getOffset() == 0) {
			return false;
		}

		// languages that are alligned, tend not to have direct addresses.
		if (program.getLanguage().getInstructionAlignment() != 1) {
			return false;
		}

		// only analyze programs with address spaces > 16 bits
		return program.getAddressFactory().getDefaultAddressSpace().getSize() >= 32;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_RELOCATION_GUIDE, relocationGuideEnabled, null,
			OPTION_DESCRIPTION_RELOCATION_GUIDE);

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		relocationGuideEnabled =
			options.getBoolean(OPTION_NAME_RELOCATION_GUIDE, relocationGuideEnabled);
	}

	@Override
	public void analysisEnded(Program program) {
		// Do nothing
	}
}
