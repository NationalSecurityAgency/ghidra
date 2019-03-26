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
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.bin.format.pef.PefConstants;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PefLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class PowerPCAddressAnalyzer extends ConstantPropagationAnalyzer {

	private static final String OPTION_NAME_CHECK_NIBBLE = "Restrict Address to same 256M page";
	private static final String OPTION_DESCRIPTION_CHECK_NIBBLE = "";
	private static final boolean OPTION_DEFAULT_CHECK_HIGH_NIBBLE = false;

	private static final String OPTION_NAME_MARK_DUAL_INSTRUCTION =
		"Mark dual instruction references";
	private static final String OPTION_DESCRIPTION_MARK_DUAL_INSTRUCTION =
		"Turn on to mark all potential dual instruction refs,\n" + "(lis - addi/orri/subi)\n" +
			"even if they are not seen to be used as a reference.";
	private static final boolean OPTION_DEFAULT_MARK_DUAL_INSTRUCTION = false;

	private static final String OPTION_NAME_PROPAGATE_R2 = "Propagate r2 register value";
	private static final String OPTION_DESCRIPTION_PROPAGATE_R2 =
		"Propagate r2 register value into called functions\n" +
			"to facilitate function descriptor resolution.";

	private static final String OPTION_NAME_PROPAGATE_R30 = "Propagate r30 register value";
	private static final String OPTION_DESCRIPTION_PROPAGATE_R30 =
		"Propagate r30 register value into called functions\n";

	private static final String SWITCH_OPTION_NAME = "Switch Table Recovery";
	private static final String SWITCH_OPTION_DESCRIPTION = "Turn on to recover switch tables";
	private static final boolean SWITCH_OPTION_DEFAULT_VALUE = true;

	private boolean markupDualInstructionOption = OPTION_DEFAULT_MARK_DUAL_INSTRUCTION;
	private boolean checkHighNibbleOption = OPTION_DEFAULT_CHECK_HIGH_NIBBLE;
	private boolean propagateR2value; // see computed default
	private boolean propagateR30value; // see computed default
	private boolean recoverSwitchTables = SWITCH_OPTION_DEFAULT_VALUE;

	private final static String PROCESSOR_NAME = "PowerPC";

	public PowerPCAddressAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	private boolean getDefaultPropagateR2Option(Program program) {
		// TODO: R2 propagation had been disabled for PEF - should it be enabled by default?
		boolean isELF = ElfLoader.ELF_NAME.equals(program.getExecutableFormat());
		return isELF && program.getLanguage().getLanguageDescription().getSize() == 64;
	}

	private boolean getDefaultPropagateR30Option(Program program) {
		boolean isELF = ElfLoader.ELF_NAME.equals(program.getExecutableFormat());
		boolean is32bit = program.getLanguage().getLanguageDescription().getSize() == 32;
		// The use of r30 as a GOT pointer during function calls can occurs with the V1.0 ABI 
		// for relocatable PIC code.  The presence of the dynamic table entry DT_PPC_GOT 
		// can be used as an indicator and the associated symbol __DT_PPC_GOT created by
		// the ELF Loader.
		return isELF && is32bit && program.getSymbolTable().getSymbols("__DT_PPC_GOT").hasNext();
	}

	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);

		options.registerOption(OPTION_NAME_CHECK_NIBBLE, checkHighNibbleOption, null,
			OPTION_DESCRIPTION_CHECK_NIBBLE);

		options.registerOption(OPTION_NAME_MARK_DUAL_INSTRUCTION, markupDualInstructionOption, null,
			OPTION_DESCRIPTION_MARK_DUAL_INSTRUCTION);

		options.registerOption(SWITCH_OPTION_NAME, recoverSwitchTables, null,
			SWITCH_OPTION_DESCRIPTION);

		options.registerOption(OPTION_NAME_PROPAGATE_R2, getDefaultPropagateR2Option(program), null,
			OPTION_DESCRIPTION_PROPAGATE_R2);

		options.registerOption(OPTION_NAME_PROPAGATE_R30, getDefaultPropagateR30Option(program),
			null, OPTION_DESCRIPTION_PROPAGATE_R30);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		checkHighNibbleOption = options.getBoolean(OPTION_NAME_CHECK_NIBBLE, checkHighNibbleOption);

		markupDualInstructionOption =
			options.getBoolean(OPTION_NAME_MARK_DUAL_INSTRUCTION, markupDualInstructionOption);

		recoverSwitchTables = options.getBoolean(SWITCH_OPTION_NAME, recoverSwitchTables);

		propagateR2value = options.getBoolean(OPTION_NAME_PROPAGATE_R2, propagateR2value);
		propagateR30value = options.getBoolean(OPTION_NAME_PROPAGATE_R30, propagateR30value);
	}

	@Override
	public AddressSet flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		RegisterValue initR2Value = lookupR2(program, flowStart);
		final RegisterValue startingR2Value = initR2Value;

		boolean isPEF = PefLoader.PEF_NAME.equals(program.getExecutableFormat());

		Register r2 = program.getRegister("r2");
		Register r30 = program.getRegister("r30");

		// TODO: NEEDS MORE WORK !!!
		// - attempt to flow and restore r2 after calls

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(trustWriteMemOption) {

				@Override
				public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
					return false;
				}

				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
					if (markupDualInstructionOption) {
						markupDualInstructions(context, instr);
					}

					if ((propagateR2value || propagateR30value) && instr.getFlowType().isCall()) {

						// TODO: Should this be done with evaluateDestination instead

						Reference[] refs = instr.getReferencesFrom();
						for (Reference ref : refs) {
							Address destAddr = ref.getToAddress();
							if (propagateR2value && program.getProgramContext().getRegisterValue(r2,
								destAddr) == null) {
								setRegisterIfNotSet(program, destAddr, startingR2Value);
							}
							if (propagateR30value) {
								RegisterValue r30Value = context.getRegisterValue(r30);
								setRegisterIfNotSet(program, destAddr, r30Value);
							}
						}
					}

					// NOTE: ELF restores r2 after returning from called function stub
					// which may not fit with restoring r2 context as done for PEF

					// handle the nasty reset of "r2"
					// TODO: this should probably be an option
					if (propagateR2value && isPEF && isPEFCallingConvention(program, instr)) {
						if (startingR2Value != null) {
							context.setRegisterValue(startingR2Value);
						}
					}
					return false;
				}

				private void markupDualInstructions(VarnodeContext context, Instruction instr) {
					String mnemonic = instr.getMnemonicString();
					if (mnemonic.equals("subi") || mnemonic.equals("addi")) {
						Register reg = instr.getRegister(0);
						if (reg != null) {
							BigInteger val = context.getValue(reg, false);
							if (val != null) {
								long lval = val.longValue();
								Address refAddr =
									instr.getMinAddress().getNewTruncatedAddress(lval, true);
								// TODO: this needs a much more thourough check.
								//       What is at the other end of the instruction!
								if ((lval > 4096 || lval < 0) &&
									program.getMemory().contains(refAddr)) {
									if (instr.getOperandReferences(2).length == 0) {
										instr.addOperandReference(2, refAddr, RefType.DATA,
											SourceType.ANALYSIS);
									}
								}
							}
						}
					}
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, RefType refType) {

					if (instr.getFlowType().isJump()) {
						// for branching instructions, if we have a good target, mark it
						// if this isn't straight code (thunk computation), let someone else lay down the reference
						return !symEval.encounteredBranch();
					}

					// don't markup li from a scalar, addresses don't fit in an instruction.
					String mnemonic = instr.getMnemonicString();
					if (mnemonic.equals("li") && instr.getScalar(1) != null) {
						return false;
					}

					// lis is only the upper half of the instruction, don't mark it as a reference.
					if (mnemonic.equals("lis")) {
						return false;
					}

					// don't use short constant on load/store as address
					if (mnemonic.startsWith("ld") || mnemonic.startsWith("lw") ||
						mnemonic.startsWith("lb") || mnemonic.startsWith("st")) {
						for (Object obj : instr.getOpObjects(1)) {
							if ((obj instanceof Scalar) &&
								((Scalar) obj).getUnsignedValue() == address.getOffset()) {
								return false;
							}
						}
					}

					// markup the data flow for this instruction
					if (refType.isData()) {
						return true;
					}

					return super.evaluateReference(context, instr, pcodeop, address, size, refType);
				}

				@Override
				public boolean evaluateDestination(VarnodeContext context,
						Instruction instruction) {
					String mnemonic = instruction.getMnemonicString();
					if (!instruction.getFlowType().isJump()) {
						return false;
					}
					if (mnemonic.equals("bcctr") || mnemonic.equals("bcctrl") ||
						mnemonic.equals("bctr")) {
						// record the destination that is unknown
						if (!checkAlreadyRecovered(instruction.getProgram(),
							instruction.getMinAddress())) {
							destSet.addRange(instruction.getMinAddress(),
								instruction.getMinAddress());
						}
					}
					return false;
				}

				@Override
				public Long unknownValue(VarnodeContext context, Instruction instruction,
						Varnode node) {
					if (node.isRegister()) {
						Register reg = program.getRegister(node.getAddress());
						if (reg != null) {
							if (reg.getName().equals("xer_so")) {
								return new Long(0);
							}
							if (propagateR2value && reg.getName().equals("r2") &&
								startingR2Value != null && startingR2Value.hasValue()) {
								return new Long(startingR2Value.getUnsignedValue().longValue());
							}
						}
					}
					return null;
				}

				@Override
				public boolean followFalseConditionalBranches() {
					return true;
				}

				@Override
				public boolean evaluateSymbolicReference(VarnodeContext context, Instruction instr,
						Address address) {
					return false;
				}

				@Override
				public boolean allowAccess(VarnodeContext context, Address addr) {
					return trustWriteMemOption;
				}
			};

		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		if (recoverSwitchTables) {
			recoverSwitches(program, symEval, eval.getDestinationSet(), monitor);
		}

		return resultSet;
	}

	private void setRegisterIfNotSet(Program program, Address addr, RegisterValue regValue) {
		if (regValue == null || !regValue.hasValue() ||
			regValue.getUnsignedValue().equals(BigInteger.ZERO)) {
			return;
		}
		ProgramContext programContext = program.getProgramContext();
		RegisterValue oldValue = programContext.getRegisterValue(regValue.getRegister(), addr);
		if (oldValue != null && oldValue.hasValue() &&
			!oldValue.getUnsignedValueIgnoreMask().equals(BigInteger.ZERO)) {
			return;
		}
		try {
			programContext.setRegisterValue(addr, addr, regValue);
			if (program.getListing().getFunctionAt(addr) != null) {
				AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
				analysisMgr.functionDefined(addr); // kick function for re-analysis
				analysisMgr.codeDefined(addr); // kick off code value propagation for the function
			}
		}
		catch (ContextChangeException e) {
			throw new AssertException("unexpected", e);
		}
	}

	private RegisterValue lookupR2(Program program, Address flowStart) {
		RegisterValue initR2Value = null;
		if (propagateR2value) {
			initR2Value =
				program.getProgramContext().getRegisterValue(program.getRegister("r2"), flowStart);
			if (initR2Value == null || !initR2Value.hasValue()) {
				initR2Value = findR2Value(program, flowStart);
				setRegisterIfNotSet(program, flowStart, initR2Value);
			}
		}
		return initR2Value;
	}

	private boolean checkAlreadyRecovered(Program program, Address addr) {
		int referenceCountFrom = program.getReferenceManager().getReferenceCountFrom(addr);

		if (referenceCountFrom > 1) {
			return true;
		}
		Reference[] refs = program.getReferenceManager().getReferencesFrom(addr);
		if (refs.length == 1 && !refs[0].getReferenceType().isData()) {
			return true;
		}

		return false;
	}

	private void recoverSwitches(final Program program, SymbolicPropogator symEval,
			AddressSet destinationSet, TaskMonitor monitor) throws CancelledException {

		final ArrayList<Address> targetList = new ArrayList<>();

		// now handle symbolic execution assuming values!
		class SwitchEvaluator implements ContextEvaluator {

			private static final int STARTING_MAX_TABLE_SIZE = 64;

			long tableIndexOffset;
			Address targetSwitchAddr = null;
			boolean hitTheGuard = false;
			Long assumeValue = new Long(0);
			int tableSizeMax = STARTING_MAX_TABLE_SIZE;

			public void setGuard(boolean hitGuard) {
				hitTheGuard = hitGuard;
			}

			public void setAssume(Long assume) {
				assumeValue = assume;
			}

			public void setTargetSwitchAddr(Address addr) {
				targetSwitchAddr = addr;
			}

			public int getMaxTableSize() {
				return tableSizeMax;
			}

			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				return false;
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				// find the cmpli to set the size of the table
				//    tableSize = size
				String mnemonic = instr.getMnemonicString();
				if ((mnemonic.compareToIgnoreCase("cmpi") == 0) ||
					(mnemonic.compareToIgnoreCase("cmpwi") == 0) ||
					(mnemonic.compareToIgnoreCase("cmpli") == 0) ||
					(mnemonic.compareToIgnoreCase("cmplwi") == 0)) {
					int numOps = instr.getNumOperands();
					if (numOps > 1) {
						Register reg = instr.getRegister(numOps - 2);
						if ((reg != null)) {
							Scalar scalar = instr.getScalar(numOps - 1);
							if (scalar != null) {
								int newTableSizeMax = (int) scalar.getSignedValue() + 1;
								if (newTableSizeMax > 0 && newTableSizeMax < 128) {
									tableSizeMax = newTableSizeMax;
								}
								hitTheGuard = true;
								RegisterValue rval = context.getRegisterValue(reg);
								context.clearRegister(reg);
								if (rval != null) {
									long lval = rval.getSignedValue().longValue();
									if (lval < 0) {
										tableIndexOffset = -lval;
									}
								}
							}
						}
					}
				}
				if (instr.getFlowType().isConditional()) {
					hitTheGuard = true;
				}

				return false;
			}

			@Override
			public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop,
					Address constant, int size, RefType refType) {
				return null;
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, RefType refType) {

				// TODO: if ever loading from instructions in memory, must EXIT!
				if (!((refType.isComputed() || refType.isConditional()) &&
					program.getMemory().contains(address))) {
					if (refType.isRead()) {
						createDataType(program, instr, address);
					}
					return false;
				}
				if (!targetList.contains(address)) {
					targetList.add(address);
				}
				return true; // just go ahead and mark up the instruction
			}

			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				return instruction.getMinAddress().equals(targetSwitchAddr);
			}

			@Override
			public Long unknownValue(VarnodeContext context, Instruction instruction,
					Varnode node) {
				if (node.isRegister()) {
					if (instruction.getFlowType().isJump()) {
						return null;
					}
					Register reg = program.getRegister(node.getAddress());
					if (reg != null) {
						// never assume for flags, or control registers
						if (reg.getName().equals("xer_so") || reg.getName().startsWith("cr")) {
							return new Long(0);
						}
					}
					if (hitTheGuard) {
						return assumeValue;
					}
				}
				return null;
			}

			@Override
			public boolean followFalseConditionalBranches() {
				return false;
			}

			@Override
			public boolean evaluateSymbolicReference(VarnodeContext context, Instruction instr,
					Address address) {
				return false;
			}

			@Override
			public boolean allowAccess(VarnodeContext context, Address addr) {
				return false;
			}
		}

		SwitchEvaluator switchEvaluator = new SwitchEvaluator();

		// now flow with the simple block of this branch....

		// for each unknown branch destination,
		AddressIterator iter = destinationSet.getAddresses(true);
		SimpleBlockModel model = new SimpleBlockModel(program);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Address loc = iter.next();

			// first see if something else has already done this!
			int referenceCountFrom = program.getReferenceManager().getReferenceCountFrom(loc);
			if (referenceCountFrom > 2) {
				continue;
			}

			CodeBlock bl = null;
			try {
				bl = model.getFirstCodeBlockContaining(loc, monitor);
			}
			catch (CancelledException e) {
				return;
			}

			AddressSet branchSet = new AddressSet(bl);
			CodeBlockReferenceIterator bliter;
			try {
				bliter = bl.getSources(monitor);
				boolean oneSource = (bl.getNumSources(monitor) == 1);
				while (bliter.hasNext()) {
					CodeBlockReference sbl = bliter.next();
					if (sbl.getFlowType().isCall()) {
						continue;
					}
					if ((sbl.getFlowType().isFallthrough() || oneSource) ||
						!sbl.getFlowType().isConditional()) {
						bl = sbl.getSourceBlock();
						if (bl != null) {
							branchSet.add(bl);
						}
					}
				}
			}
			catch (CancelledException e) {
				break;
			}

			for (long assume = 0; assume < switchEvaluator.getMaxTableSize(); assume++) {
				switchEvaluator.setAssume(new Long(assume));
				switchEvaluator.setGuard(false);
				switchEvaluator.setTargetSwitchAddr(loc);

				symEval.flowConstants(branchSet.getMinAddress(), branchSet, switchEvaluator, false,
					monitor);
				// if it didn't get it after try with 0
				if (assume > 0 && targetList.size() < 1) {
					break;
				}
				if (symEval.readExecutable()) {
					break;
				}
			}
			// re-create the function body with the newly found code
			if (targetList.size() > 1) {
				AddressTable table;
				table = new AddressTable(loc, targetList.toArray(new Address[0]),
					program.getDefaultPointerSize(), 0, false);
				table.fixupFunctionBody(program, program.getListing().getInstructionAt(loc),
					monitor);
				labelTable(program, loc, targetList);
			}
			else if (targetList.size() == 1) {
				Function f = program.getFunctionManager().getFunctionContaining(loc);
				CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
			}
		}
	}

	private void createDataType(Program program, Instruction instr, Address address) {
		if (!program.getListing().isUndefined(address, address)) {
			return;
		}
		String mnemonic = instr.getMnemonicString();
		if (mnemonic.startsWith("l") || mnemonic.startsWith("s")) {
			char endCh = mnemonic.charAt(1);
			DataType dt = null;
			switch (endCh) {
				case 'd':
					dt = Undefined8DataType.dataType;
					break;
				case 'w':
					dt = Undefined4DataType.dataType;
					break;
				case 'h':
					dt = Undefined2DataType.dataType;
					break;
				case 'b':
					dt = Undefined1DataType.dataType;
					break;
			}
			if (dt != null) {
				try {
					program.getListing().createData(address, dt);
				}
				catch (CodeUnitInsertionException e) {
					// ignore
				}
				catch (DataTypeConflictException e) {
					// ignore
				}
			}
		}
	}

	private RegisterValue findR2Value(Program program, Address start) {

		if (PefLoader.PEF_NAME.equals(program.getExecutableFormat())) {
			return findPefR2Value(program, start);
		}
//		if (ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
//			return findElfR2Value(program, start);
//		}
		return null;
	}

//	private RegisterValue findElfR2Value(Program program, Address start) {
//
//		// look for TOC_BASE injected by PowerPC_ElfExtension
//		Symbol tocSym = SymbolUtilities.getLabelOrFunctionSymbol(program,
//			PowerPC64_ElfExtension.TOC_BASE, this, false);
//		if (tocSym == null) {
//			return null;
//		}
//
//		Register r2 = program.getRegister("r2");
//		return new RegisterValue(r2, BigInteger.valueOf(tocSym.getAddress().getOffset()));
//	}

	private RegisterValue findPefR2Value(Program program, Address start) {

		Listing listing = program.getListing();
		ReferenceManager referenceManager = program.getReferenceManager();
		Symbol tocSymbol = SymbolUtilities.getExpectedLabelOrFunctionSymbol(program,
			PefConstants.TOC, err -> Msg.error(this, err));
		if (tocSymbol == null) {
			return null;
		}

		PseudoDisassembler pdis = new PseudoDisassembler(program);
		ReferenceIterator refIter = referenceManager.getReferencesTo(start);

		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			// if is a data pointer
			Data data = listing.getDataAt(ref.getFromAddress());
			if (data == null) {
				continue;
			}
			if (!data.isPointer()) {
				continue;
			}
			// check after the data pointer to see if it is the same as the TOC value
			Address dataAddr = data.getMaxAddress().add(1);
			Address tocAddr = pdis.getIndirectAddr(dataAddr);
			if (tocSymbol.getAddress().equals(tocAddr)) {
				BigInteger tocValue = BigInteger.valueOf(tocAddr.getOffset());
				Register r2 = program.getRegister("r2");
				return new RegisterValue(r2, tocValue);
			}
		}
		return null;
	}

	protected boolean isPEFCallingConvention(Program program, Instruction instr) {

		if (instr.getMnemonicString().equals("lwz")) {
			Register reg = instr.getRegister(0);
			if (reg != null && reg.getName().equals("r2")) {
				Object[] objs = instr.getOpObjects(1);
				Register stackRegister = program.getCompilerSpec().getStackPointer();
				for (Object obj : objs) {
					if (obj instanceof Register && ((Register) obj) != stackRegister) {
						return false;
					}
					// TODO: verify stack offset for 64-bit PEF
					if (obj instanceof Scalar && ((Scalar) obj).getValue() != 0x14) {
						return false;
					}
				}
				Address fallAddr = instr.getFallFrom();
				Instruction fallInstr = program.getListing().getInstructionContaining(fallAddr);
				if (fallInstr != null && fallInstr.getFlowType().isCall()) {
					return true;
				}
			}
		}
		return false;
	}

	private void labelTable(Program program, Address loc, ArrayList<Address> targets) {
		Namespace space = null;

		Instruction start_inst = program.getListing().getInstructionAt(loc);

		// not putting switch into functions anymore
		//    program.getSymbolTable().getNamespace(start_inst.getMinAddress());
		String spaceName = "switch_" + start_inst.getMinAddress();
		try {
			space = program.getSymbolTable().createNameSpace(space, spaceName, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException e) {
			space = program.getSymbolTable().getNamespace(spaceName, program.getGlobalNamespace());
		}
		catch (InvalidInputException e) {
			// just go with default space
		}

		int tableNumber = 0;
		for (Address addr : targets) {
			AddLabelCmd lcmd = new AddLabelCmd(addr, "case_" + Long.toHexString(tableNumber), space,
				SourceType.ANALYSIS);
			tableNumber++;
			lcmd.setNamespace(space);

			lcmd.applyTo(program);
		}
	}
}
