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
import java.util.Arrays;
import java.util.HashSet;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class MipsAddressAnalyzer extends ConstantPropagationAnalyzer {

	private static final int MAX_UNIQUE_GP_SYMBOLS = 50;
	private final static String OPTION_NAME_SWITCH_TABLE = "Attempt to recover switch tables";
	private final static String OPTION_DESCRIPTION_SWITCH_TABLE = "";

	private static final String OPTION_NAME_MARK_DUAL_INSTRUCTION =
		"Mark dual instruction references";
	private static final String OPTION_DESCRIPTION_MARK_DUAL_INSTRUCTION =
		"Turn on to mark all potential dual instruction refs," + "\n" + "(lis - addi/orri/subi)" +
			"\n" + " even if they are not seen to be used as a reference.";

	private static final String OPTION_NAME_ASSUME_T9_ENTRY = "Assume T9 set to Function entry";
	private static final String OPTION_DESCRIPTION_ASSUME_T9_ENTRY =
		"Turn on to assume that T9 is set to the entry address of a function when unset T9 register usage encountered";

	private static final String OPTION_NAME_RECOVER_GP = "Recover global GP register writes";
	private static final String OPTION_DESCRIPTION_RECOVER_GP =
		"Discover writes to the global GP register and assume as constant at the start of functions if only one value has been discovered.";

	private static final boolean OPTION_DEFAULT_SWITCH_TABLE = false;
	private static final boolean OPTION_DEFAULT_MARK_DUAL_INSTRUCTION = false;
	private static final boolean OPTION_DEFAULT_ASSUME_T9_ENTRY = true;
	private static final boolean OPTION_DEFAULT_RECOVER_GP = true;

	private boolean trySwitchTables = OPTION_DEFAULT_SWITCH_TABLE;
	private boolean markupDualInstructionOption = OPTION_DEFAULT_MARK_DUAL_INSTRUCTION;
	private boolean assumeT9EntryAddress = OPTION_DEFAULT_ASSUME_T9_ENTRY;
	private boolean discoverGlobalGPSetting = OPTION_DEFAULT_RECOVER_GP;

	private String[] strLoadStore =
		{ "addiu", "daddiu", "lw", "_lw", "sw", "_sw", "sh", "_sh", "sd", "_sd", "lbu", "lhu" };
	private HashSet<String> targetLoadStore = new HashSet<String>(Arrays.asList(strLoadStore));

	private Register t9;

	private Register gp;
	private Register rareg;

	private Register isamode;
	private Register ismbit;

	private Address gp_assumption_value = null;

	private final static String PROCESSOR_NAME = "MIPS";

	public MipsAddressAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		t9 = program.getRegister("t9");
		gp = program.getRegister("gp");
		rareg = program.getRegister("ra");
		isamode = program.getProgramContext().getRegister("ISA_MODE");
		ismbit = program.getProgramContext().getRegister("ISAModeSwitch");

		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		gp_assumption_value = null;

		// check for the _gp symbol to see what the global gp value should be
		checkForGlobalGP(program, set, monitor);

		return super.added(program, set, monitor, log);
	}

	/**
	 * Check for a global GP register symbol or discovered symbol
	 * @param set
	 */
	private void checkForGlobalGP(Program program, AddressSetView set, TaskMonitor monitor) {
		// don't want to check for it
		if (!discoverGlobalGPSetting) {
			return;
		}

		// TODO: Use gp_value provided by MIPS .reginfo or dynamic attributes - check for Elf loader symbol
		// see MIPS_ElfExtension.MIPS_GP_VALUE_SYMBOL
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, "_mips_gp_value",
			err -> Msg.error(this, err));
		if (symbol != null) {
			gp_assumption_value = symbol.getAddress();
			return;
		}

		if (set != null && !set.isEmpty()) {
			// if GP is already Set, don't go looking for a value.
			AddressRangeIterator registerValueAddressRanges =
				program.getProgramContext().getRegisterValueAddressRanges(gp);
			while (registerValueAddressRanges.hasNext()) {
				// but set it so we know if the value we are assuming actually changes
				AddressRange next = registerValueAddressRanges.next();
				if (set.contains(next.getMinAddress(), next.getMaxAddress())) {
					RegisterValue registerValue =
						program.getProgramContext().getRegisterValue(gp, next.getMinAddress());
					gp_assumption_value = next.getMinAddress().getNewAddress(
						registerValue.getUnsignedValue().longValue());
					return;
				}
			}
		}

		// look for the global _gp variable set by ELF binaries

		symbol =
			SymbolUtilities.getLabelOrFunctionSymbol(program, "_gp", err -> Msg.error(this, err));
		if (symbol == null) {
			symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, "_GP",
				err -> Msg.error(this, err));
		}

		if (symbol != null) {
			gp_assumption_value = symbol.getAddress();
		}

		// look for any setting of _gp_# variables
		Symbol s1 =
			SymbolUtilities.getLabelOrFunctionSymbol(program, "_gp_1", err -> Msg.error(this, err));
		if (s1 == null) {
			return;
		}
		// if we found a _gp symbol we set, and there is a global symbol, something is amiss
		if (gp_assumption_value != null && s1.getAddress().equals(gp_assumption_value)) {
			gp_assumption_value = null;
			return;
		}
		Symbol s2 =
			SymbolUtilities.getLabelOrFunctionSymbol(program, "_gp_2", err -> Msg.error(this, err));
		if (s2 == null) {
			// if there is only 1, assume can use the value for now
			gp_assumption_value = s1.getAddress();
		}
		return;
	}

	public Symbol setGPSymbol(Program program, Address toAddr) {
		int index = 1;
		// Only try max times. More than max settings of GP is overkill
		while (index < MAX_UNIQUE_GP_SYMBOLS) {
			try {
				String symname = "_gp_" + index++;
				// check if it already exists
				Symbol existingSymbol =
					SymbolUtilities.getLabelOrFunctionSymbol(program, symname, err -> {
						/* ignore multiple symbols, if even one exists we need to skip if it has a different address */ });
				if (existingSymbol != null) {
					if (existingSymbol.getAddress().equals(toAddr)) {
						return existingSymbol;
					}
					continue;  // can't use this one, look for the next free gp_<x> symbol
				}
				Symbol createSymbol =
					program.getSymbolTable().createLabel(toAddr, symname, SourceType.ANALYSIS);
				return createSymbol;
			}
			catch (InvalidInputException e) {
				break;
			}

		}
		return null;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// get the function body
		final Function func = program.getFunctionManager().getFunctionContaining(flowStart);

		final AddressSet coveredSet = new AddressSet();

		Address currentGPAssumptionValue = gp_assumption_value;

		if (func != null) {
			flowStart = func.getEntryPoint();
			if (currentGPAssumptionValue != null) {
				ProgramContext programContext = program.getProgramContext();
				RegisterValue gpVal = programContext.getRegisterValue(gp, flowStart);
				if (gpVal == null || !gpVal.hasValue()) {
					gpVal = new RegisterValue(gp,
						BigInteger.valueOf(currentGPAssumptionValue.getOffset()));
					try {
						program.getProgramContext().setRegisterValue(func.getEntryPoint(),
							func.getEntryPoint(), gpVal);
					}
					catch (ContextChangeException e) {
						throw new AssertException("unexpected", e); // only happens for context register
					}
				}
			}
		}

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {
			private Address localGPAssumptionValue = currentGPAssumptionValue;

			private boolean mustStopNow = false; // if something discovered in processing, mustStop flag

			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				return mustStopNow;
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				if (markupDualInstructionOption) {
					markupDualInstructions(context, instr);
				}

				// if ra is a constant and is set right after this, this is a call
				// this was copylefted from the arm analyzer
				Varnode raVal = context.getRegisterVarnodeValue(rareg);
				if (raVal != null) {
					if (raVal.isConstant()) {
						long target = raVal.getAddress().getOffset();
						Address addr = instr.getMaxAddress();
						if (target == (addr.getOffset() + 1) && !instr.getFlowType().isCall()) {
							instr.setFlowOverride(FlowOverride.CALL);
							// need to trigger disassembly below! if not already
							MipsExtDisassembly(program, instr, context, addr.add(1), monitor);

							// need to trigger re-function creation!
							Function f = program.getFunctionManager().getFunctionContaining(
								instr.getMinAddress());

							if (f != null) {
								try {
									CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
								}
								catch (CancelledException e) {
									return true;
								}
								//AutoAnalysisManager.getAnalysisManager(program).functionDefined(
								//	func.getBody());
							}
						}
					}
				}

				// check if the GP register is set
				FlowType flowType = instr.getFlowType();
				if (discoverGlobalGPSetting && (flowType.isCall() || flowType.isTerminal())) {
					// check for GP set
					RegisterValue registerValue = context.getRegisterValue(gp);
					if (registerValue != null) {
						BigInteger value = registerValue.getUnsignedValue();
						long unsignedValue = value.longValue();
						if (localGPAssumptionValue == null ||
							!(unsignedValue == localGPAssumptionValue.getOffset())) {
							synchronized (gp) {
								Address gpRefAddr =
									instr.getMinAddress().getNewAddress(unsignedValue);
								setGPSymbol(program, gpRefAddr);

								Address lastSetAddr = context.getLastSetLocation(gp, value);
								Instruction lastSetInstr = instr;
								if (lastSetAddr != null) {
									Instruction instructionAt =
										program.getListing().getInstructionContaining(lastSetAddr);
									if (instructionAt != null) {
										lastSetInstr = instructionAt;
									}
								}
								symEval.makeReference(context, lastSetInstr, -1,
									instr.getMinAddress().getAddressSpace().getSpaceID(),
									unsignedValue, 1, RefType.DATA, PcodeOp.UNIMPLEMENTED, true,
									monitor);
								if (localGPAssumptionValue == null) {
									program.getBookmarkManager().setBookmark(
										lastSetInstr.getMinAddress(), BookmarkType.WARNING,
										"GP Global Register Set",
										"Global GP Register is set here.");
								}
								if (localGPAssumptionValue != null &&
									!localGPAssumptionValue.equals(gpRefAddr)) {
									localGPAssumptionValue = gp_assumption_value = null;
								}
								else {
									localGPAssumptionValue = gp_assumption_value = gpRefAddr;
								}
							}
						}
					}
				}
				return mustStopNow;
			}

			private void markupDualInstructions(VarnodeContext context, Instruction instr) {
				String mnemonic = instr.getMnemonicString();
				if (targetLoadStore.contains(mnemonic)) {
					Register reg = instr.getRegister(0);
					if (reg != null) {
						BigInteger val = context.getValue(reg, false);
						if (val != null) {
							long lval = val.longValue();
							Address refAddr = null;
							try {
								refAddr = instr.getMinAddress().getNewAddress(lval);
							} catch (AddressOutOfBoundsException e) {
								// invalid reference
								return;
							}
							if ((lval > 4096 || lval < 0) && lval != 0xffff &&
								program.getMemory().contains(refAddr)) {

								int opCheck = 0;
								if (instr.getOperandReferences(opCheck).length == 0) {
									instr.addOperandReference(opCheck, refAddr, RefType.DATA,
										SourceType.ANALYSIS);
								}
							}
						}
					}
				}
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, RefType refType) {

				Address addr = address;

				//if (instr.getFlowType().isJump() && !instr.getPrototype().hasDelaySlots()) {
				// if this isn't straight code (thunk computation), let someone else lay down the reference
				//	return !symEval.encounteredBranch();
				//}

				if (instr.getMnemonicString().endsWith("lui")) {
					return false;
				}

				if ((refType.isJump() || refType.isCall()) & refType.isComputed()) {
					//if (refType.isJump() || refType.isCall()) {
					addr = MipsExtDisassembly(program, instr, context, address, monitor);
					//addr = flowISA(program, instr, context, address);
					if (addr == null) {
						addr = address;
					}
				}

				// if this is a call, some processors use the register value
				// used in the call for PIC calculations
				if (refType.isCall()) {
					// set the called function to have a constant value for this register
					// WARNING: This might not always be the case, if called directly or with a different register
					//          But then it won't matter, because the function won't depend on the registers value.
					if (instr.getFlowType().isComputed()) {
						Register reg = instr.getRegister(0);
						if (reg != null && t9.equals(reg) && assumeT9EntryAddress) {
							BigInteger val = context.getValue(reg, false);
							if (val != null) {
								try {
									// clear the register, so it won't be set below this call.
									//  if it is assumed to be set to the same value, it can lead
									//   to incorrect re-use of the value (non-returning functions)
									context.clearRegister(reg);

									// need to add the reference here, register operand will no longer have a value
									instr.addOperandReference(0, addr, refType,
										SourceType.ANALYSIS);

									// set the register value on the target address
									ProgramContext progContext = program.getProgramContext();
									if (progContext.getValue(reg, addr, false) == null) {
										progContext.setValue(reg, addr, addr, val);
										// if we do this, probably need to restart code analysis with function body,
										AutoAnalysisManager amgr =
											AutoAnalysisManager.getAnalysisManager(program);
										amgr.codeDefined(new AddressSet(addr));
									}
								}
								catch (ContextChangeException e) {
									// ignore context change
								}
							}
						}
					}
				}

				return super.evaluateReference(context, instr, pcodeop, address, size, refType);
			}

			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				FlowType flowtype = instruction.getFlowType();
				if (!flowtype.isJump()) {
					return false;
				}

				if (trySwitchTables) {
					String mnemonic = instruction.getMnemonicString();
					if (mnemonic.equals("jr")) {
						fixJumpTable(program, instruction, monitor);
					}
				}

				return false;
			}

			@Override
			public Long unknownValue(VarnodeContext context, Instruction instruction,
					Varnode node) {
				if (assumeT9EntryAddress && node.isRegister() &&
					context.getRegisterVarnode(t9).contains(node.getAddress())) {
					// if get a T9 Register, need to stop evaluating
					// if can't find the beginning of the function, then must stop and assume something else
					// will pick it up.
					if (func != null) {
						Address funcAddr = func.getEntryPoint();
						Long value = new Long(funcAddr.getOffset());
						try {
							ProgramContext progContext = program.getProgramContext();
							// if T9 hasn't already been set
							if (progContext.getValue(t9, funcAddr, false) == null) {
								progContext.setRegisterValue(funcAddr, funcAddr,
									new RegisterValue(t9, BigInteger.valueOf(value)));
								// if we do this, need to restart code analysis with function body,
								// since this is not ready.
								AutoAnalysisManager amgr =
									AutoAnalysisManager.getAnalysisManager(program);
								coveredSet.add(func.getBody());
								amgr.codeDefined(coveredSet);
							}
						}
						catch (ContextChangeException e) {
							throw new AssertException("Unexpected Exception", e);
						}
					}
					else {
						//  If there is no function, kick the can to an analyzer that waits for functions
						//  to be created and sets the T9...
					}
					mustStopNow = true;
				}
				return null;
			}
		};

		AddressSet resultSet = symEval.flowConstants(flowStart, null, eval, true, monitor);

		// Add in any addresses we should assume got covered
		//   These addresses are put on because we had to stop analysis due to an unknown register value
		resultSet.add(coveredSet);

		return resultSet;
	}

	Address MipsExtDisassembly(Program program, Instruction instruction, VarnodeContext context,
			Address target, TaskMonitor monitor) {
		if (target == null) {
			return null;
		}

		Address addr = flowISA(program, instruction, context, target);
		if (addr != null) {
			MemoryBlock block = program.getMemory().getBlock(addr);
			if (block == null || !block.isExecute() || !block.isInitialized() ||
				block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
				return addr;
			}

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSet disassembleAddrs = dis.disassemble(addr, null);
			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembleAddrs);
		}

		return addr;
	}

	Address flowISA(Program program, Instruction instruction, VarnodeContext context,
			Address target) {
		if (target == null) {
			return null;
		}

		Address addr = instruction.getMinAddress().getNewAddress(target.getOffset() & 0xfffffffe);

		Listing listing = program.getListing();

		if (isamode != null && listing.getUndefinedDataAt(addr) != null) {
			boolean inM16Mode = false;
			RegisterValue curvalue = context.getRegisterValue(isamode, instruction.getMinAddress());
			if (curvalue != null && curvalue.hasValue()) {
				inM16Mode = (curvalue.getUnsignedValue().intValue() == 1);
			}
			// if the ISM bit is set, that trumps any mode we are tracking
			RegisterValue tbvalue = context.getRegisterValue(ismbit);
			if (tbvalue != null && tbvalue.hasValue()) {
				inM16Mode = (tbvalue.getUnsignedValue().intValue() == 1);
			}
			BigInteger m16ModeValue = BigInteger.valueOf(inM16Mode ? 1 : 0);
			try {
				program.getProgramContext().setValue(isamode, addr, addr, m16ModeValue);
			}
			catch (ContextChangeException e) {
				throw new AssertException("Unexpected Exception", e);
			}
			return addr;
		}

		// instruction already there
		return null;
	}

	/**
	 * @param program
	 * @param startInstr
	 * @param monitor
	 */
	private void fixJumpTable(Program program, Instruction startInstr, TaskMonitor monitor) {
		int tableLen = -1;
		Address tableAddr = null;
		int valueSize = -1;
		Register target = null;

		// if already has more than one reference from it, assume it has been
		// done!
		Address addr = startInstr.getMinAddress();
		if (checkAlreadyRecovered(program, addr)) {
			return;
		}

		// search backward for:
		// sltiu instruction, that is the size of the table
		// addiu instruction, the reference there is the table
		Instruction curInstr = startInstr;
		while (tableLen == -1 || (target != null && tableAddr == null)) {
			Address fallAddr = curInstr.getFallFrom();
			Instruction prevInstr = null;
			if (fallAddr != null) {
				prevInstr = program.getListing().getInstructionContaining(fallAddr);
			}
			if (prevInstr == null) {
				ReferenceIterator iter = curInstr.getReferenceIteratorTo();
				if (iter.hasNext()) {
					Reference ref = iter.next();
					if (!ref.getReferenceType().isCall()) {
						prevInstr =
							program.getListing().getInstructionContaining(ref.getFromAddress());
					}
				}
			}
			if (!curInstr.isInDelaySlot() && prevInstr != null &&
				prevInstr.getPrototype().hasDelaySlots()) {
				prevInstr = prevInstr.getNext();
			}
			if (prevInstr == null) {
				return;
			}
			if (prevInstr.getMinAddress().compareTo(curInstr.getMinAddress()) >= 0) {
				return;
			}
			curInstr = prevInstr;

			// this is the size of the table
			if (tableLen == -1 && (curInstr.getMnemonicString().equals("sltiu") ||
				curInstr.getMnemonicString().equals("_sltiu"))) {
				Scalar scalar = curInstr.getScalar(2);
				if (scalar == null) {
					return;
				}
				tableLen = (int) scalar.getUnsignedValue();
				if (tableLen > 255 || tableLen < 2) {
					return;
				}
				continue;
			}
			// this is the table location
			// assumes the mips markup has already found the lui/addiu pair
			if (tableAddr == null && curInstr.getMnemonicString().equals("addiu")) {
				if (target == null || target.equals(curInstr.getRegister(0))) {
					Reference[] refs = curInstr.getReferencesFrom();
					if (refs == null || refs.length == 0) {
						return;
					}
					tableAddr = refs[0].getToAddress();
				}
			}

			if (tableLen == -1) {
				// this is the step of the table
				if (valueSize == -1 && (curInstr.getMnemonicString().equals("sll") ||
					curInstr.getMnemonicString().equals("_sll"))) {
					valueSize = 1 << (int) curInstr.getScalar(2).getUnsignedValue();
				}
				if (tableAddr == null) {
					if (valueSize == -1 && curInstr.getMnemonicString().equals("lw")) {
						valueSize = 4;
					}
					if (curInstr.getMnemonicString().equals("addu")) {
						target = curInstr.getRegister(2);
					}
				}
			}
		}

		if (tableAddr == null) {
			return;
		}

		if (tableLen <= 0) {
			return;
		}

		if (valueSize == -1) {
			valueSize = program.getDefaultPointerSize();
		}

		AddressTable table = AddressTable.getEntry(program, tableAddr, monitor, false, tableLen,
			valueSize, 0, AddressTable.MINIMUM_SAFE_ADDRESS, true);
		if (table == null) {
			table = AddressTable.getEntry(program, tableAddr, monitor, false, 3, valueSize, 0,
				AddressTable.MINIMUM_SAFE_ADDRESS, true);
			if (table != null) {
				Msg.error(this,
					"**** MIPS Analyzer: SHOULD be a table of size " + tableLen + " at " +
						tableAddr + " got " + table.getNumberAddressEntries() +
						" from instruction at " + startInstr.getMinAddress());
			}
			else {
				Msg.error(this, "**** MIPS Analyzer: SHOULD be a table of size " + tableLen +
					" at " + tableAddr + " from instruction at " + startInstr.getMinAddress());
				return;
			}
		}
		if (tableLen < table.getNumberAddressEntries()) {
			table.truncate(tableLen);
		}

		// We don't do indexes, even if it says it has one. So get rid of it.
		if (table.getIndexLength() != 0) {
			table = new AddressTable(table.getTopAddress(), table.getTableElements(), null, 0,
				valueSize, 0, false);
		}
		table.createSwitchTable(program, startInstr, 1, false, monitor);
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

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		options.registerOption(OPTION_NAME_SWITCH_TABLE, OPTION_DEFAULT_SWITCH_TABLE, null,
			OPTION_DESCRIPTION_SWITCH_TABLE);

		options.registerOption(OPTION_NAME_MARK_DUAL_INSTRUCTION,
			OPTION_DEFAULT_MARK_DUAL_INSTRUCTION, null, OPTION_DESCRIPTION_MARK_DUAL_INSTRUCTION);

		options.registerOption(OPTION_NAME_ASSUME_T9_ENTRY, OPTION_DEFAULT_ASSUME_T9_ENTRY, null,
			OPTION_DESCRIPTION_ASSUME_T9_ENTRY);

		options.registerOption(OPTION_NAME_RECOVER_GP, OPTION_DEFAULT_RECOVER_GP, null,
			OPTION_DESCRIPTION_RECOVER_GP);

		trySwitchTables = options.getBoolean(OPTION_NAME_SWITCH_TABLE, OPTION_DEFAULT_SWITCH_TABLE);

		markupDualInstructionOption = options.getBoolean(OPTION_NAME_MARK_DUAL_INSTRUCTION,
			OPTION_DEFAULT_MARK_DUAL_INSTRUCTION);

		assumeT9EntryAddress =
			options.getBoolean(OPTION_NAME_ASSUME_T9_ENTRY, OPTION_DEFAULT_ASSUME_T9_ENTRY);

		discoverGlobalGPSetting =
			options.getBoolean(OPTION_NAME_RECOVER_GP, OPTION_DEFAULT_RECOVER_GP);
	}

}
