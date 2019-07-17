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
import java.util.*;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class Motorola68KAnalyzer extends ConstantPropagationAnalyzer {
	private static final String SWITCH_OPTION_NAME = "Switch Table Recovery";
	private static final String SWITCH_OPTION_DESCRIPTION = "Turn on to recover switch tables";
	private static final boolean SWITCH_OPTION_DEFAULT_VALUE = false;

	private boolean recoverSwitchTables = SWITCH_OPTION_DEFAULT_VALUE;

	private final static String PROCESSOR_NAME = "68000";

	public Motorola68KAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		return true;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(trustWriteMemOption) {
				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
					String mnemonic = instr.getMnemonicString();

					if (mnemonic.equals("pea")) {
						// retrieve the value pushed onto the stack
						try {
							Varnode stackValue = context.getValue(context.getStackVarnode(), this);
							Varnode value = context.getValue(stackValue, this);
							if (value != null && value.isConstant()) {
								long lval = value.getOffset();
								Address refAddr = instr.getMinAddress().getNewAddress(lval);
								if (lval <= 4096 || ((lval % 1024) == 0) || lval < 0 ||
									lval == 0xffff || lval == 0xff00 || lval == 0xffffff ||
									lval == 0xff0000 || lval == 0xff00ff || lval == 0xffffffff ||
									lval == 0xffffff00 || lval == 0xffff0000 ||
									lval == 0xff000000) {
									return false;
								}
								if (program.getMemory().contains(refAddr)) {
									if (instr.getOperandReferences(0).length == 0) {
										instr.addOperandReference(0, refAddr, RefType.DATA,
											SourceType.ANALYSIS);
									}
								}
							}
						}
						catch (NotFoundException e) {
							// value not found doesn't matter
						}
					}
					if (mnemonic.equals("lea")) {
						Register destReg = instr.getRegister(1);
						if (destReg == null) {
							return false;
						}
						RegisterValue value = context.getRegisterValue(destReg);
						if (value != null) {
							BigInteger rval = value.getUnsignedValue();
							long lval = rval.longValue();
							Address refAddr = instr.getMinAddress().getNewAddress(lval);
							if ((lval > 4096 || lval < 0) &&
								program.getMemory().contains(refAddr) ||
								Arrays.asList(instr.getOpObjects(0)).contains(
									program.getRegister("PC"))) {
								if (instr.getOperandReferences(0).length == 0) {
									instr.addOperandReference(0, refAddr, RefType.DATA,
										SourceType.ANALYSIS);
								}
							}
						}
					}
					return false;
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, RefType refType) {
					if (instr.getFlowType().isJump()) {
						return false;
					}
					if (instr.getNumOperands() > 2) {
						return false;
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
					if (mnemonic.equals("jmp")) {
						// record the destination that is unknown
						int numRefs = instruction.getReferencesFrom().length;
						if (numRefs >= 4) {
							destSet.addRange(instruction.getMinAddress(),
								instruction.getMinAddress());
						}
					}
					return false;
				}
			};

		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		//
		// Don't do switch analysis here, let Decomp do it.  But if it is already done, mark up the data references
		//
		// TODO: This most likely does not need to be done, or should be done in a general switch recovery algorithm.
		//       Leave here for now as off.
		if (recoverSwitchTables) {
			recoverSwitches(program, symEval, eval.getDestinationSet(), monitor);
		}

		return resultSet;
	}

	int tableSizeMax;

	private void recoverSwitches(final Program program, SymbolicPropogator symEval,
			AddressSet destSet, TaskMonitor monitor) throws CancelledException {

		final ArrayList<CreateDataCmd> dataCmdList = new ArrayList<CreateDataCmd>();

		final ArrayList<Address> targetList = new ArrayList<Address>();

		// now handle symbolic execution assuming values!
		class SwitchEvaluator implements ContextEvaluator {
			Long assumeValue;

			boolean hitTheGuard;

			Address targetSwitchAddr;

			public void setGuard(boolean hitGuard) {
				hitTheGuard = hitGuard;
			}

			public void setAssume(Long assume) {
				assumeValue = assume;
			}

			public void setTargetSwitchAddr(Address addr) {
				targetSwitchAddr = addr;
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
				if (mnemonic.startsWith("cmpi")) {
					int numOps = instr.getNumOperands();
					if (numOps > 1) {
						Register reg = instr.getRegister(numOps - 1);
						if ((reg != null)) {
							Scalar scalar = instr.getScalar(numOps - 2);
							if (scalar != null) {
								int svalue = (int) scalar.getSignedValue() + 1;
								if (svalue > 0 && svalue < 128) {
									tableSizeMax = svalue;
								}
								RegisterValue rval = context.getRegisterValue(reg);
								if (rval != null) {
									long lval = rval.getSignedValue().longValue();
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
				if (targetList.contains(address)) {
					return false;
				}
				// TODO: if ever loading from instructions in memory, must EXIT!
				if (!(instr.getFlowType().isComputed() && program.getMemory().contains(address))) {
					Program program = instr.getProgram();
					if (!program.getListing().isUndefined(address, address)) {
						return false;
					}
					String mnemonic = instr.getMnemonicString();
					if (mnemonic.startsWith("move")) {
						CreateDataCmd cdata = null;
						char endCh = mnemonic.charAt(mnemonic.length() - 1);
						switch (endCh) {
							case 'w':
								cdata = new CreateDataCmd(address, false, false,
									Undefined2DataType.dataType);
								break;
							case 'l':
								cdata = new CreateDataCmd(address, false, false,
									Undefined4DataType.dataType);
								break;
							case 'b':
								cdata = new CreateDataCmd(address, false, false,
									Undefined1DataType.dataType);
								break;
						}
						CodeUnit u =
							instr.getProgram().getListing().getInstructionContaining(address);
						if (u != null) {
							return false;
						}
						u = instr.getProgram().getListing().getCodeUnitAt(address);
						if (!targetList.isEmpty() &&
							instr.getProgram().getReferenceManager().hasReferencesTo(
								u.getMinAddress())) {
							int newTableSizeMax = assumeValue.intValue();
							if (newTableSizeMax > 0 && newTableSizeMax < 128) {
								tableSizeMax = newTableSizeMax;
							}
							return false;
						}
						dataCmdList.add(cdata);
					}
					return false;
				}
				long diff = address.subtract(instr.getMinAddress());
				if ((diff > 0 && diff < (8 * 1024)) && !context.readExecutableCode()) {
					targetList.add(address);
					return false; // just go ahead and mark up the instruction
				}
				if (context.readExecutableCode() && targetList.isEmpty()) {
					context.clearReadExecutableCode();
					return false;
				}
				return false;
			}

			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				return instruction.getMinAddress().equals(targetSwitchAddr);
			}

			@Override
			public Long unknownValue(VarnodeContext context, Instruction instruction,
					Varnode node) {
				if (node.isRegister()) {
					Register reg = program.getRegister(node.getAddress());
					if (reg != null) {
					}
				}

				return assumeValue;
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

		// clear past constants.  This example doesn't seem to depend on them
		symEval = new SymbolicPropogator(program);
		// now flow with the simple block of this branch....

		// for each unknown branch destination,
		AddressIterator iter = destSet.getAddresses(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Address loc = iter.next();
			Instruction instr = program.getListing().getInstructionAt(loc);
			Address maxAddress = instr.getMaxAddress();
			Address prev = instr.getFallFrom();
			if (prev == null) {
				continue;
			}
			instr = program.getListing().getInstructionAt(prev);

			Address minAddress = instr.getMinAddress();
			prev = instr.getFallFrom();
			if (prev == null) {
				continue;
			}
			instr = program.getListing().getInstructionAt(prev);
			if (instr.getMnemonicString().startsWith("add") &&
				instr.getRegister(0).equals(instr.getRegister(1))) {
				minAddress = instr.getMinAddress();
			}

			AddressSet branchSet = new AddressSet(minAddress, maxAddress);

			tableSizeMax = 64;
			for (long assume = 0; assume < tableSizeMax; assume++) {
				switchEvaluator.setAssume(new Long(assume));
				switchEvaluator.setGuard(false);
				switchEvaluator.setTargetSwitchAddr(loc);

				symEval.flowConstants(minAddress, branchSet, switchEvaluator, false, monitor);
				if (symEval.readExecutable()) {
					break;
				}
				// if it didn't get it after try with 0
				if (assume > 0 && targetList.size() < 1) {
					break;
				}
			}
			// re-create the function body with the newly found code
			if (targetList.size() > 1) {
				AddressTable table;
				//table = new AddressTable(loc, targetList.toArray(new Address[0]), program.getDefaultPointerSize(), 0, 0);
				//table.fixupFunctionBody(program, program.getListing().getInstructionAt(loc), monitor);
				createData(program, dataCmdList);
				//labelTable(program, loc, targetList);
			}
		}
	}

	private void createData(Program program, ArrayList<CreateDataCmd> dataCommands) {
		for (Iterator<CreateDataCmd> iterator = dataCommands.iterator(); iterator.hasNext();) {
			CreateDataCmd createDataCmd = iterator.next();
			createDataCmd.applyTo(program);
		}
	}

	private void labelTable(Program program, Address loc, ArrayList<Address> targets) {
		Namespace space = null;

		Instruction start_inst = program.getListing().getInstructionAt(loc);

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
		for (Iterator<Address> iterator = targets.iterator(); iterator.hasNext();) {
			Address addr = iterator.next();

			AddLabelCmd lcmd = new AddLabelCmd(addr, "case_" + Long.toHexString(tableNumber), space,
				SourceType.ANALYSIS);
			tableNumber++;
			lcmd.setNamespace(space);

			lcmd.applyTo(program);
		}
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		options.registerOption(SWITCH_OPTION_NAME, recoverSwitchTables, null,
			SWITCH_OPTION_DESCRIPTION);
		recoverSwitchTables = options.getBoolean(SWITCH_OPTION_NAME, recoverSwitchTables);
	}
}
