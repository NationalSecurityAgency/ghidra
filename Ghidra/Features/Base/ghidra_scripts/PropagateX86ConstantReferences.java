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
//This script propagates constants in a function creating references wherever a store or load is
//found.  If a register has a value at the beginning of a function, that register value is assumed
//to be a constant.
//Any values loaded from memory are assumed to be constant.
//If a reference does not make sense on an operand, then it is added to the mnemonic.
//
//@category Analysis.X86

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.*;

public class PropagateX86ConstantReferences extends GhidraScript {

	private ArrayList<Address> targetList;

	private int tableSizeMax;

	private Long assumeValue;

	protected long tableIndexOffset;

	protected boolean hitTheGuard;

	@Override
	public void run() throws Exception {
		long numInstructions = currentProgram.getListing().getNumInstructions();
		monitor.initialize((int) (numInstructions));
		monitor.setMessage("Constant Propagation Markup");

		// set up the address set to restrict processing
		AddressSet restrictedSet = new AddressSet(currentSelection);
		if (restrictedSet.isEmpty()) {
			Function curFunc = currentProgram.getFunctionManager().getFunctionContaining(
				currentLocation.getAddress());
			if (curFunc != null) {
				restrictedSet = new AddressSet(curFunc.getEntryPoint());
			}
			else {
				restrictedSet = new AddressSet(currentLocation.getAddress());
			}
		}

		// iterate over all functions within the restricted set
		FunctionIterator fiter =
			currentProgram.getFunctionManager().getFunctions(restrictedSet, true);
		while (fiter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			// get the function body
			Function func = fiter.next();
			Address start = func.getEntryPoint();

			// follow all flows building up context
			// use context to fill out addresses on certain instructions
			//   Always trust values read from writable memory
			ConstantPropagationContextEvaluator eval =
				new ConstantPropagationContextEvaluator(true) {
					@Override
					public boolean evaluateDestination(VarnodeContext context,
							Instruction instruction) {
						//String mnemonic = instruction.getMnemonicString();
						if (!instruction.getFlowType().isJump()) {
							return false;
						}
						if (instruction.getFlowType().isComputed()) {
							// record the destination that is unknown
							if (instruction.getReferencesFrom().length <= 0) {
								destSet.addRange(instruction.getMinAddress(),
									instruction.getMinAddress());
							}
						}
						return false;
					}

					@Override
					public boolean evaluateContext(VarnodeContext context, Instruction instr) {
						String mnemonic = instr.getMnemonicString();
						if (mnemonic.equals("LEA")) {
							Register reg = instr.getRegister(0);
							if (reg != null) {
								BigInteger val = context.getValue(reg, false);
								if (val != null) {
									long lval = val.longValue();
									Address refAddr = instr.getMinAddress().getNewAddress(lval);
									if ((lval > 4096 || lval < 0) &&
										currentProgram.getMemory().contains(refAddr)) {
										if (instr.getOperandReferences(1).length == 0) {
											instr.addOperandReference(1, refAddr, RefType.DATA,
												SourceType.ANALYSIS);
										}
									}
								}
							}
						}
						return false;
					}

					@Override
					public boolean evaluateReference(VarnodeContext context, Instruction instr,
							int pcodeop, Address address, int size, RefType refType) {
						return true; // just go ahead and mark up the instruction
					}
				};

			SymbolicPropogator symEval = new SymbolicPropogator(currentProgram);
			symEval.setParamRefCheck(true);
			symEval.setReturnRefCheck(true);
			symEval.setStoredRefCheck(true);

			symEval.flowConstants(start, func.getBody(), eval, true, monitor);

			// now handle symbolic execution assuming values!
			eval = new ConstantPropagationContextEvaluator() {

				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
					// find the cmpli to set the size of the table
					// tableSize = size
					String mnemonic = instr.getMnemonicString();
					if ((mnemonic.compareToIgnoreCase("CMP") == 0)) {
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
									RegisterValue rval = context.getRegisterValue(reg);
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
				public Address evaluateConstant(VarnodeContext context, Instruction instr,
						int pcodeop, Address constant, int size, RefType refType) {
					// don't create any references from constants, only looking for flow refs
					return null;
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, RefType refType) {
					// TODO: if ever loading from instructions in memory, must
					// EXIT!
					if (!(instr.getFlowType().isComputed() &&
						currentProgram.getMemory().contains(address))) {
						return false;
					}
					targetList.add(address);
					return true; // just go ahead and mark up the instruction
				}

				@Override
				public boolean followFalseConditionalBranches() {
					// trying to recover jump destination, so stick with the branch that should be
					// followed based on good computed constant values
					return false;
				}

				@Override
				public Long unknownValue(VarnodeContext context, Instruction instruction,
						Varnode node) {
					if (hitTheGuard) {
						return assumeValue;
					}
					return null;
				}

				@Override
				public boolean allowAccess(VarnodeContext context, Address addr) {
					return true;
				}
			};

			// now flow with the simple block of this branch....

			// for each unknown branch destination,
			AddressIterator iter = eval.getDestinationSet().getAddresses(true);
			SimpleBlockModel model = new SimpleBlockModel(currentProgram);
			while (iter.hasNext() && !monitor.isCancelled()) {
				Address loc = iter.next();
				CodeBlock bl = null;
				try {
					bl = model.getFirstCodeBlockContaining(loc, monitor);
				}
				catch (CancelledException e) {
					break;
				}
				AddressSet branchSet = new AddressSet(bl);
				CodeBlockReferenceIterator bliter;
				try {
					bliter = bl.getSources(monitor);
					while (bliter.hasNext()) {
						CodeBlockReference sbl = bliter.next();
						if (sbl.getFlowType().isFallthrough() ||
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

				targetList = new ArrayList<Address>();
				tableSizeMax = 64;
				tableIndexOffset = 0;
				for (long assume = 0; assume < tableSizeMax; assume++) {
					assumeValue = new Long(assume);
					hitTheGuard = false;

					symEval.flowConstants(branchSet.getMinAddress(), branchSet, eval, false,
						monitor);

					if (symEval.readExecutable()) {
						break;
					}
					// if it didn't get it after try with 0, or 1...
					if (assume > 0 && targetList.size() < 1) {
						break;
					}
				}
				// re-create the function body with the newly found code
				if (targetList.size() > 1) {
					AddressTable table;
					table = new AddressTable(loc, targetList.toArray(new Address[0]),
						currentProgram.getDefaultPointerSize(), 0, false);
					table.fixupFunctionBody(currentProgram,
						currentProgram.getListing().getInstructionAt(loc), monitor);
					labelTable(currentProgram, loc, targetList);
				}
			}
		}
	}

	private void labelTable(Program program, Address loc, ArrayList<Address> targets) {
		Namespace space = null;

		Instruction start_inst = program.getListing().getInstructionAt(loc);

		// not putting switch into functions anymore
		// program.getSymbolTable().getNamespace(start_inst.getMinAddress());
		String spaceName = "switch_" + start_inst.getMinAddress();
		try {
			space = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(),
				spaceName, SourceType.ANALYSIS);
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
}
