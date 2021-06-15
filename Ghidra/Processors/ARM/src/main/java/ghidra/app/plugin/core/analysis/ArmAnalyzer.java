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
import java.util.Iterator;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ArmAnalyzer extends ConstantPropagationAnalyzer {
	private static final String SWITCH_OPTION_NAME = "Switch Table Recovery";
	private static final String SWITCH_OPTION_DESCRIPTION = "Turn on to recover switch tables";
	private static final boolean SWITCH_OPTION_DEFAULT_VALUE = false;

	private boolean recoverSwitchTables = SWITCH_OPTION_DEFAULT_VALUE;

	private static final long MAX_DISTANCE = (4 * 1024);

	private Register tbRegister;
	private Register tmodeRegister;
	private Register lrRegister;

	private final static String PROCESSOR_NAME = "ARM";

	public ArmAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		tmodeRegister = program.getProgramContext().getRegister("TMode");
		tbRegister = program.getProgramContext().getRegister("ISAModeSwitch");
		lrRegister = program.getProgramContext().getRegister("lr");

		return true;
	}

	@Override
	public AddressSet flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(trustWriteMemOption) {

				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {

					FlowType ftype = instr.getFlowType();
					if (ftype.isComputed() && ftype.isJump()) {
						Varnode pcVal = context.getRegisterVarnodeValue(
							program.getLanguage().getProgramCounter());
						if (pcVal != null) {
							if (isLinkRegister(context, pcVal) &&
								!instr.getFlowType().isTerminal()) {
								// need to set the return override
								instr.setFlowOverride(FlowOverride.RETURN);
							}
						}
						// if LR is a constant and is set right after this, this is a call
						Varnode lrVal = context.getRegisterVarnodeValue(lrRegister);
						if (lrVal != null) {
							if (lrVal.isConstant()) {
								long target = lrVal.getAddress().getOffset();
								Address addr = instr.getMaxAddress().add(1);
								if (target == addr.getOffset() && !instr.getFlowType().isCall()) {
									// if there are is a read reference there as well,
									//  then this is really a branch, not a call
									if (hasDataReferenceTo(program, addr)) {
										return false;
									}
									instr.setFlowOverride(FlowOverride.CALL);
									// need to trigger disassembly below! if not already
									doArmThumbDisassembly(program, instr, context, addr,
										instr.getFlowType(), false, monitor);
									// need to trigger re-function creation!
									Function f = program.getFunctionManager().getFunctionContaining(
										instr.getMinAddress());
									if (f != null) {
										try {
											CreateFunctionCmd.fixupFunctionBody(program, f,
												monitor);
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

					}
					return false;
				}

				/**
				 * Check if there are any data references to this location.
				 * @param program
				 * @param addr
				 * @return true if there are any data references to addr
				 */
				private boolean hasDataReferenceTo(Program program, Address addr) {
					ReferenceManager refMgr = program.getReferenceManager();
					if (!refMgr.hasReferencesTo(addr)) {
						return false;
					}
					ReferenceIterator referencesTo = refMgr.getReferencesTo(addr);
					while (referencesTo.hasNext()) {
						Reference reference = referencesTo.next();
						if (reference.getReferenceType().isData()) {
							return true;
						}
					}
					return false;
				}

				private boolean isLinkRegister(VarnodeContext context, Varnode pcVal) {
					return (pcVal.isRegister() &&
						pcVal.getAddress().equals(lrRegister.getAddress())) ||
						(context.isSymbol(pcVal) &&
							pcVal.getAddress().getAddressSpace().getName().equals(
								lrRegister.getName()) &&
							pcVal.getOffset() == 0);
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, RefType refType) {
					if (refType.isJump() && refType.isComputed() &&
						program.getMemory().contains(address) && address.getOffset() != 0) {
						if (instr.getMnemonicString().startsWith("tb")) {
							return false;
						}
						doArmThumbDisassembly(program, instr, context, address, instr.getFlowType(),
							true, monitor);
						return !symEval.encounteredBranch();
					}
					if (refType.isData() && program.getMemory().contains(address)) {
						if (refType.isRead() || refType.isWrite()) {
							createData(program, address, size);
							instr.addOperandReference(instr.getNumOperands() - 1, address, refType,
								SourceType.ANALYSIS);
							return false;
						}
					}
					else if (refType.isCall() && refType.isComputed()) {
						// must disassemble right now, because TB flag could get set back at end of blx
						doArmThumbDisassembly(program, instr, context, address, instr.getFlowType(),
							true, monitor);
						return false;
					}

					return super.evaluateReference(context, instr, pcodeop, address, size, refType);
				}

				@Override
				public boolean evaluateDestination(VarnodeContext context,
						Instruction instruction) {
					FlowType flowType = instruction.getFlowType();
					if (!flowType.isJump()) {
						return false;
					}

					Reference[] refs = instruction.getReferencesFrom();
					if (refs.length <= 0 ||
						(refs.length == 1 && refs[0].getReferenceType().isData()) ||
						symEval.encounteredBranch()) {
						destSet.addRange(instruction.getMinAddress(), instruction.getMinAddress());
					}
					return false;
				}
			};

		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		if (recoverSwitchTables) {
			recoverSwitches(program, eval.getDestinationSet(), symEval, monitor);
		}

		return resultSet;
	}

	private void recoverSwitches(final Program program, AddressSet destSet,
			SymbolicPropogator symEval, TaskMonitor monitor) throws CancelledException {

		// now handle symbolic execution assuming values!
		class SwitchEvaluator implements ContextEvaluator {

			int tableSizeMax = 64;
			Long assumeValue = new Long(0);
			Address targetSwitchAddr = null;
			int addrByteSize = 1;
			boolean hitTheGuard = false;
			ArrayList<Address> targetList = new ArrayList<Address>();
			ArrayList<Address> accessList = new ArrayList<Address>();

			public void init(Address loc, int maxSize) {
				addrByteSize = 1;
				assumeValue = new Long(0);
				tableSizeMax = maxSize;
				targetSwitchAddr = loc;
				hitTheGuard = false;

				targetList.clear();
				accessList.clear();
			}

			public void initForCase(Long assume) {
				assumeValue = new Long(assume);
				hitTheGuard = false;
			}

			public int getTableSizeMax() {
				return tableSizeMax;
			}

			public int getAddrByteSize() {
				return addrByteSize;
			}

			public ArrayList<Address> getTargetList() {
				return targetList;
			}

			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				return false;
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				if (context.readExecutableCode()) {
					return true;
				}
				// find the cmpli to set the size of the table
				//    tableSize = size
				String mnemonic = instr.getMnemonicString();
				if ((mnemonic.compareToIgnoreCase("cmp") == 0)) {
					int numOps = instr.getNumOperands();
					if (numOps > 1) {
						Register reg = instr.getRegister(numOps - 2);
						if ((reg != null)) {
							context.clearRegister(reg);
							Scalar scalar = instr.getScalar(numOps - 1);
							if (scalar != null) {
								int newTableSizeMax = (int) scalar.getSignedValue() + 2;
								if (newTableSizeMax > 0 && newTableSizeMax < 128) {
									tableSizeMax = newTableSizeMax;
								}
//								RegisterValue rval = context.getRegisterValue(reg);
//								if (rval != null) {
//									long lval = rval.getSignedValue().longValue();
//									if (lval < 0)
//										tableIndexOffset = -lval;
//								} else {
//								}
							}
						}
					}
					hitTheGuard = true;
				}
				if ((mnemonic.compareToIgnoreCase("sub") == 0)) {
					int numOps = instr.getNumOperands();
					if (numOps > 1) {
						Register reg = instr.getRegister(numOps - 2);
						if ((reg != null)) {
							BigInteger val = context.getValue(reg, true);
							if (val == null) {
								return false;
							}
							context.clearRegister(reg);
							Scalar scalar = instr.getScalar(numOps - 1);
							if (scalar == null) {
								return false;
							}
							context.setValue(reg,
								val.add(BigInteger.valueOf(scalar.getSignedValue())));
							val = context.getValue(reg, true);
//							if (scalar != null) {
//								tableSizeMax = (int) scalar.getSignedValue() + 1;
//								RegisterValue rval = context.getRegisterValue(reg);
//								if (rval != null) {
//									long lval = rval.getSignedValue().longValue();
//									if (lval < 0)
//										tableIndexOffset = -lval;
//								} else {
//								}
//							}
						}
					}
//					hitTheGuard = true;
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

				// if ever see a reference to 0, something went wrong, stop the process
				if (address == null) {
					return terminatePropogation(context);
				}

				// for switches, if access is below 256, then there is a problem
				// if ever loading from instructions in memory, must EXIT!
				//
				long offset = address.getOffset();
				if ((offset >= 0 && offset < 256) || context.readExecutableCode()) {
					return terminatePropogation(context);
				}
				if (!((refType.isComputed() || refType.isConditional() == !followConditional) &&
					program.getMemory().contains(address))) {
					if (refType.isRead()) {
						if (targetList.contains(address)) {
							return terminatePropogation(context);
						}
						size = createDataType(instr, address);
						if (size != 0) {
							addrByteSize = size;
						}
					}
					return false;
				}
				if (refType.isJump() || refType.isCall()) {
					if (accessList.contains(address)) {
						return terminatePropogation(context);
					}
					long diff = Math.abs(address.subtract(targetSwitchAddr));
					// don't allow jumps backward, or too far if this is not a call
					if (refType.isCall() || diff < 32 * 1024) {
						address = flowArmThumb(program, instr, context, address,
							instr.getFlowType(), false);
						if (address != null) {
							targetList.add(address);
						}
					}
					return false;
				}
				// no markup, computing the jump table
				return false;
			}

			private boolean terminatePropogation(VarnodeContext context) {
				hitTheGuard = false;
				context.setReadExecutableCode();
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
						// never assume for flags, or control registers
						String regName = reg.getName();
						if (regName.equals("sp")) {
							return null;
						}
						if (!regName.startsWith("r")) {
							return new Long(0);
						}
					}
					if (hitTheGuard) {
						return assumeValue;
					}
				}
				if (hitTheGuard && context.isSymbol(node)) {
					return assumeValue;
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
				accessList.add(addr);
				return false;
			}
		}

		SwitchEvaluator switchEvaluator = new SwitchEvaluator();

		// now flow with the simple block of this branch....

		// for each unknown branch destination,
		AddressIterator iter = destSet.getAddresses(true);
		SimpleBlockModel model = new SimpleBlockModel(program);
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
					if (hasCallsTo(program, bl)) {
						break;
					}
					CodeBlockReference sbl = bliter.next();
					bl = sbl.getSourceBlock();
					if (bl == null) {
						continue;
					}
					if (!sbl.getFlowType().isCall()) {
						branchSet.add(bl);
					}
					if (sbl.getFlowType().isJump() && bl.getNumSources(monitor) == 1) {
						if (sbl.getFlowType().isConditional()) {
							followConditional = true;
							break;
						}
						bliter = bl.getSources(monitor);
					}
				}
			}
			catch (CancelledException e) {
				break;
			}

			switchEvaluator.init(loc, 64);

			Instruction targetInstr = program.getListing().getInstructionAt(loc);

			SymbolicPropogator targetEval = symEval;
			// if this is a tbX instruction, don't assume any old values
			if (targetInstr != null && targetInstr.getMnemonicString().startsWith("tb")) {
				targetEval = new SymbolicPropogator(program);
			}

			Address zeroAddr = targetInstr.getMinAddress().getNewAddress(0);
			for (long assume = 0; assume < switchEvaluator.getTableSizeMax(); assume++) {
				switchEvaluator.initForCase(new Long(assume));

				targetEval.flowConstants(branchSet.getMinAddress(), branchSet, switchEvaluator,
					false, monitor);
				// go around once, table might be 1 based
				if (assume > 0 && targetEval.readExecutable()) {
					break;
				}
				// if it didn't get it after try with 1
				if (assume > 1 && switchEvaluator.getTargetList().size() < 1) {
					break;
				}
				// if the target list ever contains zero, is bad
				if (switchEvaluator.getTargetList().contains(zeroAddr)) {
					switchEvaluator.getTargetList().clear();
					break;
				}
			}

			// re-create the function body with the newly found code
			if (switchEvaluator.getTargetList().size() > 1) {
				Iterator<Address> liter = switchEvaluator.getTargetList().iterator();
				Address firstAddress = switchEvaluator.getTargetList().get(0);
				while (liter.hasNext()) {
					if (!firstAddress.equals(liter.next())) {
						AddressTable table;
						table = new AddressTable(loc,
							switchEvaluator.getTargetList().toArray(new Address[0]),
							switchEvaluator.getAddrByteSize(), 0, false);
						Instruction jmpInstr = program.getListing().getInstructionAt(loc);
						if (jmpInstr.getReferencesFrom().length <= 1) {
							Iterator<Address> jmpIter = switchEvaluator.getTargetList().iterator();
							while (jmpIter.hasNext()) {
								Address address = jmpIter.next();
								jmpInstr.addMnemonicReference(address, jmpInstr.getFlowType(),
									SourceType.ANALYSIS);
							}
						}
						table.disassemble(program, jmpInstr, monitor);
						table.fixupFunctionBody(program, jmpInstr, monitor);
						labelTable(program, loc, switchEvaluator.getTargetList());
						switchEvaluator.getTargetList().clear();
						break;
					}
				}
			}
			if (switchEvaluator.getTargetList().size() > 0) {
				AddressTable table;
				table = new AddressTable(loc, switchEvaluator.getTargetList().toArray(new Address[0]),
						switchEvaluator.getAddrByteSize(), 0, false);
				table.disassemble(program, targetInstr,monitor);
			}
		}
	}

	/*
	 * @return true if there are currently any call references to this CodeBlock
	 */
	private boolean hasCallsTo(Program program, CodeBlock bl) {
		Address startAddr = bl.getFirstStartAddress();
		ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(startAddr);
		while (referencesTo.hasNext()) {
			Reference reference = referencesTo.next();
			if (reference.getReferenceType().isCall()) {
				return true;
			}
		}
		return false;
	}

	private int createDataType(Instruction instr, Address address) {
		Program program = instr.getProgram();
		if (!program.getListing().isUndefined(address, address)) {
			return 0;
		}

		String mnemonic = instr.getMnemonicString();

		int charOff = 0;
		if (mnemonic.startsWith("ldrex") || mnemonic.startsWith("strex")) {
			charOff = 5;
		}
		else if (mnemonic.startsWith("ldrs") || mnemonic.startsWith("strs")) {
			charOff = 4;
		}
		else if (mnemonic.startsWith("ldr") || mnemonic.startsWith("str")) {
			charOff = 3;
		}
		else if (mnemonic.startsWith("ld") || mnemonic.startsWith("st")) {
			charOff = 2;
		}
		else if (mnemonic.startsWith("tbh")) {
			charOff = 2;
		}
		else if (mnemonic.startsWith("tbb")) {
			charOff = 2;
		}
		else if (mnemonic.startsWith("vldr") || mnemonic.startsWith("vstr")) {
			charOff = mnemonic.length() - 2;
		}

		if (charOff <= 0) {
			return 0;
		}

		DataType dt = Undefined4DataType.dataType;
		if (mnemonic.length() > charOff) {
			char endCh = mnemonic.charAt(charOff);
			switch (endCh) {
				case '6':
					dt = Undefined8DataType.dataType;
					break;
				case '3':
					dt = Undefined4DataType.dataType;
					break;
				case 'l':
					dt = Undefined4DataType.dataType;
					break;
				case 'w':
				case 'h':
					dt = Undefined2DataType.dataType;
					break;
				case 'b':
					dt = Undefined1DataType.dataType;
					break;
			}
		}

		//new CreateDataCmd(address, dt).applyTo(program);
		Data data = null;
		try {
			data = program.getListing().createData(address, dt);
		}
		catch (CodeUnitInsertionException e) {
			data = program.getListing().getDefinedDataAt(address);
		}
		catch (DataTypeConflictException e) {
			// ignore data type conflict
		}
		int addrByteSize = dt.getLength();
		//data = program.getListing().getDefinedDataAt(address);
		if (data != null) {
			Object dValue = data.getValue();
			// if the value at the location looks like a pointer, create a pointer
			if (dValue != null && dValue instanceof Scalar) {
				Scalar sValue = (Scalar) dValue;

				long value = sValue.getUnsignedValue();
				if (value < 4096 || value == 0xffff || value == 0xff00 || value == 0xffffff ||
					value == 0xff0000 || value == 0xff00ff || value == 0xffffffff ||
					value == 0xffffff00 || value == 0xffff0000 || value == 0xff000000) {
					return 0;
				}

				// If the access is a read, and the data is not far away, consider it constant
				long distance = address.getOffset() - instr.getAddress().getOffset();
				if (distance > 0 && distance < MAX_DISTANCE) {
					markDataAsConstant(data);
				}

//				Address sAddr = address.getNewAddress(sValue.getUnsignedValue());
//					if (program.getMemory().contains(sAddr)) {
//						program.getListing().clearCodeUnits(address, address);
//						new CreateDataCmd(address, DataTypeFactory.POINTER).applyTo(program);
//					}
			}
		}
		return addrByteSize;
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

	/**
	 * Disassemble at the specified target address and optionally create a mnemonic flow reference.
	 * @param monitor
	 * @param instruction flow from instruction
	 * @param target disassembly address
	 * @param flowType if not null a reference from the instruction mnemonic will be created to the specified
	 * target address using this flowType.
	 * @param addReference
	 */
	Address flowArmThumb(Program program, Instruction instruction, VarnodeContext context,
			Address target, FlowType flowType, boolean addReference) {
		if (target == null) {
			return null;
		}
		long bxOffset = target.getOffset();
		long thumbMode = bxOffset & 0x1;

		Address addr = instruction.getMinAddress().getNewAddress(bxOffset & 0xfffffffe);

		Listing listing = program.getListing();

		if (flowType != null) {
			int opIndex = -1;
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				int opType = instruction.getOperandType(i);
				// markup the program counter for any flow
				if ((opType & OperandType.REGISTER) != 0 || (opType & OperandType.DYNAMIC) != 0) {
					opIndex = i;
					break;
				}
			}

			if (addReference) {
				Reference[] refsFrom = instruction.getReferencesFrom();
				boolean foundRef = false;
				for (Reference element : refsFrom) {
					if (element.getToAddress().equals(addr)) {
						// reference already there, assume thumb bit propagated
						foundRef = true;
						break;
					}
				}
				if (!foundRef) {
					if (opIndex == -1) {
						instruction.addMnemonicReference(addr, flowType, SourceType.ANALYSIS);
					}
					else {
						instruction.addOperandReference(opIndex, addr, flowType,
							SourceType.ANALYSIS);
					}
				}
			}
		}

		if (tmodeRegister != null && listing.getUndefinedDataAt(addr) != null) {
			boolean inThumbMode = false;
			RegisterValue curvalue =
				context.getRegisterValue(tmodeRegister, instruction.getMinAddress());
			if (curvalue != null && curvalue.hasValue()) {
				inThumbMode = (curvalue.getUnsignedValue().intValue() == 1);
			}
			// if the TB register is set, that trumps any mode we are tracking
			RegisterValue tbvalue = context.getRegisterValue(tbRegister);
			if (tbvalue != null && tbvalue.hasValue()) {
				inThumbMode = (tbvalue.getUnsignedValue().intValue() == 1);
			}
			else {
				// blx instruction on a direct address in ARM mode always goes to thumb mode
				if (instruction.getMnemonicString().equals("blx") || thumbMode != 0) {
					inThumbMode = true;
				}
			}
			BigInteger thumbModeValue = BigInteger.valueOf(inThumbMode ? 1 : 0);
			try {
				program.getProgramContext().setValue(tmodeRegister, addr, addr, thumbModeValue);
			}
			catch (ContextChangeException e) {
				Msg.error(this, "Unexpected Exception", e);
			}
			return addr;
		}

		// instruction already there
		return null;
	}

	/**
	 * Disassemble at the specified target address and optionally create a mnemonic flow reference.
	 * @param monitor
	 * @param instruction flow from instruction
	 * @param target disassembly address
	 * @param flowType if not null a reference from the instruction mnemonic will be created to the specified
	 * target address using this flowType.
	 * @param addRef true if a reference should be added.
	 *
	 */
	void doArmThumbDisassembly(Program program, Instruction instruction, VarnodeContext context,
			Address target, FlowType flowType, boolean addRef, TaskMonitor monitor) {
		if (target == null) {
			return;
		}
		
		target = flowArmThumb(program, instruction, context, target, flowType, addRef);
		if (target == null) {
			return;
		}

		// this is here so the reference gets created, but not - disassembled if it is in a bad part of memory.
		// something computed it into the memory
		MemoryBlock block = program.getMemory().getBlock(target);
		if (block == null || !block.isExecute() || !block.isInitialized() ||
			block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
			return;
		}
		
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		AddressSet disassembleAddrs = dis.disassemble(target, null);
		AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembleAddrs);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		options.registerOption(SWITCH_OPTION_NAME, recoverSwitchTables, null,
			SWITCH_OPTION_DESCRIPTION);
		recoverSwitchTables = options.getBoolean(SWITCH_OPTION_NAME, recoverSwitchTables);
	}

}
