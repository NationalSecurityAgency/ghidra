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
package ghidra.program.model.symbol;

import java.util.HashSet;
import java.util.NoSuchElementException;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.datastruct.IntObjectHashtable;

/**
 * Factory class to create RefType objects.
 */
public class RefTypeFactory {

	private static final IntObjectHashtable<RefType> REFTYPE_LOOKUP_BY_TYPE_MAP =
		new IntObjectHashtable<>();
	static {
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.INVALID.getValue(), RefType.INVALID);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.FLOW.getValue(), RefType.FLOW);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.FALL_THROUGH.getValue(), RefType.FALL_THROUGH);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.UNCONDITIONAL_JUMP.getValue(),
			RefType.UNCONDITIONAL_JUMP);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CONDITIONAL_JUMP.getValue(),
			RefType.CONDITIONAL_JUMP);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.UNCONDITIONAL_CALL.getValue(),
			RefType.UNCONDITIONAL_CALL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CONDITIONAL_CALL.getValue(),
			RefType.CONDITIONAL_CALL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.TERMINATOR.getValue(), RefType.TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.COMPUTED_JUMP.getValue(), RefType.COMPUTED_JUMP);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CONDITIONAL_TERMINATOR.getValue(),
			RefType.CONDITIONAL_TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.COMPUTED_CALL.getValue(), RefType.COMPUTED_CALL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CALL_TERMINATOR.getValue(), RefType.CALL_TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.COMPUTED_CALL_TERMINATOR.getValue(),
			RefType.COMPUTED_CALL_TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CONDITIONAL_CALL_TERMINATOR.getValue(),
			RefType.CONDITIONAL_CALL_TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.JUMP_TERMINATOR.getValue(), RefType.JUMP_TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CONDITIONAL_COMPUTED_CALL.getValue(),
			RefType.CONDITIONAL_COMPUTED_CALL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.CONDITIONAL_COMPUTED_JUMP.getValue(),
			RefType.CONDITIONAL_COMPUTED_JUMP);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.JUMP_TERMINATOR.getValue(), RefType.JUMP_TERMINATOR);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.INDIRECTION.getValue(), RefType.INDIRECTION);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.DATA.getValue(), RefType.DATA);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.PARAM.getValue(), RefType.PARAM);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.DATA_IND.getValue(), RefType.DATA_IND);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.READ.getValue(), RefType.READ);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.WRITE.getValue(), RefType.WRITE);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.READ_WRITE.getValue(), RefType.READ_WRITE);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.READ_IND.getValue(), RefType.READ_IND);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.WRITE_IND.getValue(), RefType.WRITE_IND);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.READ_WRITE_IND.getValue(), RefType.READ_WRITE_IND);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.EXTERNAL_REF.getValue(), RefType.EXTERNAL_REF);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.__CALL_OVERRIDE_UNCONDITIONAL,
			RefType.CALL_OVERRIDE_UNCONDITIONAL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.__JUMP_OVERRIDE_UNCONDITIONAL,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.__CALLOTHER_OVERRIDE_CALL,
			RefType.CALLOTHER_OVERRIDE_CALL);
		REFTYPE_LOOKUP_BY_TYPE_MAP.put(RefType.__CALLOTHER_OVERRIDE_JUMP,
			RefType.CALLOTHER_OVERRIDE_JUMP);
	}

	private static RefType[] memoryRefTypes = new RefType[] { RefType.INDIRECTION,
		RefType.COMPUTED_CALL, RefType.COMPUTED_JUMP, RefType.CONDITIONAL_CALL,
		RefType.CONDITIONAL_JUMP, RefType.UNCONDITIONAL_CALL, RefType.UNCONDITIONAL_JUMP,
		RefType.CONDITIONAL_COMPUTED_CALL, RefType.CONDITIONAL_COMPUTED_JUMP, RefType.PARAM,
		RefType.DATA, RefType.DATA_IND, RefType.READ, RefType.READ_IND, RefType.WRITE,
		RefType.WRITE_IND, RefType.READ_WRITE, RefType.READ_WRITE_IND,
		RefType.CALL_OVERRIDE_UNCONDITIONAL, RefType.JUMP_OVERRIDE_UNCONDITIONAL,
		RefType.CALLOTHER_OVERRIDE_CALL, RefType.CALLOTHER_OVERRIDE_JUMP };

	private static HashSet<RefType> validMemRefTypes = new HashSet<>();
	static {
		for (RefType rt : memoryRefTypes) {
			validMemRefTypes.add(rt);
		}
	}

	private static RefType[] stackRefTypes =
		new RefType[] { RefType.DATA, RefType.READ, RefType.WRITE, RefType.READ_WRITE };

	private static RefType[] dataRefTypes = new RefType[] { RefType.DATA, RefType.PARAM,
		RefType.READ, RefType.WRITE, RefType.READ_WRITE, };

	private static RefType[] extRefTypes =
		new RefType[] { RefType.COMPUTED_CALL, RefType.COMPUTED_JUMP, RefType.CONDITIONAL_CALL,
			RefType.CONDITIONAL_JUMP, RefType.UNCONDITIONAL_CALL, RefType.UNCONDITIONAL_JUMP,
			RefType.CONDITIONAL_COMPUTED_CALL, RefType.CONDITIONAL_COMPUTED_JUMP, RefType.DATA,
			RefType.DATA_IND, RefType.READ, RefType.READ_IND, RefType.WRITE, RefType.WRITE_IND,
			RefType.READ_WRITE, RefType.READ_WRITE_IND, RefType.CALL_OVERRIDE_UNCONDITIONAL,
			RefType.CALLOTHER_OVERRIDE_CALL, RefType.CALLOTHER_OVERRIDE_JUMP };

	public static RefType[] getMemoryRefTypes() {
		return memoryRefTypes;
	}

	public static RefType[] getStackRefTypes() {
		return stackRefTypes;
	}

	public static RefType[] getDataRefTypes() {
		return dataRefTypes;
	}

	public static RefType[] getExternalRefTypes() {
		return extRefTypes;
	}

	/**
	 * Get static instance of the specified RefType/FlowType
	 * @param type ref-type value
	 * @return ref-type instance
	 * @throws NoSuchElementException if ref-type is not defined
	 */
	public static RefType get(byte type) {
		RefType rt = REFTYPE_LOOKUP_BY_TYPE_MAP.get(type);
		if (rt == null) {
			throw new NoSuchElementException("RefType not defined: " + type);
		}
		return rt;
	}

	/**
	 * Get the default stack data RefType for the specified code-unit/opIndex and register
	 * @param cu the code unit
	 * @param reg the register
	 * @param opIndex the op index
	 * @return default RefType
	 */
	public static RefType getDefaultRegisterRefType(CodeUnit cu, Register reg, int opIndex) {
		RefType rt = RefType.DATA;
		if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;
			Object[] objs = instr.getResultObjects();
			for (Object obj : objs) {
				if (reg == obj) {
					rt = RefType.WRITE;
					break;
				}
			}
			objs = instr.getInputObjects();
			for (Object obj : objs) {
				if (reg == obj) {
					rt = (rt == RefType.WRITE) ? RefType.READ_WRITE : RefType.READ;
					break;
				}
			}
		}
		return rt;
	}

	private static final long[] MASKS = { 0L, 0x0ffL, 0x0ffffL, 0x0ffffffL, 0x0ffffffffL,
		0x0ffffffffffL, 0x0ffffffffffffL, 0x0ffffffffffffffL, 0xffffffffffffffffL };

	/**
	 * Get the default register data RefType for the specified code-unit/opIndex and register
	 * @param cu the code unit to get the default stack ref type.
	 * @param opIndex the operand index.
	 * @return the default register datat refType.
	 */
	public static RefType getDefaultStackRefType(CodeUnit cu, int opIndex) {

		if (!(cu instanceof Instruction)) {
			return RefType.DATA;
		}

		Instruction instr = (Instruction) cu;

		Object[] objs = instr.getOpObjects(opIndex);
		Scalar s = null;
		int scalarSize = 0;
		Register r = null;
		for (Object obj : objs) {
			if (obj instanceof Register) {
				if (r != null) {
					return RefType.DATA; // can't handle more than one register
				}
				r = (Register) obj;
			}
			else if (obj instanceof Scalar) {
				if (s != null) {
					return RefType.DATA; // can't handle more than one scalar
				}
				s = (Scalar) obj;
				scalarSize = s.bitLength() >> 3;
			}
		}
		if (r == null) {
			return RefType.DATA;
		}

		RefType refType = RefType.DATA;
		PcodeOp[] instrOps = instr.getPcode(true);

		Address stackOffsetAddr = null;
		if (s == null) {
			stackOffsetAddr = r.getAddress();
		}
		else {
			PcodeOp[] opOps = instr.getPcode(opIndex);
			for (PcodeOp op : opOps) {
				int opCode = op.getOpcode();
				Varnode[] inputs = op.getInputs();
				// Handle register w/ scalar case
				if (opCode == PcodeOp.INT_ADD || opCode == PcodeOp.INT_SUB) {
					int matchCnt = 0;
					for (int i = 0; i < inputs.length; i++) {
						Varnode input = inputs[i];
						Address addr = input.getAddress();
						// INT_SUB input order must be Register,Scalar
						if ((opCode == PcodeOp.INT_ADD || i == 0) && input.isRegister() &&
							addr.equals(r.getAddress())) {
							++matchCnt;
						}
						else if ((opCode == PcodeOp.INT_ADD || i == 1) && input.isConstant()) {
							int size = input.getSize();
							long value = s == null ? 0 : s.getValue();
							if (size >= scalarSize && size <= 8 &&
								addr.getOffset() == (value & MASKS[size])) {
								++matchCnt;
							}
						}
					}
					if (matchCnt == 2) {
						stackOffsetAddr = op.getOutput().getAddress();
						refType = getLoadStoreRefType(instrOps, 0, stackOffsetAddr, refType);
						break;
					}
				}
			}
		}

		if (stackOffsetAddr != null) {
			HashSet<Address> addrs = new HashSet<>();
			addrs.add(stackOffsetAddr);
			for (int opSeq = 0; opSeq < instrOps.length; opSeq++) {
				PcodeOp op = instrOps[opSeq];
				int opCode = op.getOpcode();
				Varnode[] inputs = op.getInputs();
				if (opCode == PcodeOp.COPY || opCode == PcodeOp.INT_ZEXT) {
					if (addrs.contains(inputs[0].getAddress())) {
						RefType rt = getLoadStoreRefType(instrOps, opSeq + 1,
							op.getOutput().getAddress(), refType);
						if (rt == RefType.READ) {
							if (refType == RefType.WRITE) {
								return RefType.READ_WRITE;
							}
							refType = rt;
						}
						else if (rt == RefType.WRITE) {
							if (refType == RefType.READ) {
								return RefType.READ_WRITE;
							}
							refType = rt;
						}
					}
				}
			}
		}

		return refType;
	}

	/**
	 * Determine default FlowType for a specified instruction and flow destination toAddr.
	 * @param instr instruction
	 * @param toAddr flow destination address
	 * @param allowComputedFlowType if true and an absolute flow type is not found
	 * a computed flow type will be returned if only one exists.
	 * @return FlowType or null if unable to determine
	 */
	public static FlowType getDefaultFlowType(Instruction instr, Address toAddr,
			boolean allowComputedFlowType) {

		if (!toAddr.isMemoryAddress() && !toAddr.isExternalAddress()) {
			throw new IllegalArgumentException("Unsupported toAddr address space type");
		}

		FlowType flowType = null;
		boolean simpleFlow =
			(instr.getFlowType() != RefType.INVALID && instr.getDefaultFlows().length <= 1);
		if (simpleFlow) {
			// only use default if simple flow
			flowType = getDefaultJumpOrCallFlowType(instr);
		}

		if (flowType != null && (!flowType.isComputed() || allowComputedFlowType)) {
			return flowType;
		}

		if (simpleFlow || toAddr.isExternalAddress()) {
			// Don't bother looking if not complex flow or address is external
			return null;
		}

		// Assumption - it is assumed that any complex flow type is due to the presence of
		// multiple conditional flows.  Does not handle use of constant offsets since
		// language should be using Address locations for all flow pcode!

		// TODO: Verify that above assumption is valid !!

		PcodeOp[] pcodeOps = instr.getPcode();
		for (PcodeOp op : pcodeOps) {
			int opcode = op.getOpcode();
			if (opcode == PcodeOp.CBRANCH || opcode == PcodeOp.BRANCH) {
				if (op.getInput(0).getAddress().equals(toAddr)) {
					return RefType.CONDITIONAL_JUMP;
				}
			}
			else if (opcode == PcodeOp.CALL) {
				if (op.getInput(0).getAddress().equals(toAddr)) {
					return RefType.CONDITIONAL_CALL;
				}
			}
		}

		if (flowType == null && allowComputedFlowType) {
			flowType = getDefaultComputedFlowType(instr);
		}
		return flowType;
	}

	/**
	 * Determine default computed FlowType for a specified instruction.  It is assumed
	 * that all computed flows utilize a register in its destination specification/computation.
	 * @param instr instruction
	 * @return FlowType or null if unable to determine
	 */
	public static FlowType getDefaultComputedFlowType(Instruction instr) {

		if (instr.getFlowType() != RefType.INVALID && instr.getDefaultFlows().length <= 1) {
			// Don't bother looking if not complex flow
			return getDefaultJumpOrCallFlowType(instr);
		}

		// Assumption - it is assumed that any complex flow type is due to the presence of
		// multiple conditional flows.

		// TODO: Verify that above assumption is valid !!

		FlowType flowType = null;
		PcodeOp[] pcodeOps = instr.getPcode();
		for (PcodeOp op : pcodeOps) {
			int opcode = op.getOpcode();
			if (opcode == PcodeOp.BRANCHIND) {
				if (flowType == RefType.CONDITIONAL_COMPUTED_CALL) {
					return null; // more than one flow type
				}
				flowType = RefType.CONDITIONAL_COMPUTED_JUMP;
			}
			else if (opcode == PcodeOp.CALLIND) {
				if (flowType == RefType.CONDITIONAL_COMPUTED_JUMP) {
					return null; // more than one flow type
				}
				flowType = RefType.CONDITIONAL_COMPUTED_CALL;
			}
		}

		return flowType;
	}

	/**
	 * Get the default memory flow/data RefType for the specified code unit and opIndex.
	 * @param cu the code unit
	 * @param opIndex the op index
	 * @param toAddr reference destination
	 * @param ignoreExistingReferences if true existing references will not influence default
	 * reference type returned.
	 * @return default RefType
	 */
	public static RefType getDefaultMemoryRefType(CodeUnit cu, int opIndex, Address toAddr,
			boolean ignoreExistingReferences) {

		boolean speculativeFlowNotAllowed = false;

		if (toAddr != null && toAddr.isMemoryAddress()) {
			MemoryBlock block = cu.getProgram().getMemory().getBlock(toAddr);
			if (block != null && block.isMapped()) {
				ignoreExistingReferences = true;
				speculativeFlowNotAllowed = true;
			}
		}

		RefType refType = null;

		if (toAddr != null && (cu instanceof Instruction)) {

			if (!toAddr.isMemoryAddress() && !toAddr.isExternalAddress()) {
				throw new IllegalArgumentException("Unsupported toAddr address space type");
			}

			Instruction instr = (Instruction) cu;
			Address[] flowAddrs = instr.getDefaultFlows();
			for (Address flowAddr : flowAddrs) {
				if (toAddr.equals(flowAddr)) {
					refType = getDefaultFlowType(instr, toAddr, false);
					if (refType == null) {
						// we should always find default flows and this should not happen
						refType = RefType.INVALID;
					}
					return refType;
				}
			}

			for (Object resultObj : instr.getResultObjects()) {
				if (resultObj.equals(toAddr)) {
					refType = RefType.WRITE;
					break;
				}
			}

			for (Object inputObj : instr.getInputObjects()) {
				if (inputObj.equals(toAddr)) {
					if (refType == RefType.WRITE) {
						return RefType.READ_WRITE;
					}
					refType = instr.getOperandRefType(opIndex);
					if (refType != RefType.INDIRECTION) {
						return RefType.READ;
					}
				}
			}
			if (refType != null) {
				return refType;
			}
		}

		if (!ignoreExistingReferences) {
			Reference[] refs = cu.getProgram()
					.getReferenceManager()
					.getReferencesFrom(
						cu.getMinAddress(), opIndex);
			for (Reference ref : refs) {
				if (ref.getToAddress().equals(toAddr)) {
					return ref.getReferenceType();
				}
				if (ref.isPrimary()) {
					refType = ref.getReferenceType();
				}
			}
			if (refType != null) {
				return refType;
			}
		}

		if (cu instanceof Instruction) {
			Instruction inst = (Instruction) cu;
			if (toAddr != null) {
				refType = getMemRefType(inst, toAddr);
			}
			if (refType == null && !speculativeFlowNotAllowed) {
				refType = getDefaultComputedFlowType(inst);
			}
			if (refType != null) {
				return refType;
			}
		}

		return RefType.DATA;
	}

	/**
	 * Return default flow-type without terminator
	 * @param inst the instruction
	 * @return call/jump flow type or null
	 */
	private static FlowType getDefaultJumpOrCallFlowType(Instruction inst) {
		FlowType flowType = inst.getFlowType();
		if (flowType.isConditional()) {
			if (flowType.isComputed()) {
				if (flowType.isCall()) {
					return RefType.CONDITIONAL_COMPUTED_CALL;
				}
				else if (flowType.isJump()) {
					return RefType.CONDITIONAL_COMPUTED_JUMP;
				}
			}
			else if (flowType.isCall()) {
				return RefType.CONDITIONAL_CALL;
			}
			else if (flowType.isJump()) {
				return RefType.CONDITIONAL_JUMP;
			}
		}
		if (flowType.isComputed()) {
			if (flowType.isCall()) {
				return RefType.COMPUTED_CALL;
			}
			else if (flowType.isJump()) {
				return RefType.COMPUTED_JUMP;
			}
		}
		else if (flowType.isCall()) {
			return RefType.UNCONDITIONAL_CALL;
		}
		else if (flowType.isJump()) {
			return RefType.UNCONDITIONAL_JUMP;
		}
		return null;
	}

	private static RefType getMemRefType(Instruction instr, Address memAddr) {

		long memOffset = memAddr.getAddressableWordOffset();

		RefType refType = null;
		Varnode offsetVarnode = null;
		Varnode valueVarnode = null;
		for (PcodeOp op : instr.getPcode()) {
			Varnode[] inputs = op.getInputs();
			if (op.getOpcode() == PcodeOp.INT_ZEXT || op.getOpcode() == PcodeOp.COPY) {
				if (inputs[0].isConstant() && inputs[0].getOffset() == memOffset) {
					offsetVarnode = op.getOutput();
					refType = RefType.DATA;
					continue;
				}
			} // TODO: Could track copy of offsetVarnode thus producing multiple offsetVarnodes
			if (op.getOpcode() == PcodeOp.STORE) {
				if (memAddr.getAddressSpace().getUnique() == inputs[0].getSpace() &&
					(memOffset == inputs[1].getOffset() || inputs[1].equals(offsetVarnode))) {
					if (refType != null && refType.isRead()) {
						return RefType.READ_WRITE;
					}
					refType = RefType.WRITE;
				}
			}
			else if (op.getOpcode() == PcodeOp.LOAD) {
				if (memAddr.getAddressSpace().getSpaceID() == inputs[0].getOffset() &&
					(memOffset == inputs[1].getOffset() || inputs[1].equals(offsetVarnode))) {
					if (refType != null && refType.isWrite()) {
						return RefType.READ_WRITE;
					}
					refType = RefType.READ;
					valueVarnode = op.getOutput();
				}
			}
			else {
				for (Varnode in : inputs) {
					if (refType == null && in.isConstant() && in.getOffset() == memOffset) {
						refType = RefType.DATA;
					}
					// changed to only compare the address offsets because of problem with overlay spaces
					// probably should look into why one is in an overlay and the other isn't when
					// they should match
					else if (in.isAddress() && in.getAddress().getOffset() == memAddr.getOffset()) {
						if (refType != null && refType.isWrite()) {
							return RefType.READ_WRITE;
						}
						refType = RefType.READ;
					}
				}
			}
			if (valueVarnode != null && isFlowOp(op) && valueVarnode.equals(inputs[0])) {
				return RefType.INDIRECTION;
			}
		}
		return refType;
	}

	private static boolean isFlowOp(PcodeOp op) {
		int opcode = op.getOpcode();
		return opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND || opcode == PcodeOp.CBRANCH ||
			opcode == PcodeOp.BRANCH || opcode == PcodeOp.BRANCHIND;
	}

	private static RefType getLoadStoreRefType(PcodeOp[] ops, int startOpSeq, Address offsetAddr,
			RefType refType) {

		for (int opSeq = startOpSeq; opSeq < ops.length; opSeq++) {
			PcodeOp op = ops[opSeq];
			int opCode = op.getOpcode();
			Varnode[] inputs = op.getInputs();

			// Check for load/store using outputAddr
			if (opCode == PcodeOp.LOAD) {
				if (inputs[1].getAddress().equals(offsetAddr)) {
					if (refType == RefType.WRITE) {
						return RefType.READ_WRITE;
					}
					refType = RefType.READ;
				}
			}
			else if (opCode == PcodeOp.STORE) {
				if (inputs[1].getAddress().equals(offsetAddr)) {
					if (refType == RefType.READ) {
						return RefType.READ_WRITE;
					}
					refType = RefType.WRITE;
				}
			}
		}

		return refType;
	}

}
