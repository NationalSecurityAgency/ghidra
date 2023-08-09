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
package wasm.analysis;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.LEB128;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.Msg;
import wasm.format.WasmEnums.ValType;
import wasm.format.sections.structures.WasmFuncType;

/**
 * This preanalysis pass is partially patterned after the validation algorithm
 * described in the Appendix:
 * https://webassembly.github.io/spec/core/appendix/algorithm.html
 */
public class WasmFunctionAnalysis {

	private WasmFuncSignature func;
	/* null in the value stack means Unknown */
	private List<ValType> valueStack = new ArrayList<>();
	private List<ControlFrame> controlStack = new ArrayList<>();
	private Map<Address, StackEffect> stackEffects = new HashMap<>();
	private Map<Address, Long> globalGetSets = new HashMap<>();
	private ContextRegister contextreg = new ContextRegister();

	public WasmFunctionAnalysis(WasmFuncSignature func) {
		this.func = func;
	}

	/*
	 * Cache for program context changes so we can set the context register once,
	 * instead of piece-by-piece
	 */
	private static class ContextRegister {
		private static class RegisterDefinition {
			private int start;
			private int end;

			public RegisterDefinition(int start, int end) {
				this.start = start;
				this.end = end;
			}

			public int getShift() {
				return CONTEXT_REG_WIDTH - 1 - end;
			}

			public int getWidth() {
				return end - start + 1;
			}
		}

		/* These definitions must be synced with WebAssembly.slaspec */
		private static final int CONTEXT_REG_WIDTH = 128;
		private static final RegisterDefinition REG_IS_DIRECTIVE = new RegisterDefinition(0, 0);
		private static final RegisterDefinition REG_IS_RETURN = new RegisterDefinition(1, 1);
		private static final RegisterDefinition REG_IS_GLOBAL_SP = new RegisterDefinition(2, 2);
		private static final RegisterDefinition REG_DIRECTIVE_TYPE = new RegisterDefinition(3, 5);
		private static final RegisterDefinition REG_OPERAND_SIZE = new RegisterDefinition(6, 13);
		private static final RegisterDefinition REG_CASE_INDEX = new RegisterDefinition(32, 63);
		private static final RegisterDefinition REG_BR_TARGET = new RegisterDefinition(64, 95);
		private static final RegisterDefinition REG_SP = new RegisterDefinition(96, 127);

		private static final int DIRECTIVE_CASE = 0;
		private static final int DIRECTIVE_DEFAULT = 1;
		private static final int DIRECTIVE_LOCALS = 2;
		private static final int DIRECTIVE_LOCAL = 3;

		private Map<Address, BigInteger> contextValues = new HashMap<>();

		private void setRegister(Address address, RegisterDefinition reg, long value) {
			if (!contextValues.containsKey(address)) {
				contextValues.put(address, BigInteger.ZERO);
			}

			if (value < 0 || value > (1L << reg.getWidth()) - 1) {
				throw new ArithmeticException("Context register value " + value + " is out of range");
			}
			contextValues.put(address, contextValues.get(address).or(BigInteger.valueOf(value).shiftLeft(reg.getShift())));
		}

		public BigInteger getContext(Address address) {
			return contextValues.get(address);
		}

		public void commitContext(Program program) {
			ProgramContext context = program.getProgramContext();
			Register contextRegister = context.getBaseContextRegister();
			for (Map.Entry<Address, BigInteger> entry : contextValues.entrySet()) {
				Address address = entry.getKey();
				if (program.getListing().getInstructionContaining(address) != null)
					continue;

				RegisterValue value = new RegisterValue(contextRegister, entry.getValue());
				try {
					context.setRegisterValue(address, address, value);
				} catch (ContextChangeException e) {
					Msg.error(this, "Failed to set context register at " + address, e);
				}
			}
			contextValues.clear();
		}

		public void setIsReturn(Address address, int value) {
			setRegister(address, REG_IS_RETURN, value);
		}

		/**
		 * Set how large the stack operand is. This currently affects local.*, global.*
		 * and select instructions.
		 */
		public void setOperandSize(Address address, ValType type) {
			if (type != null) {
				// might be null if we're in an unreachable area
				setRegister(address, REG_OPERAND_SIZE, type.getSize());
			}
		}

		/** Mark this global.* instruction as operating on the C stack pointer. */
		public void setIsGlobalSp(Address address, boolean value) {
			setRegister(address, REG_IS_GLOBAL_SP, value ? 1 : 0);
		}

		/** Set the address that this instruction branches to. */
		public void setBranchTarget(Address address, Address target) {
			setRegister(address, REG_BR_TARGET, target.getOffset());
		}

		/**
		 * Set the virtual stack pointer. Our SLEIGH converts stack operations into
		 * register operations by using the stack pointer to index a register file.
		 */
		public void setStackPointer(Address address, long value) {
			setRegister(address, REG_SP, value);
		}

		/* Number of locals table entries */
		public void setLocalsDeclaration(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_LOCALS);
		}

		/* One entry in the function locals table */
		public void setLocalDeclaration(Address address) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_LOCAL);
		}

		/**
		 * Disassemble this "instruction" as a case statement underneath a br_table. We
		 * break out case statements individually in order to provide each one with a
		 * unique branch target.
		 */
		public void setBrTableCase(Address address, int index) {
			setRegister(address, REG_IS_DIRECTIVE, 1);
			if (index == -1) {
				setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_DEFAULT);
			} else {
				setRegister(address, REG_DIRECTIVE_TYPE, DIRECTIVE_CASE);
				setRegister(address, REG_CASE_INDEX, index);
			}
		}
	}

	private static class BlockType {
		ValType[] params;
		ValType[] returns;

		public BlockType(WasmFuncSignature func) {
			/* A function's parameters are in local variables rather than the stack */
			params = new ValType[0];
			returns = func.getReturns();
		}

		public BlockType(WasmAnalysis analysis, long blocktype) {
			if (blocktype == -0x40) {
				params = new ValType[0];
				returns = new ValType[0];
			} else if (blocktype < 0) {
				params = new ValType[0];
				returns = new ValType[] { ValType.fromByte((int) blocktype + 0x80) };
			} else {
				WasmFuncType type = analysis.getType((int) blocktype);
				params = type.getParamTypes();
				returns = type.getReturnTypes();
			}
		}
	}

	private enum BlockKind {
		FUNCTION,
		BLOCK,
		IF,
		LOOP
	}

	private class ControlFrame {
		Address startAddress;
		BlockKind blockKind;
		BlockType blockType;
		List<ValType> initialStack;
		/** A list of instruction address which branch to this block. */
		List<Address> branchAddresses = new ArrayList<>();
		boolean unreachable = false;
		boolean hasElse = false;

		public ControlFrame(Address address, BlockType blockType) {
			this.startAddress = address;
			this.blockKind = BlockKind.FUNCTION;
			this.blockType = blockType;
			this.initialStack = new ArrayList<>();
		}

		public ControlFrame(Address address, BlockKind blockKind, BlockType blockType, List<ValType> stack) {
			this.startAddress = address;
			this.blockKind = blockKind;
			this.blockType = blockType;
			this.initialStack = new ArrayList<>(stack);
		}

		public ValType[] getBranchArguments() {
			if (blockKind == BlockKind.LOOP) {
				return blockType.params;
			} else {
				return blockType.returns;
			}
		}

		/**
		 * Track a branch to this block.
		 * 
		 * @param program
		 * @param stack
		 *            Value stack after the parameters ({@link #getBranchArguments})
		 *            have been popped
		 * @param address
		 *            Address of the branch instruction
		 */
		public void addBranch(Address address) {
			branchAddresses.add(address);
		}

		public void setElse(Address address) {
			hasElse = true;
			if (blockKind != BlockKind.IF) {
				throw new ValidationException(address, "else without corresponding if");
			}
			contextreg.setBranchTarget(startAddress, address.add(1));
		}

		public void setEnd(Address address) {
			if (blockKind == BlockKind.IF && !hasElse) {
				contextreg.setBranchTarget(startAddress, address);
			}

			Address branchTarget;
			if (blockKind == BlockKind.LOOP) {
				branchTarget = startAddress;
			} else {
				branchTarget = address;
			}
			for (Address branch : branchAddresses) {
				contextreg.setBranchTarget(branch, branchTarget);
			}
		}

		@Override
		public String toString() {
			return blockKind + "@" + startAddress;
		}
	}

	// #region Exported pre-analysis results
	public static class StackEffect {
		private int popHeight; // Height of the stack *after* the pops
		private ValType[] toPop;
		private int pushHeight; // Height of the stack *before* the pushes
		private ValType[] toPush;

		public StackEffect(int popHeight, ValType[] toPop, int pushHeight, ValType[] toPush) {
			this.popHeight = popHeight;
			this.toPop = toPop;
			this.pushHeight = pushHeight;
			this.toPush = toPush;
		}

		public int getPopHeight() {
			return popHeight;
		}

		public ValType[] getToPop() {
			if (toPop == null) {
				return new ValType[0];
			}
			return toPop;
		}

		public int getPushHeight() {
			return pushHeight;
		}

		public ValType[] getToPush() {
			if (toPush == null) {
				return new ValType[0];
			}
			return toPush;
		}
	}

	public WasmFuncSignature getSignature() {
		return func;
	}

	/**
	 * Set the stack effect of this instruction - which types it pushes and pops.
	 * This is used to handle variable-argument instructions, which currently
	 * includes branch, call and return instructions. TODO: Ideally, these would be
	 * saved to the program context, which would save us from having to re-analyze
	 * functions when reopening the DB.
	 */
	private void setStackEffect(Address address, int popHeight, ValType[] toPop, int pushHeight, ValType[] toPush) {
		stackEffects.put(address, new StackEffect(popHeight, toPop, pushHeight, toPush));
	}

	public StackEffect getStackEffect(Address address) {
		return stackEffects.get(address);
	}
	// #endregion

	// #region BinaryReader utilities
	private static long readLeb128(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::unsigned);
	}

	private static long readSignedLeb128(BinaryReader reader) throws IOException {
		return reader.readNext(LEB128::signed);
	}
	// #endregion

	// #region Value stack manipulation
	private void pushValue(Address instAddress, ValType type) {
		valueStack.add(type);
	}

	private ValType popValue(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		if (valueStack.size() <= curBlock.initialStack.size()) {
			/* If our stack is polymorphic, popping off an empty stack is ok */
			if (curBlock.unreachable)
				return null;
			throw new ValidationException(instAddress, "pop from empty stack");
		}
		return valueStack.remove(valueStack.size() - 1);
	}

	private ValType popValue(Address instAddress, ValType expected) {
		ValType actual = popValue(instAddress);
		if (actual != expected && actual != null && expected != null) {
			throw new ValidationException(instAddress, "pop type mismatch: got " + actual + ", expected " + expected);
		}
		return actual;
	}

	private void pushValues(Address instAddress, ValType[] types) {
		for (int i = 0; i < types.length; i++) {
			pushValue(instAddress, types[i]);
		}
	}

	private ValType[] popValues(Address instAddress, ValType[] types) {
		ValType[] popped = new ValType[types.length];
		for (int i = types.length - 1; i >= 0; i--) {
			popped[i] = popValue(instAddress, types[i]);
		}
		return popped;
	}
	// #endregion

	// #region Control stack manipulation
	private void pushBlock(Address instAddress, ControlFrame block) {
		controlStack.add(block);
		pushValues(instAddress, block.blockType.params);
	}

	private ControlFrame popBlock(Address instAddress) {
		if (controlStack.isEmpty()) {
			throw new ValidationException(instAddress, "pop from empty block stack");
		}
		ControlFrame block = getBlock(instAddress, 0);
		popValues(instAddress, block.blockType.returns);
		if (valueStack.size() != block.initialStack.size()) {
			throw new ValidationException(instAddress, "block end has wrong number of parameters");
		}
		controlStack.remove(controlStack.size() - 1);
		return block;
	}

	private ControlFrame getBlock(Address instAddress, long labelidx) {
		if (labelidx >= controlStack.size()) {
			throw new ValidationException(instAddress, "invalid label index " + labelidx);
		}
		return controlStack.get(controlStack.size() - 1 - (int) labelidx);
	}

	/** Mark stack as polymorphic from this point to the end of the block */
	private void markUnreachable(Address instAddress) {
		ControlFrame curBlock = getBlock(instAddress, 0);
		valueStack = new ArrayList<>(curBlock.initialStack);
		curBlock.unreachable = true;
	}
	// #endregion

	// #region Common instruction code
	private void memoryLoad(BinaryReader reader, Address instAddress, ValType destType) throws IOException {
		readLeb128(reader); /* align */
		readLeb128(reader); /* offset */
		popValue(instAddress, ValType.i32);
		pushValue(instAddress, destType);
	}

	private void memoryStore(BinaryReader reader, Address instAddress, ValType destType) throws IOException {
		readLeb128(reader); /* align */
		readLeb128(reader); /* offset */
		popValue(instAddress, destType);
		popValue(instAddress, ValType.i32);
	}

	private void unaryOp(Address instAddress, ValType srcType, ValType destType) {
		popValue(instAddress, srcType);
		pushValue(instAddress, destType);
	}

	private void binaryOp(Address instAddress, ValType srcType, ValType destType) {
		popValue(instAddress, srcType);
		popValue(instAddress, srcType);
		pushValue(instAddress, destType);
	}

	// #endregion

	private void analyzeOpcode(WasmAnalysis analysis, Address instAddress, BinaryReader reader) throws IOException {
		contextreg.setStackPointer(instAddress, valueStack.size());
		int opcode = reader.readNextUnsignedByte();
		switch (opcode) {
		case 0x00: /* unreachable */
			markUnreachable(instAddress);
			break;
		case 0x01: /* nop */
			break;

		case 0x02: /* block bt */ {
			BlockType blocktype = new BlockType(analysis, readSignedLeb128(reader));
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.BLOCK, blocktype, valueStack));
			break;
		}
		case 0x03: /* loop bt */ {
			BlockType blocktype = new BlockType(analysis, readSignedLeb128(reader));
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.LOOP, blocktype, valueStack));
			break;
		}
		case 0x04: /* if bt */ {
			BlockType blocktype = new BlockType(analysis, readSignedLeb128(reader));
			popValue(instAddress, ValType.i32);
			popValues(instAddress, blocktype.params);
			pushBlock(instAddress, this.new ControlFrame(instAddress, BlockKind.IF, blocktype, valueStack));
			break;
		}
		case 0x05: /* else */ {
			ControlFrame block = popBlock(instAddress);
			if (block.blockKind != BlockKind.IF) {
				throw new ValidationException(instAddress, "else without matching if");
			}

			/*
			 * The else instruction itself serves as a branch to the end of the block. The
			 * branch from the if instruction will go to the instruction after the else.
			 */
			block.addBranch(instAddress);
			block.setElse(instAddress);

			block.unreachable = false;
			pushBlock(instAddress, block);
			break;
		}
		case 0x0B: /* end */ {
			ControlFrame block = popBlock(instAddress);
			// this stack effect will only be used by the final end
			setStackEffect(instAddress, valueStack.size(), block.blockType.returns, 0, null);
			pushValues(instAddress, block.blockType.returns);
			block.setEnd(instAddress);
			if (controlStack.isEmpty()) {
				contextreg.setIsReturn(instAddress, 1);
			}
			break;
		}

		case 0x0C: /* br l */ {
			long labelidx = readLeb128(reader);

			ControlFrame block = getBlock(instAddress, labelidx);
			ValType[] arguments = block.getBranchArguments();
			popValues(instAddress, arguments);
			setStackEffect(instAddress, valueStack.size(), arguments, block.initialStack.size(), arguments);
			block.addBranch(instAddress);

			markUnreachable(instAddress);
			break;
		}
		case 0x0D: /* br_if l */ {
			long labelidx = readLeb128(reader);
			popValue(instAddress, ValType.i32);

			ControlFrame block = getBlock(instAddress, labelidx);
			ValType[] arguments = block.getBranchArguments();
			popValues(instAddress, arguments);
			setStackEffect(instAddress, valueStack.size(), arguments, block.initialStack.size(), arguments);
			block.addBranch(instAddress);
			pushValues(instAddress, arguments);

			break;
		}
		case 0x0E: /* br_table l* l */ {
			long count = readLeb128(reader);
			popValue(instAddress, ValType.i32);
			for (int i = 0; i < count + 1; i++) {
				Address caseAddress = func.getStartAddr().add(reader.getPointerIndex());
				contextreg.setBrTableCase(caseAddress, (i < count) ? i : -1);
				long labelidx = readLeb128(reader);

				ControlFrame block = getBlock(caseAddress, labelidx);
				ValType[] arguments = block.getBranchArguments();
				ValType[] actualArgs = popValues(caseAddress, arguments);
				setStackEffect(caseAddress, valueStack.size(), arguments, block.initialStack.size(), arguments);
				block.addBranch(caseAddress);
				if (i < count) {
					pushValues(caseAddress, actualArgs);
				}
			}
			markUnreachable(instAddress);
			break;
		}
		case 0x0F: /* return */ {
			popValues(instAddress, func.getReturns());
			setStackEffect(instAddress, valueStack.size(), func.getReturns(), 0, null);
			markUnreachable(instAddress);
			break;
		}
		case 0x10: /* call x */ {
			long funcidx = readLeb128(reader);
			WasmFuncSignature targetFunc = analysis.getFunction((int) funcidx);
			ValType[] params = targetFunc.getParams();
			ValType[] returns = targetFunc.getReturns();
			popValues(instAddress, params);
			setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), returns);
			contextreg.setBranchTarget(instAddress, targetFunc.getStartAddr());
			pushValues(instAddress, returns);
			break;
		}
		case 0x11: /* call_indirect x y */ {
			long typeidx = readLeb128(reader);
			long tableidx = readLeb128(reader);
			if (analysis.getTableType((int) tableidx) != ValType.funcref) {
				throw new ValidationException(instAddress, "call_indirect does not reference a function table");
			}
			WasmFuncType type = analysis.getType((int) typeidx);

			popValue(instAddress, ValType.i32);
			ValType[] params = type.getParamTypes();
			ValType[] returns = type.getReturnTypes();
			popValues(instAddress, params);
			setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), returns);
			pushValues(instAddress, returns);
			break;
		}

		case 0x1A: /* drop */ {
			popValue(instAddress);
			break;
		}
		case 0x1B: /* select */ {
			popValue(instAddress, ValType.i32);
			ValType t1 = popValue(instAddress);
			ValType t2 = popValue(instAddress);
			if (t1 != null && t2 != null && t1 != t2) {
				throw new ValidationException(instAddress, "inconsistent types in select");
			}
			ValType resultType = (t1 != null) ? t1 : t2;
			contextreg.setOperandSize(instAddress, resultType);
			pushValue(instAddress, resultType);
			break;
		}
		case 0x1C: /* select t */ {
			long count = readLeb128(reader);
			if (count != 1) {
				throw new ValidationException(instAddress, "only select t is supported");
			}
			ValType t = ValType.fromByte(reader.readNextUnsignedByte());
			popValue(instAddress, ValType.i32);
			popValue(instAddress, t);
			popValue(instAddress, t);
			pushValue(instAddress, t);
			break;
		}

		case 0x20: /* local.get x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			contextreg.setOperandSize(instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x21: /* local.set x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			contextreg.setOperandSize(instAddress, type);
			popValue(instAddress, type);
			break;
		}
		case 0x22: /* local.tee x */ {
			long localidx = readLeb128(reader);
			ValType type = func.getLocals()[(int) localidx];
			contextreg.setOperandSize(instAddress, type);
			popValue(instAddress, type);
			pushValue(instAddress, type);
			break;
		}
		case 0x23: /* global.get x */ {
			long globalidx = readLeb128(reader);
			ValType type = analysis.getGlobalType((int) globalidx);
			contextreg.setOperandSize(instAddress, type);
			globalGetSets.put(instAddress, globalidx);
			pushValue(instAddress, type);
			break;
		}
		case 0x24: /* global.set x */ {
			long globalidx = readLeb128(reader);
			ValType type = analysis.getGlobalType((int) globalidx);
			contextreg.setOperandSize(instAddress, type);
			globalGetSets.put(instAddress, globalidx);
			popValue(instAddress, type);
			break;
		}

		case 0x25: /* table.get x */ {
			long tableidx = readLeb128(reader);
			ValType type = analysis.getTableType((int) tableidx);
			popValue(instAddress, ValType.i32);
			pushValue(instAddress, type);
			break;
		}
		case 0x26: /* table.set x */ {
			long tableidx = readLeb128(reader);
			ValType type = analysis.getTableType((int) tableidx);
			popValue(instAddress, type);
			popValue(instAddress, ValType.i32);
			break;
		}

		case 0x28: /* i32.load memarg */
		case 0x2C: /* i32.load8_s memarg */
		case 0x2D: /* i32.load8_u memarg */
		case 0x2E: /* i32.load16_s memarg */
		case 0x2F: /* i32.load16_u memarg */
			memoryLoad(reader, instAddress, ValType.i32);
			break;
		case 0x29: /* i64.load memarg */
		case 0x30: /* i64.load8_s memarg */
		case 0x31: /* i64.load8_u memarg */
		case 0x32: /* i64.load16_s memarg */
		case 0x33: /* i64.load16_u memarg */
		case 0x34: /* i64.load32_s memarg */
		case 0x35: /* i64.load32_u memarg */
			memoryLoad(reader, instAddress, ValType.i64);
			break;
		case 0x2A: /* f32.load memarg */
			memoryLoad(reader, instAddress, ValType.f32);
			break;
		case 0x2B: /* f64.load memarg */
			memoryLoad(reader, instAddress, ValType.f64);
			break;

		case 0x36: /* i32.store memarg */
		case 0x3A: /* i32.store8 memarg */
		case 0x3B: /* i32.store16 memarg */
			memoryStore(reader, instAddress, ValType.i32);
			break;
		case 0x37: /* i64.store memarg */
		case 0x3C: /* i64.store8 memarg */
		case 0x3D: /* i64.store16 memarg */
		case 0x3E: /* i64.store32 memarg */
			memoryStore(reader, instAddress, ValType.i64);
			break;
		case 0x38: /* f32.store memarg */
			memoryStore(reader, instAddress, ValType.f32);
			break;
		case 0x39: /* f64.store memarg */
			memoryStore(reader, instAddress, ValType.f64);
			break;

		case 0x3F: /* memory.size */ {
			readLeb128(reader); /* memidx */
			pushValue(instAddress, ValType.i32);
			break;
		}
		case 0x40: /* memory.grow */ {
			readLeb128(reader); /* memidx */
			popValue(instAddress, ValType.i32);
			pushValue(instAddress, ValType.i32);
			break;
		}

		case 0x41: /* i32.const i32 */ {
			readSignedLeb128(reader); /* value */
			pushValue(instAddress, ValType.i32);
			break;
		}
		case 0x42: /* i64.const i64 */ {
			readSignedLeb128(reader); /* value */
			pushValue(instAddress, ValType.i64);
			break;
		}
		case 0x43: /* f32.const f32 */ {
			reader.readNextByteArray(4); /* value */
			pushValue(instAddress, ValType.f32);
			break;
		}
		case 0x44: /* f64.const f64 */ {
			reader.readNextByteArray(8); /* value */
			pushValue(instAddress, ValType.f64);
			break;
		}

		case 0x45: /* i32.eqz */
			unaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x46: /* i32.eq */
		case 0x47: /* i32.ne */
		case 0x48: /* i32.lt_s */
		case 0x49: /* i32.lt_u */
		case 0x4A: /* i32.gt_s */
		case 0x4B: /* i32.gt_u */
		case 0x4C: /* i32.le_s */
		case 0x4D: /* i32.le_u */
		case 0x4E: /* i32.ge_s */
		case 0x4F: /* i32.ge_u */
			binaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x50: /* i64.eqz */
			unaryOp(instAddress, ValType.i64, ValType.i32);
			break;
		case 0x51: /* i64.eq */
		case 0x52: /* i64.ne */
		case 0x53: /* i64.lt_s */
		case 0x54: /* i64.lt_u */
		case 0x55: /* i64.gt_s */
		case 0x56: /* i64.gt_u */
		case 0x57: /* i64.le_s */
		case 0x58: /* i64.le_u */
		case 0x59: /* i64.ge_s */
		case 0x5A: /* i64.ge_u */
			binaryOp(instAddress, ValType.i64, ValType.i32);
			break;
		case 0x5B: /* f32.eq */
		case 0x5C: /* f32.ne */
		case 0x5D: /* f32.lt */
		case 0x5E: /* f32.gt */
		case 0x5F: /* f32.le */
		case 0x60: /* f32.ge */
			binaryOp(instAddress, ValType.f32, ValType.i32);
			break;
		case 0x61: /* f64.eq */
		case 0x62: /* f64.ne */
		case 0x63: /* f64.lt */
		case 0x64: /* f64.gt */
		case 0x65: /* f64.le */
		case 0x66: /* f64.ge */
			binaryOp(instAddress, ValType.f64, ValType.i32);
			break;
		case 0x67: /* i32.clz */
		case 0x68: /* i32.ctz */
		case 0x69: /* i32.popcnt */
			unaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x6A: /* i32.add */
		case 0x6B: /* i32.sub */
		case 0x6C: /* i32.mul */
		case 0x6D: /* i32.div_s */
		case 0x6E: /* i32.div_u */
		case 0x6F: /* i32.rem_s */
		case 0x70: /* i32.rem_u */
		case 0x71: /* i32.and */
		case 0x72: /* i32.or */
		case 0x73: /* i32.xor */
		case 0x74: /* i32.shl */
		case 0x75: /* i32.shr_s */
		case 0x76: /* i32.shr_u */
		case 0x77: /* i32.rotl */
		case 0x78: /* i32.rotr */
			binaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0x79: /* i64.clz */
		case 0x7A: /* i64.ctz */
		case 0x7B: /* i64.popcnt */
			unaryOp(instAddress, ValType.i64, ValType.i64);
			break;
		case 0x7C: /* i64.add */
		case 0x7D: /* i64.sub */
		case 0x7E: /* i64.mul */
		case 0x7F: /* i64.div_s */
		case 0x80: /* i64.div_u */
		case 0x81: /* i64.rem_s */
		case 0x82: /* i64.rem_u */
		case 0x83: /* i64.and */
		case 0x84: /* i64.or */
		case 0x85: /* i64.xor */
		case 0x86: /* i64.shl */
		case 0x87: /* i64.shr_s */
		case 0x88: /* i64.shr_u */
		case 0x89: /* i64.rotl */
		case 0x8A: /* i64.rotr */
			binaryOp(instAddress, ValType.i64, ValType.i64);
			break;
		case 0x8B: /* f32.abs */
		case 0x8C: /* f32.neg */
		case 0x8D: /* f32.ceil */
		case 0x8E: /* f32.floor */
		case 0x8F: /* f32.trunc */
		case 0x90: /* f32.nearest */
		case 0x91: /* f32.sqrt */
			unaryOp(instAddress, ValType.f32, ValType.f32);
			break;
		case 0x92: /* f32.add */
		case 0x93: /* f32.sub */
		case 0x94: /* f32.mul */
		case 0x95: /* f32.div */
		case 0x96: /* f32.min */
		case 0x97: /* f32.max */
		case 0x98: /* f32.copysign */
			binaryOp(instAddress, ValType.f32, ValType.f32);
			break;
		case 0x99: /* f64.abs */
		case 0x9A: /* f64.neg */
		case 0x9B: /* f64.ceil */
		case 0x9C: /* f64.floor */
		case 0x9D: /* f64.trunc */
		case 0x9E: /* f64.nearest */
		case 0x9F: /* f64.sqrt */
			unaryOp(instAddress, ValType.f64, ValType.f64);
			break;
		case 0xA0: /* f64.add */
		case 0xA1: /* f64.sub */
		case 0xA2: /* f64.mul */
		case 0xA3: /* f64.div */
		case 0xA4: /* f64.min */
		case 0xA5: /* f64.max */
		case 0xA6: /* f64.copysign */
			binaryOp(instAddress, ValType.f64, ValType.f64);
			break;
		case 0xA7: /* i32.wrap_i64 */
			unaryOp(instAddress, ValType.i64, ValType.i32);
			break;
		case 0xA8: /* i32.trunc_f32_s */
		case 0xA9: /* i32.trunc_f32_u */
			unaryOp(instAddress, ValType.f32, ValType.i32);
			break;
		case 0xAA: /* i32.trunc_f64_s */
		case 0xAB: /* i32.trunc_f64_u */
			unaryOp(instAddress, ValType.f64, ValType.i32);
			break;
		case 0xAC: /* i64.extend_i32_s */
		case 0xAD: /* i64.extend_i32_u */
			unaryOp(instAddress, ValType.i32, ValType.i64);
			break;
		case 0xAE: /* i64.trunc_f32_s */
		case 0xAF: /* i64.trunc_f32_u */
			unaryOp(instAddress, ValType.f32, ValType.i64);
			break;
		case 0xB0: /* i64.trunc_f64_s */
		case 0xB1: /* i64.trunc_f64_u */
			unaryOp(instAddress, ValType.f64, ValType.i64);
			break;
		case 0xB2: /* f32.convert_i32_s */
		case 0xB3: /* f32.convert_i32_u */
			unaryOp(instAddress, ValType.i32, ValType.f32);
			break;
		case 0xB4: /* f32.convert_i64_s */
		case 0xB5: /* f32.convert_i64_u */
			unaryOp(instAddress, ValType.i64, ValType.f32);
			break;
		case 0xB6: /* f32.demote_f64 */
			unaryOp(instAddress, ValType.f64, ValType.f32);
			break;
		case 0xB7: /* f64.convert_i32_s */
		case 0xB8: /* f64.convert_i32_u */
			unaryOp(instAddress, ValType.i32, ValType.f64);
			break;
		case 0xB9: /* f64.convert_i64_s */
		case 0xBA: /* f64.convert_i64_u */
			unaryOp(instAddress, ValType.i64, ValType.f64);
			break;
		case 0xBB: /* f64.promote_f32 */
			unaryOp(instAddress, ValType.f32, ValType.f64);
			break;
		case 0xBC: /* i32.reinterpret_f32 */
			unaryOp(instAddress, ValType.f32, ValType.i32);
			break;
		case 0xBD: /* i64.reinterpret_f64 */
			unaryOp(instAddress, ValType.f64, ValType.i64);
			break;
		case 0xBE: /* f32.reinterpret_i32 */
			unaryOp(instAddress, ValType.i32, ValType.f32);
			break;
		case 0xBF: /* f64.reinterpret_i64 */
			unaryOp(instAddress, ValType.i64, ValType.f64);
			break;
		case 0xC0: /* i32.extend8_s */
		case 0xC1: /* i32.extend16_s */
			unaryOp(instAddress, ValType.i32, ValType.i32);
			break;
		case 0xC2: /* i64.extend8_s */
		case 0xC3: /* i64.extend16_s */
		case 0xC4: /* i64.extend32_s */
			unaryOp(instAddress, ValType.i64, ValType.i64);
			break;

		case 0xD0: /* ref.null t */ {
			ValType reftype = ValType.fromByte(reader.readNextUnsignedByte());
			pushValue(instAddress, reftype);
			break;
		}
		case 0xD1: /* ref.is_null */
			popValue(instAddress);
			pushValue(instAddress, ValType.i32);
			break;
		case 0xD2: /* ref.func x */ {
			long funcidx = readLeb128(reader);
			WasmFuncSignature targetFunc = analysis.getFunction((int) funcidx);
			contextreg.setBranchTarget(instAddress, targetFunc.getStartAddr());
			pushValue(instAddress, ValType.funcref);
			break;
		}
		case 0xFC: {
			int opcode2 = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			switch (opcode2) {
			case 0x00: /* i32.trunc_sat_f32_s */
			case 0x01: /* i32.trunc_sat_f32_u */
				unaryOp(instAddress, ValType.f32, ValType.i32);
				break;
			case 0x02: /* i32.trunc_sat_f64_s */
			case 0x03: /* i32.trunc_sat_f64_u */
				unaryOp(instAddress, ValType.f64, ValType.i32);
				break;
			case 0x04: /* i64.trunc_sat_f32_s */
			case 0x05: /* i64.trunc_sat_f32_u */
				unaryOp(instAddress, ValType.f32, ValType.i64);
				break;
			case 0x06: /* i64.trunc_sat_f64_s */
			case 0x07: /* i64.trunc_sat_f64_u */
				unaryOp(instAddress, ValType.f64, ValType.i64);
				break;
			case 0x08: /* memory.init x */ {
				readLeb128(reader); /* dataidx */
				readLeb128(reader); /* memidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x09: /* data.drop x */ {
				readLeb128(reader); /* dataidx */
				break;
			}
			case 0x0A: /* memory.copy */ {
				readLeb128(reader); /* memidx */
				readLeb128(reader); /* memidx2 */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x0B: /* memory.fill */ {
				readLeb128(reader); /* memidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x0C: /* table.init x y */ {
				readLeb128(reader); /* elemidx */
				readLeb128(reader); /* tableidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x0D: /* elem.drop x */ {
				readLeb128(reader); /* elemidx */
				break;
			}
			case 0x0E: /* table.copy x y */ {
				readLeb128(reader); /* tableidx */
				readLeb128(reader); /* tableidx2 */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.i32);
				break;
			}
			case 0x0F: /* table.grow x */ {
				readLeb128(reader); /* tableidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress);
				pushValue(instAddress, ValType.i32);
				break;
			}
			case 0x10: /* table.size x */ {
				readLeb128(reader); /* tableidx */
				pushValue(instAddress, ValType.i32);
				break;
			}
			case 0x11: /* table.fill x */ {
				readLeb128(reader); /* tableidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress);
				popValue(instAddress, ValType.i32);
				break;
			}
			default:
				Msg.warn(this, "Illegal opcode 0xfc " + String.format("0x%02x", opcode2) + " at " + instAddress);
				break;
			}
			break;
		}
		case 0xFD: {
			int opcode2 = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			switch (opcode2) {
			case 0x0: /* v128.load */
			case 0x1: /* v128.load8x8_s */
			case 0x2: /* v128.load8x8_u */
			case 0x3: /* v128.load16x4_s */
			case 0x4: /* v128.load16x4_u */
			case 0x5: /* v128.load32x2_s */
			case 0x6: /* v128.load32x2_u */
			case 0x7: /* v128.load8_splat */
			case 0x8: /* v128.load16_splat */
			case 0x9: /* v128.load32_splat */
			case 0xA: /* v128.load64_splat */
				memoryLoad(reader, instAddress, ValType.v128);
				break;
			case 0xB: /* v128.store */
				memoryStore(reader, instAddress, ValType.v128);
				break;
			case 0xC: /* v128.const */
				reader.readNextByteArray(16); /* value */
				pushValue(instAddress, ValType.v128);
				break;
			case 0xD: /* i8x16.shuffle */
				for (int i = 0; i < 16; i++)
					reader.readNextByte(); /* laneidx16 */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xE: /* i8x16.swizzle */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xF: /* i8x16.splat */
			case 0x10: /* i16x8.splat */
			case 0x11: /* i32x4.splat */
				unaryOp(instAddress, ValType.i32, ValType.v128);
				break;
			case 0x12: /* i64x2.splat */
				unaryOp(instAddress, ValType.i64, ValType.v128);
				break;
			case 0x13: /* f32x4.splat */
				unaryOp(instAddress, ValType.f32, ValType.v128);
				break;
			case 0x14: /* f64x2.splat */
				unaryOp(instAddress, ValType.f64, ValType.v128);
				break;
			case 0x15: /* i8x16.extract_lane_s */
			case 0x16: /* i8x16.extract_lane_u */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x17: /* i8x16.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x18: /* i16x8.extract_lane_s */
			case 0x19: /* i16x8.extract_lane_u */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x1A: /* i16x8.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x1B: /* i32x4.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x1C: /* i32x4.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x1D: /* i64x2.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.i64);
				break;
			case 0x1E: /* i64x2.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.i64);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x1F: /* f32x4.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.f32);
				break;
			case 0x20: /* f32x4.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.f32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x21: /* f64x2.extract_lane */
				reader.readNextByte(); /* laneidx */
				unaryOp(instAddress, ValType.v128, ValType.f64);
				break;
			case 0x22: /* f64x2.replace_lane */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.f64);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x23: /* i8x16.eq */
			case 0x24: /* i8x16.ne */
			case 0x25: /* i8x16.lt_s */
			case 0x26: /* i8x16.lt_u */
			case 0x27: /* i8x16.gt_s */
			case 0x28: /* i8x16.gt_u */
			case 0x29: /* i8x16.le_s */
			case 0x2A: /* i8x16.le_u */
			case 0x2B: /* i8x16.ge_s */
			case 0x2C: /* i8x16.ge_u */
			case 0x2D: /* i16x8.eq */
			case 0x2E: /* i16x8.ne */
			case 0x2F: /* i16x8.lt_s */
			case 0x30: /* i16x8.lt_u */
			case 0x31: /* i16x8.gt_s */
			case 0x32: /* i16x8.gt_u */
			case 0x33: /* i16x8.le_s */
			case 0x34: /* i16x8.le_u */
			case 0x35: /* i16x8.ge_s */
			case 0x36: /* i16x8.ge_u */
			case 0x37: /* i32x4.eq */
			case 0x38: /* i32x4.ne */
			case 0x39: /* i32x4.lt_s */
			case 0x3A: /* i32x4.lt_u */
			case 0x3B: /* i32x4.gt_s */
			case 0x3C: /* i32x4.gt_u */
			case 0x3D: /* i32x4.le_s */
			case 0x3E: /* i32x4.le_u */
			case 0x3F: /* i32x4.ge_s */
			case 0x40: /* i32x4.ge_u */
			case 0x41: /* f32x4.eq */
			case 0x42: /* f32x4.ne */
			case 0x43: /* f32x4.lt */
			case 0x44: /* f32x4.gt */
			case 0x45: /* f32x4.le */
			case 0x46: /* f32x4.ge */
			case 0x47: /* f64x2.eq */
			case 0x48: /* f64x2.ne */
			case 0x49: /* f64x2.lt */
			case 0x4A: /* f64x2.gt */
			case 0x4B: /* f64x2.le */
			case 0x4C: /* f64x2.ge */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x4D: /* v128.not */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x4E: /* v128.and */
			case 0x4F: /* v128.andnot */
			case 0x50: /* v128.or */
			case 0x51: /* v128.xor */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x52: /* v128.bitselect */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x53: /* v128.any_true */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x54: /* v128.load8_lane */
			case 0x55: /* v128.load16_lane */
			case 0x56: /* v128.load32_lane */
			case 0x57: /* v128.load64_lane */
				readLeb128(reader); /* align */
				readLeb128(reader); /* offset */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.i32);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x58: /* v128.store8_lane */
			case 0x59: /* v128.store16_lane */
			case 0x5A: /* v128.store32_lane */
			case 0x5B: /* v128.store64_lane */
				readLeb128(reader); /* align */
				readLeb128(reader); /* offset */
				reader.readNextByte(); /* laneidx */
				popValue(instAddress, ValType.v128);
				popValue(instAddress, ValType.i32);
				break;
			case 0x5C: /* v128.load32_zero */
			case 0x5D: /* v128.load64_zero */
				readLeb128(reader); /* align */
				readLeb128(reader); /* offset */
				popValue(instAddress, ValType.i32);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x5E: /* f32x4.demote_f64x2_zero */
			case 0x5F: /* f64x2.promote_low_f32x4 */
			case 0x60: /* i8x16.abs */
			case 0x61: /* i8x16.neg */
			case 0x62: /* i8x16.popcnt */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x63: /* i8x16.all_true */
			case 0x64: /* i8x16.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x65: /* i8x16.narrow_i16x8_s */
			case 0x66: /* i8x16.narrow_i16x8_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x67: /* f32x4.ceil */
			case 0x68: /* f32x4.floor */
			case 0x69: /* f32x4.trunc */
			case 0x6A: /* f32x4.nearest */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x6B: /* i8x16.shl */
			case 0x6C: /* i8x16.shr_s */
			case 0x6D: /* i8x16.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x6E: /* i8x16.add */
			case 0x6F: /* i8x16.add_sat_s */
			case 0x70: /* i8x16.add_sat_u */
			case 0x71: /* i8x16.sub */
			case 0x72: /* i8x16.sub_sat_s */
			case 0x73: /* i8x16.sub_sat_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x74: /* f64x2.ceil */
			case 0x75: /* f64x2.floor */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x76: /* i8x16.min_s */
			case 0x77: /* i8x16.min_u */
			case 0x78: /* i8x16.max_s */
			case 0x79: /* i8x16.max_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x7A: /* f64x2.trunc */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x7B: /* i8x16.avgr_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x7C: /* i16x8.extadd_pairwise_i8x16_s */
			case 0x7D: /* i16x8.extadd_pairwise_i8x16_u */
			case 0x7E: /* i32x4.extadd_pairwise_i16x8_s */
			case 0x7F: /* i32x4.extadd_pairwise_i16x8_u */
			case 0x80: /* i16x8.abs */
			case 0x81: /* i16x8.neg */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x82: /* i16x8.q15mulr_sat_s */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x83: /* i16x8.all_true */
			case 0x84: /* i16x8.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0x85: /* i16x8.narrow_i32x4_s */
			case 0x86: /* i16x8.narrow_i32x4_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x87: /* i16x8.extend_low_i8x16_s */
			case 0x88: /* i16x8.extend_high_i8x16_s */
			case 0x89: /* i16x8.extend_low_i8x16_u */
			case 0x8A: /* i16x8.extend_high_i8x16_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x8B: /* i16x8.shl */
			case 0x8C: /* i16x8.shr_s */
			case 0x8D: /* i16x8.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0x8E: /* i16x8.add */
			case 0x8F: /* i16x8.add_sat_s */
			case 0x90: /* i16x8.add_sat_u */
			case 0x91: /* i16x8.sub */
			case 0x92: /* i16x8.sub_sat_s */
			case 0x93: /* i16x8.sub_sat_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x94: /* f64x2.nearest */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0x95: /* i16x8.mul */
			case 0x96: /* i16x8.min_s */
			case 0x97: /* i16x8.min_u */
			case 0x98: /* i16x8.max_s */
			case 0x99: /* i16x8.max_u */
			case 0x9B: /* i16x8.avgr_u */
			case 0x9C: /* i16x8.extmul_low_i8x16_s */
			case 0x9D: /* i16x8.extmul_high_i8x16_s */
			case 0x9E: /* i16x8.extmul_low_i8x16_u */
			case 0x9F: /* i16x8.extmul_high_i8x16_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xA0: /* i32x4.abs */
			case 0xA1: /* i32x4.neg */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xA3: /* i32x4.all_true */
			case 0xA4: /* i32x4.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0xA7: /* i32x4.extend_low_i16x8_s */
			case 0xA8: /* i32x4.extend_high_i16x8_s */
			case 0xA9: /* i32x4.extend_low_i16x8_u */
			case 0xAA: /* i32x4.extend_high_i16x8_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xAB: /* i32x4.shl */
			case 0xAC: /* i32x4.shr_s */
			case 0xAD: /* i32x4.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0xAE: /* i32x4.add */
			case 0xB1: /* i32x4.sub */
			case 0xB5: /* i32x4.mul */
			case 0xB6: /* i32x4.min_s */
			case 0xB7: /* i32x4.min_u */
			case 0xB8: /* i32x4.max_s */
			case 0xB9: /* i32x4.max_u */
			case 0xBA: /* i32x4.dot_i16x8_s */
			case 0xBC: /* i32x4.extmul_low_i16x8_s */
			case 0xBD: /* i32x4.extmul_high_i16x8_s */
			case 0xBE: /* i32x4.extmul_low_i16x8_u */
			case 0xBF: /* i32x4.extmul_high_i16x8_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xC0: /* i64x2.abs */
			case 0xC1: /* i64x2.neg */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xC3: /* i64x2.all_true */
			case 0xC4: /* i64x2.bitmask */
				unaryOp(instAddress, ValType.v128, ValType.i32);
				break;
			case 0xC7: /* i64x2.extend_low_i32x4_s */
			case 0xC8: /* i64x2.extend_high_i32x4_s */
			case 0xC9: /* i64x2.extend_low_i32x4_u */
			case 0xCA: /* i64x2.extend_high_i32x4_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xCB: /* i64x2.shl */
			case 0xCC: /* i64x2.shr_s */
			case 0xCD: /* i64x2.shr_u */
				popValue(instAddress, ValType.i32);
				popValue(instAddress, ValType.v128);
				pushValue(instAddress, ValType.v128);
				break;
			case 0xCE: /* i64x2.add */
			case 0xD1: /* i64x2.sub */
			case 0xD5: /* i64x2.mul */
			case 0xD6: /* i64x2.eq */
			case 0xD7: /* i64x2.ne */
			case 0xD8: /* i64x2.lt_s */
			case 0xD9: /* i64x2.gt_s */
			case 0xDA: /* i64x2.le_s */
			case 0xDB: /* i64x2.ge_s */
			case 0xDC: /* i64x2.extmul_low_i32x4_s */
			case 0xDD: /* i64x2.extmul_high_i32x4_s */
			case 0xDE: /* i64x2.extmul_low_i32x4_u */
			case 0xDF: /* i64x2.extmul_high_i32x4_u */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xE0: /* f32x4.abs */
			case 0xE1: /* f32x4.neg */
			case 0xE3: /* f32x4.sqrt */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xE4: /* f32x4.add */
			case 0xE5: /* f32x4.sub */
			case 0xE6: /* f32x4.mul */
			case 0xE7: /* f32x4.div */
			case 0xE8: /* f32x4.min */
			case 0xE9: /* f32x4.max */
			case 0xEA: /* f32x4.pmin */
			case 0xEB: /* f32x4.pmax */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xEC: /* f64x2.abs */
			case 0xED: /* f64x2.neg */
			case 0xEF: /* f64x2.sqrt */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xF0: /* f64x2.add */
			case 0xF1: /* f64x2.sub */
			case 0xF2: /* f64x2.mul */
			case 0xF3: /* f64x2.div */
			case 0xF4: /* f64x2.min */
			case 0xF5: /* f64x2.max */
			case 0xF6: /* f64x2.pmin */
			case 0xF7: /* f64x2.pmax */
				binaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			case 0xF8: /* i32x4.trunc_sat_f32x4_s */
			case 0xF9: /* i32x4.trunc_sat_f32x4_u */
			case 0xFA: /* f32x4.convert_i32x4_s */
			case 0xFB: /* f32x4.convert_i32x4_u */
			case 0xFC: /* i32x4.trunc_sat_f64x2_s_zero */
			case 0xFD: /* i32x4.trunc_sat_f64x2_u_zero */
			case 0xFE: /* f64x2.convert_low_i32x4_s */
			case 0xFF: /* f64x2.convert_low_i32x4_u */
				unaryOp(instAddress, ValType.v128, ValType.v128);
				break;
			default:
				Msg.warn(this, "Illegal opcode 0xfd " + String.format("0x%02x", opcode2) + " at " + instAddress);
				break;
			}
			break;
		}
		default:
			Msg.warn(this, "Illegal opcode " + String.format("0x%02x", opcode) + " at " + instAddress);
			break;
		}
	}

	public void analyzeFunction(WasmAnalysis analysis, BinaryReader reader) throws IOException {
		Address startAddress = func.getStartAddr();
		long functionLength = func.getEndAddr().subtract(func.getStartAddr());

		// read the function locals
		Address instAddress;

		instAddress = startAddress.add(reader.getPointerIndex());
		contextreg.setLocalsDeclaration(instAddress);
		long count = readLeb128(reader);
		for (int i = 0; i < count; i++) {
			instAddress = startAddress.add(reader.getPointerIndex());
			contextreg.setLocalDeclaration(instAddress);
			readLeb128(reader); /* count */
			readLeb128(reader); /* type */
		}

		instAddress = startAddress.add(reader.getPointerIndex());
		pushBlock(instAddress, new ControlFrame(instAddress, new BlockType(func)));
		while (reader.getPointerIndex() <= functionLength) {
			instAddress = startAddress.add(reader.getPointerIndex());
			analyzeOpcode(analysis, instAddress, reader);
		}
	}

	public BigInteger getContext(Address address) {
		return contextreg.getContext(address);
	}

	public void applyContext(Program program, int cStackGlobal) {
		for (Map.Entry<Address, Long> entry : globalGetSets.entrySet()) {
			if (entry.getValue() == cStackGlobal) {
				contextreg.setIsGlobalSp(entry.getKey(), entry.getValue() == cStackGlobal);
			}
		}
		contextreg.commitContext(program);
	}
}
