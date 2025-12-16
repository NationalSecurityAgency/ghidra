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
package ghidra.app.util.bin.format.dwarf.expression;

import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFForm;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;

/**
 * Evaluates a {@link DWARFExpression}.
 * <p>
 * If an instruction needs a value in a register or memory location, the current {@link ValueReader}
 * callback will be called to fetch the value.  The default implementation is to throw an exception,
 * but future work may plug in a constant propagation callback. 
 */
public class DWARFExpressionEvaluator {

	/**
	 * Default limit for the number of execution steps to allow in an expression.
	 */
	private static final int DEFAULT_MAX_STEP_COUNT = 1000;

	public interface ValueReader {
		Object getValue(Varnode vn) throws DWARFExpressionValueException;

		ValueReader DUMMY = new ValueReader() {
			@Override
			public Object getValue(Varnode vn) throws DWARFExpressionValueException {
				throw new DWARFExpressionValueException(vn);
			}
		};

	}

	private final DWARFProgram dprog;
	private final DWARFCompilationUnit cu;
	private final Language lang;

	private ValueReader valReader = ValueReader.DUMMY;

	private int maxStepCount = DEFAULT_MAX_STEP_COUNT;

	private DWARFRegisterMappings registerMappings;

	/**
	 * The subprogram's DW_AT_frame_base value
	 */
	private Varnode frameBaseVal;

	private List<Object> stack = new ArrayList<>();

	private DWARFExpression expr;
	private DWARFExpressionInstruction instr;
	private int instrIndex = -1;
	private int stepCount = 0;

	public DWARFExpressionEvaluator(DWARFCompilationUnit cu) {
		this.cu = cu;
		this.dprog = cu.getProgram();
		this.registerMappings =
			Objects.requireNonNullElse(dprog.getRegisterMappings(), DWARFRegisterMappings.DUMMY);
		this.lang = dprog.getGhidraProgram().getLanguage();
	}

	public DWARFCompilationUnit getDWARFCompilationUnit() {
		return cu;
	}

	public DWARFExpression getExpr() {
		return expr;
	}

	public boolean isEmpty() {
		return stack.isEmpty();
	}

	public int getPtrSize() {
		return cu.getPointerSize();
	}

	public void setFrameBaseStackLocation(int offset) {
		this.frameBaseVal = newStackVarnode(offset, 0);
	}

	public void setFrameBaseVal(Varnode frameBaseVal) {
		this.frameBaseVal = frameBaseVal;
	}

	public void setValReader(ValueReader valReader) {
		this.valReader = valReader;
	}

	public ValueReader withStaticStackRegisterValues(Integer stackOffset,
			Integer stackFrameOffset) {
		return new ValueReader() {
			@Override
			public Varnode getValue(Varnode vn) throws DWARFExpressionValueException {
				Register reg;
				if (vn.isRegister() && (reg = lang.getRegister(vn.getAddress(), 0)) != null) {
					if (reg == registerMappings.getStackFrameRegister() &&
						stackFrameOffset != null) {
						return newStackVarnode(stackFrameOffset, 0);
					}
					if (reg == registerMappings.getStackRegister() && stackOffset != null) {
						return newStackVarnode(stackOffset, 0);
					}
				}
				throw new DWARFExpressionValueException(vn);
			}
		};
	}

	public int getMaxStepCount() {
		return maxStepCount;
	}

	public void setMaxStepCount(int maxStepCount) {
		this.maxStepCount = maxStepCount;
	}

	public void push(Address addr) {
		push(new Varnode(addr, 0));
	}

	public void push(Register reg) {
		push(new Varnode(reg.getAddress(), reg.getMinimumByteSize()));
	}

	public void push(boolean b) {
		push(b ? 1L : 0L);
	}

	public void push(long l) {
		push(new Scalar(getPtrSize() * 8, l));
	}

	public void push(Object val) {
		stack.addLast(val);
	}

	/**
	 * Peek at the top value of the stack.
	 * 
	 * @return top value of the stack
	 * @throws DWARFExpressionException if stack is empty
	 */
	public Object peek() throws DWARFExpressionException {
		if (stack.isEmpty()) {
			throw new DWARFExpressionException("DWARF expression stack empty");
		}
		return stack.getLast();
	}

	/**
	 * Pop the top value off the stack.
	 * 
	 * @return top value of the stack
	 * @throws DWARFExpressionException if stack is empty
	 */
	public Object pop() throws DWARFExpressionException {
		if (stack.isEmpty()) {
			throw new DWARFExpressionException("DWARF expression stack empty");
		}
		return stack.removeLast();
	}

	/**
	 * Pop the top value off the stack, and coerce it into a scalar.
	 * 
	 * @return top value of the stack, as a scalar 
	 * @throws DWARFExpressionException if stack is empty or value can not be used as a scalar
	 */
	public Scalar popScalar() throws DWARFExpressionException {
		return stackValueToScalar(pop());
	}

	private Scalar stackValueToScalar(Object val) throws DWARFExpressionException {
		switch (val) {
			case Scalar s:
				return s;
			case Varnode varnode:
				if (varnode.isRegister()) {
					// try to deref the register and hopefully get a const varnode
					return stackValueToScalar(valReader.getValue(varnode));
				}
				if (DWARFUtil.isConstVarnode(varnode)) {
					return new Scalar(varnode.getSize() * 8, varnode.getOffset());
				}
				// fall thru, throw exception
			default:
		}
		throw new DWARFExpressionException(
			"Unable to convert stack value to scalar: %s".formatted(val));
	}

	/**
	 * Pop the top value off the stack, and coerce it into a varnode.
	 * 
	 * @return top value of the stack, as a varnode
	 * @throws DWARFExpressionException if stack is empty or value can not be used as a varnode
	 */
	public Varnode popVarnode() throws DWARFExpressionException {
		Object tmp = pop();
		return switch (tmp) {
			case Scalar s when s.bitLength() == cu.getPointerSize() * 8 -> newAddrVarnode(
				s.getUnsignedValue());
			case Varnode varnode -> varnode;
			default -> throw new DWARFExpressionException(
				"Unable to convert DWARF expression stack value %s to address".formatted(tmp));
		};
	}

	/**
	 * Pop the top value off the stack, and coerce it into a scalar long.
	 * 
	 * @return top value of the stack, as a scalar long
	 * @throws DWARFExpressionException if stack is empty or value can not be used as a long
	 */
	public long popLong() throws DWARFExpressionException {
		Scalar s = popScalar();
		return s.getValue();
	}

	/**
	 * Executes the instructions found in the expression.
	 * 
	 * @param exprBytes raw bytes of the expression
	 * @throws DWARFExpressionException if error
	 */
	public void evaluate(byte[] exprBytes) throws DWARFExpressionException {
		evaluate(DWARFExpression.read(exprBytes, cu));
	}

	/**
	 * Executes the instructions found in the expression.
	 * 
	 * @param exprBytes raw bytes of the expression
	 * @param stackArgs any values to push onto the stack before execution
	 * @throws DWARFExpressionException if error
	 */
	public void evaluate(byte[] exprBytes, long... stackArgs) throws DWARFExpressionException {
		evaluate(DWARFExpression.read(exprBytes, cu), stackArgs);
	}

	/**
	 * Sets the current expression.
	 * 
	 * @param expr {@link DWARFExpression}
	 */
	public void setExpression(DWARFExpression expr) {
		this.expr = expr;
		instr = null;
		instrIndex = 0;
		stepCount = 0;
	}

	/**
	 * {@return true if there are instructions that can be evaluated}
	 */
	public boolean hasNext() {
		return instrIndex < expr.getInstructionCount();
	}

	/**
	 * Evaluates the next instruction in the expression.
	 * 
	 * @return true if there are more instructions
	 * @throws DWARFExpressionException if error
	 */
	public boolean step() throws DWARFExpressionException {
		if (hasNext()) {
			try {
				evaluateInstruction(expr.getInstruction(instrIndex));
				instrIndex++;
				stepCount++;
			}
			catch (DWARFExpressionException dee) {
				if (dee.getExpression() == null) {
					dee.setExpression(expr);
					dee.setInstructionIndex(instrIndex);
				}
				throw dee;
			}
		}

		return hasNext();
	}

	/**
	 * Executes the instructions found in the expression.
	 * 
	 * @param expr {@link DWARFException} to evaluate
	 * @param stackArgs - pushed 0..N, so stackArgs[0] will be deepest, stackArgs[N] will be topmost.
	 * @throws DWARFExpressionException if error
	 */
	public void evaluate(DWARFExpression expr, long... stackArgs)
			throws DWARFExpressionException {
		for (long l : stackArgs) {
			push(l);
		}
		evaluate(expr);
	}

	public void evaluate(DWARFExpression expr) throws DWARFExpressionException {
		setExpression(expr);
		while (hasNext()) {
			if (stepCount >= maxStepCount) {
				throw new DWARFExpressionException(
					"Excessive expression run length, terminating after %d operations"
							.formatted(stepCount));
			}
			if (Thread.currentThread().isInterrupted()) {
				throw new DWARFExpressionException(
					"Thread interrupted while evaluating DWARF expression, terminating after %d operations"
							.formatted(stepCount));
			}
			step();
		}
	}

	private Register getReg(int dwarfRegNum) throws DWARFExpressionException {
		Register reg = registerMappings.getGhidraReg(dwarfRegNum);
		if (reg == null) {
			throw new DWARFExpressionException(
				"Unknown/unmapped DWARF register: %d".formatted(dwarfRegNum));
		}
		return reg;
	}

	private void evaluateInstruction(DWARFExpressionInstruction _instr)
			throws DWARFExpressionException {
		this.instr = _instr;
		if (DWARFExpressionOpCode.isInRange(instr.opcode, DW_OP_lit0, DW_OP_lit31)) {
			push(instr.opcode.getRelativeOpCodeOffset(DW_OP_lit0));
		}
		else if (DWARFExpressionOpCode.isInRange(instr.opcode, DW_OP_breg0, DW_OP_breg31)) {
			// Retrieve address held in register X and add offset from operand0 and push result on stack.
			Register register = getReg(instr.opcode.getRelativeOpCodeOffset(DW_OP_breg0));
			long offset = instr.getOperandValue(0);
			Object regVal = valReader.getValue(newRegisterVarnode(register));
			if (regVal instanceof Varnode regVN &&
				(DWARFUtil.isStackVarnode(regVN) || regVN.isConstant())) {
				push(new Varnode(regVN.getAddress().add(offset), 0));
			}
			else if (regVal instanceof Scalar s) {
				push(s.getValue() + offset);
			}
			else {
				throw new DWARFExpressionException("Unable to deref register value " + regVal);
			}
		}
		else if (DWARFExpressionOpCode.isInRange(instr.opcode, DW_OP_reg0, DW_OP_reg31)) {
			Register register = getReg(instr.opcode.getRelativeOpCodeOffset(DW_OP_reg0));
			Object regVal = valReader.getValue(newRegisterVarnode(register));
			push(regVal);
		}
		else {
			switch (instr.opcode) {
				case DW_OP_addr:
					push(dprog.getDataAddress(instr.getOperandValue(0)));
					break;

				case DW_OP_const1u:
				case DW_OP_const2u:
				case DW_OP_const4u:
				case DW_OP_const8u:
				case DW_OP_const1s:
				case DW_OP_const2s:
				case DW_OP_const4s:
				case DW_OP_const8s:
				case DW_OP_constu:
				case DW_OP_consts:
					push(instr.getOperandValue(0));
					break;

				// Register Based Addressing
				case DW_OP_regx:
					Register register = getReg((int) instr.getOperandValue(0));
					push(register);
					break;
				case DW_OP_fbreg: {
					if (frameBaseVal == null) {
						throw new DWARFExpressionException(
							"Frame base has not been set, DW_OP_fbreg can not be evaluated");
					}
					long fbOffset = instr.getOperandValue(0);
					push(new Varnode(frameBaseVal.getAddress().add(fbOffset), 0));
				}
				// Stack Operations
				case DW_OP_dup:
					push(peek());
					break;
				case DW_OP_drop:
					pop();
					break;
				case DW_OP_pick: {
					int index = (int) instr.getOperandValue(0);
					if (index >= stack.size()) {
						throw new DWARFExpressionException(
							"Invalid index for DW_OP_pick: " + index);
					}
					Object elem = stack.get(stack.size() - index - 1);
					push(elem);
					break;
				}
				case DW_OP_over: {
					if (stack.size() < 2) {
						throw new DWARFExpressionException(
							"Not enough items on stack[size=%d] for DW_OP_over"
									.formatted(stack.size()));
					}
					push(stack.get(stack.size() - 2));
					break;
				}
				case DW_OP_swap: {
					Object firstValue = pop();
					Object secondValue = pop();
					push(firstValue);
					push(secondValue);
					break;
				}
				case DW_OP_rot: {
					Object firstValue = pop();
					Object secondValue = pop();
					Object thirdValue = pop();
					push(firstValue);
					push(thirdValue);
					push(secondValue);
					break;
				}
				case DW_OP_deref: {
					// Treat top stack value as a location, deref it and fetch a ptrSize'd value
					// and push it on stack

					if (instrIndex == expr.getInstructionCount() - 1) {
						// If this was the last instruction, throw a special exception that lets
						// the caller figure out what happened and accommodate this in some 
						// situations.
						// TODO: trailing NOPs were skipped when checking this condition previously... dunno if needed for real
						Varnode location = popVarnode();
						throw new DWARFExpressionTerminalDerefException(instr, location);
					}
					throw new DWARFExpressionUnsupportedOpException(instr);
				}

				case DW_OP_call_frame_cfa: {
					if (!registerMappings.hasStaticCFA()) {
						throw new DWARFExpressionException(
							"CFA not specified in DWARF register mappings for this arch");
					}
					push(newStackVarnode(registerMappings.getCallFrameCFA(), 0));
					break;
				}

				// Arithmetic and Logical Operations
				case DW_OP_abs: {
					Scalar val = popScalar();
					Scalar absVal = new Scalar(val.bitLength(), Math.abs(val.getSignedValue()));
					push(absVal);
					break;
				}
				case DW_OP_and: {// bitwise and
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = firstValue.getUnsignedValue() & secondValue.getUnsignedValue();
					int bitCount = Math.max(firstValue.bitLength(), secondValue.bitLength());
					push(new Scalar(bitCount, tmp));
					break;
				}
				case DW_OP_div: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					if (firstValue.getValue() == 0) {
						throw new DWARFExpressionException("Divide by zero");
					}
					long tmp = secondValue.getValue() / firstValue.getValue();
					push(new Scalar(secondValue.bitLength(), tmp));
					break;
				}
				case DW_OP_minus: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() - firstValue.getValue();
					int bitCount = Math.max(firstValue.bitLength(), secondValue.bitLength());
					push(new Scalar(bitCount, tmp));
					break;
				}
				case DW_OP_mod: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					if (firstValue.getValue() == 0) {
						throw new DWARFExpressionException("Divide by zero");
					}
					long tmp = secondValue.getValue() % firstValue.getValue();
					push(new Scalar(secondValue.bitLength(), tmp));
					break;
				}
				case DW_OP_mul: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() * firstValue.getValue();
					int bitCount = Math.max(firstValue.bitLength(), secondValue.bitLength());
					push(new Scalar(bitCount, tmp));
					break;
				}
				case DW_OP_neg: {
					Scalar firstValue = popScalar();
					long tmp = -firstValue.getSignedValue();
					push(new Scalar(firstValue.bitLength(), tmp));
					break;
				}
				case DW_OP_not: {// bitwise neg
					Scalar firstValue = popScalar();
					long tmp = ~firstValue.getValue();
					push(new Scalar(firstValue.bitLength(), tmp));
					break;
				}
				case DW_OP_or: {// bitwise or
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() | firstValue.getValue();
					int bitCount = Math.max(firstValue.bitLength(), secondValue.bitLength());
					push(new Scalar(bitCount, tmp));
					break;
				}
				case DW_OP_plus: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() + firstValue.getValue();
					int bitCount = Math.max(firstValue.bitLength(), secondValue.bitLength());
					push(new Scalar(bitCount, tmp));
					break;
				}
				case DW_OP_plus_uconst: {
					Scalar firstValue = popScalar();
					long opValue = instr.getOperandValue(0);
					long tmp = firstValue.getValue() + opValue;
					push(new Scalar(firstValue.bitLength(), tmp));
					break;
				}
				case DW_OP_shl: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() << firstValue.getValue();
					push(new Scalar(secondValue.bitLength(), tmp));
					break;
				}
				case DW_OP_shr: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() >>> firstValue.getValue();
					push(new Scalar(secondValue.bitLength(), tmp));
					break;
				}
				case DW_OP_shra: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() >> firstValue.getValue();
					push(new Scalar(secondValue.bitLength(), tmp));
					break;
				}
				case DW_OP_xor: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					long tmp = secondValue.getValue() ^ firstValue.getValue();
					int bitCount = Math.max(firstValue.bitLength(), secondValue.bitLength());
					push(new Scalar(bitCount, tmp));
					break;
				}
				// Control Flow Operations, values treated as signed for comparison
				case DW_OP_le: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					push(secondValue.getSignedValue() <= firstValue.getSignedValue());
					break;
				}
				case DW_OP_ge: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					push(secondValue.getSignedValue() >= firstValue.getSignedValue());
					break;
				}
				case DW_OP_eq: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					push(secondValue.getValue() == firstValue.getValue());
					break;
				}
				case DW_OP_lt: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					push(secondValue.getSignedValue() < firstValue.getSignedValue());
					break;
				}
				case DW_OP_gt: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					push(secondValue.getSignedValue() > firstValue.getSignedValue());
					break;
				}
				case DW_OP_ne: {
					Scalar firstValue = popScalar();
					Scalar secondValue = popScalar();
					push(secondValue.getSignedValue() != firstValue.getSignedValue());
					break;
				}
				case DW_OP_skip: {
					long destOffset = instr.getOperandValue(0) + instr.getOffset();
					int newInstrIndex = expr.findInstructionByOffset(destOffset);
					if (newInstrIndex == -1) {
						throw new DWARFExpressionException("Invalid skip offset " + destOffset);
					}
					instrIndex = newInstrIndex - 1;// 1 before the target op index because the for() loop will ++ the index value
					break;
				}
				case DW_OP_bra: {
					long destOffset = instr.getOperandValue(0) + instr.getOffset();
					Scalar firstValue = popScalar();
					if (firstValue.getValue() != 0) {
						int newInstrIndex = expr.findInstructionByOffset(destOffset);
						if (newInstrIndex == -1) {
							throw new DWARFExpressionException("Invalid bra offset " + destOffset);
						}
						instrIndex = newInstrIndex - 1;// 1 before the target op index because the for() loop will ++ the index value
					}
					break;
				}

				// Special Operations
				case DW_OP_nop: {
					break;
				}
				case DW_OP_stack_value:
					// This op is a flag to the debugger that the requested value does not exist in memory
					// (on the host) but that the result of this expression gives you the value
					throw new DWARFExpressionUnsupportedOpException(instr);
				case DW_OP_addrx:
					try {
						long addr = dprog.getAddress(DWARFForm.DW_FORM_addrx,
							instr.getOperandValue(0), cu);
						push(addr);
						break;
					}
					catch (IOException e) {
						throw new DWARFExpressionException(
							"Invalid indirect address index: " + instr.getOperandValue(0));
					}
				case DW_OP_constx: // same as addrx, but different relocation-able specifications
					try {
						long addr = dprog.getAddress(DWARFForm.DW_FORM_addrx,
							instr.getOperandValue(0), cu);
						push(addr);
						break;
					}
					catch (IOException e) {
						throw new DWARFExpressionException(
							"Invalid indirect address index: " + instr.getOperandValue(0));
					}

				default:
					throw new DWARFExpressionUnsupportedOpException(instr);

			}
		}
	}

	private Varnode newStackVarnode(long offset, int size) {
		return new Varnode(dprog.getStackSpace().getAddress(offset), size);
	}

	private Varnode newRegisterVarnode(Register reg) {
		return new Varnode(reg.getAddress(), reg.getMinimumByteSize());
	}

	private Varnode newAddrVarnode(long l) {
		return new Varnode(dprog.getDataAddress(l), cu.getPointerSize());
	}

	@Override
	public String toString() {
		return """
				DWARFExpressionEvaluator
				  frameBaseVal = %s
				  stepCount = %d
				  status: %s

				Stack:
				%s
				Instructions:
				%s
				""".formatted( //
			frameBaseVal != null ? frameBaseVal.toString() : "not set",
			stepCount,
			getStatusString(),
			getStackAsString().indent(2),
			expr != null
					? expr.toString(instrIndex, true, true, dprog.getRegisterMappings()).indent(2)
					: "  no expr");
	}

	private String getStackAsString() {
		StringBuilder sb = new StringBuilder();

		int stackindex = 0;
		for (Object stackVal : stack.reversed()) {
			sb.append("%3d: %s\n".formatted(stackindex, stackVal));
			stackindex++;
		}
		return sb.toString();
	}

	private String getStatusString() {
		if (instrIndex == -1) {
			return "Not started";
		}
		else if (expr != null && instrIndex == expr.getInstructionCount()) {
			return "Finished";
		}
		return "Running";
	}


}
