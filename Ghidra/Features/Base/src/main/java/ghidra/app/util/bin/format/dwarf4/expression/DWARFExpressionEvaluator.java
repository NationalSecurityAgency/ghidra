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
package ghidra.app.util.bin.format.dwarf4.expression;

import static ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionOpCodes.*;

import java.util.ArrayDeque;

import ghidra.app.util.bin.format.dwarf4.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf4.DebugInfoEntry;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.dwarf4.next.DWARFRegisterMappings;
import ghidra.program.model.lang.Register;

/**
 * Evaluates a subset of DWARF expression opcodes.
 * <p>
 * Limitations:<p>
 * Can not access memory during evaluation of expressions.<br>
 * Some opcodes must be the last operation in the expression (deref, regX)<br>
 * Can only specify offset from register for framebase and stack relative<br>
 * <p>
 * Result can be a numeric value (ie. static address) or a register 'name' or a stack based offset.
 * <p>
 */
public class DWARFExpressionEvaluator {

	/**
	 * Default limit for the number of execution steps to allow in an expression.
	 */
	private static final int DEFAULT_MAX_STEP_COUNT = 1000;

	private final int dwarfFormat;

	private int maxStepCount = DEFAULT_MAX_STEP_COUNT;

	/**
	 * Mirror of {@link DWARFCompilationUnit#getPointerSize()}
	 */
	private final byte pointerSize;

	/**
	 * Mirror of {@link DWARFProgram#isLittleEndian()}
	 */
	private final boolean isLittleEndian;

	private DWARFRegisterMappings registerMappings;

	/**
	 * The subprogram's DW_AT_frame_base value
	 */
	private long frameOffset = -1;
	private int lastRegister = -1;
	/**
	 * The value at the top of the stack is a framebase offset
	 */
	private boolean lastStackRelative;

	/**
	 * Indicates that the result of the expression is held in register {@link #lastRegister}
	 */
	private boolean registerLoc;

	/**
	 * Indicates that the result of the expression is pointed to by the value in
	 * register {{@link #lastRegister} (ie. lastRegister is a pointer to the result)
	*/
	private boolean isDeref;

	private boolean dwarfStackValue;// true if dwarf says that value does not exist in memory
	private boolean useUnknownRegister;
	private ArrayDeque<Long> stack = new ArrayDeque<Long>();

	private DWARFExpression expr;
	private DWARFExpressionOperation currentOp;
	private int currentOpIndex = -1;

	public static DWARFExpressionEvaluator create(DebugInfoEntry die) {
		DWARFCompilationUnit compUnit = die.getCompilationUnit();
		DWARFProgram prog = die.getCompilationUnit().getProgram();
		DWARFExpressionEvaluator evaluator = new DWARFExpressionEvaluator(compUnit.getPointerSize(),
			!prog.isBigEndian(), compUnit.getFormat(), prog.getRegisterMappings());

		return evaluator;
	}

	public DWARFExpressionEvaluator(byte pointerSize, boolean isLittleEndian, int dwarfFormat,
			DWARFRegisterMappings registerMappings) {
		this.pointerSize = pointerSize;
		this.isLittleEndian = isLittleEndian;
		this.dwarfFormat = dwarfFormat;
		this.registerMappings = registerMappings;
	}

	public void setFrameBase(long fb) {
		this.frameOffset = fb;
	}

	public void push(long l) {
		stack.push(l);
		lastRegister = -1;
		lastStackRelative = false;
		registerLoc = false;
	}

	public long peek() throws DWARFExpressionException {
		if (stack.isEmpty()) {
			throw new DWARFExpressionException("DWARF expression stack empty");
		}
		return stack.peek().longValue();
	}

	public long pop() throws DWARFExpressionException {
		if (stack.isEmpty()) {
			throw new DWARFExpressionException("DWARF expression stack empty");
		}
		return stack.pop().longValue();
	}

	/**
	 * Returns the {@link Register register} that holds the contents of the object that the
	 * {@link DWARFExpression expression} points to.
	 * <p>
	 * Note, you should check {@link #isDeref()} to see if the register is just a pointer
	 * to the object instead of the object itself.
	 * <p>
	 * @return
	 */
	public Register getTerminalRegister() {
		return registerMappings.getGhidraReg(lastRegister);
	}

	public boolean isDeref() {
		return isDeref;
	}

	public DWARFExpression readExpr(byte[] exprBytes) throws DWARFExpressionException {
		DWARFExpression tmp =
			DWARFExpression.read(exprBytes, pointerSize, isLittleEndian, dwarfFormat);
		return tmp;
	}

	public DWARFExpressionResult evaluate(byte[] exprBytes) throws DWARFExpressionException {
		return evaluate(readExpr(exprBytes));
	}

	/**
	 * @param _expr
	 * @param stackArgs - pushed 0..N, so stackArgs[0] will be deepest, stackArgs[N] will be topmost.
	 * @return
	 * @throws DWARFExpressionException
	 */
	public DWARFExpressionResult evaluate(DWARFExpression _expr, long... stackArgs)
			throws DWARFExpressionException {
		for (long l : stackArgs) {
			push(l);
		}
		return evaluate(_expr);
	}

	public DWARFExpressionResult evaluate(DWARFExpression _expr) throws DWARFExpressionException {
		this.expr = _expr;
		currentOp = null;
		int stepCount = 0;
		for (currentOpIndex =
			0; currentOpIndex < expr.getOpCount(); currentOpIndex++, stepCount++) {
			currentOp = expr.getOp(currentOpIndex);

			try {
				if (stepCount >= maxStepCount) {
					throw new DWARFExpressionException(
						"Excessive expression run length, terminating after " + stepCount +
							" operations");
				}
				if (Thread.currentThread().isInterrupted()) {
					throw new DWARFExpressionException(
						"Thread interrupted while evaluating DWARF expression, terminating after " +
							stepCount + " operations");
				}

				_preValidateCurrentOp();
				_evaluateCurrentOp();
			}
			catch (DWARFExpressionException dee) {
				if (dee.getExpression() == null) {
					dee.setExpression(expr);
					dee.setStep(currentOpIndex);
				}
				throw dee;
			}
		}

		return new DWARFExpressionResult(stack);
	}

	public String getStackAsString() {
		StringBuilder sb = new StringBuilder();

		int stackindex = 0;
		for (Long stackElement : stack) {
			sb.append(String.format("%3d: [%08x]  %d\n", stackindex, stackElement, stackElement));
			stackindex++;
		}
		return sb.toString();
	}

	private void _preValidateCurrentOp() throws DWARFExpressionException {
		// throw a DWARFExpressionException if op not valid in this context
		int opcode = currentOp.getOpCode();
		boolean isLastOperation = (currentOpIndex == expr.getLastActiveOpIndex());

		switch (opcode) {
			case DW_OP_fbreg:
				if (frameOffset == -1) {
					throw new DWARFExpressionException(
						"Frame base has not been set, DW_OP_fbreg can not be evaluated");
				}
				break;
			case DW_OP_deref:
				if (!(registerLoc || lastStackRelative)) {
					throw new DWARFExpressionException(
						"Can not evaluate DW_OP_deref for non-register location");
				}
				if (!isLastOperation) {
					throw new DWARFExpressionException(
						"Non-terminal DW_OP_deref can't be evaluated");
				}

				break;
			default:
				if (((opcode >= DW_OP_reg0 && opcode <= DW_OP_reg31) || (opcode == DW_OP_regx)) &&
					(!isLastOperation)) {
					throw new DWARFExpressionException(
						"Non-terminal DW_OP_reg? can't be evaluated");
				}
		}

	}

	private void _evaluateCurrentOp() throws DWARFExpressionException {
		int opcode = currentOp.getOpCode();
		if (DWARFExpressionOpCodes.UNSUPPORTED_OPCODES.contains(opcode)) {
			throw new DWARFExpressionException(
				"Can not evaluate unsupported opcode " + DWARFExpressionOpCodes.toString(opcode));
		}

		if (opcode >= DW_OP_lit0 && opcode <= DW_OP_lit31) {
			push(currentOp.getRelativeOpCodeOffset(DW_OP_lit0));
		}
		else if (opcode >= DW_OP_breg0 && opcode <= DW_OP_breg31) {
			// Retrieve value held in register X and add offset from operand and push result on stack.
			// Fake it using zero as register value.
			// Mainly only useful if offset is zero or if non-zero the register happens to
			// be the the stack pointer.
			long offset = currentOp.getOperandValue(0);
			push(0 /*fake register value */ + offset);
			lastRegister = currentOp.getRelativeOpCodeOffset(DW_OP_breg0);

			if (lastRegister == registerMappings.getDWARFStackPointerRegNum()) {
				lastStackRelative = true;
			}
			else {
				useUnknownRegister = true;
				if (offset == 0) {
					registerLoc = true;
				}
			}

		}
		else if (opcode >= DW_OP_reg0 && opcode <= DW_OP_reg31) {
			push(0);// TODO: not sure why we are pushing a zero on stack, not part of DWARF std.
			lastRegister = currentOp.getRelativeOpCodeOffset(DW_OP_reg0);
			registerLoc = true;
		}
		else if (opcode == DW_OP_regx) {
			push(0);// TODO: not sure why we are pushing a zero on stack, not part of DWARF std.
			lastRegister = (int) currentOp.getOperandValue(0);
			registerLoc = true;
		}
		else {
			switch (opcode) {
				case DW_OP_addr:
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
					push(currentOp.getOperandValue(0));
					break;
				// Register Based Addressing
				case DW_OP_fbreg:
					push(frameOffset + currentOp.getOperandValue(0));
					lastStackRelative = true;
					break;
				// Stack Operations
				case DW_OP_dup:
					push(peek());
					break;
				case DW_OP_drop:
					pop();
					break;
				case DW_OP_pick: {
					long index = currentOp.getOperandValue(0);
					if (index >= stack.size()) {
						throw new DWARFExpressionException(
							"Invalid index for DW_OP_pick: " + index);
					}
					dw_op_pick((int) index);

					break;
				}
				case DW_OP_over: {
					if (stack.size() < 2) {
						throw new DWARFExpressionException(
							"Not enough items on stack[size=" + stack.size() + "] for DW_OP_over");
					}
					dw_op_pick(1);

					break;
				}
				case DW_OP_swap: {
					long firstValue = pop();
					long secondValue = pop();
					push(firstValue);
					push(secondValue);
					break;
				}
				case DW_OP_rot: {
					long firstValue = pop();
					long secondValue = pop();
					long thirdValue = pop();
					push(firstValue);
					push(thirdValue);
					push(secondValue);
					break;
				}
				case DW_OP_deref: {
					isDeref = true;
					// Real deref should pop the top value from stack, deref it,
					// and push value found at that address on stack.
					// Since we can only handle the subset of deref usages that are
					// register or framebased, leave the stack alone so that the
					// register or framebase offset can be accessed.
					break;
				}

				case DW_OP_call_frame_cfa: {
					push(registerMappings.getCallFrameCFA());
					break;
				}

					// Arithmetic and Logical Operations
				case DW_OP_abs: {
					push(Math.abs(pop()));
					break;
				}
				case DW_OP_and: {// bitwise and
					long firstValue = pop();
					long secondValue = pop();
					push(firstValue & secondValue);
					break;
				}
				case DW_OP_div: {
					long firstValue = pop();
					long secondValue = pop();
					if (firstValue == 0) {
						throw new DWARFExpressionException("Divide by zero");
					}
					push(secondValue / firstValue);
					break;
				}
				case DW_OP_minus: {
					long firstValue = pop();
					long secondValue = pop();
					push(secondValue - firstValue);
					break;
				}
				case DW_OP_mod: {
					long firstValue = pop();
					long secondValue = pop();
					if (firstValue == 0) {
						throw new DWARFExpressionException("Divide by zero");
					}
					push(secondValue % firstValue);
					break;
				}
				case DW_OP_mul: {
					long firstValue = pop();
					long secondValue = pop();
					push(firstValue * secondValue);
					break;
				}
				case DW_OP_neg: {
					long firstValue = pop();
					push(-firstValue);
					break;
				}
				case DW_OP_not: {// bitwise neg
					long firstValue = pop();
					push(~firstValue);
					break;
				}
				case DW_OP_or: {// bitwise or
					long firstValue = pop();
					long secondValue = pop();
					push(firstValue | secondValue);
					break;
				}
				case DW_OP_plus: {
					long firstValue = pop();
					long secondValue = pop();
					push(firstValue + secondValue);
					break;
				}
				case DW_OP_plus_uconst: {
					long firstValue = pop();
					long value = currentOp.getOperandValue(0);
					push(firstValue + value);
					break;
				}
				case DW_OP_shl: {
					long firstValue = pop();
					long secondValue = pop();
					push(secondValue << firstValue);
					break;
				}
				case DW_OP_shr: {
					long firstValue = pop();
					long secondValue = pop();
					push(secondValue >>> firstValue);
					break;
				}
				case DW_OP_shra: {
					long firstValue = pop();
					long secondValue = pop();
					push(secondValue >> firstValue);
					break;
				}
				case DW_OP_xor: {
					long firstValue = pop();
					long secondValue = pop();
					push(firstValue ^ secondValue);
					break;
				}
					// Control Flow Operations, values treated as signed for comparison
				case DW_OP_le: {
					long firstValue = pop();
					long secondValue = pop();
					push((secondValue <= firstValue) ? 1L : 0L);
					break;
				}
				case DW_OP_ge: {
					long firstValue = pop();
					long secondValue = pop();
					push((secondValue >= firstValue) ? 1L : 0L);
					break;
				}
				case DW_OP_eq: {
					long firstValue = pop();
					long secondValue = pop();
					push((secondValue == firstValue) ? 1L : 0L);
					break;
				}
				case DW_OP_lt: {
					long firstValue = pop();
					long secondValue = pop();
					push((secondValue < firstValue) ? 1L : 0L);
					break;
				}
				case DW_OP_gt: {
					long firstValue = pop();
					long secondValue = pop();
					push((secondValue > firstValue) ? 1L : 0L);
					break;
				}
				case DW_OP_ne: {
					long firstValue = pop();
					long secondValue = pop();
					push((secondValue != firstValue) ? 1L : 0L);
					break;
				}
				case DW_OP_skip: {
					long destOffset = currentOp.getOperandValue(0) + currentOp.getOffset();
					int newStep = expr.findOpByOffset(destOffset);
					if (newStep == -1) {
						throw new DWARFExpressionException("Invalid skip offset " + destOffset);
					}
					currentOpIndex = newStep - 1;// 1 before the target op index because the for() loop will ++ the index value
					break;
				}
				case DW_OP_bra: {
					long destOffset = currentOp.getOperandValue(0) + currentOp.getOffset();
					long firstValue = pop();
					if (firstValue != 0) {
						int newStep = expr.findOpByOffset(destOffset);
						if (newStep == -1) {
							throw new DWARFExpressionException("Invalid bra offset " + destOffset);
						}
						currentOpIndex = newStep - 1;// 1 before the target op index because the for() loop will ++ the index value
					}
					break;
				}

					// Special Operations
				case DW_OP_nop: {
					break;
				}
				case DW_OP_stack_value:
					// This op is a flag to the debugger that the requested value does not exist in memory
					// (on the host) but that the result of this expression gives you value
					dwarfStackValue = true;
					break;
				default:
					throw new DWARFExpressionException("Unimplemented DWARF expression opcode " +
						DWARFExpressionOpCodes.toString(opcode));
			}
		}
	}

	private void dw_op_pick(int index) {
		int stackindex = 0;
		for (Long stackElement : stack) {
			if (stackindex == index) {
				push(stackElement);
				break;
			}
			stackindex++;
		}
	}

	@Override
	public String toString() {
		return "DWARFExpressionEvaluator [pointerSize=" + pointerSize + ", isLittleEndian=" +
			isLittleEndian + ", frameOffset=" + frameOffset + ", lastRegister=" + lastRegister +
			", lastStackRelative=" + lastStackRelative + ", registerLoc=" + registerLoc +
			", isDeref=" + isDeref + ", dwarfStackValue=" + dwarfStackValue +
			", useUnknownRegister=" + useUnknownRegister + "]\nStack:\n" + getStackAsString() +
			"\n" + (expr != null ? expr.toString(currentOpIndex, true, true) : "no expr");
	}

	public int getMaxStepCount() {
		return maxStepCount;
	}

	public void setMaxStepCount(int maxStepCount) {
		this.maxStepCount = maxStepCount;
	}

	public boolean isDwarfStackValue() {
		return this.dwarfStackValue;
	}

	public boolean useUnknownRegister() {
		return useUnknownRegister;
	}

	public boolean isRegisterLocation() {
		return registerLoc;
	}

	public Register getLastRegister() {
		return registerMappings.getGhidraReg(lastRegister);
	}

	public int getRawLastRegister() {
		return lastRegister;
	}

	public boolean isStackRelative() {
		return lastStackRelative;
	}

}
