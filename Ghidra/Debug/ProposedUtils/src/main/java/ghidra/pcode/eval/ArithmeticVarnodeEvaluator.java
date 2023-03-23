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
package ghidra.pcode.eval;

import java.util.Map;

import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An abstract implementation of {@link VarnodeEvaluator} that evaluates ops using a bound
 * {@link PcodeArithmetic}.
 * 
 * @param <T> the type of values resulting from evaluation
 */
public abstract class ArithmeticVarnodeEvaluator<T> extends AbstractVarnodeEvaluator<T> {
	/**
	 * A convenience for concatenating two varnodes
	 * 
	 * <p>
	 * There is no p-code op for catenation, but it is easily achieved as one might do in C or
	 * SLEIGH: {@code shift} the left piece then {@code or} it with the right piece.
	 * 
	 * @param <T> the type of values
	 * @param arithmetic the p-code arithmetic for values of type {@link T}
	 * @param sizeTotal the expected output size in bytes
	 * @param upper the value of the left (more significant) piece
	 * @param lower the value of the right (less significant) piece
	 * @param sizeLower the size of the lower piece
	 * @return the result of concatenation
	 */
	public static <T> T catenate(PcodeArithmetic<T> arithmetic, int sizeTotal, T upper, T lower,
			int sizeLower) {
		T zext = arithmetic.unaryOp(PcodeOp.INT_ZEXT, sizeTotal, sizeLower, lower);
		T shift = arithmetic.binaryOp(PcodeOp.INT_LEFT, sizeTotal, sizeTotal, upper, 4,
			arithmetic.fromConst(sizeLower * 8, 4));
		return arithmetic.binaryOp(PcodeOp.INT_OR, sizeTotal, sizeTotal, shift, sizeTotal, zext);
	}

	private final PcodeArithmetic<T> arithmetic;

	/**
	 * Construct an evaluator
	 * 
	 * @param arithmetic the arithmetic for computing p-code op outputs
	 */
	public ArithmeticVarnodeEvaluator(PcodeArithmetic<T> arithmetic) {
		this.arithmetic = arithmetic;
	}

	@Override
	protected T catenate(int sizeTotal, T upper, T lower, int sizeLower) {
		return catenate(arithmetic, sizeTotal, upper, lower, sizeLower);
	}

	@Override
	public T evaluateStorage(Program program, VariableStorage storage) {
		return evaluateStorage(program, storage, arithmetic.fromConst(0, storage.size()));
	}

	@Override
	protected T evaluateConstant(long value, int size) {
		return arithmetic.fromConst(value, size);
	}

	@Override
	protected T evaluateAbstract(Program program, AddressSpace space, T offset, int size,
			Map<Varnode, T> already) {
		long concrete = arithmetic.toLong(offset, Purpose.LOAD);
		Address address = space.getAddress(concrete);
		// There is no actual varnode to have a defining op, so this will be a leaf
		return evaluateMemory(translateMemory(program, address), size);
	}

	@Override
	protected T evaluateUnaryOp(Program program, PcodeOp op, UnaryOpBehavior unOp,
			Map<Varnode, T> already) {
		Varnode in1Var = op.getInput(0);
		T in1 = evaluateVarnode(program, in1Var, already);
		return arithmetic.unaryOp(op, in1);
	}

	@Override
	protected T evaluateBinaryOp(Program program, PcodeOp op, BinaryOpBehavior binOp,
			Map<Varnode, T> already) {
		Varnode in1Var = op.getInput(0);
		Varnode in2Var = op.getInput(1);
		T in1 = evaluateVarnode(program, in1Var, already);
		T in2 = evaluateVarnode(program, in2Var, already);
		return arithmetic.binaryOp(op, in1, in2);
	}

	@Override
	protected T evaluatePtrAdd(Program program, PcodeOp op, Map<Varnode, T> already) {
		Varnode baseVar = op.getInput(0);
		Varnode indexVar = op.getInput(1);
		int size = getIntConst(op.getInput(2));
		Varnode outVar = op.getOutput();
		T base = evaluateVarnode(program, baseVar, already);
		T index = evaluateVarnode(program, indexVar, already);
		return arithmetic.ptrAdd(outVar.getSize(), baseVar.getSize(), base, indexVar.getSize(),
			index, size);
	}

	@Override
	protected T evaluatePtrSub(Program program, PcodeOp op, Map<Varnode, T> already) {
		Varnode baseVar = op.getInput(0);
		Varnode offsetVar = op.getInput(1);
		Varnode outVar = op.getOutput();
		T base = evaluateVarnode(program, baseVar, already);
		T offset = evaluateVarnode(program, offsetVar, already);
		return arithmetic.ptrSub(outVar.getSize(),
			baseVar.getSize(), base,
			offsetVar.getSize(), offset);
	}

	@Override
	protected T evaluateLoad(Program program, PcodeOp op, Map<Varnode, T> already) {
		int spaceID = getIntConst(op.getInput(0));
		AddressSpace space = program.getAddressFactory().getAddressSpace(spaceID);
		Varnode inOffset = op.getInput(1);
		T offset = evaluateVarnode(program, inOffset, already);
		Varnode outVar = op.getOutput(); // Only for measuring size
		T out = evaluateAbstract(program, space, offset, outVar.getSize(), already);
		return arithmetic.modAfterLoad(outVar.getSize(),
			inOffset.getSize(), offset,
			outVar.getSize(), out);
	}
}
