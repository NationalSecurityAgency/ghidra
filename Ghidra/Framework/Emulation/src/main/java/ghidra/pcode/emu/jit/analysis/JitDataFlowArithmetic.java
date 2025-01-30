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
package ghidra.pcode.emu.jit.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.OpBehaviorSubpiece;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code arithmetic for interpreting p-code and constructing a use-def graph
 * 
 * <p>
 * This is used for intra-block data flow analysis. We leverage the same API as is used for concrete
 * p-code interpretation, but we use it for an abstraction. The type of the interpretation is
 * {@code T:=}{@link JitVal}, which can consist of constants and variables in the use-def graph. The
 * arithmetic must be provided to the {@link JitDataFlowExecutor}. The intra-block portions of the
 * use-def graph are populated as each block is interpreted by the executor.
 * 
 * <p>
 * The general strategy for each of the arithmetic operations is to 1) generate the output SSA
 * variable for the op, 2) generate the op node for the generated output and given inputs, 3) enter
 * the op into the use-def graph as the definition of its output, 4) record the inputs and used by
 * the new op, and finally 5) return the generated output.
 * 
 * <p>
 * There should only need to be one of these per data flow model, not per block.
 */
public class JitDataFlowArithmetic implements PcodeArithmetic<JitVal> {
	private static final OpBehaviorSubpiece OB_SUBPIECE =
		(OpBehaviorSubpiece) OpBehaviorFactory.getOpBehavior(PcodeOp.SUBPIECE);

	private final JitDataFlowModel dfm;
	private final Endian endian;

	/**
	 * Construct the arithmetic
	 * 
	 * @param context the analysis context
	 * @param dfm the owning data flow model
	 */
	public JitDataFlowArithmetic(JitAnalysisContext context, JitDataFlowModel dfm) {
		this.dfm = dfm;
		this.endian = context.getEndian();
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	/**
	 * Remove {@code amt} bytes from the right of the <em>varnode</em>.
	 * 
	 * <p>
	 * "Right" is considered with respect to the machine endianness. If it is little endian, then
	 * the byte are shaved from the <em>left</em> of the value. This should be used when getting
	 * values from the state to remove pieces from off-cut values. It should be applied before the
	 * pieces are ordered according to machine endianness.
	 * 
	 * @param in1Vn the varnode representing the input
	 * @param amt the number of bytes to remove
	 * @param in1 the input (really a value read from the state)
	 * @return the resulting value
	 */
	public JitVal truncFromRight(Varnode in1Vn, int amt, JitVal in1) {
		Varnode outVn = new Varnode(in1Vn.getAddress(), in1Vn.getSize() - amt);
		return subpiece(outVn, endian.isBigEndian() ? amt : 0, in1);
	}

	/**
	 * Remove {@code amt} bytes from the left of the <em>varnode</em>.
	 * 
	 * <p>
	 * "Left" is considered with respect to the machine endianness. If it is little endian, then the
	 * byte are shaved from the <em>right</em> of the value. This should be used when getting values
	 * from the state to remove pieces from off-cut values. It should be applied before the pieces
	 * are ordered according to machine endianness.
	 * 
	 * @param in1Vn the varnode representing the input
	 * @param amt the number of bytes to remove
	 * @param in1 the input (really a value read from the state)
	 * @return the resulting value
	 */
	public JitVal truncFromLeft(Varnode in1Vn, int amt, JitVal in1) {
		Varnode outVn = new Varnode(in1Vn.getAddress().add(amt), in1Vn.getSize() - amt);
		return subpiece(outVn, endian.isBigEndian() ? 0 : amt, in1);
	}

	private void removeOffsetFromRight(List<JitVal> parts, int offset) {
		JitVal p;
		do {
			p = parts.remove(parts.size() - 1);
			offset -= p.size();
		}
		while (offset > 0);
		if (offset < 0) {
			JitVal np = shaveFromRight(-offset, p);
			parts.add(np);
			offset += np.size();
			assert offset == 0;
		}
	}

	private void removeFromLeftToSize(List<JitVal> parts, int size) {
		int actualSize = 0;
		JitVal p;
		int i = parts.size();
		do {
			p = parts.get(--i);
			actualSize += p.size();
		}
		while (actualSize < size);
		if (actualSize > size) {
			JitVal np = shaveFromLeft(-size, p);
			parts.set(i + 1, np);
			actualSize -= p.size();
			actualSize += np.size();
			assert actualSize == size;
		}
		while (i > 0) {
			parts.remove(--i);
		}
	}

	/**
	 * Try to produce a simplified {@link JitSynthSubPieceOp} or {@link JitCatenateOp}
	 * 
	 * <p>
	 * This takes an input, subpiece offset, and output variable. If the input variable is the
	 * result of another subpiece, the result can be a single simplified subpiece. Similarly, if the
	 * input is the result of a catenation, then the result can be a simplified catenation, or
	 * possibly subpiece.
	 * 
	 * If either of these situations applies, and simplification is possible, this returns a
	 * non-null result, and that result is added to the use-def graph specifying the given output
	 * variable as the simplified output. Otherwise, the result is null and the caller should create
	 * a new subpiece op.
	 * 
	 * @param out the output variable
	 * @param offset the subpiece offset (number of bytes shifted right)
	 * @param v the input value
	 * @return the output variable, as the result of the simplified sub-graph.
	 */
	private JitVal trySimplifiedSubPiece(JitOutVar out, int offset, JitVal v) {
		if (!(v instanceof JitOutVar vOut)) {
			return null;
		}
		if (vOut.definition() instanceof JitSynthSubPieceOp subsub) {
			subsub.unlink();
			return dfm
					.notifyOp(new JitSynthSubPieceOp(out, offset + subsub.offset(), subsub.v()))
					.out();
		}
		if (vOut.definition() instanceof JitCatenateOp cat) {
			cat.unlink();
			List<JitVal> newParts = new ArrayList<>(cat.parts());
			removeOffsetFromRight(newParts, offset);
			removeFromLeftToSize(newParts, out.size());
			assert !newParts.isEmpty();
			if (newParts.size() == 1) {
				// Context should already be notified
				return newParts.get(0);
			}
			return dfm.notifyOp(new JitCatenateOp(out, newParts)).out();
		}
		return null;
	}

	/**
	 * Construct the result of taking the subpiece
	 * 
	 * <p>
	 * If the input is another subpiece or a catenation, the result may be simplified. In
	 * particular, the subpiece of a catenation may be a smaller catenation. No matter the case, the
	 * given output variable is made the output of the subpiece result, and the use-def graph is
	 * updated accordingly.
	 * 
	 * @param outVn the output variable
	 * @param offset the subpiece offset (number of bytes shifted right)
	 * @param v the input value
	 * @return the output variable, as the result of the simplified sub-graph
	 */
	private JitVal subpiece(Varnode outVn, int offset, JitVal v) {
		JitOutVar out = dfm.generateOutVar(outVn);
		JitVal simplified = trySimplifiedSubPiece(out, offset, v);
		if (simplified != null) {
			return simplified;
		}
		return dfm.notifyOp(new JitSynthSubPieceOp(out, offset, v)).out();
	}

	private Varnode subPieceVn(int size, int offset, Varnode whole) {
		if (endian.isBigEndian()) {
			return new Varnode(whole.getAddress().add(whole.getSize() - offset - size), size);
		}
		return new Varnode(whole.getAddress().add(offset), size);
	}

	/**
	 * Remove {@code amt} bytes from the right of the value.
	 * 
	 * <p>
	 * The value is unaffected by the machine endianness, except to designate the output varnode.
	 * 
	 * @param amt the number of bytes to remove
	 * @param in1 the input
	 * @return the output
	 */
	public JitVal shaveFromRight(int amt, JitVal in1) {
		return subpiece(in1.size() - amt, amt, in1);
	}

	/**
	 * Remove {@code amt} bytes from the left of the value.
	 * 
	 * <p>
	 * The value is unaffected by the machine endianness, except to designate the output varnode.
	 * 
	 * @param amt the number of bytes to remove
	 * @param in1 the input
	 * @return the output
	 */
	public JitVal shaveFromLeft(int amt, JitVal in1) {
		return subpiece(in1.size() - amt, 0, in1);
	}

	/**
	 * Compute the subpiece of a value.
	 * 
	 * <p>
	 * The result is added to the use-def graph. The output varnode is computed from the input
	 * varnode and the subpiece parameters. This is used to handle variable retrieval when an access
	 * only include parts of a value previously written. Consider the x86 assembly:
	 * 
	 * <pre>
	 * MOV RAX, qword ptr [...]
	 * MOV dword ptr [...], EAX
	 * </pre>
	 * 
	 * <p>
	 * The second line reads {@code EAX}, which consists of only the lower part of {@code RAX}.
	 * Thus, we synthesize a subpiece op. These are distinct from an actual {@link PcodeOp#SUBPIECE}
	 * op, since we sometimes needs to filter out synthetic ops.
	 * 
	 * @param size the size of the output variable in bytes
	 * @param offset the subpiece offset (number of bytes shifted right)
	 * @param v the input value
	 * @return the output value
	 */
	public JitVal subpiece(int size, int offset, JitVal v) {
		if (v instanceof JitConstVal c) {
			return new JitConstVal(size,
				OB_SUBPIECE.evaluateBinary(size, v.size(), c.value(), BigInteger.valueOf(offset)));
		}
		if (v instanceof JitVarnodeVar vv) {
			Varnode inVn = vv.varnode();
			Varnode outVn = subPieceVn(size, offset, inVn);
			return subpiece(outVn, offset, v);
		}
		throw new UnsupportedOperationException("unsupported subpiece of " + v);
	}

	/**
	 * Construct the catenation of the given values to form the given output varnode.
	 * 
	 * <p>
	 * The result is added to the use-def graph. This is used to handle variable retrieval when the
	 * pattern of accesses indicates catenation. Consider the x86 assembly:
	 * 
	 * <pre>
	 * MOV AH, byte ptr [...]
	 * MOV AL, byte ptr [...]
	 * MOV word ptr [...], AX
	 * </pre>
	 * 
	 * <p>
	 * On the third line, the value in {@code AX} is the catenation of whatever values were written
	 * into {@code AH} and {@code AL}. Thus, we synthesize a catenation op node in the use-def
	 * graph.
	 * 
	 * @param outVn the output varnode
	 * @param parts the list of values to catenate, ordered by machine endianness
	 * @return the output value
	 * @see MiniDFState#getDefinitions(AddressSpace, long, int)
	 */
	public JitVal catenate(Varnode outVn, List<JitVal> parts) {
		return dfm.notifyOp(new JitCatenateOp(dfm.generateOutVar(outVn), parts)).out();
	}

	@Override
	public JitVal unaryOp(PcodeOp op, JitVal in1) {
		return dfm.notifyOp(JitOp.unOp(op, dfm.generateOutVar(op.getOutput()), in1)).out();
	}

	@Override
	public JitVal unaryOp(int opcode, int sizeout, int sizein1, JitVal in1) {
		throw new AssertionError();
	}

	@Override
	public JitVal binaryOp(PcodeOp op, JitVal in1, JitVal in2) {
		return dfm.notifyOp(JitOp.binOp(op, dfm.generateOutVar(op.getOutput()), in1, in2)).out();
	}

	@Override
	public JitVal binaryOp(int opcode, int sizeout, int sizein1, JitVal in1, int sizein2,
			JitVal in2) {
		throw new AssertionError();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We override this to record the {@link JitStoreOp store} op into the use-def graph. As
	 * "output" we just return {@code inValue}. The executor will call
	 * {@link JitDataFlowState#setVar(AddressSpace, JitVal, int, boolean, JitVal) setVal}, but the
	 * state will just ignore it, because it will be an indirect memory write.
	 */
	@Override
	public JitVal modBeforeStore(PcodeOp op, AddressSpace space, JitVal inOffset, JitVal inValue) {
		return dfm.notifyOp(new JitStoreOp(op, space, inOffset, inValue)).value();
	}

	@Override
	public JitVal modBeforeStore(int sizeinOffset, AddressSpace space, JitVal inOffset,
			int sizeinValue, JitVal inValue) {
		throw new AssertionError();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We override this to record the {@link JitLoadOp load} op into the use-def graph. For our
	 * {@code inValue}, the {@link JitDataFlowState state} will have just returned the
	 * {@link JitIndirectMemoryVar#INSTANCE dummy indirect} variable definition. We must not "use"
	 * this. Instead, we must take our other parameters to construct the load op and return its
	 * output.
	 */
	@Override
	public JitVal modAfterLoad(PcodeOp op, AddressSpace space, JitVal inOffset, JitVal inValue) {
		return dfm.notifyOp(new JitLoadOp(
			op, dfm.generateOutVar(op.getOutput()), space, inOffset)).out();
	}

	@Override
	public JitVal modAfterLoad(int sizeinOffset, AddressSpace space, JitVal inOffset,
			int sizeinValue, JitVal inValue) {
		throw new AssertionError();
	}

	@Override
	public JitVal fromConst(byte[] value) {
		BigInteger bigVal =
			Utils.bytesToBigInteger(value, value.length, endian.isBigEndian(), false);
		return JitVal.constant(value.length, bigVal);
	}

	@Override
	public byte[] toConcrete(JitVal value, Purpose purpose) {
		if (value instanceof JitConstVal c) {
			return Utils.bigIntegerToBytes(c.value(), c.size(), endian.isBigEndian());
		}
		throw new ConcretionError("Cannot concretize " + value, purpose);
	}

	@Override
	public long sizeOf(JitVal value) {
		return value.size();
	}
}
