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
package ghidra.pcode.exec;

import java.util.Objects;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;

/**
 * An arithmetic composed from two.
 * 
 * <p>
 * The new arithmetic operates on tuples where each is subject to its respective arithmetic. One
 * exception is {@link #toConcrete(Pair, Purpose)}. This arithmetic defers to left ("control")
 * arithmetic. Thus, conventionally, when part of the pair represents the concrete value, it should
 * be the left.
 * 
 * <p>
 * See {@link PairedPcodeExecutorStatePiece} regarding composing three or more elements. Generally,
 * it's recommended the client provide its own "record" type and the corresponding arithmetic and
 * state piece to manipulate it. Nesting pairs would work, but is not recommended.
 * 
 * @param <L> the type of the left ("control") element
 * @param <R> the type of the right ("auxiliary") element
 */
public class PairedPcodeArithmetic<L, R> implements PcodeArithmetic<Pair<L, R>> {
	private final PcodeArithmetic<L> leftArith;
	private final PcodeArithmetic<R> rightArith;
	private final Endian endian;

	/**
	 * Construct a composed arithmetic from the given two
	 * 
	 * @param leftArith the left ("control") arithmetic
	 * @param rightArith the right ("rider") arithmetic
	 */
	public PairedPcodeArithmetic(PcodeArithmetic<L> leftArith, PcodeArithmetic<R> rightArith) {
		Endian lend = leftArith.getEndian();
		Endian rend = rightArith.getEndian();
		if (lend != null && rend != null && lend != rend) {
			throw new IllegalArgumentException("Arithmetics must agree in endianness");
		}
		this.endian = lend != null ? lend : rend;
		this.leftArith = leftArith;
		this.rightArith = rightArith;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		PairedPcodeArithmetic<?, ?> that = (PairedPcodeArithmetic<?, ?>) obj;
		if (!Objects.equals(this.leftArith, that.leftArith)) {
			return false;
		}
		if (!Objects.equals(this.rightArith, that.rightArith)) {
			return false;
		}
		return true;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	@Override
	public Pair<L, R> unaryOp(int opcode, int sizeout, int sizein1,
			Pair<L, R> in1) {
		return Pair.of(
			leftArith.unaryOp(opcode, sizeout, sizein1, in1.getLeft()),
			rightArith.unaryOp(opcode, sizeout, sizein1, in1.getRight()));
	}

	@Override
	public Pair<L, R> unaryOp(PcodeOp op, Pair<L, R> in1) {
		return Pair.of(
			leftArith.unaryOp(op, in1.getLeft()),
			rightArith.unaryOp(op, in1.getRight()));
	}

	@Override
	public Pair<L, R> binaryOp(int opcode, int sizeout, int sizein1,
			Pair<L, R> in1, int sizein2, Pair<L, R> in2) {
		return Pair.of(
			leftArith.binaryOp(opcode, sizeout, sizein1, in1.getLeft(), sizein2, in2.getLeft()),
			rightArith.binaryOp(opcode, sizeout, sizein1, in1.getRight(), sizein2, in2.getRight()));
	}

	@Override
	public Pair<L, R> binaryOp(PcodeOp op, Pair<L, R> in1, Pair<L, R> in2) {
		return Pair.of(
			leftArith.binaryOp(op, in1.getLeft(), in2.getLeft()),
			rightArith.binaryOp(op, in1.getRight(), in2.getRight()));
	}

	@Override
	public Pair<L, R> modBeforeStore(int sizeout, int sizeinAddress, Pair<L, R> inAddress,
			int sizeinValue, Pair<L, R> inValue) {
		return Pair.of(
			leftArith.modBeforeStore(sizeout, sizeinAddress, inAddress.getLeft(), sizeinValue,
				inValue.getLeft()),
			rightArith.modBeforeStore(sizeout, sizeinAddress, inAddress.getRight(), sizeinValue,
				inValue.getRight()));
	}

	@Override
	public Pair<L, R> modAfterLoad(int sizeout, int sizeinAddress, Pair<L, R> inAddress,
			int sizeinValue, Pair<L, R> inValue) {
		return Pair.of(
			leftArith.modAfterLoad(sizeout, sizeinAddress, inAddress.getLeft(), sizeinValue,
				inValue.getLeft()),
			rightArith.modAfterLoad(sizeout, sizeinAddress, inAddress.getRight(), sizeinValue,
				inValue.getRight()));
	}

	@Override
	public Pair<L, R> fromConst(byte[] value) {
		return Pair.of(leftArith.fromConst(value), rightArith.fromConst(value));
	}

	@Override
	public byte[] toConcrete(Pair<L, R> value, Purpose purpose) {
		return leftArith.toConcrete(value.getLeft(), purpose);
	}

	@Override
	public long sizeOf(Pair<L, R> value) {
		return leftArith.sizeOf(value.getLeft());
		// TODO: Assert that the right agrees? Nah. Some aux types have no size.
	}

	/**
	 * Get the left ("control") arithmetic
	 * 
	 * @return the arithmetic
	 */
	public PcodeArithmetic<L> getLeft() {
		return leftArith;
	}

	/**
	 * Get the right ("rider") arithmetic
	 * 
	 * @return the arithmetic
	 */
	public PcodeArithmetic<R> getRight() {
		return rightArith;
	}
}
