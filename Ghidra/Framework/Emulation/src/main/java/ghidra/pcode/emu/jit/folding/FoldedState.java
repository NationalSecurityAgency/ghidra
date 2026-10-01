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
package ghidra.pcode.emu.jit.folding;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;

import generic.ULongSpan;
import generic.ULongSpan.DefaultULongSpanSet;
import generic.ULongSpan.MutableULongSpanSet;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;

/**
 * A p-code executor state on {@link MaskedBytes}.
 * <p>
 * This is used as the state for interpretation when computing folded constants. Because the JIT
 * only elides passage through registers and uniques, those are the only spaces we actually store
 * here. Otherwise, this is roughly equivalent to {@link BytesPcodeExecutorState}, but we store both
 * the values and masks of the {@link MaskedBytes} into the backing byte arrays.
 */
public class FoldedState implements PcodeExecutorState<MaskedBytes> {

	private final Language language;
	private final FoldedArithmetic arithmetic;

	private final FoldedSpace uniqSpace = new FoldedSpace();
	private final FoldedSpace regSpace = new FoldedSpace();

	private class FoldedSpace {
		SemisparseByteArray values = new SemisparseByteArray();
		SemisparseByteArray masks = new SemisparseByteArray();

		void setVar(long off, MaskedBytes value) {
			values.putData(off, value.val);
			masks.putData(off, value.msk);
		}

		MaskedBytes getVar(long off, int size) {
			byte[] values = new byte[size];
			byte[] masks = new byte[size];
			this.values.getData(off, values);
			this.masks.getData(off, masks);
			return new MaskedBytes(values, masks);
		}

		void clear() {
			values.clear();
			masks.clear();
		}

		void addAll(FoldedSpace that) {
			this.values.putAll(that.values);
			this.masks.putAll(that.masks);
		}

		boolean intersect(FoldedSpace that) {
			boolean changed = false;
			MutableULongSpanSet union = new DefaultULongSpanSet();
			union.addAll(this.values.getInitialized());
			union.addAll(that.values.getInitialized());
			byte[] thisVal = new byte[1];
			byte[] thatVal = new byte[1];
			byte[] thisMsk = new byte[1];
			byte[] thatMsk = new byte[1];
			for (ULongSpan span : union.spans()) {
				for (long i = span.min(); Long.compareUnsigned(i, span.max()) <= 0; i++) {
					if (this.values.isInitialized(i)) {
						this.values.getData(i, thisVal);
						Arrays.fill(thatVal, (byte) 0);
						that.values.getData(i, thatVal);
						this.masks.getData(i, thisMsk);
						Arrays.fill(thatMsk, (byte) 0);
						that.masks.getData(i, thatMsk);

						int origMsk = thisMsk[0];

						thisMsk[0] &= thatMsk[0];
						int diffs = thisVal[0] ^ thatVal[0];
						thisMsk[0] &= ~diffs;
						thisVal[0] &= thisMsk[0];

						changed |= (origMsk != thisMsk[0]);

						this.values.putData(i, thisVal);
						this.masks.putData(i, thisMsk);
					}
				}
			}
			return changed;
		}
	}

	/**
	 * Construct a constant-folding state for the given language
	 * 
	 * @param language the language
	 */
	public FoldedState(Language language) {
		this.language = language;
		this.arithmetic = language.isBigEndian() ? FoldedArithmetic.BE : FoldedArithmetic.LE;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public FoldedArithmetic getArithmetic() {
		return arithmetic;
	}

	@Override
	public Stream<PcodeExecutorStatePiece<?, ?>> streamPieces() {
		return Stream.of(this);
	}

	@Override
	public void setVar(AddressSpace space, MaskedBytes offset, int size, boolean quantize,
			MaskedBytes val) {
		setVarInternal(space, offset, size, val);
	}

	@Override
	public void setVarInternal(AddressSpace space, MaskedBytes offset, int size,
			MaskedBytes val) {
		try {
			if (space.isUniqueSpace()) {
				long off = arithmetic.toLong(offset, Purpose.STORE);
				uniqSpace.setVar(off, val);
			}
			else if (space.isRegisterSpace()) {
				long off = arithmetic.toLong(offset, Purpose.STORE);
				regSpace.setVar(off, val);
			}
		}
		catch (ConcretionError e) {
			Msg.warn(this, "Should not get unknown offsets in unique or register space");
		}
	}

	@Override
	public MaskedBytes getVar(AddressSpace space, MaskedBytes offset, int size, boolean quantize,
			Reason reason) {
		return getVarInternal(space, offset, size, reason);
	}

	@Override
	public MaskedBytes getVarInternal(AddressSpace space, MaskedBytes offset, int size,
			Reason reason) {
		try {
			if (space.isConstantSpace()) {
				return offset.zext(size, arithmetic.getEndian());
			}
			else if (space.isUniqueSpace()) {
				long off = arithmetic.toLong(offset, Purpose.LOAD);
				return uniqSpace.getVar(off, size);
			}
			else if (space.isRegisterSpace()) {
				long off = arithmetic.toLong(offset, Purpose.LOAD);
				return regSpace.getVar(off, size);
			}
		}
		catch (ConcretionError e) {
			Msg.warn(this, "Should not get unknown offsets in unique or register space");
		}
		return MaskedBytes.ofUnknown(size);
	}

	@Override
	public Map<Register, MaskedBytes> getRegisterValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		uniqSpace.clear();
		regSpace.clear();
	}

	/**
	 * Fork this state, without callbacks, because they're not supported here.
	 * 
	 * @return the copy
	 */
	public FoldedState fork() {
		return fork(null);
	}

	@Override
	public FoldedState fork(PcodeStateCallbacks cb) {
		if (cb != null) {
			throw new UnsupportedOperationException("callbacks");
		}
		FoldedState newState = new FoldedState(language);
		newState.uniqSpace.addAll(this.uniqSpace);
		newState.regSpace.addAll(this.regSpace);
		return newState;
	}

	/**
	 * Merge the given state into this one, modifying this state in place
	 * <p>
	 * This is the merging operation used by {@link FoldRevalidator}. Where we have known values
	 * (1-bits in the mask) the other must also have known values, or else we erase our mask (and
	 * value) bits. If the other also has known values at the same offset, the values must match, or
	 * else we erase. These checks and erasures are applied with bit-level granularity. Any erasure
	 * results in a return of {@code true} (without short circuiting).
	 * 
	 * @param that the other state
	 * @return true if this state changed as a result of this intersection
	 */
	public boolean intersectInPlace(FoldedState that) {
		boolean uniqChanged = this.uniqSpace.intersect(that.uniqSpace);
		boolean regChanged = this.regSpace.intersect(that.regSpace);
		return uniqChanged | regChanged;
	}
}
