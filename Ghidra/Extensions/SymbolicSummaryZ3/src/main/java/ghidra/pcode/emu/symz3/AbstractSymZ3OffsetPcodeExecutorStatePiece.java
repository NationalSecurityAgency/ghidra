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
package ghidra.pcode.emu.symz3;

import java.math.BigInteger;
import java.util.stream.Stream;

import com.microsoft.z3.BitVecNum;
import com.microsoft.z3.Context;

import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;
import ghidra.util.Msg;

/**
 * An abstract executor state piece which internally uses SymZ3Value to address contents
 * 
 * <p>
 * This also provides an internal mechanism for breaking the piece down into the spaces defined by a
 * language. It also provides for the special treatment of the {@code unique} space.
 * 
 * @param <S> the type of an execute state space, internally associated with an address space
 */
public abstract class AbstractSymZ3OffsetPcodeExecutorStatePiece<S>
		implements PcodeExecutorStatePiece<SymValueZ3, SymValueZ3> {

	protected final Language language;
	protected final PcodeArithmetic<SymValueZ3> addressArithmetic;
	protected final PcodeArithmetic<SymValueZ3> arithmetic;
	protected final PcodeStateCallbacks cb;
	protected final AddressSpace uniqueSpace;

	/**
	 * Construct a state piece for the given language and arithmetic
	 * 
	 * @param language the language (used for its memory model)
	 * @param addressArithmetic the arithmetic used for addresses
	 * @param arithmetic an arithmetic used to generate default values of {@code T}
	 * @param cb callbacks to receive emulation events
	 */
	public AbstractSymZ3OffsetPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<SymValueZ3> addressArithmetic, PcodeArithmetic<SymValueZ3> arithmetic,
			PcodeStateCallbacks cb) {
		this.language = language;
		this.addressArithmetic = addressArithmetic;
		this.arithmetic = arithmetic;
		this.cb = cb;
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public PcodeArithmetic<SymValueZ3> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public PcodeArithmetic<SymValueZ3> getArithmetic() {
		return arithmetic;
	}

	@Override
	public Stream<PcodeExecutorStatePiece<?, ?>> streamPieces() {
		return Stream.of(this);
	}

	/**
	 * Set a value in the unique space
	 * 
	 * <p>
	 * Some state pieces treat unique values in a way that merits a separate implementation. This
	 * permits the standard path to be overridden.
	 * 
	 * @param offset the offset in unique space to store the value
	 * @param size the number of bytes to write (the size of the value)
	 * @param val the value to store
	 */
	protected void setUnique(SymValueZ3 offset, int size, SymValueZ3 val, PcodeStateCallbacks cb) {
		S s = getForSpace(uniqueSpace, true);
		setInSpace(s, offset, size, val, cb);
	}

	/**
	 * Get a value from the unique space
	 * 
	 * Some state pieces treat unique values in a way that merits a separate implementation. This
	 * permits the standard path to be overridden.
	 * 
	 * @param offset the offset in unique space to get the value
	 * @param size the number of bytes to read (the size of the value)
	 * @return the read value
	 */
	protected SymValueZ3 getUnique(SymValueZ3 offset, int size, PcodeStateCallbacks cb) {
		S s = getForSpace(uniqueSpace, false);
		return getFromSpace(s, offset, size, cb);
	}

	/**
	 * Get the internal space for the given address space
	 * 
	 * @param space the address space
	 * @param toWrite in case internal spaces are generated lazily, this indicates the space must be
	 *            present, because it is going to be written to.
	 * @return the space, or {@code null}
	 * @see AbstractSpaceMap
	 */
	protected abstract S getForSpace(AddressSpace space, boolean toWrite);

	/**
	 * Set a value in the given space
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the number of bytes to write (the size of the value)
	 * @param val the value to store
	 * @param cb callbacks to receive emulation events
	 */
	protected abstract void setInSpace(S space, SymValueZ3 offset, int size, SymValueZ3 val,
			PcodeStateCallbacks cb);

	/**
	 * Get a value from the given space
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the number of bytes to read (the size of the value)
	 * @param cb callbacks to receive emulation events
	 * @return the read value
	 */
	protected abstract SymValueZ3 getFromSpace(S space, SymValueZ3 offset, int size,
			PcodeStateCallbacks cb);

	/**
	 * In case spaces are generated lazily, and we're reading from a space that doesn't yet exist,
	 * "read" a default value.
	 * 
	 * <p>
	 * By default, the returned value is 0, which should be reasonable for all implementations.
	 * 
	 * @param size the number of bytes to read (the size of the value)
	 * @return the default value
	 */
	protected SymValueZ3 getFromNullSpace(int size, PcodeStateCallbacks cb) {
		Msg.warn(this,
			"getFromNullSpace is returning 0 but that might not be what we want for symz3");
		return arithmetic.fromConst(0, size);
	}

	protected void setVarInternal(AddressSpace space, SymValueZ3 offset, int size, boolean quantize,
			SymValueZ3 val, PcodeStateCallbacks cb) {
		//Msg.info(this, "setVar for space: " + space + " offset: " + offset + " size: " + size + " val: " + val);
		assert val != null;
		assert offset != null;

		//checkRange(space, offset, size);
		/**
		 * FROM DAN: If you care to check that the offset makes sense within a given space, then fix
		 * this
		 * 
		 * My suggestion: If offset is constant, convert to long and invoke checkRange. If not, just
		 * don't check. Note that the default implementation of setVar(space, long, size, quantize,
		 * val) will already call checkRange.
		 */
		if (space.isConstantSpace()) {
			throw new IllegalArgumentException("Cannot write to constant space");
		}
		if (space.isUniqueSpace()) {
			setUnique(offset, size, val, cb);
			return;
		}
		S s = getForSpace(space, true);
		//offset = quantizeOffset(space, offset);
		/**
		 * FROM DAN: quantize probably doesn't make sense for you. You could check if concrete,
		 * convert to long, and quantize. You could also express the quantization symbolically, but
		 * it rarely comes up.
		 */
		setInSpace(s, offset, size, val, cb);
	}

	@Override
	public void setVar(AddressSpace space, SymValueZ3 offset, int size, boolean quantize,
			SymValueZ3 val) {
		setVarInternal(space, offset, size, quantize, val, cb);
	}

	@Override
	public void setVarInternal(AddressSpace space, SymValueZ3 offset, int size, SymValueZ3 val) {
		setVarInternal(space, offset, size, false, val, PcodeStateCallbacks.NONE);
	}

	protected SymValueZ3 getVarInternal(AddressSpace space, SymValueZ3 offset, int size,
			boolean quantize, Reason reason, PcodeStateCallbacks cb) {
		//checkRange(space, offset, size);
		//Msg.info(this, "getVar for space: " + space + " offset: " + offset + " size: " + size + " quantize: " + quantize);
		if (space.isConstantSpace()) {
			/**
			 * Totally clueless what "quantize" does and we are perhaps improperly ignoring it
			 * 
			 * For architectures that can't address any arbitrary byte, it adjusts the offset and
			 * size to the floor addressable word. Not applicable to x86, so you can get away
			 * ignoring it there.
			 **/
			//Msg.debug(this, "request of constant from offset: " + offset + " size: " + size);
			try (Context ctx = new Context()) {
				assert offset.getBitVecExpr(ctx).isNumeral();
				BitVecNum bvn = (BitVecNum) offset.getBitVecExpr(ctx);
				BigInteger b = bvn.getBigInteger();
				return new SymValueZ3(ctx, ctx.mkBV(b.toString(), size * 8));
			}
		}
		if (space.isUniqueSpace()) {
			return getUnique(offset, size, cb);
		}
		S s = getForSpace(space, false);
		//Msg.info(this, "Now we likely have a space to get from: " + s);
		if (s == null) {
			return getFromNullSpace(size, cb);
		}
		//offset = quantizeOffset(space, offset);
		return getFromSpace(s, offset, size, cb);
	}

	@Override
	public SymValueZ3 getVar(AddressSpace space, SymValueZ3 offset, int size, boolean quantize,
			Reason reason) {
		return getVarInternal(space, offset, size, quantize, reason, cb);
	}

	@Override
	public SymValueZ3 getVarInternal(AddressSpace space, SymValueZ3 offset, int size,
			Reason reason) {
		return getVarInternal(space, offset, size, false, reason, PcodeStateCallbacks.NONE);
	}
}
