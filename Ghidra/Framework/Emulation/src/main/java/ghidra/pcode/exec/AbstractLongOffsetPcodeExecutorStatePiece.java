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

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * An abstract executor state piece which internally uses {@code long} to address contents
 * 
 * <p>
 * This also provides an internal mechanism for breaking the piece down into the spaces defined by a
 * language. It also provides for the special treatment of the {@code unique} space.
 * 
 * @param <A> the type used to address contents, convertible to and from {@code long}
 * @param <T> the type of values stored
 * @param <S> the type of an execute state space, internally associated with an address space
 */
public abstract class AbstractLongOffsetPcodeExecutorStatePiece<A, T, S>
		implements PcodeExecutorStatePiece<A, T> {

	protected static <S> void forkMap(Map<AddressSpace, S> into, Map<AddressSpace, S> from,
			Function<S, S> forker) {
		for (Entry<AddressSpace, S> ent : from.entrySet()) {
			into.put(ent.getKey(), forker.apply(ent.getValue()));
		}
	}

	protected final Language language;
	protected final PcodeArithmetic<A> addressArithmetic;
	protected final PcodeArithmetic<T> arithmetic;
	protected final PcodeStateCallbacks cb;
	protected final AddressSpace uniqueSpace;

	/**
	 * Construct a state piece for the given language and arithmetic
	 * 
	 * @param language the language (used for its memory model)
	 * @param addressArithmetic an arithmetic used to generate default values of {@code A}
	 * @param arithmetic an arithmetic used to generate default values of {@code T}. It must be able
	 *            to derive concrete sizes, i.e., {@link PcodeArithmetic#sizeOf(Object)} must always
	 *            return the correct value.
	 * @param cb callbacks to receive emulation events
	 */
	public AbstractLongOffsetPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<A> addressArithmetic, PcodeArithmetic<T> arithmetic,
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
	public PcodeArithmetic<A> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
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
	 * @param cb callbacks to receive emulation events
	 */
	protected void setUnique(long offset, int size, T val, PcodeStateCallbacks cb) {
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
	 * @param reason the reason for reading state
	 * @param cb callbacks to receive emulation events
	 * @return the read value
	 */
	protected T getUnique(long offset, int size, Reason reason, PcodeStateCallbacks cb) {
		S s = getForSpace(uniqueSpace, false);
		return getFromSpace(s, offset, size, reason, cb);
	}

	/**
	 * Get the internal space for the given address space
	 * 
	 * @param space the address space
	 * @param toWrite in case internal spaces are generated lazily, this indicates the space must be
	 *            present, because it is going to be written to.
	 * @return the space, or {@code null}
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
	protected abstract void setInSpace(S space, long offset, int size, T val,
			PcodeStateCallbacks cb);

	/**
	 * Get a value from the given space
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the number of bytes to read (the size of the value)
	 * @param reason the reason for reading state
	 * @param cb callbacks to receive emulation events
	 * @return the read value
	 */
	protected abstract T getFromSpace(S space, long offset, int size, Reason reason,
			PcodeStateCallbacks cb);

	/**
	 * In case spaces are generated lazily, and we're reading from a space that doesn't yet exist,
	 * "read" a default value.
	 * 
	 * <p>
	 * By default, the returned value is 0, which should be reasonable for all implementations.
	 * 
	 * @param size the number of bytes to read (the size of the value)
	 * @param reason the reason for reading state
	 * @param cb callbacks to receive emulation events
	 * @return the default value
	 */
	protected T getFromNullSpace(int size, Reason reason, PcodeStateCallbacks cb) {
		return arithmetic.fromConst(0, size);
	}

	protected void setVarInternal(AddressSpace space, long offset, int size, boolean quantize,
			T val, PcodeStateCallbacks cb) {
		if (space.isConstantSpace()) {
			throw new IllegalArgumentException("Cannot write to constant space");
		}
		if (space.isUniqueSpace()) {
			setUnique(offset, size, val, cb);
			return;
		}
		S s = getForSpace(space, true);
		if (quantize) {
			offset = quantizeOffset(space, offset);
		}
		setInSpace(s, offset, size, val, cb);
	}

	@Override
	public void setVar(AddressSpace space, A offset, int size, boolean quantize, T val) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.STORE);
		setVar(space, lOffset, size, quantize, val);
	}

	@Override
	public void setVarInternal(AddressSpace space, A offset, int size, T val) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.STORE);
		setVarInternal(space, lOffset, size, val);
	}

	/**
	 * Check that the size of the value matches that given
	 * 
	 * <p>
	 * Extensions may override this and do nothing when the abstract type has no defined size
	 * 
	 * @param size the size in bytes
	 * @param val the value
	 * @return the value, possibly adjusted
	 */
	protected T checkSize(int size, T val) {
		int valSize = (int) arithmetic.sizeOf(val);
		if (valSize > size) {
			throw new IllegalArgumentException(
				"Value is larger than variable: " + valSize + " > " + size);
		}
		if (valSize < size) {
			Msg.warn(this, "Value is smaller than variable: " + valSize + " < " + size +
				". Zero extending");
			val = arithmetic.unaryOp(PcodeOp.INT_ZEXT, size, valSize, val);
		}
		return val;
	}

	@Override
	public void setVar(AddressSpace space, long offset, int size, boolean quantize, T val) {
		checkRange(space, offset, size);
		val = checkSize(size, val);
		setVarInternal(space, offset, size, quantize, val, cb);
	}

	@Override
	public void setVarInternal(AddressSpace space, long offset, int size, T val) {
		setVarInternal(space, offset, size, false, val, PcodeStateCallbacks.NONE);
	}

	protected T getVarInternal(AddressSpace space, long offset, int size, boolean quantize,
			Reason reason, PcodeStateCallbacks cb) {
		if (space.isConstantSpace()) {
			return arithmetic.fromConst(offset, size);
		}
		if (space.isUniqueSpace()) {
			return getUnique(offset, size, reason, cb);
		}
		S s = getForSpace(space, false);
		if (s == null) {
			AddressSet set = PcodeStateCallbacks.rngSet(space, offset, size);
			if (set.equals(cb.readUninitialized(this, set))) {
				return getFromNullSpace(size, reason, cb);
			}
			s = getForSpace(space, false);
			if (s == null) {
				return getFromNullSpace(size, reason, cb);
			}
		}
		if (quantize) {
			offset = quantizeOffset(space, offset);
		}
		return getFromSpace(s, offset, size, reason, cb);
	}

	@Override
	public T getVar(AddressSpace space, A offset, int size, boolean quantize, Reason reason) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.LOAD);
		return getVar(space, lOffset, size, quantize, reason);
	}

	@Override
	public T getVarInternal(AddressSpace space, A offset, int size, Reason reason) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.LOAD);
		return getVarInternal(space, lOffset, size, reason);
	}

	@Override
	public T getVar(AddressSpace space, long offset, int size, boolean quantize, Reason reason) {
		checkRange(space, offset, size);
		return getVarInternal(space, offset, size, quantize, reason, cb);
	}

	@Override
	public T getVarInternal(AddressSpace space, long offset, int size, Reason reason) {
		return getVarInternal(space, offset, size, false, reason, PcodeStateCallbacks.NONE);
	}

	/**
	 * Can the given space for register values, as in {@link #getRegisterValues()}
	 * 
	 * @param s the space to scan
	 * @param registers the registers known to be in the corresponding address space
	 * @return the map of registers to values
	 */
	protected abstract Map<Register, T> getRegisterValuesFromSpace(S s, List<Register> registers);

	@Override
	public Map<Register, T> getRegisterValues() {
		Map<AddressSpace, List<Register>> regsBySpace = language.getRegisters()
				.stream()
				.collect(Collectors.groupingBy(Register::getAddressSpace));
		Map<Register, T> result = new HashMap<>();
		for (Map.Entry<AddressSpace, List<Register>> ent : regsBySpace.entrySet()) {
			S s = getForSpace(ent.getKey(), false);
			if (s == null) {
				continue;
			}
			result.putAll(getRegisterValuesFromSpace(s, ent.getValue()));
		}
		return result;
	}
}
