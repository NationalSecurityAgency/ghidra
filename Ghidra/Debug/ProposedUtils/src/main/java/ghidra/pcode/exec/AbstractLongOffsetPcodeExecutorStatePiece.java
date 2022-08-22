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

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

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

	/**
	 * A map of address spaces to objects which store or cache state for that space
	 *
	 * @param <S> the type of object for each address space
	 */
	public abstract static class AbstractSpaceMap<S> {
		protected final Map<AddressSpace, S> spaces = new HashMap<>();

		public abstract S getForSpace(AddressSpace space, boolean toWrite);

		public Collection<S> values() {
			return spaces.values();
		}
	}

	/**
	 * Use this when each S contains the complete state for the address space
	 * 
	 * @param <S> the type of object for each address space
	 */
	public abstract static class SimpleSpaceMap<S> extends AbstractSpaceMap<S> {
		/**
		 * Construct a new space internally associated with the given address space
		 * 
		 * <p>
		 * As the name implies, this often simply wraps {@code S}'s constructor
		 * 
		 * @param space the address space
		 * @return the new space
		 */
		protected abstract S newSpace(AddressSpace space);

		@Override
		public S getForSpace(AddressSpace space, boolean toWrite) {
			return spaces.computeIfAbsent(space, s -> newSpace(s));
		}
	}

	/**
	 * Use this when each S is possibly a cache to some other state (backing) object
	 *
	 * @param <B> the type of the object backing the cache for each address space
	 * @param <S> the type of cache for each address space
	 */
	public abstract static class CacheingSpaceMap<B, S> extends AbstractSpaceMap<S> {
		/**
		 * Get the object backing the cache for the given address space
		 * 
		 * @param space the space
		 * @return the backing object
		 */
		protected abstract B getBacking(AddressSpace space);

		/**
		 * Construct a new space internally associated with the given address space, having the
		 * given backing
		 * 
		 * <p>
		 * As the name implies, this often simply wraps {@code S}'s constructor
		 * 
		 * @param space the address space
		 * @param backing the backing, if applicable. null for the unique space
		 * @return the new space
		 */
		protected abstract S newSpace(AddressSpace space, B backing);

		@Override
		public S getForSpace(AddressSpace space, boolean toWrite) {
			return spaces.computeIfAbsent(space,
				s -> newSpace(s, s.isUniqueSpace() ? null : getBacking(s)));
		}
	}

	protected final Language language;
	protected final PcodeArithmetic<A> addressArithmetic;
	protected final PcodeArithmetic<T> arithmetic;
	protected final AddressSpace uniqueSpace;

	/**
	 * Construct a state piece for the given language and arithmetic
	 * 
	 * @param language the language (used for its memory model)
	 * @param arithmetic an arithmetic used to generate default values of {@code T}
	 */
	public AbstractLongOffsetPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<A> addressArithmetic, PcodeArithmetic<T> arithmetic) {
		this.language = language;
		this.addressArithmetic = addressArithmetic;
		this.arithmetic = arithmetic;
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
	}

	@Override
	public PcodeArithmetic<A> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public PcodeArithmetic<T> getArithmetic() {
		return arithmetic;
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
	protected void setUnique(long offset, int size, T val) {
		S s = getForSpace(uniqueSpace, true);
		setInSpace(s, offset, size, val);
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
	protected T getUnique(long offset, int size) {
		S s = getForSpace(uniqueSpace, false);
		return getFromSpace(s, offset, size);
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
	 */
	protected abstract void setInSpace(S space, long offset, int size, T val);

	/**
	 * Get a value from the given space
	 * 
	 * @param space the address space
	 * @param offset the offset within the space
	 * @param size the number of bytes to read (the size of the value)
	 * @return the read value
	 */
	protected abstract T getFromSpace(S space, long offset, int size);

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
	protected T getFromNullSpace(int size) {
		return arithmetic.fromConst(0, size);
	}

	@Override
	public void setVar(AddressSpace space, A offset, int size, boolean quantize, T val) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.STORE);
		setVar(space, lOffset, size, quantize, val);
	}

	@Override
	public void setVar(AddressSpace space, long offset, int size, boolean quantize, T val) {
		checkRange(space, offset, size);
		if (space.isConstantSpace()) {
			throw new IllegalArgumentException("Cannot write to constant space");
		}
		if (space.isUniqueSpace()) {
			setUnique(offset, size, val);
			return;
		}
		S s = getForSpace(space, true);
		offset = quantizeOffset(space, offset);
		setInSpace(s, offset, size, val);
	}

	@Override
	public T getVar(AddressSpace space, A offset, int size, boolean quantize) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.LOAD);
		return getVar(space, lOffset, size, quantize);
	}

	@Override
	public T getVar(AddressSpace space, long offset, int size, boolean quantize) {
		checkRange(space, offset, size);
		if (space.isConstantSpace()) {
			return arithmetic.fromConst(offset, size);
		}
		if (space.isUniqueSpace()) {
			return getUnique(offset, size);
		}
		S s = getForSpace(space, false);
		if (s == null) {
			return getFromNullSpace(size);
		}
		offset = quantizeOffset(space, offset);
		return getFromSpace(s, offset, size);
	}
}
