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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

/**
 * An abstract executor state piece which internally uses {@code long} to address contents
 * 
 * @param <A> the type used to address contents, convertible to and from {@code long}
 * @param <T> the type of values stored
 * @param <S> the type of an execute state space, internally associated with an address space
 */
public abstract class AbstractLongOffsetPcodeExecutorStatePiece<A, T, S>
		implements PcodeExecutorStatePiece<A, T> {

	protected final Language language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final AddressSpace uniqueSpace;

	/**
	 * Construct a state piece for the given language and arithmetic
	 * 
	 * @param language the langauge (used for its memory model)
	 * @param arithmetic an arithmetic used to generate default values of {@code T}
	 */
	public AbstractLongOffsetPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<T> arithmetic) {
		this.language = language;
		this.arithmetic = arithmetic;
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
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

	/**
	 * Convert an offset of type {@code A} to {@code long}
	 * 
	 * @param offset the offset as an {@code A}
	 * @return the offset as a long
	 */
	protected abstract long offsetToLong(A offset);

	@Override
	public void setVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit,
			T val) {
		setVar(space, offsetToLong(offset), size, truncateAddressableUnit, val);
	}

	@Override
	public void setVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit,
			T val) {
		checkRange(space, offset, size);
		if (space.isConstantSpace()) {
			throw new IllegalArgumentException("Cannot write to constant space");
		}
		if (space.isUniqueSpace()) {
			setUnique(offset, size, val);
			return;
		}
		S s = getForSpace(space, true);
		offset = truncateOffset(space, offset);
		setInSpace(s, offset, size, val);
	}

	@Override
	public T getVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit) {
		return getVar(space, offsetToLong(offset), size, truncateAddressableUnit);
	}

	@Override
	public T getVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit) {
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
		offset = truncateOffset(space, offset);
		return getFromSpace(s, offset, size);
	}
}
