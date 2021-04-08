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

public abstract class AbstractLongOffsetPcodeExecutorStatePiece<A, T, S>
		implements PcodeExecutorStatePiece<A, T> {

	protected final Language language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final AddressSpace uniqueSpace;

	public AbstractLongOffsetPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<T> arithmetic) {
		this.language = language;
		this.arithmetic = arithmetic;
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
	}

	protected void setUnique(long offset, int size, T val) {
		S s = getForSpace(uniqueSpace, true);
		setInSpace(s, offset, size, val);
	}

	protected T getUnique(long offset, int size) {
		S s = getForSpace(uniqueSpace, false);
		return getFromSpace(s, offset, size);
	}

	protected abstract S getForSpace(AddressSpace space, boolean toWrite);

	protected abstract void setInSpace(S space, long offset, int size, T val);

	protected abstract T getFromSpace(S space, long offset, int size);

	protected T getFromNullSpace(int size) {
		return arithmetic.fromConst(0, size);
	}

	protected abstract long offsetToLong(A offset);

	@Override
	public void setVar(AddressSpace space, A offset, int size, boolean truncateAddressableUnit,
			T val) {
		setVar(space, offsetToLong(offset), size, truncateAddressableUnit, val);
	}

	@Override
	public void setVar(AddressSpace space, long offset, int size, boolean truncateAddressableUnit,
			T val) {
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
