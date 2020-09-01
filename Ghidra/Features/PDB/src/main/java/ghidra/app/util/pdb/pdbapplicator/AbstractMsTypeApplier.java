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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Abstract class representing the applier/wrapper for a specific {@link AbstractMsType}.  The
 *  {link {@link #apply()} method creates an associated {@link DataType}, if
 *  applicable.  Methods associated with the {@link AbstractMsTypeApplier} or derived class will
 *  make fields available to the user, first by trying to get them from the {@link DataType},
 *  otherwise getting them from the {@link AbstractMsType}.
 */
public abstract class AbstractMsTypeApplier implements Comparable<AbstractMsTypeApplier> {

	protected PdbApplicator applicator;
	protected AbstractMsType msType;
	protected int index;
	protected DataType dataType;
	// separate copy for now.  Might eventually just replace dataType (above)--would have to
	//  change getDataType().
	protected DataType resolvedDataType;
	protected boolean resolved = false;
	protected boolean applied = false;

	protected Set<AbstractMsTypeApplier> waitSet = new HashSet<>();

	/**
	 * Constructor.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractMsType} to apply.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public AbstractMsTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		if (msType == null) {
			throw new IllegalArgumentException("PDB Type Applying null AbstractMsType");
		}
		this.applicator = applicator;
		this.msType = msType;
		RecordNumber recordNumber = msType.getRecordNumber();
		if (recordNumber != null) {
			index = recordNumber.getNumber();
		}
		else {
			index = -1;
		}
		dataType = null;
	}

	public boolean isApplied() {
		return applied;
	}

	public void setApplied() {
		applied = true;
	}

	boolean isDeferred() {
		return false;
	}

	void deferredApply() throws PdbException, CancelledException {
		// default is to do nothing, as most appliers are not deferrable (or should not be).
	}

	public AbstractMsTypeApplier getDependencyApplier() {
		return this;
	}

	/**
	 * Resolves the type through the DataTypeManager and makes the resolved type primary.
	 */
	public void resolve() {
		if (resolved) {
			return;
		}
		if (dataType != null) {
			resolvedDataType = applicator.resolve(dataType);
		}
		resolved = true;
	}

	/**
	 * Returns the {@link AbstractMsType} associated with this applier/wrapper.
	 * @return {@link AbstractMsType} associated with this applier/wrapper.
	 */
	public AbstractMsType getMsType() {
		return msType;
	}

	/**
	 * Returns the {@link DataType} associated with this applier/wrapper.
	 * @return {@link DataType} associated with this applier/wrapper.
	 */
	public DataType getDataType() {
		if (resolved) {
			return resolvedDataType;
		}
		return dataType;
	}

	/**
	 * Returns either a DataTypeDB or an type (IMPL that might be an empty container) that
	 * suffices to break cyclical dependencies in data type generation.
	 * @return the data type.
	 */
	DataType getCycleBreakType() {
		return getDataType();
	}

	/**
	 * Apply the {@link AbstractMsType} in an attempt to create a Ghidra type.
	 * @throws PdbException if there was a problem processing the data.
	 * @throws CancelledException upon user cancellation
	 */
	public abstract void apply() throws PdbException, CancelledException;

	/**
	 * Returns the size of the type or 0 if unknown.
	 * @return the size; zero if unknown.
	 */
	public abstract BigInteger getSize();

	/**
	 * Returns the (long) size of the type or 0 if unknown. Or Long.MAX_VALUE if too large.
	 * @return the size; zero if unknown.
	 */
	public long getSizeLong() {
		return PdbApplicator.bigIntegerToLong(applicator, getSize());
	}

	/**
	 * Returns the (int) size of the type or 0 if unknown. Or Integer.MAX_VALUE if too large.
	 * @return the size; zero if unknown.
	 */
	public int getSizeInt() {
		return PdbApplicator.bigIntegerToInt(applicator, getSize());
	}

	@Override
	public String toString() {
		return msType.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + index;
		result = prime * result + msType.getClass().getSimpleName().hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		AbstractMsTypeApplier other = (AbstractMsTypeApplier) obj;
		if (index != other.index) {
			return false;
		}
		if (!msType.getClass().getSimpleName().equals(other.msType.getClass().getSimpleName())) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(AbstractMsTypeApplier o) {
		int val = hashCode() - o.hashCode();
		return val;
	}

	protected void waitSetPut(AbstractMsTypeApplier applier) {
		waitSet.add(applier);
	}

	protected boolean waitSetRemove(AbstractMsTypeApplier applier) {
		return waitSet.remove(applier);
	}

	protected boolean waitSetIsEmpty() {
		return waitSet.isEmpty();
	}

	protected AbstractMsTypeApplier waitSetGetNext() {
		List<AbstractMsTypeApplier> list = new ArrayList<>(waitSet);
		return list.get(0);
	}

}
