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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Abstract class representing the applier for a specific {@link AbstractMsType}.  The
 * {@link #apply()} method creates an associated {@link DataType}, if applicable.
 * Methods associated with the {@link MsTypeApplier} or derived class will
 * make fields available to the user, first by trying to get them from the {@link DataType},
 * otherwise getting them from the {@link AbstractMsType}.
 */
public abstract class MsTypeApplier {

	protected PdbApplicator applicator;
	protected AbstractMsType msType;
	protected int index;
	protected DataType dataType;
	// separate copy for now.  Might eventually just replace dataType (above)--would have to
	//  change getDataType().
	protected DataType resolvedDataType;
	protected boolean resolved = false;
	protected boolean applied = false;

	private boolean isDeferred = false;

	protected Set<MsTypeApplier> waitSet = new HashSet<>();

	/**
	 * Constructor.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractMsType} to apply.
	 */
	public MsTypeApplier(PdbApplicator applicator, AbstractMsType msType) {
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

	/**
	 * Puts message to {@link PdbLog} and to Msg.info()
	 * @param originator a Logger instance, "this", or YourClass.class
	 * @param message the message to display
	 */
	protected void pdbLogAndInfoMessage(Object originator, String message) {
		applicator.pdbLogAndInfoMessage(originator, message);
	}

	/**
	 * Returns {@code true} if the type has been applied
	 * @return {@code true} if applied.
	 */
	boolean isApplied() {
		return applied;
	}

	/**
	 * Sets the {@code applied} flag to {@code true}
	 */
	void setApplied() {
		applied = true;
	}

	/**
	 * Sets the isDeferred flag to indicate that the application of the information should be
	 * done when the {@link @deferredApply()} method is called
	 */
	void setDeferred() {
		isDeferred = true;
	}

	/**
	 * Returns {@code true} if the application as been deferred (during the {@link #apply()}
	 * method.  The {@link #deferredApply()} method will need to be applied at the appropriate
	 * place in the processing sequence (depending on data dependency ordering) as determined
	 * and driven by the {@link PdbApplicator}.
	 * @return {@code true} if application was deferred
	 */
	boolean isDeferred() {
		return isDeferred;
	}

	/**
	 * Performs the work required in a deferred application of the data type.  This method
	 * is used by the {@link PdbApplicator} in the correct data dependency sequence.
	 * @throws PdbException on error applying the data type
	 * @throws CancelledException on user cancellation
	 */
	void deferredApply() throws PdbException, CancelledException {
		// default is to do nothing, as most appliers are not deferrable (or should not be).
	}

	/**
	 * Returns the applier for this type that needs to be called when the data type is processed
	 * in dependency order.  This will usually return "this," except in cases where there can be
	 * forward references and definition appliers for the same type.
	 * @return the applier to be used for doing the real applier work when dependency order
	 * matters.
	 */
	MsTypeApplier getDependencyApplier() {
		return this;
	}

	/**
	 * Resolves the type through the DataTypeManager and makes the resolved type primary.
	 */
	void resolve() {
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
	AbstractMsType getMsType() {
		return msType;
	}

	/**
	 * Returns the {@link DataType} associated with this applier/wrapper.
	 * @return {@link DataType} associated with this applier/wrapper.
	 */
	DataType getDataType() {
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
	abstract void apply() throws PdbException, CancelledException;

	/**
	 * Returns the size of the type or 0 if unknown.
	 * @return the size; zero if unknown.
	 */
	abstract BigInteger getSize();

	/**
	 * Returns the (long) size of the type or 0 if unknown. Or Long.MAX_VALUE if too large.
	 * @return the size; zero if unknown.
	 */
	long getSizeLong() {
		return PdbApplicator.bigIntegerToLong(applicator, getSize());
	}

	/**
	 * Returns the (int) size of the type or 0 if unknown. Or Integer.MAX_VALUE if too large.
	 * @return the size; zero if unknown.
	 */
	int getSizeInt() {
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
		MsTypeApplier other = (MsTypeApplier) obj;
		if (index != other.index) {
			return false;
		}
		if (!msType.getClass().getSimpleName().equals(other.msType.getClass().getSimpleName())) {
			return false;
		}
		return true;
	}

	protected void waitSetPut(MsTypeApplier applier) {
		waitSet.add(applier);
	}

	protected boolean waitSetRemove(MsTypeApplier applier) {
		return waitSet.remove(applier);
	}

	protected boolean waitSetIsEmpty() {
		return waitSet.isEmpty();
	}

	protected MsTypeApplier waitSetGetNext() {
		List<MsTypeApplier> list = new ArrayList<>(waitSet);
		return list.get(0);
	}

}
