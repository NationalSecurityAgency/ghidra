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
package ghidra.app.plugin.core.datamgr;

import java.util.Date;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.DateUtils;
import ghidra.util.UniversalID;

public class DataTypeSyncInfo {

	private final DataType refDt;
	private final DataType sourceDt;
	private final DataTypeManager sourceDTM;
	private final DataTypeSyncState syncState;

	public DataTypeSyncInfo(DataType refDt, DataTypeManager sourceDTM) {
		this.refDt = refDt;
		this.sourceDTM = sourceDTM;
		UniversalID dtId = refDt.getUniversalID();
		if (sourceDTM != null && dtId != null) {
			sourceDt = sourceDTM.getDataType(sourceDTM.getLocalSourceArchive(), dtId);
		}
		else {
			sourceDt = null;
		}
		syncState = computeSyncState();
	}

	public DataTypeSyncState getSyncState() {
		return syncState;
	}

	private DataTypeSyncState computeSyncState() {
		if (sourceDTM == null) {
			return DataTypeSyncState.UNKNOWN;
		}
		if (sourceDt == null) {
			return DataTypeSyncState.ORPHAN;
		}
		if (canUpdate()) {
			return canCommit() ? DataTypeSyncState.CONFLICT : DataTypeSyncState.UPDATE;
		}
		if (canCommit()) {
			return DataTypeSyncState.COMMIT;
		}
		return DataTypeSyncState.IN_SYNC;
	}

	public boolean canUpdate() {
		if (sourceDt == null) {
			return false;
		}
		if (sourceDt.getLastChangeTime() == refDt.getLastChangeTimeInSourceArchive()) {
			// no change to source
			return false;
		}
		// Special case where user committed changes to archive, but then didn't save the archive. 
		if (refDt.getLastChangeTimeInSourceArchive() > sourceDt.getLastChangeTime()) {
			// our previous commit was not saved
			return false;
		}
		return true;
	}

	public boolean canCommit() {
		if (sourceDt == null) {
			return true;
		}
		if (refDt.getLastChangeTime() != refDt.getLastChangeTimeInSourceArchive()) {
			// normal commit case
			return true;
		}
		// Special case where user committed changes to archive, but then didn't save the archive. 
		if (refDt.getLastChangeTimeInSourceArchive() > sourceDt.getLastChangeTime()) {
			// our previous commit was not saved
			return true;
		}
		// no change
		return false;
	}

	public boolean canRevert() {
		return sourceDt != null && canCommit();
	}

	/**
	 * Commits the data type to the source archive.
	 * Call canCommit() to check the state before calling this.
	 * @see #canCommit()
	 */
	public void commit() {
		DataTypeSynchronizer.commitAssumingTransactionsOpen(sourceDTM, refDt);
	}

	/**
	 * Updates the data type from the one in the source archive.
	 * Call canUpdate() to check the state before calling this.
	 * @see #canUpdate()
	 */
	public void update() {
		DataTypeSynchronizer.updateAssumingTransactionsOpen(refDt.getDataTypeManager(), sourceDt);
	}

	/**
	 * Reverts the data type to match the one in the source archive.
	 * Call canRevert() to check the state before calling this.
	 * @see #canRevert()
	 */
	public void revert() {
		DataTypeSynchronizer.updateAssumingTransactionsOpen(refDt.getDataTypeManager(), sourceDt);
	}

	/**
	 * Disassociates this DataTypeSyncInfo's data type from its source archive.
	 */
	public void disassociate() {
		DataTypeManager refDTM = refDt.getDataTypeManager();
		refDTM.disassociate(refDt);
	}

	public String getSourceDtPath() {
		if (sourceDt == null) {
			return "";
		}
		return sourceDt.getPathName();
	}

	public String getRefDtPath() {
		return refDt.getPathName();
	}

	public long getLastChangeTime(boolean useSource) {
		DataType dt = useSource ? sourceDt : refDt;
		if (canUpdate()) {
			return dt.getLastChangeTime();
		}
		return Long.MAX_VALUE;
	}

	public String getLastChangeTimeString(boolean useSource) {
		DataType dt = useSource ? sourceDt : refDt;
		if (canUpdate()) {
			return getDateString(dt.getLastChangeTime());
		}
		return "";
	}

	public String getLastSyncTimeString() {
		return getDateString(refDt.getLastChangeTimeInSourceArchive());
	}

	public long getLastSyncTime() {
		return refDt.getLastChangeTimeInSourceArchive();
	}

	private String getDateString(long date) {
		if (date == 0) {
			return "";
		}
		return DateUtils.formatDateTimestamp(new Date(date));
	}

	public DataType getRefDataType() {
		return refDt;
	}

	public DataType getSourceDataType() {
		return sourceDt;
	}

	public boolean hasChange() {
		if (sourceDt == null) {
			return true;
		}
		if (!DataTypeSynchronizer.namesAreEquivalent(sourceDt, refDt)) {
			return true;
		}
		if (!StringUtils.equals(refDt.getDescription(), sourceDt.getDescription())) {
			return true;
		}
		DataType dt = sourceDt.clone(refDt.getDataTypeManager());
		return !dt.isEquivalent(refDt);
	}

	public void syncTimes() {
		if (sourceDt == null) {
			throw new IllegalStateException("Can't sync datatypes with missing source datatype.");
		}
		long lastChangeTime = sourceDt.getLastChangeTime();
		refDt.setLastChangeTimeInSourceArchive(lastChangeTime);
		refDt.setLastChangeTime(lastChangeTime);
	}

	public String getName() {
		return refDt.getName();
	}

}
