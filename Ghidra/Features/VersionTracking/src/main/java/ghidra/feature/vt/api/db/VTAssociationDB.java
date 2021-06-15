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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTAssociationTableDBAdapter.AssociationTableDescriptor.*;

import java.util.Collection;

import db.DBRecord;
import ghidra.feature.vt.api.impl.MarkupItemManagerImpl;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class VTAssociationDB extends DatabaseObject implements VTAssociation {

	public DBRecord record;
	private MarkupItemManagerImpl markupManager;
	public final AssociationDatabaseManager associationDBM;

	public VTAssociationDB(AssociationDatabaseManager associationManager,
			DBObjectCache<VTAssociationDB> cache, DBRecord record) {
		super(cache, record.getKey());
		this.associationDBM = associationManager;
		this.record = record;
		markupManager = new MarkupItemManagerImpl(this);
	}

	@Override
	public void setInvalid() {
		super.setInvalid();
		markupManager.clearCache();
	}

	public VTAssociationManager getAssociationManager() {
		return associationDBM;
	}

	// this method is only on the association DB and not the interface
	public AssociationDatabaseManager getAssociationDatabaseManager() {
		return associationDBM;
	}

	public AssociationDatabaseManager getAssociationManagerDB() {
		return associationDBM;
	}

	@Override
	public VTSession getSession() {
		return associationDBM.getSession();
	}

	@Override
	public Collection<VTAssociation> getRelatedAssociations() {
		return associationDBM.getRelatedAssociationsBySourceAndDestinationAddress(
			getSourceAddress(), getDestinationAddress());
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord associationRecord) {
		if (associationRecord == null) {
			associationRecord = associationDBM.getAssociationRecord(key);
		}
		if (associationRecord == null) {
			return false;
		}
		record = associationRecord;
		return true;
	}

	@Override
	public Address getSourceAddress() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			return associationDBM.getSourceAddressFromLong(
				record.getLongValue(SOURCE_ADDRESS_COL.column()));
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public Address getDestinationAddress() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			return associationDBM.getDestinationAddressFromLong(
				record.getLongValue(DESTINATION_ADDRESS_COL.column()));
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public VTAssociationType getType() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			byte associationTypeOrdinal = record.getByteValue(TYPE_COL.column());
			return VTAssociationType.values()[associationTypeOrdinal];
		}
		finally {
			associationDBM.lock.release();
		}
	}

	public void markupItemStatusChanged(VTMarkupItem markupItem) {
		associationDBM.markupItemStatusChanged(markupItem);
	}

	@Override
	public VTAssociationStatus getStatus() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			return VTAssociationStatus.values()[record.getByteValue(STATUS_COL.column())];
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public VTAssociationMarkupStatus getMarkupStatus() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			return new VTAssociationMarkupStatus(record.getByteValue(APPLIED_STATUS_COL.column()));
		}
		finally {
			associationDBM.lock.release();
		}
	}

	DBRecord getRecord() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			return record;
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public String toString() {
		return "VTAssociation[" + getSourceAddress() + " <-> " + getDestinationAddress() + "]";
	}

	@Override
	public int hashCode() {
		return getSourceAddress().hashCode() + getDestinationAddress().hashCode();
	}

	@Override
	public void setAccepted() throws VTAssociationStatusException {
		associationDBM.setAssociationAccepted(this);
	}

	@Override
	public void setRejected() throws VTAssociationStatusException {
		VTAssociationStatus status = getStatus();
		if (status == VTAssociationStatus.REJECTED) {
			return;
		}
		if (status == VTAssociationStatus.ACCEPTED) {
			throw new VTAssociationStatusException("Can't reject an already accepted association");
		}

		setStatus(VTAssociationStatus.REJECTED);
	}

	@Override
	public void clearStatus() throws VTAssociationStatusException {
		associationDBM.clearAcceptedAssociation(this);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof VTAssociation)) {
			return false;
		}
		VTAssociation other = (VTAssociation) obj;
		return getSourceAddress().equals(other.getSourceAddress()) &&
			getDestinationAddress().equals(other.getDestinationAddress());
	}

	@Override
	public int getVoteCount() {
		associationDBM.lock.acquire();
		try {
			checkIsValid();
			return record.getIntValue(VOTE_COUNT_COL.column());
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public void setMarkupStatus(VTAssociationMarkupStatus status) {
		associationDBM.lock.acquire();
		try {
			checkDeleted();
			VTAssociationMarkupStatus existingStatus = getMarkupStatus();
			if (status.equals(existingStatus)) {
				return; // no change in status
			}

			record.setByteValue(APPLIED_STATUS_COL.column(), (byte) status.getStatusValue());
			associationDBM.updateAssociationRecord(record);
			associationDBM.getSession().setObjectChanged(
				VTChangeManager.DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED, this, existingStatus,
				status);
		}
		finally {
			associationDBM.lock.release();
		}
	}

	public void setStatus(VTAssociationStatus status) {
		associationDBM.lock.acquire();
		try {
			checkDeleted();
			VTAssociationStatus existingStatus = getStatus();
			if (status == existingStatus) {
				return; // no change in status
			}

			record.setByteValue(STATUS_COL.column(), (byte) status.ordinal());
			associationDBM.updateAssociationRecord(record);
			associationDBM.getSession().setObjectChanged(
				VTChangeManager.DOCR_VT_ASSOCIATION_STATUS_CHANGED, this, existingStatus, status);
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public void setVoteCount(int voteCount) {
		associationDBM.lock.acquire();
		try {
			checkDeleted();
			voteCount = Math.max(0, voteCount);
			record.setIntValue(VOTE_COUNT_COL.column(), voteCount);
			associationDBM.updateAssociationRecord(record);
			associationDBM.getSession().setObjectChanged(VTChangeManager.DOCR_VT_VOTE_COUNT_CHANGED,
				this, null, null);
		}
		finally {
			associationDBM.lock.release();
		}
	}

	@Override
	public Collection<VTMarkupItem> getMarkupItems(TaskMonitor monitor) throws CancelledException {
		return markupManager.getMarkupItems(monitor);
	}

	@Override
	public boolean hasAppliedMarkupItems() {
		return markupManager.hasAppliedMarkupItems();
	}
}
