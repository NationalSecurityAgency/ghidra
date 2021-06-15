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

import static ghidra.feature.vt.api.main.VTAssociationStatus.*;

import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.feature.vt.api.impl.MarkupItemStorage;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.Address;
import ghidra.util.Lock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class AssociationDatabaseManager implements VTAssociationManager {
	private VTAssociationTableDBAdapter associationTableAdapter;
	private final VTSessionDB session;

	private VTMatchMarkupItemTableDBAdapter markupItemTableAdapter;
	private DBObjectCache<MarkupItemStorageDB> markupItemCache;
	private List<AssociationHook> associationHooks = new ArrayList<>();
	private DBObjectCache<VTAssociationDB> associationCache;
	Lock lock;

	public static AssociationDatabaseManager createAssociationManager(DBHandle dbHandle,
			VTSessionDB session) throws IOException {
		AssociationDatabaseManager manager = new AssociationDatabaseManager(session);
		manager.associationTableAdapter = VTAssociationTableDBAdapter.createAdapter(dbHandle);
		manager.markupItemTableAdapter = VTMatchMarkupItemTableDBAdapter.createAdapter(dbHandle);
		return manager;
	}

	public static AssociationDatabaseManager getAssociationManager(DBHandle dbHandle,
			VTSessionDB session, OpenMode openMode, TaskMonitor monitor) throws VersionException {
		AssociationDatabaseManager manager = new AssociationDatabaseManager(session);
		manager.associationTableAdapter =
			VTAssociationTableDBAdapter.getAdapter(dbHandle, openMode, monitor);
		manager.markupItemTableAdapter =
			VTMatchMarkupItemTableDBAdapter.getAdapter(dbHandle, openMode, monitor);
		return manager;
	}

	AssociationDatabaseManager(VTSessionDB session) {
		this.session = session;
		lock = session.getLock();
		associationCache = new DBObjectCache<>(10);
		markupItemCache = new DBObjectCache<>(10);
	}

	public Collection<MarkupItemStorageDB> getAppliedMarkupItems(TaskMonitor monitor,
			VTAssociation association) throws CancelledException {

		Collection<MarkupItemStorageDB> items = new ArrayList<>();
		VTAssociationDB associationDB = (VTAssociationDB) association;
		try {
			lock.acquire();
			int recordCount = markupItemTableAdapter.getRecordCount();
			if (recordCount == 0) {
				recordCount = 1; // to give the appearance of progress
			}

			monitor.setMessage("Processing stored markup items");
			monitor.initialize(recordCount);

			RecordIterator records = markupItemTableAdapter.getRecords(associationDB.getKey());
			while (records.hasNext()) {
				monitor.checkCanceled();
				DBRecord record = records.next();
				items.add(getMarkupItemForRecord(record));
				monitor.incrementProgress(1);
			}

			monitor.setProgress(recordCount);
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return items;
	}

	DBRecord getMarkupItemRecord(long key) {
		try {
			return markupItemTableAdapter.getRecord(key);
		}
		catch (IOException e) {
			session.dbError(e);
		}
		return null;
	}

	public MarkupItemStorage addMarkupItem(MarkupItemStorage markupItemStorage) {

		VTAssociation association = markupItemStorage.getAssociation();

		try {
			setAssociationAccepted(association);
		}
		catch (VTAssociationStatusException e) {
			throw new AssertException("Attempted to add markup item on an non-accepted associaton");
		}

		return createMarkupItemDB(markupItemStorage);
	}

	void removeMarkupItem(MarkupItemStorageDB appliedMarkupItemDB) {

		VTAssociationDB association = (VTAssociationDB) appliedMarkupItemDB.getAssociation();

		validateAcceptedState(appliedMarkupItemDB, association);

		try {
			markupItemTableAdapter.removeMatchMarkupItemRecord(appliedMarkupItemDB.getKey());
		}
		catch (IOException e) {
			session.dbError(e);
		}
	}

	private void validateAcceptedState(MarkupItemStorageDB appliedItem,
			VTAssociationDB association) {
		//
		// For any 'applied' markup item we assume that its association will be 'ACCEPTED'.  The
		// exception to this rule is when we have markup items in the database, but that are not
		// applied (like when we change the destination address without applying)
		//
		VTAssociationStatus associationStatus = association.getStatus();
		VTMarkupItemStatus status = appliedItem.getStatus();
		if (status.isUnappliable()) {
			if (associationStatus != ACCEPTED) {
				throw new AssertException("Cannot have an applied markup item with an " +
					"association that is not ACCEPTED");
			}
		}
	}

	private MarkupItemStorageDB getMarkupItemForRecord(DBRecord markupItemRecord) {
		try {
			lock.acquire();
			MarkupItemStorageDB markupItem = markupItemCache.get(markupItemRecord);
			if (markupItem == null) {
				markupItem = new MarkupItemStorageDB(markupItemRecord, markupItemCache, this);
			}
			return markupItem;
		}
		finally {
			lock.release();
		}
	}

	Address getDestinationAddressFromLong(long longValue) {
		return session.getDestinationAddressFromLong(longValue);
	}

	long getLongFromDestinationAddress(Address address) {
		return session.getLongFromDestinationAddress(address);
	}

	Address getSourceAddressFromLong(long longValue) {
		return session.getSourceAddressFromLong(longValue);
	}

	DBRecord getAssociationRecord(long key) {
		try {
			return associationTableAdapter.getRecord(key);
		}
		catch (IOException e) {
			session.dbError(e);
		}
		return null;
	}

	private MarkupItemStorageDB createMarkupItemDB(MarkupItemStorage markupItem) {

		try {
			DBRecord record = markupItemTableAdapter.createMarkupItemRecord(markupItem);
			MarkupItemStorageDB appliedMarkupItem = getMarkupItemForRecord(record);
			return appliedMarkupItem;
		}
		catch (IOException e) {
			session.dbError(e);
		}

		return null;
	}

	VTAssociationDB getOrCreateAssociationDB(Address sourceAddress, Address destinationAddress,
			VTAssociationType type) {

		VTAssociationDB existingAssociation =
			getExistingAssociationDB(sourceAddress, destinationAddress);
		if (existingAssociation != null) {
			return existingAssociation;
		}

		long sourceLong = session.getLongFromSourceAddress(sourceAddress);
		long destinationLong = session.getLongFromDestinationAddress(destinationAddress);

		boolean isBlocked = isBlocked(sourceAddress, destinationAddress);

		VTAssociationDB newAssociation = null;
		try {
			lock.acquire();
			DBRecord record = associationTableAdapter.insertRecord(sourceLong, destinationLong, type,
				isBlocked ? BLOCKED : AVAILABLE, 0);
			newAssociation = new VTAssociationDB(this, associationCache, record);
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		session.setChanged(VTChangeManager.DOCR_VT_ASSOCIATION_ADDED, null, newAssociation);
		return newAssociation;
	}

	void removeAssociation(VTAssociation association) {
		VTAssociationDB existingAssociation = (VTAssociationDB) association;
		long id = existingAssociation.getKey();
		try {
			associationTableAdapter.removeAssociaiton(id);
			session.setChanged(VTChangeManager.DOCR_VT_ASSOCIATION_REMOVED, existingAssociation,
				null);
		}
		catch (IOException e) {
			session.dbError(e);
		}
		associationCache.delete(id);
		existingAssociation.setInvalid();

	}

	private boolean isBlocked(VTAssociation association) {
		return isBlocked(association.getSourceAddress(), association.getDestinationAddress());
	}

	private boolean isBlocked(Address sourceAddress, Address destinationAddress) {
		long sourceID = session.getLongFromSourceAddress(sourceAddress);
		long destinationID = session.getLongFromDestinationAddress(destinationAddress);
		try {
			Set<DBRecord> relatedRecords =
				associationTableAdapter.getRelatedAssociationRecordsBySourceAndDestinationAddress(
					sourceID, destinationID);
			for (DBRecord record : relatedRecords) {
				VTAssociationDB associationDB = getAssociationForRecord(record);
				VTAssociationStatus status = associationDB.getStatus();
				if (status == ACCEPTED) {
					return true;
				}
			}
		}
		catch (IOException e) {
			session.dbError(e);
		}

		return false;
	}

	@Override
	public int getAssociationCount() {
		return associationTableAdapter.getRecordCount();
	}

	@Override
	public List<VTAssociation> getAssociations() {
		List<VTAssociation> list = new ArrayList<>();
		lock.acquire();
		try {
			RecordIterator iterator = associationTableAdapter.getRecords();
			for (; iterator.hasNext();) {
				DBRecord nextRecord = iterator.next();
				list.add(getAssociationForRecord(nextRecord));
			}
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return list;
	}

	@Override
	public VTAssociation getAssociation(Address sourceAddress, Address destinationAddress) {
		lock.acquire();
		try {
			long addressKey = session.getLongFromSourceAddress(sourceAddress);
			RecordIterator iterator =
				associationTableAdapter.getRecordsForSourceAddress(addressKey);
			while (iterator.hasNext()) {
				DBRecord record = iterator.next();
				VTAssociationDB associationDB = getAssociationForRecord(record);
				if (associationDB.getDestinationAddress().equals(destinationAddress)) {
					return associationDB;
				}
			}
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	VTAssociationDB getExistingAssociationDB(Address sourceAddress, Address destinationAddress) {

		long addressKey = session.getLongFromSourceAddress(sourceAddress);
		try {
			RecordIterator iterator =
				associationTableAdapter.getRecordsForSourceAddress(addressKey);
			while (iterator.hasNext()) {
				DBRecord record = iterator.next();
				VTAssociationDB associationDB = getAssociationForRecord(record);
				Address dbDestinatonAddress = associationDB.getDestinationAddress();
				if (destinationAddress.equals(dbDestinatonAddress)) {
					return associationDB;
				}
			}
		}
		catch (IOException e) {
			session.dbError(e);
		}

		return null;
	}

	private VTAssociationDB getAssociationForRecord(DBRecord record) {
		if (record == null) {
			throw new AssertException("How can we have a null record?!!!");
		}
		try {
			lock.acquire();
			VTAssociationDB associationDB = associationCache.get(record);
			if (associationDB == null) {
				associationDB = new VTAssociationDB(this, associationCache, record);
			}
			return associationDB;
		}
		finally {
			lock.release();
		}
	}

	VTAssociationDB getAssociation(long associationKey) {
		try {
			lock.acquire();
			VTAssociationDB associationDB = associationCache.get(associationKey);
			if (associationDB != null) {
				return associationDB;
			}
			DBRecord record = associationTableAdapter.getRecord(associationKey);
			if (record == null) {
				return null;
			}
			return new VTAssociationDB(this, associationCache, record);
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	public VTSessionDB getSession() {
		return session;
	}

	@Override
	public Collection<VTAssociation> getRelatedAssociationsBySourceAddress(Address sourceAddress) {
		lock.acquire();
		try {
			long sourceID = session.getLongFromSourceAddress(sourceAddress);
			Set<DBRecord> relatedRecords =
				associationTableAdapter.getRelatedAssociationRecordsBySourceAddress(sourceID);
			List<VTAssociation> associations = new ArrayList<>();
			for (DBRecord record : relatedRecords) {
				associations.add(getAssociationForRecord(record));
			}
			return associations;
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return Collections.emptyList();
	}

	@Override
	public Collection<VTAssociation> getRelatedAssociationsByDestinationAddress(
			Address destinationAddress) {
		lock.acquire();
		try {
			long destinationID = session.getLongFromDestinationAddress(destinationAddress);
			Set<DBRecord> relatedRecords =
				associationTableAdapter.getRelatedAssociationRecordsByDestinationAddress(
					destinationID);
			List<VTAssociation> associations = new ArrayList<>();
			for (DBRecord record : relatedRecords) {
				associations.add(getAssociationForRecord(record));
			}
			return associations;
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return Collections.emptyList();
	}

	@Override
	public Collection<VTAssociation> getRelatedAssociationsBySourceAndDestinationAddress(
			Address sourceAddress, Address destinationAddress) {
		lock.acquire();
		try {
			long sourceID = session.getLongFromSourceAddress(sourceAddress);
			long destinationID = session.getLongFromDestinationAddress(destinationAddress);
			Set<DBRecord> relatedRecords =
				associationTableAdapter.getRelatedAssociationRecordsBySourceAndDestinationAddress(
					sourceID, destinationID);
			List<VTAssociation> associations = new ArrayList<>();
			for (DBRecord record : relatedRecords) {
				associations.add(getAssociationForRecord(record));
			}
			return associations;
		}
		catch (IOException e) {
			session.dbError(e);
		}
		finally {
			lock.release();
		}
		return Collections.emptyList();
	}

	void clearAcceptedAssociation(VTAssociation association) throws VTAssociationStatusException {

		VTAssociationStatus status = association.getStatus();
		if (status != ACCEPTED && status != REJECTED) {
			throw new VTAssociationStatusException("Cannot clear an association that " +
				"is not already ACCEPTED or REJECTED - current status: " + status);
		}

		VTAssociationDB associationDB = (VTAssociationDB) association;

		// validate that we cannot clear the accepted state of the given association while it
		// has applied markup items
		verifyAssociationContainsNoAppliedMarkupItems(association);

		if (status == ACCEPTED) {
			associationDB.setStatus(AVAILABLE);
			associationDB.setInvalid();
			unblockRelatedAssociations(associationDB);
			for (AssociationHook hook : associationHooks) {
				hook.associationCleared(associationDB);
			}
		}
		else {
			associationDB.setStatus(isBlocked(associationDB) ? BLOCKED : AVAILABLE);
		}
	}

	void setAssociationAccepted(VTAssociation association) throws VTAssociationStatusException {

		VTAssociationStatus status = association.getStatus();
		if (status == ACCEPTED) {
			return;
		}

		if (status.isBlocked()) {
			throw new VTAssociationStatusException("Cannot ACCEPT a blocked association!");
		}

		VTAssociationDB associationDB = (VTAssociationDB) association;
		associationDB.setStatus(ACCEPTED);
		blockRelatedAssociations(associationDB);
		for (AssociationHook hook : associationHooks) {
			hook.associationAccepted(associationDB);
		}
	}

	private void verifyAssociationContainsNoAppliedMarkupItems(VTAssociation association)
			throws VTAssociationStatusException {
		if (association.hasAppliedMarkupItems()) {
			throw new VTAssociationStatusException(
				"VTMarkupItemManager contains applied " + "markup items");
		}
	}

	private void blockRelatedAssociations(VTAssociationDB association) {
		Set<VTAssociationDB> relatedAssociations = getRelatedAssociations(association);
		for (VTAssociationDB relatedAssociation : relatedAssociations) {
			VTAssociationStatus status = relatedAssociation.getStatus();
			switch (status) {
				case ACCEPTED:
					throw new AssertException("Attempted to block already accepted association!");
				case AVAILABLE:
					relatedAssociation.setStatus(BLOCKED);
					break;
				case BLOCKED:
					break; // already blocked
				case REJECTED:
					break; // rejected has precedence

			}
		}
	}

	private void unblockRelatedAssociations(VTAssociationDB association) {
		Set<VTAssociationDB> relatedAssociations = getRelatedAssociations(association);
		for (VTAssociationDB relatedAssociation : relatedAssociations) {
			VTAssociationStatus status = relatedAssociation.getStatus();
			switch (status) {
				case ACCEPTED:
				case AVAILABLE:
					throw new AssertException("Attempted to unblock a non-blocked association!");
				case BLOCKED:
					relatedAssociation.setInvalid();
					relatedAssociation.setStatus(computeBlockedStatus(relatedAssociation));
					break;
				case REJECTED:
					break; // rejected is still rejected

			}
		}
	}

	private VTAssociationStatus computeBlockedStatus(VTAssociationDB association) {
		Set<VTAssociationDB> relatedAssociations = getRelatedAssociations(association);
		for (VTAssociationDB relatedAssociation : relatedAssociations) {
			if (relatedAssociation.getStatus() == ACCEPTED) {
				return BLOCKED;
			}
		}
		return AVAILABLE;
	}

	private Set<VTAssociationDB> getRelatedAssociations(VTAssociationDB association) {
		long sourceID = session.getLongFromSourceAddress(association.getSourceAddress());
		long destinationID =
			session.getLongFromDestinationAddress(association.getDestinationAddress());

		Set<VTAssociationDB> relatedAssociaitons = new HashSet<>();
		try {
			Set<DBRecord> relatedRecords =
				associationTableAdapter.getRelatedAssociationRecordsBySourceAndDestinationAddress(
					sourceID, destinationID);
			relatedRecords.remove(association.getRecord()); // don't change the given association
			for (DBRecord record : relatedRecords) {
				relatedAssociaitons.add(getAssociationForRecord(record));
			}
		}
		catch (IOException e) {
			session.dbError(e);
		}
		return relatedAssociaitons;
	}

	void updateAssociationRecord(DBRecord record) {
		try {
			associationTableAdapter.updateRecord(record);
		}
		catch (IOException e) {
			session.dbError(e);
		}
	}

	void updateMarkupRecord(DBRecord record) {
		try {
			markupItemTableAdapter.updateRecord(record);
		}
		catch (IOException e) {
			session.dbError(e);
		}
	}

	void invalidateCache() {
		associationCache.invalidate();
		markupItemCache.invalidate();
	}

	void addAssociationHook(AssociationHook hook) {
		associationHooks.add(hook);
	}

	void removeAssociationHook(AssociationHook hook) {
		associationHooks.remove(hook);
	}

	void removeMarkupRecord(DBRecord record) {
		try {
			markupItemTableAdapter.removeMatchMarkupItemRecord(record.getKey());
		}
		catch (IOException e) {
			session.dbError(e);
		}
	}

	void markupItemStatusChanged(VTMarkupItem markupItem) {
		for (AssociationHook hook : associationHooks) {
			hook.markupItemStatusChanged(markupItem);
		}
	}

}
