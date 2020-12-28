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

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import db.*;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.feature.vt.api.correlator.program.ImpliedMatchProgramCorrelator;
import ghidra.feature.vt.api.correlator.program.ManualMatchProgramCorrelator;
import ghidra.feature.vt.api.impl.*;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.*;

public class VTSessionDB extends DomainObjectAdapterDB implements VTSession, VTChangeManager {
	private final static Field[] COL_FIELDS = new Field[] { StringField.INSTANCE };
	private final static String[] COL_TYPES = new String[] { "Value" };
	private final static Schema SCHEMA =
		new Schema(0, StringField.INSTANCE, "Key", COL_FIELDS, COL_TYPES);

	private static final String PROGRAM_ID_PROPERTYLIST_NAME = "ProgramIDs";
	private static final String SOURCE_PROGRAM_ID_PROPERTY_KEY = "SourceProgramID";
	private static final String DESTINATION_PROGRAM_ID_PROPERTY_KEY = "DestinationProgramID";
	private static final String UNUSED_DEFAULT_NAME = "Untitled";
	private static final int EVENT_NOTIFICATION_DELAY = 500;
	private static final int EVENT_BUFFER_SIZE = 100;

	private static final long MANUAL_MATCH_SET_ID = 0;
	private static final long IMPLIED_MATCH_SET_ID = -1;
	private static final String PROPERTY_TABLE_NAME = "PropertyTable";
	private static final String DB_VERSION_PROPERTY_NAME = "DB_VERSION";

	/**
	 * DB_VERSION should be incremented any time a change is made to the overall
	 * database schema associated with any of the adapters.
	 * 14-Nov-2019 - version 2 - Corrected fixed length indexing implementation causing
	 *                           change in index table low-level storage for newly
	 *                           created tables. 
	 */
	private static final int DB_VERSION = 2;

	/**
	 * UPGRADE_REQUIRED_BFORE_VERSION should be changed to DB_VERSION any time the
	 * latest version requires a forced upgrade (i.e., Read-only mode not supported
	 * until upgrade is performed).  It is assumed that read-only mode is supported
	 * if the data's version is >= UPGRADE_REQUIRED_BEFORE_VERSION and <= DB_VERSION.
	 */
	// NOTE: Schema upgrades are not currently supported
	private static final int UPGRADE_REQUIRED_BEFORE_VERSION = 1;

	private VTMatchSetTableDBAdapter matchSetTableAdapter;
	private AssociationDatabaseManager associationManager;
	private VTMatchTagDBAdapter matchTagAdapter;
	private DBObjectCache<VTMatchTagDB> tagCache = new DBObjectCache<>(10);

	private Program sourceProgram;
	private Program destinationProgram;
	private List<VTMatchSetDB> matchSets = new CopyOnWriteArrayList<>();
	private VTMatchSet manualMatchSet;
	private VTMatchSet impliedMatchSet;

	private boolean changeSetsModified = false;
	private Table propertyTable;

	public static VTSessionDB createVTSession(String name, Program sourceProgram,
			Program destinationProgram, Object consumer) throws IOException {

		VTSessionDB session = new VTSessionDB(new DBHandle(), consumer);

		int ID = session.startTransaction("Constructing New Version Tracking Match Set");
		try {
			session.propertyTable = session.dbh.createTable(PROPERTY_TABLE_NAME, SCHEMA);
			session.matchSetTableAdapter = VTMatchSetTableDBAdapter.createAdapter(session.dbh);
			session.associationManager =
				AssociationDatabaseManager.createAssociationManager(session.dbh, session);
			session.matchTagAdapter = VTMatchTagDBAdapter.createAdapter(session.dbh);
			session.initializePrograms(sourceProgram, destinationProgram);
			session.createMatchSet(
				new ManualMatchProgramCorrelator(sourceProgram, destinationProgram),
				MANUAL_MATCH_SET_ID);
			session.createMatchSet(
				new ImpliedMatchProgramCorrelator(sourceProgram, destinationProgram),
				IMPLIED_MATCH_SET_ID);
			session.updateVersion();
		}
		finally {
			session.endTransaction(ID, true);
		}
		try {
			session.addSynchronizedDomainObject(destinationProgram);
		}
		catch (Exception e) {
			session.close();
			throw new RuntimeException(e.getMessage(), e);
		}
		return session;
	}

	private void updateVersion() throws IOException {
		DBRecord record = SCHEMA.createRecord(new StringField(DB_VERSION_PROPERTY_NAME));
		record.setString(0, Integer.toString(DB_VERSION));
		propertyTable.putRecord(record);
	}

	public static VTSessionDB getVTSession(DBHandle dbHandle, OpenMode openMode, Object consumer,
			TaskMonitor monitor) throws VersionException, IOException {

		VTSessionDB session = new VTSessionDB(dbHandle, consumer);
		int storedVersion = session.getVersion();

		if (storedVersion > DB_VERSION) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
		// The following version logic holds true for DB_VERSION=2 which assumes no additional
		// DB index tables will be added when open for update/upgrade.  This will not hold
		// true for future revisions associated with table schema changes in which case the
		// UPGRADE_REQUIRED_BEFORE_VERSION value should equal DB_VERSION.
		if (storedVersion < UPGRADE_REQUIRED_BEFORE_VERSION) {
			throw new VersionException("Version Tracking Sessions do not support schema upgrades.");
		}

		session.matchSetTableAdapter =
			VTMatchSetTableDBAdapter.getAdapter(session.getDBHandle(), openMode, monitor);
		session.associationManager =
			AssociationDatabaseManager.getAssociationManager(dbHandle, session, openMode, monitor);
		session.matchTagAdapter =
			VTMatchTagDBAdapter.getAdapter(session.getDBHandle(), openMode, monitor);
		session.loadMatchSets(openMode, monitor);
		return session;
	}

	@SuppressWarnings("hiding")
	// this is from our constructor
	private void initializePrograms(Program sourceProgram, Program destinationProgram) {
		this.sourceProgram = sourceProgram;
		this.destinationProgram = destinationProgram;
		sourceProgram.addConsumer(this);
		destinationProgram.addConsumer(this);
		Options properties = getOptions(PROGRAM_ID_PROPERTYLIST_NAME);
		DomainFile sourceDomainFile = sourceProgram.getDomainFile();
		properties.setString(SOURCE_PROGRAM_ID_PROPERTY_KEY, sourceDomainFile.getFileID());
		DomainFile destinationDomainFile = destinationProgram.getDomainFile();
		properties.setString(DESTINATION_PROGRAM_ID_PROPERTY_KEY,
			destinationDomainFile.getFileID());

	}

	@Override
	public void updateDestinationProgram(Program newProgram) {
		try {
			releaseSynchronizedDomainObject();
		}
		catch (LockException e) {
			Msg.showError(this, null, "Error releasing synchronization to old program", e);
		}
		destinationProgram.release(this);
		destinationProgram = newProgram;
		destinationProgram.addConsumer(this);
		try {
			addSynchronizedDomainObject(destinationProgram);
		}
		catch (Exception e) {
			sourceProgram.release(this);
			destinationProgram.release(this);
			throw new RuntimeException(e.getMessage());
		}
	}

	@Override
	public void updateSourceProgram(Program newProgram) {
		sourceProgram.release(this);
		sourceProgram = newProgram;
		sourceProgram.addConsumer(this);
	}

	public String getSourceProgramID() {
		Options properties = getOptions(PROGRAM_ID_PROPERTYLIST_NAME);
		return properties.getString(SOURCE_PROGRAM_ID_PROPERTY_KEY, "");
	}

	public String getDestinationProgramID() {
		Options properties = getOptions(PROGRAM_ID_PROPERTYLIST_NAME);
		return properties.getString(DESTINATION_PROGRAM_ID_PROPERTY_KEY, "");
	}

	private VTSessionDB(DBHandle dbHandle, Object consumer) {
		super(dbHandle, UNUSED_DEFAULT_NAME, EVENT_NOTIFICATION_DELAY, EVENT_BUFFER_SIZE, consumer);
		propertyTable = dbHandle.getTable(PROPERTY_TABLE_NAME);
	}

	public int getVersion() throws IOException {
		// DB Version was added in release (11/6/2012)
		// if record does not exist return 0;
		if (propertyTable == null) {
			return 0;
		}
		DBRecord record = propertyTable.getRecord(new StringField(DB_VERSION_PROPERTY_NAME));

		if (record != null) {
			String s = record.getString(0);
			try {
				return Integer.parseInt(s);
			}
			catch (NumberFormatException e) {
				// just use default
			}
		}
		return 0;

	}

	@Override
	protected void setDomainFile(DomainFile df) {
		super.setDomainFile(df);
		DomainFolder parent = df.getParent();
		if (parent == null) {
			return;
		}
		if (sourceProgram != null) { // source and destination are already open
			return;
		}
		ProjectData projectData = parent.getProjectData();
		String sourceProgramID = getSourceProgramID();
		String destinationProgramID = getDestinationProgramID();
		DomainFile sourceFile = projectData.getFileByID(sourceProgramID);
		DomainFile destinationFile = projectData.getFileByID(destinationProgramID);
		if (sourceFile == null) {
			throw new RuntimeException(
				"Source program is missing for this Version Tracking Session!");
		}
		if (destinationFile == null) {
			throw new RuntimeException(
				"Destination program is missing for this Version Tracking Session!");
		}

		sourceProgram = openProgram(sourceFile, true);

		if (sourceProgram != null) {
			destinationProgram = openProgram(destinationFile, false);
		}

		if (sourceProgram == null || destinationProgram == null) {
			StringBuilder buffer = new StringBuilder(
				"Session not opened because one or both programs did not open.\n");
			if (sourceProgram != null) {
				sourceProgram.release(this);
				sourceProgram = null;
			}
			else {
				buffer.append("\tUnable to open source program \"" + sourceFile + "\"\n");
			}

			if (destinationProgram != null) {
				destinationProgram.release(this);
				destinationProgram = null;
			}
			else {
				buffer.append("\tUnable to open destination program \"" + destinationFile + "\"\n");
			}

			throw new RuntimeException(buffer.toString());
		}

		try {
			addSynchronizedDomainObject(destinationProgram);
		}
		catch (Exception e) {
			sourceProgram.release(this);
			destinationProgram.release(this);
			throw new RuntimeException(e.getMessage());
		}

	}

	private Program openProgram(DomainFile domainFile, boolean isSource) {

		OpenProgramTask openTask = new OpenProgramTask(domainFile, this);
		String type = isSource ? "(source program)" : "(destination program)";
		openTask.setOpenPromptText("Open " + type);

		TaskLauncher.launch(openTask);

		return openTask.getOpenProgram();
	}

	@Override
	public void release(Object consumer) {
		super.release(consumer);
		if (isClosed()) {
			if (sourceProgram != null) {
				sourceProgram.release(this);
				sourceProgram = null;
			}
			if (destinationProgram != null) {
				destinationProgram.release(this);
				destinationProgram = null;
			}
		}
	}

	/**
	 * @see ghidra.framework.data.DomainObjectAdapterDB#clearCache()
	 */
	@Override
	protected void clearCache(boolean all) {
		lock.acquire();
		try {
			super.clearCache(all);
			associationManager.invalidateCache();
			tagCache.invalidate();

			List<VTMatchSetDB> temp = new ArrayList<>();

			for (VTMatchSetDB matchSet : matchSets) {
				if (!matchSet.isInvalid()) {
					matchSet.invalidateCache();
					temp.add(matchSet);
				}
			}

			matchSets.retainAll(temp);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void save() throws IOException {
		try {
			save(DESTINATION_PROGRAM_ID_PROPERTY_KEY, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// can't happen because we are using a dummy monitor
		}
	}

	private void loadMatchSets(OpenMode openMode, TaskMonitor monitor)
			throws IOException, VersionException {
		RecordIterator recordIterator = matchSetTableAdapter.getRecords();
		while (recordIterator.hasNext()) {
			DBRecord record = recordIterator.next();
			matchSets.add(
				VTMatchSetDB.getMatchSetDB(record, this, getDBHandle(), openMode, monitor, lock));
		}
	}

	@Override
	public Program getSourceProgram() {
		return sourceProgram;
	}

	@Override
	public Program getDestinationProgram() {
		return destinationProgram;
	}

	@Override
	public VTMatchSet createMatchSet(VTProgramCorrelator correlator) {
		try {
			lock.acquire();
			long id = matchSetTableAdapter.getNextMatchSetID();
			return createMatchSet(correlator, id);
		}
		finally {
			lock.release();
		}
	}

	private VTMatchSet createMatchSet(VTProgramCorrelator correlator, long id) {
		try {
			DBRecord record = matchSetTableAdapter.createMatchSetRecord(id, correlator);
			VTMatchSetDB matchSet =
				VTMatchSetDB.createMatchSetDB(record, this, getDBHandle(), lock);
			matchSets.add(matchSet);
			changeSetsModified = true; // signal endTransaction to clear undo stack

			setObjectChanged(VTChangeManager.DOCR_VT_MATCH_SET_ADDED, matchSet, null, matchSet);

			return matchSet;
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	DBRecord getMatchSetRecord(long key) {
		try {
			return matchSetTableAdapter.getRecord(key);
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	long getLongFromSourceAddress(Address address) {
		if (address == null) {
			throw new NullPointerException("You must always have a valid source address!");
		}

		AddressMap addressMap = sourceProgram.getAddressMap();
		return addressMap.getKey(address, false);
	}

	long getLongFromDestinationAddress(Address address) {
		if (address == null) {
			return AddressMap.INVALID_ADDRESS_KEY;
		}

		AddressMap addressMap = destinationProgram.getAddressMap();
		return addressMap.getKey(address, false);
	}

	Address getSourceAddressFromLong(long value) {
		if (AddressMap.INVALID_ADDRESS_KEY == value) {
			throw new AssertException("How can we have an invalid address for the source?!?");
		}

		AddressMap addressMap = sourceProgram.getAddressMap();
		return addressMap.decodeAddress(value);
	}

	Address getDestinationAddressFromLong(long value) {
		if (AddressMap.INVALID_ADDRESS_KEY == value) {
			return null;
		}

		AddressMap addressMap = destinationProgram.getAddressMap();
		return addressMap.decodeAddress(value);
	}

	@Override
	public List<VTMatchSet> getMatchSets() {
		return new ArrayList<>(matchSets);
	}

	AddressSet getSourceAddressSet(DBRecord record) throws IOException {
		return matchSetTableAdapter.getSourceAddressSet(record, sourceProgram.getAddressMap());
	}

	AddressSet getDestinationAddressSet(DBRecord record) throws IOException {
		return matchSetTableAdapter.getDestinationAddressSet(record,
			destinationProgram.getAddressMap());
	}

	@Override
	public VTAssociationManager getAssociationManager() {
		return associationManager;
	}

	/** Package-level methods for accessing DB-related manager */
	public AssociationDatabaseManager getAssociationManagerDBM() {
		return associationManager;
	}

//==================================================================================================
// Inherited Methods
//==================================================================================================

	// We want the name to be the same as the DomainFile.
	@Override
	public String getName() {
		return getDomainFile().getName();
	}

	@Override
	public String getDescription() {
		return "Version Tracking Results";
	}

	@Override
	public boolean isChangeable() {
		return true;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public void setChanged(int type, Object oldValue, Object newValue) {
//        if (recordChanges) {
//        	updateChangeSet(newstart, newend);
//        }
		changed = true;

		fireEvent(new VersionTrackingChangeRecord(type, null, oldValue, newValue));
	}

	@Override
	public List<VTMatch> getMatches(VTAssociation association) {
		List<VTMatch> matches = new ArrayList<>();
		for (VTMatchSet matchSet : matchSets) {
			matches.addAll(matchSet.getMatches(association));
		}
		return matches;
	}

	@Override
	public void setObjectChanged(int type, Object affectedObject, Object oldValue,
			Object newValue) {
//        if (recordChanges) {
//        	updateChangeSet(newstart, newend);
//        }
		changed = true;

		fireEvent(new VersionTrackingChangeRecord(type, affectedObject, oldValue, newValue));
	}

	@Override
	public VTMatchSet getManualMatchSet() {
		if (manualMatchSet == null) {
			manualMatchSet = findMatchSet(ManualMatchProgramCorrelator.class.getName());
		}
		return manualMatchSet;
	}

	@Override
	public VTMatchSet getImpliedMatchSet() {
		if (impliedMatchSet == null) {
			impliedMatchSet = findMatchSet(ImpliedMatchProgramCorrelator.class.getName());
		}
		return impliedMatchSet;
	}

	private VTMatchSet findMatchSet(String correlatorClassName) {
		for (VTMatchSet matchSet : matchSets) {
			VTProgramCorrelatorInfo info = matchSet.getProgramCorrelatorInfo();
			String matchSetCorrelatorClassName = info.getCorrelatorClassName();
			if (correlatorClassName.equals(matchSetCorrelatorClassName)) {
				return matchSet;
			}
		}
		return null;
	}

	@Override
	public void deleteMatchTag(VTMatchTag tag) {
		String tagName = tag.getName();
		try {
			lock.acquire();
			VTMatchTagDB tagDB = getMatchTagDB(tagName);
			if (tagDB == null) {
				return; // not sure if this can happen
			}

			long key = tagDB.getKey();
			tagCache.delete(key);
			matchTagAdapter.deleteRecord(key);

		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		setObjectChanged(VTChangeManager.DOCR_VT_TAG_REMOVED, this, tagName, null);
	}

	@Override
	public VTMatchTagDB createMatchTag(String tagName) {
		VTMatchTagDB matchTag = null;
		try {
			lock.acquire();
			matchTag = getMatchTagDB(tagName);
			if (matchTag != null) {
				return matchTag;
			}
			DBRecord record = matchTagAdapter.insertRecord(tagName);
			matchTag = new VTMatchTagDB(this, tagCache, record);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		setObjectChanged(VTChangeManager.DOCR_VT_TAG_ADDED, matchTag, null, matchTag);
		return matchTag;
	}

	private VTMatchTagDB getMatchTagDB(String tagName) {
		Set<VTMatchTag> matchTags = getMatchTags();
		for (VTMatchTag matchTag : matchTags) {
			// Return the tag if we already have it
			if (matchTag.getName().equals(tagName)) {
				return (VTMatchTagDB) matchTag;
			}
		}
		return null;
	}

	@Override
	public Set<VTMatchTag> getMatchTags() {
		Set<VTMatchTag> tags = new HashSet<>();
		try {
			lock.acquire();
			RecordIterator records = matchTagAdapter.getRecords();
			while (records.hasNext()) {
				DBRecord record = records.next();
				tags.add(getMatchTagNew(record));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return tags;
	}

	private VTMatchTagDB getMatchTagNew(DBRecord record) {
		if (record == null) {
			throw new AssertException("How can we have a null record?!!!");
		}

		try {
			lock.acquire();
			VTMatchTagDB matchTagDB = tagCache.get(record);
			if (matchTagDB == null) {
				matchTagDB = new VTMatchTagDB(this, tagCache, record);
			}

			return matchTagDB;
		}
		finally {
			lock.release();
		}
	}

	public VTMatchTag getMatchTag(long key) {
		lock.acquire();
		try {
			VTMatchTagDB matchTagDB = tagCache.get(key);
			if (matchTagDB != null) {
				return matchTagDB;
			}
			DBRecord record = matchTagAdapter.getRecord(key);
			if (record != null) {
				return new VTMatchTagDB(this, tagCache, record);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return VTMatchTag.UNTAGGED;
	}

	DBRecord getTagRecord(long key) throws IOException {
		return matchTagAdapter.getRecord(key);
	}

	public VTMatchTagDB getOrCreateMatchTagDB(VTMatchTag tag) {
		if (tag == null) {
			return null; // can't create or locate
		}

		if (tag == VTMatchTag.UNTAGGED) {
			return null; // no DB item for the untagged state
		}

		String tagName = tag.getName();
		return createMatchTag(tagName);
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		Transaction transaction = getCurrentTransaction();
		super.endTransaction(transactionID, commit);
		if (changeSetsModified && transaction.getStatus() == Transaction.COMMITTED) {
			changeSetsModified = false;
		}
	}

	@Override
	public void addAssociationHook(AssociationHook hook) {
		associationManager.addAssociationHook(hook);
	}

	@Override
	public void removeAssociationHook(AssociationHook hook) {
		associationManager.removeAssociationHook(hook);
	}

}
