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

import static ghidra.feature.vt.api.db.VTMatchSetTableDBAdapter.ColumnDescription.*;

import java.io.*;
import java.util.*;

import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;

import db.*;
import ghidra.feature.vt.api.correlator.program.ImpliedMatchProgramCorrelator;
import ghidra.feature.vt.api.correlator.program.ManualMatchProgramCorrelator;
import ghidra.feature.vt.api.impl.*;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public class VTMatchSetDB extends DatabaseObject implements VTMatchSet {

	private final DBRecord matchSetRecord;

	private DBObjectCache<VTMatchDB> matchCache;
	private final VTSessionDB session;
	private VTMatchTableDBAdapter matchTableAdapter;

	private final Lock lock;
	private final DBHandle dbHandle;

	private ProgramCorrelatorInfoImpl correlatorInfo;
	private Options options;

	public static VTMatchSetDB createMatchSetDB(DBRecord record, VTSessionDB session,
			DBHandle dbHandle, Lock lock) throws IOException {

		VTMatchSetDB matchSetDB = new VTMatchSetDB(record, session, dbHandle, lock);
		matchSetDB.createTableAdapters(record.getKey());
		return matchSetDB;
	}

	public static VTMatchSetDB getMatchSetDB(DBRecord record, VTSessionDB session, DBHandle dbHandle,
			OpenMode openMode, TaskMonitor monitor, Lock lock) throws VersionException {

		VTMatchSetDB matchSetDB = new VTMatchSetDB(record, session, dbHandle, lock);
		matchSetDB.getTableAdapters(record.getKey(), openMode, monitor);
		return matchSetDB;
	}

	private VTMatchSetDB(DBRecord record, VTSessionDB session, DBHandle dbHandle, Lock lock) {
		super(null, record.getKey());// cache not supported
		this.matchSetRecord = record;
		this.session = session;
		this.dbHandle = dbHandle;
		this.lock = lock;

		matchCache = new DBObjectCache<>(10);
	}

	private void createTableAdapters(long tableID) throws IOException {
		matchTableAdapter = VTMatchTableDBAdapter.createAdapter(dbHandle, tableID);
	}

	private void getTableAdapters(long tableID, OpenMode openMode, TaskMonitor monitor)
			throws VersionException {
		matchTableAdapter = VTMatchTableDBAdapter.getAdapter(dbHandle, tableID, openMode, monitor);
	}

	void dbError(IOException exception) {
		session.dbError(exception);
	}

	@Override
	public VTSession getSession() {
		return session;
	}

	@Override
	public int getMatchCount() {
		return matchTableAdapter.getRecordCount();
	}

	@Override
	public VTProgramCorrelatorInfo getProgramCorrelatorInfo() {
		if (correlatorInfo == null) {
			correlatorInfo = new ProgramCorrelatorInfoImpl(this);
		}
		return correlatorInfo;
	}

	public AddressSet getSourceAddressSet() throws IOException {
		return session.getSourceAddressSet(matchSetRecord);
	}

	public AddressSet getDestinationAddressSet() throws IOException {
		return session.getDestinationAddressSet(matchSetRecord);
	}

	public String getProgramCorrelatorName() {
		return matchSetRecord.getString(CORRELATOR_NAME_COL.column());
	}

	public String getProgramCorrelatorClassName() {
		return matchSetRecord.getString(CORRELATOR_CLASS_COL.column());
	}

	public Options getOptions() {
		if (options != null) {
			return options;
		}

		String optionsString = matchSetRecord.getString(OPTIONS_COL.column());
		if (optionsString == null) {
			return new ToolOptions("EMPTY_OPTIONS_NAME");
		}

		Reader reader = new StringReader(optionsString);
		SAXBuilder builder = XmlUtilities.createSecureSAXBuilder(false, false);

		try {
			Element rootElement = builder.build(reader).getRootElement();
			options = new ToolOptions(rootElement);
		}
		catch (JDOMException e) {
			Msg.showError(this, null, "Error Loading Key Bindings", "Unable to build XML data.", e);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error Loading Key Bindings", "Unable to build XML data.", e);
		}

		return options;
	}

	@Override
	public VTMatch addMatch(VTMatchInfo info) {
		AssociationDatabaseManager associationManager = session.getAssociationManagerDBM();
		VTAssociationDB associationDB = associationManager.getOrCreateAssociationDB(
			info.getSourceAddress(), info.getDestinationAddress(), info.getAssociationType());
		VTMatchTag tag = info.getTag();
		VTMatch newMatch = null;
		try {
			lock.acquire();
			VTMatchTagDB tagDB = session.getOrCreateMatchTagDB(tag);
			DBRecord matchRecord =
				matchTableAdapter.insertMatchRecord(info, this, associationDB, tagDB);
			newMatch = getMatchForRecord(matchRecord);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		if (newMatch != null) {
			session.setObjectChanged(VTChangeManager.DOCR_VT_MATCH_ADDED, newMatch, null, newMatch);
		}
		return newMatch;
	}

	@Override
	public boolean removeMatch(VTMatch match) {
		if (!(match instanceof VTMatchDB)) {
			return false;
		}
		if (!match.getMatchSet().hasRemovableMatches()) {
			return false;
		}

		VTMatchDB matchDB = (VTMatchDB) match;

		VTAssociation association = match.getAssociation();

		// Remove the association if it was the only remaining match for that association.
		AssociationDatabaseManager associationManager = session.getAssociationManagerDBM();
		List<VTMatch> matches = session.getMatches(association);
		if (matches.size() == 1 && association.getStatus() == VTAssociationStatus.ACCEPTED) {
			return false; // can't remove the last match if the association is accepted
		}

		// Remove the match record
		Address sourceAddress = association.getSourceAddress();
		Address destinationAddress = association.getDestinationAddress();
		try {
			lock.acquire();
			long matchKey = matchDB.getKey();
			boolean deleted = matchTableAdapter.deleteRecord(matchKey);
			if (deleted) {
				matchCache.delete(matchKey);

				if (matches.size() == 1) {
					// if last match, remove association
					associationManager.removeAssociation(association);
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}

		DeletedMatch deletedMatch = new DeletedMatch(sourceAddress, destinationAddress);
		session.setObjectChanged(VTChangeManager.DOCR_VT_MATCH_DELETED, match, deletedMatch, null);
		return true;
	}

	@Override
	public int getID() {
		return (int) matchSetRecord.getKey();
	}

	@Override
	public Collection<VTMatch> getMatches() {
		List<VTMatch> list = new LinkedList<>();
		try {
			lock.acquire();
			RecordIterator iterator = matchTableAdapter.getRecords();
			while (iterator.hasNext()) {
				DBRecord nextRecord = iterator.next();
				list.add(getMatchForRecord(nextRecord));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return list;
	}

	@Override
	public Collection<VTMatch> getMatches(VTAssociation association) {
		VTAssociationDB associationDB = (VTAssociationDB) association;
		List<VTMatch> list = new LinkedList<>();
		if (associationDB == null) {
			return list; // No association, so no matches.
		}
		try {
			RecordIterator iterator = matchTableAdapter.getRecords(associationDB.getKey());
			while (iterator.hasNext()) {
				DBRecord nextRecord = iterator.next();
				VTMatch match = getMatchForRecord(nextRecord);
				list.add(match);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return list;
	}

	@Override
	public Collection<VTMatch> getMatches(Address sourceAddress, Address destinationAddress) {
		AssociationDatabaseManager associationManager = session.getAssociationManagerDBM();
		VTAssociationDB existingAssociationDB =
			associationManager.getExistingAssociationDB(sourceAddress, destinationAddress);
		if (existingAssociationDB == null) {
			return Collections.emptyList();
		}
		return getMatches(existingAssociationDB);
	}

	@Override
	protected boolean refresh() {
		return true;
	}

	@Override
	public boolean isInvalid() {
		return session.getMatchSetRecord(key) == null;
	}

	private VTMatch getMatchForRecord(DBRecord matchRecord) {
		try {
			lock.acquire();
			VTMatchDB match = matchCache.get(matchRecord);
			if (match == null) {
				match = new VTMatchDB(matchCache, matchRecord, this);
			}
			return match;
		}
		finally {
			lock.release();
		}
	}

	DBRecord getMatchRecord(long matchRecordKey) {
		try {
			return matchTableAdapter.getMatchRecord(matchRecordKey);
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	Program getDestinationProgram() {
		return session.getDestinationProgram();
	}

	Program getSourceProgram() {
		return session.getSourceProgram();
	}

	AssociationDatabaseManager getAssociationManager() {
		return session.getAssociationManagerDBM();
	}

	VTMatchTableDBAdapter getMatchTableAdapter() {
		return matchTableAdapter;
	}

	public void invalidateCache() {
		lock.acquire();
		try {
			matchCache.invalidate();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasRemovableMatches() {
		VTProgramCorrelatorInfo info = getProgramCorrelatorInfo();
		String correlatorClassName = info.getCorrelatorClassName();
		return correlatorClassName.equals(ManualMatchProgramCorrelator.class.getName()) ||
			correlatorClassName.equals(ImpliedMatchProgramCorrelator.class.getName());
	}

	@Override
	public String toString() {
		return "Match Set " + getID() + " - " + getMatchCount() + " matches [Correlator=" +
			getProgramCorrelatorInfo().getName() + "]";
	}
}
