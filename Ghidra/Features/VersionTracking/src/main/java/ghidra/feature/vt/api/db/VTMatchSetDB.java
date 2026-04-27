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

import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;

import db.*;
import ghidra.feature.vt.api.correlator.program.BasicBlockMnemonicFunctionBulker;
import ghidra.feature.vt.api.impl.*;
import ghidra.feature.vt.api.main.*;
import ghidra.framework.data.OpenMode;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public class VTMatchSetDB extends DbObject implements VTMatchSet {

	private final DBRecord matchSetRecord;

	private DbCache<VTMatchDB> matchCache;
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

	public static VTMatchSetDB getMatchSetDB(DBRecord record, VTSessionDB session,
			DBHandle dbHandle, OpenMode openMode, TaskMonitor monitor, Lock lock)
			throws VersionException {

		VTMatchSetDB matchSetDB = new VTMatchSetDB(record, session, dbHandle, lock);
		matchSetDB.getTableAdapters(record.getKey(), openMode, monitor);
		return matchSetDB;
	}

	private VTMatchSetDB(DBRecord record, VTSessionDB session, DBHandle dbHandle, Lock lock) {
		super(record.getKey());// cache not supported
		this.matchSetRecord = record;
		this.session = session;
		this.dbHandle = dbHandle;
		this.lock = lock;

		matchCache = new DbCache<>(new MatchFactory(), lock, 10);
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

		// --- PDiff score computation (before lock) ---
		// For FUNCTION matches, compute the combined PDiff similarity score so it can be
		// persisted in the DB alongside the correlator's own similarity/confidence scores.
		// This is done here (central location) so ALL correlators benefit automatically —
		// no per-correlator code changes needed.
		//
		// The score is a weighted blend:
		//   95% basic-block mnemonic hash similarity (structural comparison)
		//   5% stack frame size similarity (detects local variable allocation changes)
		//
		// Computed before lock.acquire() since hashing can be slow for large functions.
		// Skipped for DATA matches (leave null) or if already set by the caller.
		// Always compute for FUNCTION matches — VTMatchInfo is reused across addMatch()
		// calls by correlators, so the previous score would be stale if we checked for null.
		if (info.getAssociationType() == VTAssociationType.FUNCTION) {
			Program srcProg = session.getSourceProgram();
			Program dstProg = session.getDestinationProgram();
			if (srcProg != null && dstProg != null) {
				Function srcFunc =
					srcProg.getFunctionManager().getFunctionAt(info.getSourceAddress());
				Function dstFunc =
					dstProg.getFunctionManager().getFunctionAt(info.getDestinationAddress());
				if (srcFunc != null && dstFunc != null) {
					try {
						List<Long> srcHashes =
							BasicBlockMnemonicFunctionBulker.INSTANCE.hashes(srcFunc,
								TaskMonitor.DUMMY);
						List<Long> dstHashes =
							BasicBlockMnemonicFunctionBulker.INSTANCE.hashes(dstFunc,
								TaskMonitor.DUMMY);
						int srcFrameSize = srcFunc.getStackFrame().getFrameSize();
						int dstFrameSize = dstFunc.getStackFrame().getFrameSize();
						double similarity = BasicBlockMnemonicFunctionBulker
							.getCombinedSimilarity(srcHashes, dstHashes,
								srcFrameSize, dstFrameSize);
						info.setPdiffSimilarityScore(new VTScore(similarity));
					}
					catch (CancelledException e) {
						// leave null — score column will show N/A
					}
				}
			}
		}

		// --- Standard match insertion (under lock) ---
		AssociationDatabaseManager associationManager = session.getAssociationManagerDBM();
		VTAssociationDB associationDB = associationManager.getOrCreateAssociationDB(
			info.getSourceAddress(), info.getDestinationAddress(), info.getAssociationType());
		VTMatchTag tag = info.getTag();
		VTMatchDB newMatch = null;
		try (Closeable c = lock.write()) {
			VTMatchTagDB tagDB = session.getOrCreateMatchTagDB(tag);
			DBRecord matchRecord =
				matchTableAdapter.insertMatchRecord(info, this, associationDB, tagDB);
			newMatch = new VTMatchDB(matchRecord, this);
			matchCache.add(newMatch);
		}
		catch (IOException e) {
			dbError(e);
		}
		if (newMatch != null) {
			session.setObjectChanged(VTEvent.MATCH_ADDED, newMatch, null, newMatch);
		}
		return newMatch;
	}

	@Override
	public boolean removeMatch(VTMatch match) {

		if (!(match instanceof VTMatchDB matchDb)) {
			// this should not be possible from the UI
			throw new IllegalArgumentException("Can only remove matches saved to the database");
		}

		VTAssociation association = match.getAssociation();
		List<VTMatch> matches = session.getMatches(association);
		if (matches.size() == 1 && association.getStatus() == VTAssociationStatus.ACCEPTED) {
			// This method prevents deleting the association if it is accepted, as it would cause  
			// the user to lose potentially valuable information without realizing it.  To work 
			// around that issue when calling this method, the user can first un-accept the match.
			return false;
		}

		deleteMatch(matchDb);
		return true;
	}

	@Override
	public void deleteMatch(VTMatch match) {
		if (!(match instanceof VTMatchDB matchDb)) {
			// this should not be possible from the UI
			throw new IllegalArgumentException("Can only remove matches saved to the database");
		}

		VTAssociation association = match.getAssociation();
		Address sourceAddress = association.getSourceAddress();
		Address destinationAddress = association.getDestinationAddress();
		try (Closeable c = lock.write()) {
			checkDeleted();
			long matchKey = matchDb.getKey();
			boolean deleted = matchTableAdapter.deleteRecord(matchKey);
			if (deleted) {
				matchCache.delete(matchKey);

				List<VTMatch> matches = session.getMatches(association);
				if (matches.isEmpty()) {
					// if last match, remove association
					AssociationDatabaseManager manager = session.getAssociationManagerDBM();
					manager.removeAssociation(association);
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}

		DeletedMatch deletedMatch = new DeletedMatch(sourceAddress, destinationAddress);
		session.setObjectChanged(VTEvent.MATCH_DELETED, match, deletedMatch, null);
	}

	@Override
	public int getID() {
		return (int) matchSetRecord.getKey();
	}

	@Override
	public Collection<VTMatch> getMatches() {
		List<VTMatch> list = new LinkedList<>();
		try (Closeable c = lock.read()) {
			RecordIterator iterator = matchTableAdapter.getRecords();
			while (iterator.hasNext()) {
				DBRecord nextRecord = iterator.next();
				list.add(matchCache.getCachedInstance(nextRecord));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return list;
	}

	@Override
	public Collection<VTMatch> getMatches(VTAssociation association) {
		List<VTMatch> list = new LinkedList<>();
		try (Closeable c = lock.read()) {
			VTAssociationDB associationDB = (VTAssociationDB) association;
			if (associationDB == null) {
				return list; // No association, so no matches.
			}
			RecordIterator iterator = matchTableAdapter.getRecords(associationDB.getKey());
			while (iterator.hasNext()) {
				DBRecord nextRecord = iterator.next();
				VTMatch match = matchCache.getCachedInstance(nextRecord);
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
		try (Closeable c = lock.read()) {
			AssociationDatabaseManager associationManager = session.getAssociationManagerDBM();
			VTAssociationDB existingAssociationDB =
				associationManager.getExistingAssociationDB(sourceAddress, destinationAddress);
			if (existingAssociationDB == null) {
				return Collections.emptyList();
			}
			return getMatches(existingAssociationDB);
		}
	}

	@Override
	protected boolean refresh() {
		// MatchSets are not cached, so this method is not used
		return true;
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

	void invalidateCache() {
		matchCache.invalidate();
	}

	DBRecord getMatchRecord(long matchKey) {
		try {
			return matchTableAdapter.getMatchRecord(matchKey);
		}
		catch (IOException e) {
			session.dbError(e);
			return null;
		}
	}

	@Override
	public String toString() {
		return "Match Set " + getID() + " - " + getMatchCount() + " matches [Correlator=" +
			getProgramCorrelatorInfo().getName() + "]";
	}

	private class MatchFactory implements DbFactory<VTMatchDB> {

		@Override
		public VTMatchDB instantiate(long matchKey) {
			DBRecord record = getMatchRecord(matchKey);
			return record == null ? null : instantiate(record);
		}

		@Override
		public VTMatchDB instantiate(DBRecord rec) {
			return new VTMatchDB(rec, VTMatchSetDB.this);
		}
	}

}
