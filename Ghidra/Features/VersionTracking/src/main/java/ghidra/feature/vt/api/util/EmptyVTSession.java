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
package ghidra.feature.vt.api.util;

import ghidra.feature.vt.api.main.*;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class EmptyVTSession implements VTSession {

	@Override
	public VTMatchSet createMatchSet(VTProgramCorrelator correlator) {
		return null;
	}

	@Override
	public VTAssociationManager getAssociationManager() {
		return null;
	}

	@Override
	public Program getDestinationProgram() {
		return null;
	}

	@Override
	public List<VTMatchSet> getMatchSets() {
		return new ArrayList<VTMatchSet>();
	}

	@Override
	public String getName() {
		return "Empty";
	}

	@Override
	public Program getSourceProgram() {
		return null;
	}

	@Override
	public void save() throws IOException {
		// do nothing
	}

	@Override
	public void dbError(IOException e) {
		// do nothing
	}

	@Override
	public void addListener(DomainObjectListener dol) {
		// do nothing
	}

	@Override
	public void removeListener(DomainObjectListener dol) {
		// do nothing
	}

	@Override
	public void addCloseListener(DomainObjectClosedListener listener) {
		// do nothing
	}

	@Override
	public void removeCloseListener(DomainObjectClosedListener listener) {
		// do nothing
	}

	@Override
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		return null;
	}

	@Override
	public boolean removePrivateEventQueue(EventQueueID id) {
		return false;
	}

	@Override
	public void flushPrivateEventQueue(EventQueueID id) {
		// do nothing
	}

	@Override
	public VTMatchTag createMatchTag(String name) {
		return null;
	}

	@Override
	public void deleteMatchTag(VTMatchTag tag) {
		// do nothing
	}

	@Override
	public Set<VTMatchTag> getMatchTags() {
		return new HashSet<VTMatchTag>();
	}

	@Override
	public VTMatchSet getManualMatchSet() {
		throw new AssertException("EmptyVTSession has no manual match set!");
	}

	@Override
	public VTMatchSet getImpliedMatchSet() {
		throw new AssertException("EmptyVTSession has no implied match set!");
	}

	@Override
	public List<VTMatch> getMatches(VTAssociation association) {
		return new ArrayList<VTMatch>();
	}

	@Override
	public void addAssociationHook(AssociationHook hook) {
		// do nothing
	}

	@Override
	public void removeAssociationHook(AssociationHook hook) {
		// do nothing

	}

	@Override
	public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException {
		// do nothing

	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		// do nothing

	}

	@Override
	public Transaction getCurrentTransaction() {
		return null;
	}

	@Override
	public DomainObject[] getSynchronizedDomainObjects() {
		return null;
	}

	@Override
	public boolean hasTerminatedTransaction() {
		return false;
	}

	@Override
	public void releaseSynchronizedDomainObject() throws LockException {
		// do nothing
	}

	@Override
	public int startTransaction(String description) {
		return 0;
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener) {
		return 0;
	}

	@Override
	public boolean addConsumer(Object consumer) {
		return false;
	}

	@Override
	public boolean canLock() {
		return false;
	}

	@Override
	public boolean canSave() {
		return false;
	}

	@Override
	public void flushEvents() {
		// do nothing

	}

	@Override
	public void forceLock(boolean rollback, String reason) {
		// do nothing

	}

	@Override
	public ArrayList<Object> getConsumerList() {
		return null;
	}

	@Override
	public boolean isUsedBy(Object consumer) {
		return false;
	}

	@Override
	public String getDescription() {
		return null;
	}

	@Override
	public DomainFile getDomainFile() {
		return null;
	}

	@Override
	public Map<String, String> getMetadata() {
		return null;
	}

	@Override
	public long getModificationNumber() {
		return 0;
	}

	@Override
	public Options getOptions(String propertyListName) {
		return null;
	}

	@Override
	public List<String> getOptionsNames() {
		return null;
	}

	@Override
	public boolean hasExclusiveAccess() {
		return false;
	}

	@Override
	public boolean isChangeable() {
		return false;
	}

	@Override
	public boolean isChanged() {
		return false;
	}

	@Override
	public boolean isClosed() {
		return false;
	}

	@Override
	public boolean isLocked() {
		return false;
	}

	@Override
	public boolean isTemporary() {
		return false;
	}

	@Override
	public boolean lock(String reason) {
		return false;
	}

	@Override
	public void release(Object consumer) {
		// do nothing
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		// do nothing
	}

	@Override
	public void saveToPackedFile(File outputFile, TaskMonitor monitor) throws IOException,
			CancelledException {
		// do nothing
	}

	@Override
	public void setEventsEnabled(boolean v) {
		// do nothing
	}

	@Override
	public boolean isSendingEvents() {
		return true;
	}

	@Override
	public void setName(String name) {
		// do nothing
	}

	@Override
	public void setTemporary(boolean state) {
		// do nothing
	}

	@Override
	public void unlock() {
		// do nothing
	}

	@Override
	public void addTransactionListener(TransactionListener listener) {
		// do nothing
	}

	@Override
	public boolean canRedo() {
		return false;
	}

	@Override
	public boolean canUndo() {
		return false;
	}

	@Override
	public void clearUndo() {
		// do nothing
	}

	@Override
	public String getRedoName() {
		return null;
	}

	@Override
	public String getUndoName() {
		return null;
	}

	@Override
	public void redo() throws IOException {
		// do nothing
	}

	@Override
	public void removeTransactionListener(TransactionListener listener) {
		// do nothing
	}

	@Override
	public void undo() throws IOException {
		// do nothing
	}

	@Override
	public void updateDestinationProgram(Program newProgram) {
		// do nothing
	}

	@Override
	public void updateSourceProgram(Program newProgram) {
		// do nothing
	}
}
