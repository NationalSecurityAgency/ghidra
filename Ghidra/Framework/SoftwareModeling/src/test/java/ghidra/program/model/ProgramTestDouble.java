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
package ghidra.program.model;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ProgramTestDouble implements Program {

	@Override
	public int startTransaction(String description) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Transaction getCurrentTransaction() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasTerminatedTransaction() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainObject[] getSynchronizedDomainObjects() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void releaseSynchronizedDomainObject() throws LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isChanged() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setTemporary(boolean state) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isTemporary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isChangeable() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canSave() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void release(Object consumer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addListener(DomainObjectListener dol) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeListener(DomainObjectListener dol) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addCloseListener(DomainObjectClosedListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeCloseListener(DomainObjectClosedListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removePrivateEventQueue(EventQueueID id) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDescription() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DomainFile getDomainFile() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean addConsumer(Object consumer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ArrayList<Object> getConsumerList() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isUsedBy(Object consumer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setEventsEnabled(boolean v) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isSendingEvents() {
		return true;
	}

	@Override
	public void flushEvents() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void flushPrivateEventQueue(EventQueueID id) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canLock() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isLocked() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean lock(String reason) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void forceLock(boolean rollback, String reason) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void unlock() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<String> getOptionsNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Options getOptions(String propertyListName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isClosed() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasExclusiveAccess() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Map<String, String> getMetadata() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getModificationNumber() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canUndo() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean canRedo() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clearUndo() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void undo() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void redo() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getUndoName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getRedoName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addTransactionListener(TransactionListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeTransactionListener(TransactionListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Listing getListing() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressMap getAddressMap() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramDataTypeManager getDataTypeManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionManager getFunctionManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramUserData getProgramUserData() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolTable getSymbolTable() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ExternalManager getExternalManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public EquateTable getEquateTable() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Memory getMemory() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ReferenceManager getReferenceManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public BookmarkManager getBookmarkManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getDefaultPointerSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getCompiler() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCompiler(String compiler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutablePath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExecutablePath(String path) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutableFormat() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExecutableFormat(String format) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutableMD5() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExecutableMD5(String md5) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getExecutableSHA256() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setExecutableSHA256(String sha256) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Date getCreationDate() {
		throw new UnsupportedOperationException();
	}

	@Override
	public RelocationTable getRelocationTable() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Language getLanguage() {
		throw new UnsupportedOperationException();
	}

	@Override
	public CompilerSpec getCompilerSpec() {
		throw new UnsupportedOperationException();
	}

	@Override
	public LanguageID getLanguageID() {
		throw new UnsupportedOperationException();
	}

	@Override
	public PropertyMapManager getUsrPropertyManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramContext getProgramContext() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getMinAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getMaxAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramChangeSet getChanges() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressFactory getAddressFactory() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address[] parseAddress(String addrStr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address[] parseAddress(String addrStr, boolean caseSensitive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidate() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register[] getRegisters(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(Address addr, int size) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(Varnode varnode) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getImageBase() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setImageBase(Address base, boolean commit)
			throws AddressOverflowException, LockException, IllegalStateException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreImageBase() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLanguage(Language language, CompilerSpecID compilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor)
			throws IllegalStateException, IncompatibleLanguageException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getGlobalNamespace() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetPropertyMap createAddressSetPropertyMap(String name)
			throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public IntRangeMap createIntRangeMap(String name) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetPropertyMap getAddressSetPropertyMap(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public IntRangeMap getIntRangeMap(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteAddressSetPropertyMap(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteIntRangeMap(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getUniqueProgramID() {
		throw new UnsupportedOperationException();
	}

}
