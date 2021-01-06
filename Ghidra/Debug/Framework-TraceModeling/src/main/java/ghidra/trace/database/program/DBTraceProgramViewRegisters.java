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
package ghidra.trace.database.program;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.framework.data.DomainObjectEventQueues;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.IntRangeMap;
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
import ghidra.trace.database.listing.DBTraceCodeRegisterSpace;
import ghidra.trace.database.memory.DBTraceMemoryRegisterSpace;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceTimeViewport;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewRegisters implements TraceProgramView {
	protected final DomainObjectEventQueues eventQueues;

	private final DBTraceProgramView view;
	private final DBTraceThread thread;

	private final DBTraceProgramViewRegisterListing listing;
	private final DBTraceProgramViewRegisterMemory memory;
	private final DBTraceProgramViewRegistersReferenceManager referenceManager;

	public DBTraceProgramViewRegisters(DBTraceProgramView view, DBTraceCodeRegisterSpace codeSpace,
			DBTraceMemoryRegisterSpace memorySpace) {
		this.view = view;
		this.thread = codeSpace.getThread(); // TODO: Bleh, should be parameter

		this.eventQueues = new DomainObjectEventQueues(this, DBTraceProgramView.TIME_INTERVAL,
			DBTraceProgramView.BUF_SIZE, view.trace.getLock());

		// TODO: Make these create code/memory spaces lazily, to allow null at construction
		// NOTE: Use reference manager as example
		this.listing = new DBTraceProgramViewRegisterListing(view, codeSpace);
		this.memory = new DBTraceProgramViewRegisterMemory(view, memorySpace);
		this.referenceManager = new DBTraceProgramViewRegistersReferenceManager(view, thread);
	}

	@Override
	public Listing getListing() {
		return listing;
	}

	@Override
	public AddressMap getAddressMap() {
		return null;
	}

	@Override
	public TraceBasedDataTypeManager getDataTypeManager() {
		return view.getDataTypeManager();
	}

	@Override
	public FunctionManager getFunctionManager() {
		return view.getFunctionManager();
	}

	@Override
	public ProgramUserData getProgramUserData() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SymbolTable getSymbolTable() {
		return view.getSymbolTable();
	}

	@Override
	public ExternalManager getExternalManager() {
		return view.getExternalManager();
	}

	@Override
	public EquateTable getEquateTable() {
		return view.getEquateTable();
	}

	@Override
	public Memory getMemory() {
		return memory;
	}

	@Override
	public ReferenceManager getReferenceManager() {
		return referenceManager;
	}

	@Override
	public BookmarkManager getBookmarkManager() {
		return view.getBookmarkManager();
	}

	@Override
	public int getDefaultPointerSize() {
		return view.getDefaultPointerSize();
	}

	@Override
	public String getCompiler() {
		return view.getCompiler();
	}

	@Override
	public void setCompiler(String compiler) {
		view.setCompiler(compiler);
	}

	@Override
	public String getExecutablePath() {
		return view.getExecutablePath();
	}

	@Override
	public void setExecutablePath(String path) {
		view.setExecutablePath(path);
	}

	@Override
	public String getExecutableFormat() {
		return view.getExecutableFormat();
	}

	@Override
	public void setExecutableFormat(String format) {
		view.setExecutableFormat(format);
	}

	@Override
	public String getExecutableMD5() {
		return view.getExecutableMD5();
	}

	@Override
	public void setExecutableMD5(String md5) {
		view.setExecutableMD5(md5);
	}

	@Override
	public void setExecutableSHA256(String sha256) {
		view.setExecutableSHA256(sha256);
	}

	@Override
	public String getExecutableSHA256() {
		return view.getExecutableSHA256();
	}

	@Override
	public Date getCreationDate() {
		return view.getCreationDate();
	}

	@Override
	public RelocationTable getRelocationTable() {
		return view.getRelocationTable();
	}

	@Override
	public Language getLanguage() {
		return view.getLanguage();
	}

	@Override
	public CompilerSpec getCompilerSpec() {
		return view.getCompilerSpec();
	}

	@Override
	public LanguageID getLanguageID() {
		return view.getLanguageID();
	}

	@Override
	public PropertyMapManager getUsrPropertyManager() {
		return view.getUsrPropertyManager();
	}

	@Override
	public ProgramContext getProgramContext() {
		return view.getProgramContext();
	}

	@Override
	public Address getMinAddress() {
		return view.getLanguage().getAddressFactory().getRegisterSpace().getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return view.getLanguage().getAddressFactory().getRegisterSpace().getMaxAddress();
	}

	@Override
	public ProgramChangeSet getChanges() {
		return view.getChanges();
	}

	@Override
	public AddressFactory getAddressFactory() {
		return view.getAddressFactory();
	}

	@Override
	public Address[] parseAddress(String addrStr) {
		return view.parseAddress(addrStr);
	}

	@Override
	public Address[] parseAddress(String addrStr, boolean caseSensitive) {
		return view.parseAddress(addrStr, caseSensitive);
	}

	@Override
	public void invalidate() {
		view.invalidate();
	}

	@Override
	public Register getRegister(String name) {
		return view.getRegister(name);
	}

	@Override
	public Register getRegister(Address addr) {
		return view.getRegister(addr);
	}

	@Override
	public Register[] getRegisters(Address addr) {
		return view.getRegisters(addr);
	}

	@Override
	public Register getRegister(Address addr, int size) {
		return view.getRegister(addr, size);
	}

	@Override
	public Register getRegister(Varnode varnode) {
		return view.getRegister(varnode);
	}

	@Override
	public Address getImageBase() {
		return view.getImageBase();
	}

	@Override
	public void setImageBase(Address base, boolean commit)
			throws AddressOverflowException, LockException, IllegalStateException {
		view.setImageBase(base, commit);
	}

	@Override
	public void restoreImageBase() {
		view.restoreImageBase();
	}

	@Override
	public void setLanguage(Language language, CompilerSpecID compilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor)
			throws IllegalStateException, IncompatibleLanguageException, LockException {
		view.setLanguage(language, compilerSpecID, forceRedisassembly, monitor);
	}

	@Override
	public Namespace getGlobalNamespace() {
		return view.getGlobalNamespace();
	}

	@Override
	public AddressSetPropertyMap createAddressSetPropertyMap(String name)
			throws DuplicateNameException {
		return view.getAddressSetPropertyMap(name);
	}

	@Override
	public IntRangeMap createIntRangeMap(String name) throws DuplicateNameException {
		return view.createIntRangeMap(name);
	}

	@Override
	public AddressSetPropertyMap getAddressSetPropertyMap(String name) {
		return view.getAddressSetPropertyMap(name);
	}

	@Override
	public IntRangeMap getIntRangeMap(String name) {
		return view.getIntRangeMap(name);
	}

	@Override
	public void deleteAddressSetPropertyMap(String name) {
		view.deleteAddressSetPropertyMap(name);
	}

	@Override
	public void deleteIntRangeMap(String name) {
		view.deleteIntRangeMap(name);
	}

	@Override
	public long getUniqueProgramID() {
		return view.getUniqueProgramID();
	}

	@Override
	public int startTransaction(String description) {
		return view.startTransaction(description);
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener) {
		return view.startTransaction(description, listener);
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		view.endTransaction(transactionID, commit);
	}

	@Override
	public Transaction getCurrentTransaction() {
		return view.getCurrentTransaction();
	}

	@Override
	public boolean hasTerminatedTransaction() {
		return view.hasTerminatedTransaction();
	}

	@Override
	public DomainObject[] getSynchronizedDomainObjects() {
		return view.getSynchronizedDomainObjects();
	}

	@Override
	public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException {
		view.addSynchronizedDomainObject(domainObj);
	}

	@Override
	public void releaseSynchronizedDomainObject() throws LockException {
		view.releaseSynchronizedDomainObject();
	}

	@Override
	public boolean isChanged() {
		return view.isChanged();
	}

	@Override
	public void setTemporary(boolean state) {
		view.setTemporary(state);
	}

	@Override
	public boolean isTemporary() {
		return view.isTemporary();
	}

	@Override
	public boolean isChangeable() {
		return view.isChangeable();
	}

	@Override
	public boolean canSave() {
		return view.canSave();
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		view.save(comment, monitor);
	}

	@Override
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		view.saveToPackedFile(outputFile, monitor);
	}

	@Override
	public void release(Object consumer) {
		view.release(consumer);
	}

	@Override
	public void addListener(DomainObjectListener dol) {
		eventQueues.addListener(dol);
	}

	@Override
	public void removeListener(DomainObjectListener dol) {
		eventQueues.removeListener(dol);
	}

	@Override
	public void addCloseListener(DomainObjectClosedListener listener) {
		view.addCloseListener(listener);
	}

	@Override
	public void removeCloseListener(DomainObjectClosedListener listener) {
		view.removeCloseListener(listener);
	}

	@Override
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		return eventQueues.createPrivateEventQueue(listener, maxDelay);
	}

	@Override
	public boolean removePrivateEventQueue(EventQueueID id) {
		return removePrivateEventQueue(id);
	}

	@Override
	public String getDescription() {
		return view.getDescription();
	}

	@Override
	public String getName() {
		return view.getName(); // TODO: Append thread name?
	}

	@Override
	public void setName(String name) {
		view.setName(name); // TODO: Allow this?
	}

	@Override
	public DomainFile getDomainFile() {
		return view.getDomainFile();
	}

	@Override
	public boolean addConsumer(Object consumer) {
		return view.addConsumer(consumer);
	}

	@Override
	public ArrayList<Object> getConsumerList() {
		return view.getConsumerList();
	}

	@Override
	public boolean isUsedBy(Object consumer) {
		return view.isUsedBy(consumer);
	}

	@Override
	public void setEventsEnabled(boolean enabled) {
		view.setEventsEnabled(enabled);
	}

	@Override
	public boolean isSendingEvents() {
		return view.isSendingEvents();
	}

	@Override
	public void flushEvents() {
		view.flushEvents();
	}

	@Override
	public void flushPrivateEventQueue(EventQueueID id) {
		view.flushPrivateEventQueue(id);
	}

	@Override
	public boolean canLock() {
		return view.canLock();
	}

	@Override
	public boolean isLocked() {
		return view.isLocked();
	}

	@Override
	public boolean lock(String reason) {
		return view.lock(reason);
	}

	@Override
	public void forceLock(boolean rollback, String reason) {
		view.forceLock(rollback, reason);
	}

	@Override
	public void unlock() {
		view.unlock();
	}

	@Override
	public List<String> getOptionsNames() {
		return view.getOptionsNames();
	}

	@Override
	public Options getOptions(String propertyListName) {
		return view.getOptions(propertyListName);
	}

	@Override
	public boolean isClosed() {
		return view.isClosed();
	}

	@Override
	public boolean hasExclusiveAccess() {
		return view.hasExclusiveAccess();
	}

	@Override
	public Map<String, String> getMetadata() {
		return view.getMetadata();
	}

	@Override
	public long getModificationNumber() {
		return view.getModificationNumber();
	}

	@Override
	public boolean canUndo() {
		return view.canUndo();
	}

	@Override
	public boolean canRedo() {
		return view.canRedo();
	}

	@Override
	public void clearUndo() {
		view.clearUndo();
	}

	@Override
	public void undo() throws IOException {
		view.undo();
	}

	@Override
	public void redo() throws IOException {
		view.redo();
	}

	@Override
	public String getUndoName() {
		return view.getUndoName();
	}

	@Override
	public String getRedoName() {
		return view.getRedoName();
	}

	@Override
	public void addTransactionListener(TransactionListener listener) {
		view.addTransactionListener(listener);
	}

	@Override
	public void removeTransactionListener(TransactionListener listener) {
		view.removeTransactionListener(listener);
	}

	@Override
	public Trace getTrace() {
		return view.getTrace();
	}

	@Override
	public long getSnap() {
		return view.getSnap();
	}

	@Override
	public TraceTimeViewport getViewport() {
		return view.getViewport();
	}

	@Override
	public Long getMaxSnap() {
		return view.getMaxSnap();
	}

	@Override
	public TraceProgramView getViewRegisters(TraceThread thread, boolean createIfAbsent) {
		return view.getViewRegisters(thread, createIfAbsent);
	}
}
