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
package ghidra.trace.database;

import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;

import org.apache.commons.collections4.collection.CompositeCollection;

import db.DBHandle;
import db.Transaction;
import generic.depends.DependentService;
import generic.depends.err.ServiceConstructionException;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.options.Options;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.address.TraceAddressFactory;
import ghidra.trace.database.bookmark.DBTraceBookmarkManager;
import ghidra.trace.database.breakpoint.DBTraceBreakpointManager;
import ghidra.trace.database.context.DBTraceRegisterContextManager;
import ghidra.trace.database.data.DBTraceDataSettingsAdapter;
import ghidra.trace.database.data.DBTraceDataTypeManager;
import ghidra.trace.database.guest.DBTraceObjectRegisterSupport;
import ghidra.trace.database.guest.DBTracePlatformManager;
import ghidra.trace.database.listing.DBTraceCodeManager;
import ghidra.trace.database.listing.DBTraceCommentAdapter;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.module.DBTraceModuleManager;
import ghidra.trace.database.module.DBTraceStaticMappingManager;
import ghidra.trace.database.program.DBTraceProgramView;
import ghidra.trace.database.program.DBTraceVariableSnapProgramView;
import ghidra.trace.database.property.DBTraceAddressPropertyManager;
import ghidra.trace.database.stack.DBTraceStackManager;
import ghidra.trace.database.symbol.*;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.property.TraceAddressPropertyManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.CopyOnWrite.WeakHashCowSet;
import ghidra.trace.util.CopyOnWrite.WeakValueHashCowMap;
import ghidra.trace.util.TraceChangeManager;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

// TODO: Need some subscription model to ensure record lifespans stay within lifespan of threads
// Applies to creation, and to setting end snap
// Also to deleting a thread altogether. 
public class DBTrace extends DBCachedDomainObjectAdapter implements Trace, TraceChangeManager {
	protected static final String TRACE_INFO = "Trace Information";
	protected static final String NAME = "Name";
	protected static final String DATE_CREATED = "Date Created";
	protected static final String BASE_LANGUAGE = "Base Language";
	protected static final String BASE_COMPILER = "Base Compiler";
	protected static final String PLATFORM = "Platform";
	protected static final String EXECUTABLE_PATH = "Executable Location";
	protected static final String EMU_CACHE_VERSION = "Emulator Cache Version";

	protected static final int DB_TIME_INTERVAL = 500;
	protected static final int DB_BUFFER_SIZE = 1000;

	// NOTE: Using a list ensures they are invalidated in the same order as created
	// Useful since refreshing likely follows the same dependency graph and creation.
	protected List<DBTraceManager> managers = new ArrayList<>(20);

	@DependentService
	protected DBTraceAddressPropertyManager addressPropertyManager;
	@DependentService
	protected DBTraceBookmarkManager bookmarkManager;
	@DependentService
	protected DBTraceBreakpointManager breakpointManager;
	@DependentService
	protected DBTraceCodeManager codeManager;
	@DependentService
	protected DBTraceCommentAdapter commentAdapter;
	@DependentService
	protected DBTraceDataSettingsAdapter dataSettingsAdapter;
	@DependentService
	protected DBTraceDataTypeManager dataTypeManager;
	@DependentService
	protected DBTraceEquateManager equateManager;
	@DependentService
	protected DBTracePlatformManager platformManager;
	@DependentService
	protected DBTraceMemoryManager memoryManager;
	@DependentService
	protected DBTraceModuleManager moduleManager;
	@DependentService
	protected DBTraceObjectManager objectManager;
	@DependentService
	protected DBTraceOverlaySpaceAdapter overlaySpaceAdapter;
	@DependentService
	protected DBTraceReferenceManager referenceManager;
	@DependentService
	protected DBTraceRegisterContextManager registerContextManager;
	@DependentService
	protected DBTraceStackManager stackManager;
	@DependentService
	protected DBTraceStaticMappingManager staticMappingManager;
	@DependentService
	protected DBTraceSymbolManager symbolManager;
	@DependentService
	protected DBTraceThreadManager threadManager;
	@DependentService
	protected DBTraceTimeManager timeManager;

	private final DBCachedObjectStoreFactory storeFactory;

	protected Language baseLanguage;
	protected CompilerSpec baseCompilerSpec;
	protected TraceAddressFactory baseAddressFactory;

	protected DBTraceChangeSet traceChangeSet;
	protected boolean recordChanges = false;

	protected Set<DBTraceTimeViewport> viewports = new WeakHashCowSet<>();
	protected ListenerSet<DBTraceDirectChangeListener> directListeners =
		new ListenerSet<>(DBTraceDirectChangeListener.class);
	protected DBTraceVariableSnapProgramView programView;
	protected Set<DBTraceVariableSnapProgramView> programViews = new WeakHashCowSet<>();
	protected Set<TraceProgramView> programViewsView = Collections.unmodifiableSet(programViews);
	protected Map<Long, DBTraceProgramView> fixedProgramViews = new WeakValueHashCowMap<>();
	// NOTE: Can't pre-construct unmodifiableMap(fixedProgramViews), because values()' id changes
	protected ListenerSet<TraceProgramViewListener> viewListeners =
		new ListenerSet<>(TraceProgramViewListener.class);

	public DBTrace(String name, CompilerSpec baseCompilerSpec, Object consumer)
			throws IOException, LanguageNotFoundException {
		super(new DBHandle(), DBOpenMode.CREATE, TaskMonitor.DUMMY, name, DB_TIME_INTERVAL,
			DB_BUFFER_SIZE, consumer);

		this.storeFactory = new DBCachedObjectStoreFactory(this);
		this.baseLanguage = baseCompilerSpec.getLanguage();
		// Need to "downgrade" the compiler spec, so nothing program-specific seeps in
		// TODO: Should there be a TraceCompilerSpec?
		this.baseCompilerSpec =
			baseLanguage.getCompilerSpecByID(baseCompilerSpec.getCompilerSpecID());
		this.baseAddressFactory =
			new TraceAddressFactory(this.baseLanguage, this.baseCompilerSpec);

		try (Transaction tx = this.openTransaction("Create")) {
			initOptions(DBOpenMode.CREATE);
			init();
		}
		catch (VersionException | CancelledException e) {
			throw new AssertionError(e);
		}
		catch (ServiceConstructionException e) {
			e.unwrap(LanguageNotFoundException.class);
			throw new AssertionError(e);
		}
		clearUndo(false);
		changeSet = traceChangeSet = new DBTraceChangeSet();
		recordChanges = true;

		programView = createProgramView(0);
	}

	public DBTrace(DBHandle dbh, DBOpenMode openMode, TaskMonitor monitor, Object consumer)
			throws CancelledException, VersionException, IOException, LanguageNotFoundException {
		super(dbh, openMode, monitor, "Untitled", DB_TIME_INTERVAL, DB_BUFFER_SIZE, consumer);
		this.storeFactory = new DBCachedObjectStoreFactory(this);

		try (Transaction tx = this.openTransaction("Create")) {
			initOptions(openMode);
			init();
		}
		catch (ServiceConstructionException e) {
			e.unwrap(LanguageNotFoundException.class);
			throw new AssertionError(e);
		}
		clearUndo(false);
		changeSet = traceChangeSet = new DBTraceChangeSet();
		recordChanges = true;

		programView = createProgramView(0);
	}

	protected void initOptions(DBOpenMode openMode) throws IOException, CancelledException {
		Options traceInfo = getOptions(TRACE_INFO);
		if (openMode == DBOpenMode.CREATE) {
			traceInfo.setString(NAME, name);
			traceInfo.setDate(DATE_CREATED, new Date());
			traceInfo.setString(BASE_LANGUAGE, baseLanguage.getLanguageID().getIdAsString());
			traceInfo.setString(BASE_COMPILER,
				baseCompilerSpec.getCompilerSpecID().getIdAsString());
		}
		else {
			name = traceInfo.getString(NAME, "Unnamed?");
			baseLanguage = DefaultLanguageService.getLanguageService()
					.getLanguage(
						new LanguageID(traceInfo.getString(BASE_LANGUAGE, null)));
			baseCompilerSpec = baseLanguage.getCompilerSpecByID(
				new CompilerSpecID(traceInfo.getString(BASE_COMPILER, null)));
			baseAddressFactory = new TraceAddressFactory(baseLanguage, baseCompilerSpec);
		}
	}

	@Override
	public void dbError(IOException e) {
		if (e instanceof ClosedException) {
			throw new TraceClosedException(e);
		}
		super.dbError(e);
	}

	@Internal
	public void assertValidAddress(Address pc) {
		if (pc == null) {
			return;
		}
		assertValidSpace(pc.getAddressSpace());
	}

	@Internal
	public void assertValidSpace(AddressSpace as) {
		if (as == AddressSpace.OTHER_SPACE) {
			return;
		}
		if (as == Address.NO_ADDRESS.getAddressSpace()) {
			return;
		}
		if (baseAddressFactory.getAddressSpace(as.getSpaceID()) != as) {
			throw new IllegalArgumentException(
				"AddressSpace '" + as + "' is not in this trace (language=" + getBaseLanguage() +
					")");
		}
	}

	@Override
	public DBTraceChangeSet getChangeSet() {
		return traceChangeSet;
	}

	// Internal
	public DBCachedObjectStoreFactory getStoreFactory() {
		return storeFactory;
	}

	@Override
	public String getDescription() {
		return "Trace";
	}

	protected <T extends DBTraceManager> T createTraceManager(String managerName,
			ManagerSupplier<T> supplier) throws CancelledException, IOException {
		T manager = createManager(managerName, supplier);
		managers.add(manager);
		return manager;
	}

	@DependentService
	protected DBTraceAddressPropertyManager createAddressPropertyManager(
			DBTraceThreadManager threadManager) throws CancelledException, IOException {
		return createTraceManager("Address Property Manager",
			(openMode, monitor) -> new DBTraceAddressPropertyManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager));
	}

	@DependentService
	protected DBTraceBookmarkManager createBookmarkManager(DBTraceThreadManager threadManager)
			throws CancelledException, IOException {
		return createTraceManager("Bookmark Manager",
			(openMode, monitor) -> new DBTraceBookmarkManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager));
	}

	@DependentService
	protected DBTraceBreakpointManager createBreakpointManager(DBTraceThreadManager threadManager)
			throws CancelledException, IOException {
		return createTraceManager("Breakpoint Manager",
			(openMode, monitor) -> new DBTraceBreakpointManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager));
	}

	@DependentService
	protected DBTraceCodeManager createCodeManager(DBTraceThreadManager threadManager,
			DBTracePlatformManager platformManager, DBTraceDataTypeManager dataTypeManager,
			DBTraceOverlaySpaceAdapter overlayAdapter, DBTraceReferenceManager referenceManager)
			throws CancelledException, IOException {
		return createTraceManager("Code Manager",
			(openMode, monitor) -> new DBTraceCodeManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager, platformManager, dataTypeManager, overlayAdapter,
				referenceManager));
	}

	@DependentService
	protected DBTraceCommentAdapter createCommentAdapter(DBTraceThreadManager threadManager)
			throws CancelledException, IOException {
		return createTraceManager("Comment Adapter",
			(openMode, monitor) -> new DBTraceCommentAdapter(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager));
	}

	@DependentService
	protected DBTraceDataSettingsAdapter createDataSettingsAdapter(
			DBTraceThreadManager threadManager) throws CancelledException, IOException {
		return createTraceManager("Data Settings Adapter",
			(openMode, monitor) -> new DBTraceDataSettingsAdapter(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager));
	}

	@DependentService
	protected DBTraceDataTypeManager createDataTypeManager()
			throws CancelledException, IOException {
		return createTraceManager("Data Type Manager",
			(openMode, monitor) -> new DBTraceDataTypeManager(dbh, openMode, rwLock, monitor,
				this));
	}

	@DependentService
	protected DBTraceEquateManager createEquateManager(DBTraceThreadManager threadManager)
			throws CancelledException, IOException {
		return createTraceManager("Equate Manager",
			(openMode, monitor) -> new DBTraceEquateManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager));
	}

	@DependentService
	protected DBTracePlatformManager createPlatformManager()
			throws CancelledException, IOException {
		return createTraceManager("Language Manager",
			(openMode, monitor) -> new DBTracePlatformManager(dbh, openMode, rwLock, monitor,
				baseCompilerSpec, this));
	}

	@DependentService
	protected DBTraceMemoryManager createMemoryManager(DBTraceThreadManager threadManager,
			DBTraceOverlaySpaceAdapter overlayAdapter) throws IOException, CancelledException {
		return createTraceManager("Memory Manager",
			(openMode, monitor) -> new DBTraceMemoryManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager, overlayAdapter));
	}

	@DependentService
	protected DBTraceModuleManager createModuleManager() throws CancelledException, IOException {
		return createTraceManager("Module Manager",
			(openMode, monitor) -> new DBTraceModuleManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this));
	}

	@DependentService
	protected DBTraceObjectManager createObjectManager()
			throws CancelledException, IOException {
		return createTraceManager("Object Manager",
			(openMode, monitor) -> new DBTraceObjectManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this));
	}

	@DependentService
	protected DBTraceOverlaySpaceAdapter createOverlaySpaceAdapter()
			throws CancelledException, IOException {
		return createTraceManager("Overlay Space Adapter",
			(openMode, monitor) -> new DBTraceOverlaySpaceAdapter(dbh, openMode, rwLock, monitor,
				this));
	}

	@DependentService
	protected DBTraceReferenceManager createReferenceManager(DBTraceThreadManager threadManager,
			DBTraceOverlaySpaceAdapter overlayAdapter) throws CancelledException, IOException {
		return createTraceManager("Reference Manager",
			(openMode, monitor) -> new DBTraceReferenceManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager, overlayAdapter));
	}

	@DependentService
	protected DBTraceRegisterContextManager createRegisterContextManager(
			DBTraceThreadManager threadManager, DBTracePlatformManager platformManager)
			throws CancelledException, IOException {
		return createTraceManager("Context Manager",
			(openMode, monitor) -> new DBTraceRegisterContextManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager, platformManager));
	}

	@DependentService
	protected DBTraceStackManager createStackManager(DBTraceThreadManager threadManager,
			DBTraceOverlaySpaceAdapter overlayAdapter) throws CancelledException, IOException {
		return createTraceManager("Stack Manager",
			(openMode, monitor) -> new DBTraceStackManager(dbh, openMode, rwLock, monitor, this,
				threadManager, overlayAdapter));
	}

	@DependentService
	protected DBTraceStaticMappingManager createStaticMappingManager(
			DBTraceOverlaySpaceAdapter overlayAdapter) throws CancelledException, IOException {
		return createTraceManager("Static Mapping Manager", (openMode,
				monitor) -> new DBTraceStaticMappingManager(dbh, openMode, rwLock, monitor, this,
					overlayAdapter));
	}

	@DependentService
	protected DBTraceSymbolManager createSymbolManager(DBTraceThreadManager threadManager,
			DBTraceDataTypeManager dataTypeManager, DBTraceOverlaySpaceAdapter overlayAdapter)
			throws CancelledException, IOException {
		return createTraceManager("Symbol Manager",
			(openMode, monitor) -> new DBTraceSymbolManager(dbh, openMode, rwLock, monitor,
				baseLanguage, this, threadManager, dataTypeManager, overlayAdapter));
	}

	@DependentService
	protected DBTraceThreadManager createThreadManager(DBTraceObjectManager objectManager)
			throws IOException, CancelledException {
		return createTraceManager("Thread Manager",
			(openMode, monitor) -> new DBTraceThreadManager(dbh, openMode, rwLock, monitor, this,
				objectManager));
	}

	@DependentService
	protected DBTraceTimeManager createTimeManager(DBTraceThreadManager threadManager)
			throws IOException, CancelledException {
		return createTraceManager("Time Manager",
			(openMode, monitor) -> new DBTraceTimeManager(dbh, openMode, rwLock, monitor, this,
				threadManager));
	}

	@Override
	public Language getBaseLanguage() {
		return baseLanguage;
	}

	@Override
	public CompilerSpec getBaseCompilerSpec() {
		// TODO: Incorporate guest specs into guest languages?
		return baseCompilerSpec;
	}

	protected void setTraceUserData(DBTraceUserData traceUserData) {
		// TODO:
	}

	@Override // Make accessible in this package
	protected void setChanged(boolean b) {
		super.setChanged(b);
	}

	@Override
	public boolean isChangeable() {
		return true;
	}

	@Override
	public AddressFactory getBaseAddressFactory() {
		return baseAddressFactory;
	}

	@Internal
	public TraceAddressFactory getInternalAddressFactory() {
		return baseAddressFactory;
	}

	@Override
	public TraceAddressPropertyManager getAddressPropertyManager() {
		return addressPropertyManager.getApiPropertyManager();
	}

	@Internal
	public DBTraceAddressPropertyManager getInternalAddressPropertyManager() {
		return addressPropertyManager;
	}

	@Override
	public DBTraceBookmarkManager getBookmarkManager() {
		return bookmarkManager;
	}

	@Override
	public DBTraceBreakpointManager getBreakpointManager() {
		return breakpointManager;
	}

	@Override
	public DBTraceCodeManager getCodeManager() {
		return codeManager;
	}

	@Internal
	public DBTraceCommentAdapter getCommentAdapter() {
		return commentAdapter;
	}

	@Internal
	public DBTraceDataSettingsAdapter getDataSettingsAdapter() {
		return dataSettingsAdapter;
	}

	@Override
	public DBTraceDataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	@Override
	public DBTraceEquateManager getEquateManager() {
		return equateManager;
	}

	@Override
	public DBTracePlatformManager getPlatformManager() {
		return platformManager;
	}

	@Override
	public DBTraceMemoryManager getMemoryManager() {
		return memoryManager;
	}

	@Override
	public DBTraceModuleManager getModuleManager() {
		return moduleManager;
	}

	@Override
	public DBTraceObjectManager getObjectManager() {
		return objectManager;
	}

	@Internal
	public DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter() {
		return overlaySpaceAdapter;
	}

	@Override
	public DBTraceReferenceManager getReferenceManager() {
		return referenceManager;
	}

	@Override
	public DBTraceRegisterContextManager getRegisterContextManager() {
		return registerContextManager;
	}

	@Override
	public DBTraceStackManager getStackManager() {
		return stackManager;
	}

	@Override
	public DBTraceStaticMappingManager getStaticMappingManager() {
		return staticMappingManager;
	}

	@Override
	public DBTraceSymbolManager getSymbolManager() {
		return symbolManager;
	}

	@Override
	public DBTraceThreadManager getThreadManager() {
		return threadManager;
	}

	@Override
	public DBTraceTimeManager getTimeManager() {
		return timeManager;
	}

	@Override
	public void setChanged(TraceChangeRecord<?, ?> event) {
		changed = true;
		DBTraceObjectRegisterSupport.INSTANCE.processEvent(event);
		fireEvent(event);
	}

	@Override
	public void fireEvent(DomainObjectChangeRecord ev) {
		super.fireEvent(ev);
		if (directListeners != null) {
			// Some events fire during construction
			directListeners.fire.changed(ev);
		}
	}

	public void addDirectChangeListener(DBTraceDirectChangeListener listener) {
		directListeners.add(listener);
	}

	public void removeDirectChangeListener(DBTraceDirectChangeListener listener) {
		directListeners.remove(listener);
	}

	@Override
	public DBTraceProgramView getFixedProgramView(long snap) {
		// NOTE: The new viewport will need to read from the time manager during init
		DBTraceProgramView view;
		try (LockHold hold = lockRead()) {
			view = fixedProgramViews.computeIfAbsent(snap, s -> {
				Msg.debug(this, "Creating fixed view at snap=" + snap);
				return new DBTraceProgramView(this, snap, baseCompilerSpec);
			});
		}
		viewListeners.fire.viewCreated(view);
		return view;
	}

	@Override
	public DBTraceVariableSnapProgramView createProgramView(long snap) {
		// NOTE: The new viewport will need to read from the time manager during init
		DBTraceVariableSnapProgramView view;
		try (LockHold hold = lockRead()) {
			view = new DBTraceVariableSnapProgramView(this, snap, baseCompilerSpec);
			programViews.add(view);
		}
		viewListeners.fire.viewCreated(view);
		return view;
	}

	@Override
	public DBTraceVariableSnapProgramView getProgramView() {
		return programView;
	}

	@Override
	public DBTraceTimeViewport createTimeViewport() {
		try (LockHold hold = lockRead()) {
			DBTraceTimeViewport view = new DBTraceTimeViewport(this);
			viewports.add(view);
			return view;
		}
	}

	@Override
	public LockHold lockRead() {
		return LockHold.lock(rwLock.readLock());
	}

	@Override
	public LockHold lockWrite() {
		return LockHold.lock(rwLock.writeLock());
	}

	public void sourceArchiveChanged(UniversalID sourceArchiveID) {
		if (recordChanges) {
			traceChangeSet.sourceArchiveChanged(sourceArchiveID.getValue());
		}
		setChanged(
			new TraceChangeRecord<>(TraceSourceArchiveChangeType.CHANGED, null, sourceArchiveID));
	}

	public void sourceArchiveAdded(UniversalID sourceArchiveID) {
		if (recordChanges) {
			traceChangeSet.sourceArchiveAdded(sourceArchiveID.getValue());
		}
		setChanged(
			new TraceChangeRecord<>(TraceSourceArchiveChangeType.ADDED, null, sourceArchiveID));
	}

	public void dataTypeChanged(long changedID, DataType changedType) {
		if (recordChanges) {
			traceChangeSet.dataTypeChanged(changedID);
		}
		setChanged(
			new TraceChangeRecord<>(TraceDataTypeChangeType.CHANGED, null, changedID, changedType));
	}

	public void dataTypeAdded(long addedID, DataType addedType) {
		if (recordChanges) {
			traceChangeSet.dataTypeAdded(addedID);
		}
		setChanged(
			new TraceChangeRecord<>(TraceDataTypeChangeType.ADDED, null, addedID, addedType));
	}

	public void dataTypeReplaced(long replacedID, DataTypePath replacedPath, DataTypePath newPath) {
		if (recordChanges) {
			traceChangeSet.dataTypeChanged(replacedID);
		}
		setChanged(new TraceChangeRecord<>(TraceDataTypeChangeType.REPLACED, null, replacedID,
			replacedPath, newPath));
	}

	public void dataTypeMoved(long movedID, DataTypePath oldPath, DataTypePath newPath) {
		if (recordChanges) {
			traceChangeSet.dataTypeChanged(movedID);
		}
		setChanged(new TraceChangeRecord<>(TraceDataTypeChangeType.MOVED, null, movedID, oldPath,
			newPath));
	}

	public void dataTypeNameChanged(long renamedID, String oldName, String newName) {
		if (recordChanges) {
			traceChangeSet.dataTypeChanged(renamedID);
		}
		setChanged(new TraceChangeRecord<>(TraceDataTypeChangeType.RENAMED, null, renamedID,
			oldName, newName));
	}

	public void dataTypeDeleted(long deletedID, DataTypePath deletedPath) {
		if (recordChanges) {
			traceChangeSet.dataTypeChanged(deletedID);
		}
		setChanged(new TraceChangeRecord<>(TraceDataTypeChangeType.DELETED, null, deletedID,
			deletedPath, null));
	}

	public void categoryAdded(long addedID, Category addedCategory) {
		if (recordChanges) {
			traceChangeSet.categoryAdded(addedID);
		}
		setChanged(
			new TraceChangeRecord<>(TraceCategoryChangeType.ADDED, null, addedID, addedCategory));
	}

	public void categoryMoved(long movedID, CategoryPath oldPath, CategoryPath newPath) {
		if (recordChanges) {
			traceChangeSet.categoryChanged(movedID);
		}
		setChanged(new TraceChangeRecord<>(TraceCategoryChangeType.MOVED, null, movedID, oldPath,
			newPath));
	}

	public void categoryRenamed(long renamedID, String oldName, String newName) {
		if (recordChanges) {
			traceChangeSet.categoryChanged(renamedID);
		}
		setChanged(new TraceChangeRecord<>(TraceCategoryChangeType.RENAMED, null, renamedID,
			oldName, newName));
	}

	public void categoryDeleted(long deletedID, CategoryPath deletedPath) {
		if (recordChanges) {
			traceChangeSet.categoryChanged(deletedID);
		}
		setChanged(new TraceChangeRecord<>(TraceCategoryChangeType.DELETED, null, deletedID,
			deletedPath, null));
	}

	@Override
	protected void clearCache(boolean all) {
		try (LockHold hold = LockHold.lock(rwLock.writeLock())) {
			for (DBTraceManager m : managers) {
				m.invalidateCache(all);
			}
		}
	}

	// TODO: Platform option?

	public void setExecutablePath(String path) {
		getOptions(TRACE_INFO).setString(EXECUTABLE_PATH, path);
	}

	public String getExecutablePath() {
		return getOptions(TRACE_INFO).getString(EXECUTABLE_PATH, null);
	}

	public Date getCreationDate() {
		return getOptions(TRACE_INFO).getDate(DATE_CREATED, new Date(0));
	}

	@Override
	public void setEmulatorCacheVersion(long version) {
		getOptions(TRACE_INFO).setLong(EMU_CACHE_VERSION, version);
	}

	@Override
	public long getEmulatorCacheVersion() {
		return getOptions(TRACE_INFO).getLong(EMU_CACHE_VERSION, 0);
	}

	@Override
	public Collection<TraceProgramView> getAllProgramViews() {
		/**
		 * Cannot pre-construct fixedProgramViewsView, because the UnmodifiableMap will cache
		 * values() on the first call, and the CowMap will change that with every mutation. Thus,
		 * the view would not see changes to the underlying map.
		 */
		return new CompositeCollection<>(programViewsView,
			Collections.unmodifiableCollection(fixedProgramViews.values()));
	}

	protected void allViewports(Consumer<DBTraceTimeViewport> action) {
		for (DBTraceTimeViewport viewport : viewports) {
			action.accept(viewport);
		}
	}

	protected void allViews(Consumer<DBTraceProgramView> action) {
		for (DBTraceProgramView view : programViews) {
			action.accept(view);
		}
		for (DBTraceProgramView view : fixedProgramViews.values()) {
			action.accept(view);
		}
	}

	@Override
	public void addProgramViewListener(TraceProgramViewListener listener) {
		viewListeners.add(listener);
	}

	@Override
	public void removeProgramViewListener(TraceProgramViewListener listener) {
		viewListeners.remove(listener);
	}

	public void updateViewsAddRegionBlock(TraceMemoryRegion region) {
		allViews(v -> v.updateMemoryAddRegionBlock(region));
	}

	public void updateViewsChangeRegionBlockName(TraceMemoryRegion region) {
		allViews(v -> v.updateMemoryChangeRegionBlockName(region));
	}

	public void updateViewsChangeRegionBlockFlags(TraceMemoryRegion region, Lifespan lifespan) {
		allViews(v -> v.updateMemoryChangeRegionBlockFlags(region, lifespan));
	}

	public void updateViewsChangeRegionBlockRange(TraceMemoryRegion region,
			AddressRange oldRange, AddressRange newRange) {
		allViews(v -> v.updateMemoryChangeRegionBlockRange(region, oldRange, newRange));
	}

	public void updateViewsChangeRegionBlockLifespan(TraceMemoryRegion region,
			Lifespan oldLifespan, Lifespan newLifespan) {
		allViews(v -> v.updateMemoryChangeRegionBlockLifespan(region, oldLifespan, newLifespan));
	}

	public void updateViewsDeleteRegionBlock(TraceMemoryRegion region) {
		allViews(v -> v.updateMemoryDeleteRegionBlock(region));
	}

	public void updateViewsAddSpaceBlock(AddressSpace space) {
		allViews(v -> v.updateMemoryAddSpaceBlock(space));
	}

	public void updateViewsDeleteSpaceBlock(AddressSpace space) {
		allViews(v -> v.updateMemoryDeleteSpaceBlock(space));
	}

	public void updateViewsRefreshBlocks() {
		allViews(v -> v.updateMemoryRefreshBlocks());
	}

	public void updateViewsBytesChanged(AddressRange range) {
		allViews(v -> v.updateBytesChanged(range));
	}

	public void updateViewportsSnapshotAdded(TraceSnapshot snapshot) {
		allViewports(v -> v.updateSnapshotAdded(snapshot));
	}

	public void updateViewportsSnapshotChanged(TraceSnapshot snapshot) {
		allViewports(v -> v.updateSnapshotChanged(snapshot));
	}

	public void updateViewportsSnapshotDeleted(TraceSnapshot snapshot) {
		allViewports(v -> v.updateSnapshotDeleted(snapshot));
	}
}
