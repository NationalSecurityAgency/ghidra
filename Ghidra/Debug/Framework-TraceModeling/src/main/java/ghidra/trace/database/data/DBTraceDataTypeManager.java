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
package ghidra.trace.database.data;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import db.Transaction;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.data.ProgramBasedDataTypeManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.guest.DBTraceGuestPlatform;
import ghidra.trace.database.guest.DBTracePlatformManager.DBTraceHostPlatform;
import ghidra.trace.database.guest.InternalTracePlatform;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceDataTypeManager extends ProgramBasedDataTypeManagerDB
		implements TraceBasedDataTypeManager, DBTraceManager {

	/**
	 * NOTE: This "read-write" lock is actually just a compatibility wrapper around the
	 * {@link ghidra.util.Lock} for the entire trace database. There was a time when I dreamed of
	 * using an actual read-write lock (though it's not known if that'd actually achieve any
	 * appreciable speed up); however, inheriting the existing DataTypeManager implementation
	 * required its lock to be used throughout the database. Rather than convert all my code (and
	 * lose the distinction of where I need write vs. read locks), I just wrapped the API. So no,
	 * this code does not refer to the wrapper, but it does still use the lock. I keep a reference
	 * to it here in case I ever need it.
	 */
	protected final ReadWriteLock lock;
	protected final DBTrace trace;
	protected final InternalTracePlatform platform;

	private static String computePrefix(InternalTracePlatform platform) {
		return switch (platform) {
			case DBTraceHostPlatform host -> null;
			case DBTraceGuestPlatform guest -> "Guest%d_".formatted(guest.getIntKey());
			default -> throw new AssertionError();
		};
	}

	public DBTraceDataTypeManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, InternalTracePlatform platform)
			throws CancelledException, VersionException, IOException {
		super(dbh, null, openMode, computePrefix(platform), trace, trace.getLock(), monitor);
		this.lock = lock; // TODO: nothing uses this local lock - not sure what its purpose is
		this.trace = trace;
		this.platform = platform;

		setProgramArchitecture(platform, null, false, monitor);

		if (openMode == OpenMode.CREATE) {
			saveDataOrganization();
		}
	}

	@Override
	protected void dataSettingChanged(Address address) {
		// ignored - instance settings are not current supported (no AddressMap provided)
	}

	@Override
	public boolean allowsDefaultBuiltInSettings() {
		return true;
	}

	@Override
	public void invalidateCache(boolean all) {
		super.invalidateCache();
	}

	@Override
	public String getName() {
		return trace.getName();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("Name must be at least one character long: " + name);
		}

		trace.setName(name);
		categoryRenamed(CategoryPath.ROOT, getCategory(CategoryPath.ROOT));
	}

	@Override
	public InternalTracePlatform getPlatform() {
		return platform;
	}

	@Override
	public void sourceArchiveChanged(UniversalID sourceArchiveID) {
		super.sourceArchiveChanged(sourceArchiveID);
		trace.sourceArchiveChanged(sourceArchiveID);
	}

	@Override
	protected void sourceArchiveAdded(UniversalID sourceArchiveID) {
		super.sourceArchiveAdded(sourceArchiveID);
		trace.sourceArchiveAdded(sourceArchiveID);
	}

	@Override
	public void dataTypeChanged(DataType dataType, boolean isAutoChange) {
		super.dataTypeChanged(dataType, isAutoChange);
		if (!isCreatingDataType()) {
			trace.getCodeManager().invalidateCache(false);
			trace.getSymbolManager().invalidateCache(false);
			trace.dataTypeChanged(getID(dataType), dataType);
		}
	}

	@Override
	protected void dataTypeAdded(DataType addedType, DataType sourceType) {
		super.dataTypeAdded(addedType, sourceType);
		trace.dataTypeAdded(getID(addedType), addedType);
	}

	@Override
	protected void dataTypeReplaced(long replacedID, DataTypePath replacedPath,
			DataType replacementType) {
		super.dataTypeReplaced(replacedID, replacedPath, replacementType);
		trace.dataTypeReplaced(replacedID, replacedPath, replacementType.getDataTypePath());
	}

	@Override
	protected void dataTypeMoved(DataType type, DataTypePath oldPath, DataTypePath newPath) {
		super.dataTypeMoved(type, oldPath, newPath);
		trace.dataTypeMoved(getID(type), oldPath, newPath);
	}

	@Override
	protected void dataTypeNameChanged(DataType type, String oldName) {
		super.dataTypeNameChanged(type, oldName);
		trace.dataTypeNameChanged(getID(type), oldName, type.getName());
	}

	@Override
	protected void dataTypeDeleted(long deletedID, DataTypePath deletedPath) {
		super.dataTypeDeleted(deletedID, deletedPath);
		trace.dataTypeDeleted(deletedID, deletedPath);
	}

	@Override
	protected void categoryCreated(Category createdCategory) {
		super.categoryCreated(createdCategory);
		trace.categoryAdded(createdCategory.getID(), createdCategory);
	}

	@Override
	protected void categoryMoved(CategoryPath oldPath, Category category) {
		super.categoryMoved(oldPath, category);
		trace.categoryMoved(category.getID(), oldPath, category.getCategoryPath());
	}

	@Override
	protected void categoryRenamed(CategoryPath oldPath, Category category) {
		super.categoryRenamed(oldPath, category);
		trace.categoryRenamed(category.getID(), oldPath.getName(), category.getName());
	}

	@Override
	protected void categoryRemoved(Category parent, String name, long deletedID) {
		super.categoryRemoved(parent, name, deletedID);
		trace.categoryDeleted(deletedID, new CategoryPath(parent.getCategoryPath(), name));
	}

	@Override
	protected void replaceDataTypesUsed(Map<Long, Long> dataTypeReplacementMap) {
		trace.getCodeManager().replaceDataTypes(dataTypeReplacementMap);
		trace.getSymbolManager().replaceDataTypes(dataTypeReplacementMap);
	}

	@Override
	protected void deleteDataTypesUsed(Set<Long> deletedIds) {
		// TODO: Should use replacement type instead of clearing
		trace.getCodeManager().clearData(deletedIds, TaskMonitor.DUMMY);
		trace.getSymbolManager().invalidateCache(false);
	}

	@Override
	public boolean isUpdatable() {
		return trace.isChangeable();
	}

	@Override
	public Transaction openTransaction(String description) throws IllegalStateException {
		return trace.openTransaction(description);
	}

	@Override
	public int startTransaction(String description) {
		return trace.startTransaction(description);
	}

	@Override
	public void flushEvents() {
		trace.flushEvents();
	}

	@Override
	public boolean endTransaction(int transactionID, boolean commit) {
		return trace.endTransaction(transactionID, commit);
	}

	@Override
	public void close() {
		// Do nothing - cannot close a trace's data type manager
	}

	@Override
	public DBTrace getTrace() {
		return trace;
	}

	@Override
	public DomainFile getDomainFile() {
		return trace.getDomainFile();
	}

	@Override
	protected String getDomainFileID() {
		DomainFile domainFile = trace.getDomainFile(); // Can be null if never saved
		return domainFile == null ? null : domainFile.getFileID();
	}

	@Override
	public String getPath() {
		DomainFile domainFile = trace.getDomainFile(); // Can be null if never saved
		return domainFile == null ? null : domainFile.getPathname();
	}

	@Override
	public ArchiveType getType() {
		/**
		 * Note, PROGRAM reflects the expected behavior closely enough. It really just indicates the
		 * manager is part of another database, rather than stand alone. Introducing a new TRACE
		 * would have unexpected fall out.
		 */
		return ArchiveType.PROGRAM;
	}
}
