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
package ghidra.program.database.function;

import java.io.IOException;
import java.util.*;

import org.apache.commons.collections4.map.LazyMap;

import db.*;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.datastruct.Counter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class FunctionTagManagerDB implements FunctionTagManager, ErrorHandler {

	private ProgramDB program;

	// Table containing all function tags in the system.
	private FunctionTagAdapter functionTagAdapter;

	// Table mapping function tags to functions
	private FunctionTagMappingAdapter functionTagMappingAdapter;

	private DbCache<FunctionTagDB> cache;

	private Map<FunctionTag, Counter> tagCountCache;

	protected final Lock lock;

	/**
	 * Constructor.
	 *
	 * @param handle handle to database
	 * @param openMode either READ_ONLY, UPDATE, or UPGRADE
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor to use while upgrading.
	 * @throws VersionException if the database is incompatible with the current
	 * schema
	 * @throws IOException if there is a problem accessing the database.
	 * @throws CancelledException if the program loading is cancelled
	 */
	FunctionTagManagerDB(DBHandle handle, OpenMode openMode, Lock lock, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		this.lock = lock;

		functionTagAdapter = FunctionTagAdapter.getAdapter(handle, openMode, monitor);
		functionTagMappingAdapter = FunctionTagMappingAdapter.getAdapter(handle, openMode, monitor);

		cache = new DbCache<>(new TagFactory(), lock, 100);
	}

	public void setProgram(Program program) {
		this.program = (ProgramDB) program;
	}

	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	@Override
	public FunctionTagDB getFunctionTag(String name) {
		try (Closeable c = lock.read()) {
			DBRecord rec = functionTagAdapter.getRecord(name);
			if (rec != null) {
				return cache.getCachedInstance(rec);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	@Override
	public FunctionTag getFunctionTag(long id) {
		return cache.getCachedInstance(id);
	}

	@Override
	public boolean isTagAssigned(String name) {

		try (Closeable c = lock.read()) {
			FunctionTag tag = getFunctionTag(name);
			if (tag == null) {
				return false;
			}
			return functionTagMappingAdapter.isTagAssigned(tag.getId());
		}
		catch (IOException e) {
			dbError(e);
		}

		return false;
	}

	@Override
	public FunctionTag createFunctionTag(String name, String comment) {

		try (Closeable c = lock.write()) {
			// First make sure a tag doesn't already exist with this name. If it does,
			// just return it.
			FunctionTagDB tag = getFunctionTag(name);
			if (tag != null) {
				return tag;
			}

			DBRecord record = functionTagAdapter.createTagRecord(name, comment);
			tag = new FunctionTagDB(this, record);
			cache.add(tag);
			fireTagCreatedNotification(ProgramEvent.FUNCTION_TAG_CREATED, tag);

			return tag;
		}
		catch (IOException e) {
			dbError(e);
		}

		return null;
	}

	boolean isTagApplied(long functionId, long tagId) {

		try (Closeable c = lock.read()) {
			return functionTagMappingAdapter.getRecord(functionId, tagId) != null;
		}
		catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	void applyFunctionTag(long functionId, long tagId) {
		try (Closeable c = lock.write()) {
			FunctionTag tag = getFunctionTag(tagId);
			if (tag == null) {
				return; // shouldn't happen
			}

			functionTagMappingAdapter.createFunctionTagRecord(functionId, tagId);
			incrementCountCache(tag);
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	private void incrementCountCache(FunctionTag tag) {
		if (tagCountCache != null) {
			tagCountCache.get(tag).increment();
		}
	}

	private void decrementCountCache(FunctionTag tag) {
		if (tagCountCache != null) {
			tagCountCache.get(tag).decrement();
		}
	}

	boolean removeFunctionTag(long functionId, long tagId) {

		try {
			FunctionTag tag = getFunctionTag(tagId);
			if (tag == null) {
				return false; // shouldn't happen
			}

			if (functionTagMappingAdapter.removeFunctionTagRecord(functionId, tagId)) {
				decrementCountCache(tag);
				return true;
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	void updateFunctionTag(FunctionTagDB tag, String oldValue, String newValue) throws IOException {

		// Update the tag attributes.
		functionTagAdapter.updateRecord(tag.getRecord());

		// Notify subscribers of the change.
		fireTagChangedNotification(ProgramEvent.FUNCTION_TAG_CHANGED, tag, oldValue, newValue);
		invalidateFunctions();
	}

	@Override
	public List<? extends FunctionTag> getAllFunctionTags() {

		try (Closeable c = lock.read()) {
			List<FunctionTag> tags = new ArrayList<>();
			RecordIterator records = functionTagAdapter.getRecords();
			while (records.hasNext()) {
				DBRecord record = records.next();
				tags.add(cache.getCachedInstance(record));
			}

			return tags;
		}
		catch (IOException e) {
			dbError(e);
		}
		return Collections.emptyList();
	}

	public DBRecord getTagRecord(long id) throws IOException {
		return functionTagAdapter.getRecord(id);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	/**
	 * Sends a notification when a tag has been changed (edited or deleted).
	 *
	 * @param type {@link ChangeManager} change type
	 * @param tag the tag that was changed
	 * @param oldValue the old value
	 * @param newValue the new value
	 */
	private void fireTagChangedNotification(ProgramEvent eventType, FunctionTag tag,
			String oldValue, String newValue) {
		program.tagChanged(tag, eventType, oldValue, newValue);
	}

	/**
	 * Fires off a notification indicating that a new tag has been created.
	 *
	 * @param eventType {@link ChangeManager} change type
	 * @param tag the tag that was created
	 */
	private void fireTagCreatedNotification(ProgramEvent eventType, FunctionTag tag) {
		program.tagCreated(tag, eventType);
	}

	/**
	 * Fires off a notification indicating that the given tag has been deleted.
	 *
	 * @param eventType the type of change
	 * @param tag the tag that was deleted
	 */
	private void fireTagDeletedNotification(ProgramEvent eventType, FunctionTag tag) {
		program.tagChanged(tag, eventType, tag, null);
	}

	/**
	 * Deletes the given function tag.
	 *
	 * @param tag the tag to delete
	 * @throws IOException if there is an issue reading from the db
	 */
	void doDeleteTag(FunctionTag tag) throws IOException {

		// Remove all references to the tag in the two appropriate tables.
		functionTagMappingAdapter.removeFunctionTagRecord(tag.getId());
		functionTagAdapter.removeTagRecord(tag.getId());

		// Removing an object invalidates the db cache.
		cache.delete(tag.getId());

		fireTagDeletedNotification(ProgramEvent.FUNCTION_TAG_DELETED, tag);
		invalidateFunctions();
	}

	/**
	 * Tells the function manager that its tags are out of date. This
	 * will cause functions to go to the database to retrieve tags next time they
	 * are requested, rather than using their internal cache.
	 *
	 */
	private void invalidateFunctions() {
		FunctionManagerDB functionManager = program.getFunctionManager();
		functionManager.functionTagsChanged();
	}

	/**
	 * Returns all function tags associated with the given function id.
	 *
	 * @param functionId the function id
	 * @return the tags
	 * @throws IOException if there is an issue reading from the db
	 */
	Set<FunctionTag> getFunctionTagsByFunctionID(long functionId) throws IOException {
		Set<FunctionTag> tags = new HashSet<>();
		RecordIterator functionRecords =
			functionTagMappingAdapter.getRecordsByFunctionID(functionId);

		while (functionRecords.hasNext()) {
			DBRecord mappingRecord = functionRecords.next();
			DBRecord tagRecord = functionTagAdapter
					.getRecord(mappingRecord.getLongValue(FunctionTagMappingAdapter.TAG_ID_COL));
			tags.add(cache.getCachedInstance(tagRecord));
		}
		return tags;
	}

	void invalidateCache() {
		cache.invalidate();
		tagCountCache = null;
	}

	@Override
	public int getUseCount(FunctionTag tag) {
		try (Closeable c = lock.read()) {
			if (tagCountCache == null) {
				buildTagCountCache();
			}
			Counter counter = tagCountCache.get(tag);
			return counter.count();
		}
		catch (IOException e) {
			dbError(e);
			return 0;
		}
	}

	private void buildTagCountCache() throws IOException {
		Map<FunctionTag, Counter> map = LazyMap.lazyMap(new HashMap<>(), () -> new Counter());
		RecordIterator records = functionTagMappingAdapter.getRecords();
		while (records.hasNext()) {
			DBRecord mappingRecord = records.next();
			long tagId = mappingRecord.getLongValue(FunctionTagMappingAdapter.TAG_ID_COL);
			FunctionTag tag = getFunctionTag(tagId);
			map.get(tag).increment();
		}
		tagCountCache = map;
	}

	private class TagFactory implements DbFactory<FunctionTagDB> {

		@Override
		public FunctionTagDB instantiate(long dataTypeId) {
			try {
				DBRecord record = functionTagAdapter.getRecord(dataTypeId);
				return record == null ? null : instantiate(record);
			}
			catch (IOException e) {
				dbError(e);
				return null;
			}
		}

		@Override
		public FunctionTagDB instantiate(DBRecord rec) {
			return new FunctionTagDB(FunctionTagManagerDB.this, rec);
		}
	}

}
