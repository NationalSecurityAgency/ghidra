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

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class FunctionTagManagerDB implements FunctionTagManager, ErrorHandler {

	private ProgramDB program;

	// Table containing all function tags in the system.
	private FunctionTagAdapter functionTagAdapter;

	// Table mapping function tags to functions
	private FunctionTagMappingAdapter functionTagMappingAdapter;

	private DBObjectCache<FunctionTagDB> cache;

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
	 * @throws CancelledException
	 */
	FunctionTagManagerDB(DBHandle handle, int openMode, Lock lock, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		this.lock = lock;

		functionTagAdapter = FunctionTagAdapter.getAdapter(handle, openMode, monitor);
		functionTagMappingAdapter = FunctionTagMappingAdapter.getAdapter(handle, openMode, monitor);

		cache = new DBObjectCache<FunctionTagDB>(100);
	}

	@Override
	public void setProgram(Program program) {
		this.program = (ProgramDB) program;
	}

	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	@Override
	public FunctionTag getFunctionTag(String name) {
		lock.acquire();

		try {
			Record rec = functionTagAdapter.getRecord(name);
			if (rec != null) {
				return getFunctionTagFromCache(rec);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}

		return null;
	}

	@Override
	public FunctionTag getFunctionTag(long id) {

		lock.acquire();

		try {
			FunctionTag tag = cache.get(id);
			if (tag != null) {
				return tag;
			}

			Record rec = functionTagAdapter.getRecord(id);
			if (rec != null) {
				return new FunctionTagDB(this, cache, rec);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}

		return null;
	}

	@Override
	public boolean isTagAssigned(String name) {

		lock.acquire();

		try {
			FunctionTag tag = getFunctionTag(name);
			if (tag == null) {
				return false;
			}
			return functionTagMappingAdapter.isTagAssigned(tag.getId());
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}

		return false;
	}

	@Override
	public FunctionTag createFunctionTag(String name, String comment) {

		lock.acquire();

		try {
			// First make sure a tag doesn't already exist with this name. If it does,
			// just return it.
			FunctionTag tag = getFunctionTag(name);
			if (tag != null) {
				return tag;
			}

			Record record = functionTagAdapter.createTagRecord(name, comment);
			tag = getFunctionTagFromCache(record);
			fireTagCreatedNotification(ChangeManager.DOCR_FUNCTION_TAG_CREATED, tag);

			return tag;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}

		return null;
	}

	void updateFunctionTag(FunctionTagDB tag) throws IOException {

		// Update the tag attributes.
		functionTagAdapter.updateRecord(tag.getRecord());

		// Notify subscribers of the change.
		fireTagChangedNotification(ChangeManager.DOCR_FUNCTION_TAG_CHANGED, tag);
		invalidateFunctions();
	}

	/* (non-Javadoc)
	 * TODO: Be a bit smarter about this - if the cache contains all the tags in
	 *  	 the db we can just return the cache itself. If not, then go to the
	 *  	 db to get the remainder.
	 */
	@Override
	public List<? extends FunctionTag> getAllFunctionTags() {

		lock.acquire();

		try {
			List<FunctionTag> tags = new ArrayList<>();
			RecordIterator records = functionTagAdapter.getRecords();
			while (records.hasNext()) {
				Record record = records.next();
				tags.add(getFunctionTagFromCache(record));
			}

			return tags;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return Collections.emptyList();
	}

	public FunctionTagAdapter getFunctionTagAdapter() {
		return functionTagAdapter;
	}

	public FunctionTagMappingAdapter getFunctionTagMappingAdapter() {
		return functionTagMappingAdapter;
	}

	/*****************************************************************************
	 * PRIVATE METHODS
	 *****************************************************************************/

	/**
	 * Sends a notification when a tag has been changed (edited or deleted).
	 *
	 * @param type {@link ChangeManager} change type
	 * @param tag the tag that was changed
	 * @throws IOException
	 */
	private void fireTagChangedNotification(int type, FunctionTag tag) throws IOException {
		program.tagChanged(tag, type, null, null);
	}

	/**
	 * Fires off a notification indicating that a new tag has been created.
	 *
	 * @param type {@link ChangeManager} change type
	 * @param tag the tag that was created
	 * @throws IOException
	 */
	private void fireTagCreatedNotification(int type, FunctionTag tag) throws IOException {
		program.tagCreated(tag, type);
	}

	/**
	 * Fires off a notification indicating that the given tag has been deleted.
	 *
	 * @param type the type of change
	 * @param tag the tag that was deleted
	 * @throws IOException
	 */
	private void fireTagDeletedNotification(int type, FunctionTag tag) throws IOException {
		program.tagChanged(tag, type, null, null);
	}

	/**
	 * Returns the cache object for the given Record. If the object is not in
	 * the cache, a new cache object is created.
	 *
	 * @param tagRecord the tag record to retrieve
	 * @return tag new cached tag object
	 */
	private FunctionTag getFunctionTagFromCache(Record tagRecord) {
		FunctionTagDB tag = cache.get(tagRecord);
		if (tag == null) {
			tag = new FunctionTagDB(this, cache, tagRecord);
		}
		return tag;
	}

	/**
	 * Deletes the given function tag.
	 *
	 * @param tag the tag to delete
	 */
	void doDeleteTag(FunctionTag tag) throws IOException {

		// Remove all references to the tag in the two appropriate tables.
		functionTagMappingAdapter.removeFunctionTagRecord(tag.getId());
		functionTagAdapter.removeTagRecord(tag.getId());

		// Removing an object invalidates the db cache.
		cache.delete(tag.getId());

		fireTagDeletedNotification(ChangeManager.DOCR_FUNCTION_TAG_DELETED, tag);
		invalidateFunctions();
	}

	/**
	 * Tells the function manager that its tags are out of date. This
	 * will cause functions to go to the database to retrieve tags next time they
	 * are requested, rather than using their internal cache.
	 *
	 */
	private void invalidateFunctions() {
		FunctionManagerDB functionManager = (FunctionManagerDB) program.getFunctionManager();
		functionManager.functionTagsChanged();
	}

	/**
	 * Returns all function tags associated with the given function id.
	 *
	 * @param functionId the function id
	 * @return
	 * @throws IOException
	 */
	Set<FunctionTag> getFunctionTagsByFunctionID(long functionId) throws IOException {
		Set<FunctionTag> tags = new HashSet<>();
		RecordIterator functionTagMappingRecords =
			functionTagMappingAdapter.getRecordsByFunctionID(functionId);

		while (functionTagMappingRecords.hasNext()) {
			Record mappingRecord = functionTagMappingRecords.next();
			Record tagRecord = functionTagAdapter.getRecord(
				mappingRecord.getLongValue(FunctionTagMappingAdapter.TAG_ID_COL));
			tags.add(getFunctionTagFromCache(tagRecord));
		}
		return tags;
	}
}
