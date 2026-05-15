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
package ghidra.program.database;

import java.util.ConcurrentModificationException;

import db.DBRecord;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;

/**
 * Base class for objects stored in the database. 
 * <P>
 * The general contract for database objects is that there should only ever be one instance for 
 * a specific database object at any given time. To facilitate this, instances of database objects
 * should be stored in a {@link DbCache} and the cache should be queried before creating
 * any new instances.
 * <P>
 * Database objects have keys that are used by the database record and also serves as the key for
 * cache lookup. They are marked as invalid when a database cache is invalidated and can be revived
 * on a refresh as long as they haven't been deleted. 
 */
public abstract class DbObject {

	protected long key;
	private volatile boolean deleted;
	private DbCache<?> cache = DbCache.DUMMY;
	private volatile int lastValidModificationCount;
	private boolean refreshing = false;

	/**
	 * Constructs a new DatabaseObject and adds it to the specified cache.
	 * 
	 * @param key database key to uniquely identify this object
	 */
	protected DbObject(long key) {
		this.key = key;
	}

	/**
	 * This is a special method for setting the cache and should ONLY be used by the
	 * {@link DbCache} when an object is added to the cache.
	 * @param cache the cache this object was added to.
	 */
	void setCache(DbCache<?> cache) {
		this.cache = cache;
		this.lastValidModificationCount = cache.getModificationCount();
	}

	/**
	 * Get the database key for this object.
	 * @return the database key for this object.
	 */
	public long getKey() {
		return key;
	}

	/**
	 * Marks the object as deleted.
	 */
	protected void setDeleted() {
		deleted = true;
	}

	/**
	 *
	 * Invalidate this object. This does not necessarily mean that this object can never be used
	 * again. If the object can refresh itself, it may still be usable.
	 */
	public void setInvalid() {
		lastValidModificationCount = DbCache.INVALID_COUNT;
	}

	/**
	 * Marks this object as valid. Note that this call does no checking on its own should be used
	 * very carefully and only when the caller is absolutely sure that the object is valid. Used
	 * in a special case for default symbols that have no corresponding record.
	 */
	protected void setValid() {
		lastValidModificationCount = cache.getModificationCount();
	}

	/**
	 * Method for updating the cache if a object record key changed. This is a very unusual 
	 * situation and should generally be avoided.
	 * @param newKey the new key for the associated record for this object
	 */
	protected void keyChanged(long newKey) {
		long oldKey = key;
		this.key = newKey;
		cache.keyChanged(oldKey, key);
	}

	/**
	 * Returns true if the object needs to be refreshed prior to further use.  An object needs
	 * to be refreshed if the cache has been invalidated since the last time the object was 
	 * checked for validity. There is a special case if the object has been deleted. It certainly
	 * doesn't need to be refreshed but clients that have the object already in hand still want to
	 * be able to call its getter methods without encountering an error. The assumption is that
	 * eventually the client will be kicked so it knows it needs to re-aquire its objects.
	 * <P>
	 * An object that has not been deleted may be marked as stale and in need of a refresh in one of
	 * two ways. The cache was invalidated or the object was specifically marked as invalid via its
	 * {@link #setInvalid()} method. A common situation where this can occur is an undo/redo
	 * operation against the underlying database.  The methods {@link #refreshIfNeeded()},
	 * {@link #checkDeleted()}, {@link #validate(Lock)} and {@link #isDeleted(Lock)} are methods
	 * which will force a re-validation if required.
	 * <P>
	 * This method is final as it is intended to be a "fast" check that doesn't require a lock
	 * to see if the object is possibly in need of a refresh. We don't want any subclass to add
	 * additional checks that might require a database lock. The idea is that if the cache
	 * modification hasn't  changed, then we know the object is valid. If the modification count
	 * has changed then we may or may not be valid and stronger checks are needed which will require
	 * a lock. Subclasses should override {@link #refreshIfNeeded()}, {@link #refresh()} to do
	 * the more robust validation checking.
	 * 
	 * @return true if this object is invalid and must be re-validated, else false if object state
	 * is currently valid which may include a deleted state.
	 */
	protected final boolean needsRefreshing() {
		if (deleted) {
			return false;
		}
		return lastValidModificationCount != cache.getModificationCount();
	}

	/**
	 * Return true if the object is known to be valid at this time. Note that this is is subtly 
	 * different from being the inverse of {@link #needsRefreshing()}, specifically in the case
	 * where the object has been deleted. For a deleted object, the {@link #isValid} method
	 * will return false, but the {@link #needsRefreshing()} will also return false.
	 * @return true if the object is known to be valid at this time.
	 */
	public final boolean isValid() {
		if (deleted) {
			return false;
		}
		return lastValidModificationCount == cache.getModificationCount();
	}

	/**
	 * Refreshes the object's state from the database if it is possibly stale. The check to see
	 * if an object is stale is fast, so this generally is a quick call unless an undo or 
	 * redo has taken place and a true refresh is required. If a refresh is performed, the
	 * object may be discovered to be deleted. This method should only be called while
	 * holding a {@link Lock#readLock()}
	 * 
	 * @return true if the object is valid, else false if deleted
	 */
	protected boolean refreshIfNeeded() {
		return refreshIfNeeded(null);
	}

	/**
	 * Refreshes the object's state if it is stale using the given record. 
	 * If the object has already been deleted, it will immediately return false. Otherwise, it 
	 * will check to see if it needs to be refreshed, and if so, refresh it. While refreshing the
	 * object, it may be discovered that it has been deleted and marked as such. 
	 * @param record a known valid record the object can use to refresh itself, if a refresh is
	 * needed. Null is permitted, in which case the object will have to do a database lookup to
	 * retrieve a record if a refresh is needed.
	 * 
	 * @return true if the object is valid, else false if deleted
	 */
	synchronized boolean refreshIfNeeded(DBRecord record) {
		if (needsRefreshing()) {
			doRefresh(record);
		}
		return !deleted;
	}

	/**
	 * Checks if this object has been deleted, in which case any use of the object is not allowed.
	 * This method should be invoked before any modifications to the object are performed to 
	 * ensure it still exists and is in a valid state.
	 * 
	 * @throws ConcurrentModificationException if the object has been deleted from the database.
	 */
	protected void checkDeleted() {
		if (!refreshIfNeeded(null)) {
			throw new ConcurrentModificationException("Object has been deleted.");
		}
	}

	/**
	 * Internal method for performing a refresh on a database object. This method may be called
	 * recursively, which is can detect and short circuit.
	 * @param record a known valid record the object can use to refresh itself or null. If null
	 * the object will have to do its own database retrieval of its record.
	 */
	private void doRefresh(DBRecord record) {
		if (refreshing) {
			// NOTE: We need to correct such recursion cases which should be
			// avoided since object is not in a valid state until refresh completed.
			return;
		}
		refreshing = true;
		try {
			if (refresh(record)) {
				// Object is valid
				setValid();
			}
			else {
				// if refresh failed, object has been deleted
				cache.delete(key);
				setDeleted();
			}
		}
		finally {
			refreshing = false;
		}
	}

	/**
	 * This method provides a cheap (lock free) way to test if an object is valid. If this object is
	 * invalid and not deleted, then the lock will be used to refresh as needed.  A deleted object
	 * will not be refreshed.
	 * 
	 * @param lock the lock that will be used if the object needs to be refreshed.
	 * @return true if object is valid or false if deleted
	 */
	protected boolean validate(Lock lock) {
		if (isValid()) {
			return true;
		}
		if (deleted) {
			return false;
		}

		try (Closeable c = lock.read()) {
			return refreshIfNeeded();
		}
	}

	/**
	 * Returns true if this object has been deleted. Note: once an object has been deleted, it will
	 * never be "refreshed". For example, if an object is ever deleted and is resurrected via an
	 * "undo", you will have get a fresh instance of the object.
	 * 
	 * @param lock object cache lock object
	 * @return true if this object has been deleted.
	 */
	public boolean isDeleted(Lock lock) {
		return deleted || !validate(lock);
	}

	/**
	 * Tells the object to refresh its state from the database.
	 * 
	 * @return true if the object was able to refresh itself. Return false if the object was
	 *         deleted. Objects that extend this class must implement a refresh method. If an object
	 *         can never refresh itself, then it should always return false.
	 */
	protected abstract boolean refresh();

	/**
	 * Tells the object to refresh its state from the database using the specified record if not
	 * null. NOTE: The default implementation ignores the record and invokes refresh().
	 * Implementations of this method must take care if multiple database tables are used since the
	 * record supplied could correspond to another object. In some cases it may be best not to
	 * override this method or ignore the record provided.
	 * 
	 * @param record valid record associated with object's key (optional, may be null to force
	 *            record lookup or other refresh technique)
	 * @return true if the object was able to refresh itself. Return false if record is null and
	 *         object was deleted. Objects that extend this class must implement a refresh method.
	 *         If an object can never refresh itself, then it should always return false.
	 */
	protected boolean refresh(DBRecord record) {
		return refresh();
	}

}
