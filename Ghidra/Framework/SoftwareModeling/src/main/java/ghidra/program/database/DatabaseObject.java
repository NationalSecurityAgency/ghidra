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

/**
 * Base class for an cached object in the database. Database objects have keys. They are marked as
 * invalid when a database cache is cleared and can be revived on a refresh as long as they haven't
 * been deleted. Instantiating an object will cause it to be added immediately to the associated
 * cache.
 */
public abstract class DatabaseObject {

	protected long key;
	private volatile boolean deleted;
	@SuppressWarnings("rawtypes")
	private final DBObjectCache cache;
	private volatile int invalidateCount;

	/**
	 * Constructs a new DatabaseObject and adds it to the specified cache.
	 * 
	 * @param cache to be used for this object or null if object will not be cached
	 * @param key database key to uniquely identify this object
	 */
	@SuppressWarnings("unchecked")
	protected DatabaseObject(@SuppressWarnings("rawtypes") DBObjectCache cache, long key) {
		this.key = key;
		this.cache = cache;
		if (cache != null) {
			cache.put(this);
			this.invalidateCount = cache.getInvalidateCount();
		}
	}

	/**
	 * Get the database key for this object.
	 */
	public long getKey() {
		return key;
	}

	/**
	 * Marks the object as deleted.
	 */
	void setDeleted() {
		deleted = true;
	}

	/**
	 *
	 * Invalidate this object. This does not necessarily mean that this object can never be used
	 * again. If the object can refresh itself, it may still be useable.
	 */
	public void setInvalid() {
		invalidateCount = getCurrentValidationCount() - 1;
	}

	private void setValid() {
		invalidateCount = getCurrentValidationCount();
	}

	private int getCurrentValidationCount() {
		return cache != null ? cache.getInvalidateCount() : 0;
	}

	protected void keyChanged(long newKey) {
		long oldKey = key;
		this.key = newKey;
		if (cache != null) {
			cache.keyChanged(oldKey, key);
		}
	}

	/**
	 * Returns true if object is currently invalid and must be validated prior to further use. 
	 * An invalid object may result from a cache invalidation which corresponds to wide-spread 
	 * record changes.  A common situation where this can occur is an undo/redo operation
	 * against the underlying database.  The methods {@link #checkIsValid()}, {@link #checkDeleted()},
	 * {@link #validate(Lock)} and {@link #isDeleted(Lock)} are methods which will force
	 * a re-validation if required.
	 * 
	 * @return true if this object is invalid and must be re-validated, else false if object state
	 * is currently valid which may include a deleted state.
	 */
	protected boolean isInvalid() {
		return !deleted && invalidateCount != getCurrentValidationCount();
	}

	/**
	 * Checks if this object has been deleted, in which case any use of the object is not allowed.
	 * This method should be invoked before any modifications to the object are performed to 
	 * ensure it still exists and is in a valid state.
	 * 
	 * @throws ConcurrentModificationException if the object has been deleted from the database.
	 */
	protected void checkDeleted() {
		if (!checkIsValid()) {
			throw new ConcurrentModificationException("Object has been deleted.");
		}
	}

	/**
	 * Check whether this object is still valid. If the object is invalid, the object will attempt
	 * to refresh itself. If the refresh fails, the object will be marked as deleted.
	 * 
	 * @return true if the object is valid, else false if deleted
	 */
	protected boolean checkIsValid() {
		return checkIsValid(null);
	}

	/**
	 * Check whether this object is still valid. If the object is invalid, the object will attempt
	 * to refresh itself using the specified record. If the refresh fails, the object will be marked
	 * as deleted and removed from cache. If this object is already marked as deleted, the record
	 * can not be used to refresh the object.
	 * 
	 * @param record optional record which may be used to refresh invalid object
	 * @return true if the object is valid.
	 */
	protected boolean checkIsValid(DBRecord record) {
		if (isInvalid()) {
			setValid();// prevent checkIsValid recursion during refresh
			if (!refresh(record)) {
				if (cache != null) {
					cache.delete(key);
				}
				setDeleted();
				setInvalid();
			}
		}
		return !deleted;
	}

	/**
	 * This method provides a cheap (lock free) way to test if an object is valid. If this object is
	 * invalid, then the lock will be used to refresh as needed.
	 * 
	 * @param lock the lock that will be used if the object needs to be refreshed.
	 * @return true if object is valid, else false if deleted
	 */
	protected boolean validate(Lock lock) {
		if (!isInvalid()) {
			return true;
		}
		lock.acquire();
		try {
			return checkIsValid();
		}
		finally {
			lock.release();
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
