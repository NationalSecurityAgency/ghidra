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

import java.util.Collections;
import java.util.List;

import db.DBRecord;
import generic.cache.WeakReferenceCache;
import ghidra.program.model.address.KeyRange;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;

/**
 * A DbObject cache that efficiently manages the use of the database lock and uses a 
 * factory to create objects in the cache when they are not present. 
 * <P>
 * This version of the cache is designed to be used without first acquiring a database lock. It will
 * first attempt to retrieve the object without acquiring the lock. If that fails, it will acquire
 * the lock, attempt to refresh the object if necessary or possibly create a new instance using 
 * the factory and add it to the cache.
 *
 * @param <T> the type of the database object
 */
public class DbCache<T extends DbObject> {
	public static final DbCache<?> DUMMY = new DummyCache();
	public static final int INVALID_COUNT = -1;
	protected Lock lock;
	protected DbFactory<T> factory;
	protected WeakReferenceCache<Long, T> refCache;
	private volatile int modificationCount;

	/**
	 * Constructor
	 * @param factory the factory for creating new instances of database objects
	 * @param lock the database lock.
	 * @param hardCacheSize the size of the hard reference cache
	 */
	public DbCache(DbFactory<T> factory, Lock lock, int hardCacheSize) {
		this.refCache = new WeakReferenceCache<>(hardCacheSize);
		this.factory = factory;
		this.lock = lock;
	}

	private DbCache() {
		// do nothing (For Dummy)
	}

	/**
	 * Returns the number of objects currently in the cache. A database lock is not required.
	 * @return the number of objects currently in the cache.
	 */
	public int size() {
		return refCache.size();
	}

	/**
	 * Adds the given database object to the cache.
	 * @param dbObject the object to add to the cache.
	 * @return the object that was cached
	 */
	public T add(T dbObject) {
		dbObject.setCache(this);
		return refCache.add(dbObject.getKey(), dbObject);
	}

	/**
	 * Retrieves the database object with the given key from the cache. This differs from the
	 * super's get() method in that it does not require that the database lock be acquired prior
	 * to calling this method and in fact performs better if the lock is not acquired. This version
	 * will first look in the cache and if it finds one that is definitely valid (there is
	 * a quick check that doesn't require the lock), it returns it immediately. Otherwise, the
	 * cache doesn't have the object or the object needs refreshing. In this case, this method
	 * will acquire the lock, attempt refresh the object if it exists, and if necessary call a 
	 * factory method to create a new instance and add it to the cache.
	 * 
	 * @param key the key of the object to retrieve.
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public T getCachedInstance(Long key) {
		T t = refCache.get(key);
		if (t != null && t.isValid()) {
			return t;
		}

		try (Closeable c = lock.read()) {
			if (t != null && t.refreshIfNeeded()) {
				return t;
			}
			// note that the instantiateAndCacheSafely is synchronized and it will double check the cache
			// to prevent multiple threads from getting here and then creating a dbObject.
			return instantiateAndCacheSafely(key);
		}
	}

	/**
	 * Retrieves the object from the cache, but only if it already exists and is valid in the cache.
	 * It will not attempt to refresh the object or call the factory method to create new instances.
	 * 
	 * @param key the key of the object to retrieve.
	 * @return the cached object or null if the object with that key is not currently cached and
	 * valid.
	 */
	public T getIfValid(Long key) {
		T t = refCache.get(key);
		if (t != null && t.isValid()) {
			return t;
		}
		return null;
	}

	/**
	 * Retrieves the object with the given key from the cache with checking if it is valid or needs
	 * to be refreshed. It will not use the factory to create new instances if they don't exist.
	 * This method is used in very specialized situations where the caller has already done
	 * checking and they know the status of the object and how to refresh it cheaply if needed.
	 * @param key the key of the object to retrieve
	 * @return the object directly from the cache if one exists in the cache.
	 */
	public T getRaw(Long key) {
		return refCache.get(key);
	}

	/**
	 * Retrieves the database object with the given record and associated key from the cache.
	 * This form should be used in conjunction with record iterators to avoid unnecessary
	 * record query during a possible object refresh.  To benefit from the record the cached
	 * object must implement the {@link DbObject#refresh(DBRecord)} method which by default
	 * ignores the record and simply calls {@link DbObject#refresh()}.
	 * <P>
	 * This method is similar to the get() method in that it can be called without the database 
	 * lock. It will first check if the object is in the cache and definitely valid before 
	 * acquiring the lock and refreshing or creating the database object.
	 * @param dbRecord the valid record corresponding to the object to be retrieved and possibly
	 * used to refresh the associated object if found in cache
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public T getCachedInstance(DBRecord dbRecord) {
		if (dbRecord == null) {
			return null;
		}

		Long key = dbRecord.getKey();
		T t = refCache.get(key);
		if (t != null && t.isValid()) {
			return t;
		}
		try (Closeable c = lock.read()) {
			if (t != null && t.refreshIfNeeded(dbRecord)) {
				return t;
			}
			// note that the instantiateAndCacheSafely is synchronized and it will double check the cache
			// to prevent multiple threads from getting here and then creating a dbObject.
			return instantiateAndCacheSafely(dbRecord);
		}
	}

	/**
	 * Returns an List of all the cached objects. These objects have not been checked to see if they
	 * are valid or not. 
	 * @return an List of all the cached objects.
	 */
	public List<T> getCachedObjects() {
		return refCache.getCachedObjects();
	}

	/**
	 * Delete all objects from HashMap whose key is contained
	 * within the specified keyRanges.
	 * @param keyRanges key ranges to delete
	 */
	public void delete(List<KeyRange> keyRanges) {
		long rangesSize = getKeyRangesSize(keyRanges); // < 0 too many ranges
		if (rangesSize < 0 || rangesSize > refCache.size()) {
			deleteLargeKeyRanges(keyRanges);
		}
		else {
			deleteSmallKeyRanges(keyRanges);
		}
	}

	/**
	 * Marks all the cached objects as invalid.  Invalid objects will have to refresh themselves
	 * before they are allowed to be used. If an invalidated object cannot refresh itself, then
	 * the object is removed from the cache and discarded and the application can no longer use
	 * that instance of the object.
	 */
	public void invalidate() {
		// Note: the ++ operation here is not atomic, but that shouldn't be an issue. If more
		// than one thread attempts to increment the count at the same time, it is possible for
		// the count not to be incremented the full number of times, but it will be incremented
		// at least by 1, which is all that really matters.
		if (++modificationCount < 0) {
			// if it overflows, reset to 0 so it is never negative
			modificationCount = 0;
		}
	}

	/**
	 * Removes the object with the given key from the cache. A database lock is not required.
	 * @param key the key of the object to remove.
	 */
	public void delete(long key) {
		T deleted = refCache.delete(key);
		if (deleted != null) {
			deleted.setDeleted();
		}
	}

	/**
	 * Updates the cache for an object whose key has changed.
	 * @param oldKey the old key
	 * @param newKey the new key
	 */
	public void keyChanged(long oldKey, long newKey) {
		synchronized (refCache) {
			T t = refCache.delete(oldKey);
			if (t != null) {
				t.setInvalid();
				refCache.add(newKey, t);
			}
		}
	}

	/**
	 * Get the current cache modification counter value which corresponds to the number of times
	 * the entire cache has been invalidated.
	 * @return the current modification counter value
	 */
	public int getModificationCount() {
		return modificationCount;
	}

	private synchronized T instantiateAndCacheSafely(Long key) {
		// check if another thread got here first
		T t = refCache.get(key);
		if (t != null && t.refreshIfNeeded()) {
			return t;
		}

		t = factory.instantiate(key);
		if (t != null) {
			add(t);
		}
		return t;
	}

	private synchronized T instantiateAndCacheSafely(DBRecord record) {
		// check if another thread got here first
		T t = refCache.get(record.getKey());
		if (t != null && t.refreshIfNeeded()) {
			return t;
		}
		t = factory.instantiate(record);
		add(t);
		return t;
	}

	/**
	 * Delete all objects from cache whose key is contained
	 * within the specified keyRanges.  Iteration over all
	 * keys contained within keyRanges will be performed.
	 * @param keyRanges key ranges to delete
	 */
	private void deleteSmallKeyRanges(List<KeyRange> keyRanges) {
		synchronized (refCache) {
			for (KeyRange range : keyRanges) {
				for (long key = range.minKey; key <= range.maxKey; key++) {
					T dbObject = refCache.delete(key);
					if (dbObject != null) {
						dbObject.setDeleted();
					}
				}
			}
		}
	}

	/**
	 * Delete all objects from cache whose key is contained
	 * within the specified keyRanges.  Iteration over all
	 * keys contained within map will be performed.
	 * @param keyRanges key ranges to delete
	 */
	private void deleteLargeKeyRanges(List<KeyRange> keyRanges) {
		refCache.deleteIf(v -> checkInRange(v, keyRanges));
	}

	private boolean checkInRange(T t, List<KeyRange> keyRanges) {
		long key = t.getKey();
		if (keyRangesContain(keyRanges, key)) {
			t.setDeleted();
			return true;
		}
		return false;
	}

	/**
	 * Return total number of keys covered by list of keyRanges.
	 * @param keyRanges key ranges to get the number of keys
	 * @return number of keys, or -1 if more than Long.MAX_VALUE keys
	 */
	private long getKeyRangesSize(List<KeyRange> keyRanges) {
		long size = 0;
		for (KeyRange range : keyRanges) {
			size += range.length();
			if (size < 0) {
				return -1;
			}
		}
		return size;
	}

	private boolean keyRangesContain(List<KeyRange> keyRanges, long key) {
		for (KeyRange range : keyRanges) {
			if (range.contains(key)) {
				return true;
			}
		}
		return false;
	}

	private static class DummyCache extends DbCache<DbObject> {

		@Override
		public int getModificationCount() {
			return 0;
		}

		@Override
		public DbObject getCachedInstance(Long key) {
			return null;
		}

		@Override
		public DbObject getIfValid(Long key) {
			return null;
		}

		@Override
		public DbObject getCachedInstance(DBRecord dbRecord) {
			return null;
		}

		@Override
		public int size() {
			return 0;
		}

		@Override
		public DbObject add(DbObject dbObject) {
			return dbObject;
		}

		@Override
		public void keyChanged(long oldKey, long newKey) {
			// do nothing
		}

		@Override
		public void delete(long key) {
			// do nothing
		}

		@Override
		public void delete(List<KeyRange> keyRanges) {
			// do nothing
		}

		@Override
		public List<DbObject> getCachedObjects() {
			return Collections.emptyList();
		}
	}

}
