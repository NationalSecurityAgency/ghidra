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
package ghidra.framework.store.db;

import java.io.*;
import java.util.*;

import db.buffers.LocalBufferFile;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.store.FolderItem;
import ghidra.framework.store.local.ItemDeserializer;
import ghidra.framework.store.local.LockFile;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class PackedDatabaseCache {

	private static final String CACHE_DIR_PROPERTY = "pdb.cache.dir";
	private static final String CACHE_ENABLED_PROPERTY = "pdb.cache.enabled";

	private static final int SHELF_LIFE = 7 * 24 * 60 * 60 * 1000; // 7-days

	private static final String CACHE_DIR = "packed-db-cache";
	private static final String CACHE_MAP_FILE = "cache.map";
	private static final String MAP_SEPARATOR = ",";

	private static PackedDatabaseCache cache;

	private static final String PDB_PREFIX = "pdb";

	private static volatile boolean doCleanup = true;

	private static Boolean isEnabled;

	private final File cacheDir;
	private final File mapFile;
	private final LockFile lock;

	private PackedDatabaseCache(File cacheDir) throws IOException {
		this.cacheDir = cacheDir;
		if (isEnabled()) {
			if (!cacheDir.mkdir() && !cacheDir.isDirectory()) {
				throw new IOException("Failed to create cache directory: " + cacheDir);
			}
			if (!cacheDir.canExecute() || !cacheDir.canWrite()) {
				throw new IOException("permission denied: " + cacheDir);
			}
			Msg.info(this, "Packed database cache: " + cacheDir);
		}
		else {
			Msg.info(this, "Packed database cache is disabled");
		}
		mapFile = new File(cacheDir, CACHE_MAP_FILE);
		lock = new LockFile(cacheDir, "cache", "u");
	}

	public static boolean isEnabled() {
		if (isEnabled == null) {
			isEnabled = true;
			String enabled = System.getProperty(CACHE_ENABLED_PROPERTY);
			if (enabled != null) {
				enabled = enabled.trim().toLowerCase();
				isEnabled = "true".equals(enabled) || "yes".equals(enabled);
			}
		}
		return isEnabled;
	}

	public static synchronized PackedDatabaseCache getCache() throws IOException {
		if (cache == null) {
			File cacheDir = null;
			String dirpath = System.getProperty(CACHE_DIR_PROPERTY);
			if (dirpath != null) {
				cacheDir = new File(dirpath);
			}
			else {
				cacheDir = new File(Application.getUserCacheDirectory(), CACHE_DIR);
			}
			cache = new PackedDatabaseCache(cacheDir);
		}
		return cache;
	}

	private List<CachedDB> readCache() throws IOException {
		List<CachedDB> list = new ArrayList<CachedDB>();
		if (!mapFile.exists()) {
			// cleanup db directories if map is missing
			for (File f : cacheDir.listFiles()) {
				if (f.isDirectory() && f.getName().startsWith(PDB_PREFIX)) {
					FileUtilities.deleteDir(f);
				}
			}
			return list;
		}
		boolean modified = false;
		long now = (new Date()).getTime();
		BufferedReader r = new BufferedReader(new FileReader(mapFile));
		try {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.length() == 0) {
					continue;
				}
				CachedDB entry = new CachedDB(line);
				if (isBadDBDir(entry)) {
					Msg.warn(this,
						"Forcing removal of bad cached DB: " + entry.itemName + ", " + entry.dbDir);
					entry.lastAccessTime = 0; // force cleanup
				}
				long timeSinceLastAccess = now - entry.lastAccessTime;
				if (timeSinceLastAccess > SHELF_LIFE || !entry.dbDir.exists() ||
					(entry.refreshRequired() && !entry.originalPackedDBExists())) {
					if (doCleanup) {
						FileUtilities.deleteDir(entry.dbDir);
						modified = true;
					}
					continue;
				}
				list.add(entry);
			}
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, "Corrupt cache - exit and try removing it: " + cacheDir);
		}
		finally {
			r.close();
		}
		doCleanup = false;
		if (modified) {
			writeCacheList(list);
		}
		return list;
	}

	private boolean isBadDBDir(CachedDB entry) {
		File dbDir = entry.dbDir;
		File[] files = dbDir.listFiles();
		if (files == null) {
			Msg.debug(this, "CachedDB directory not found: " + entry.itemName + ", " + entry.dbDir);
			return true;
		}
		if (files.length == 0) {
			// missing/empty directory indicates not yet opened/unpacked
			entry.lastModifiedTime = 0;
			if (!entry.originalPackedDBExists()) {
				Msg.debug(this, "CachedDB has empty directory and packed file not found: " +
					entry.itemName + ", " + entry.packedDbFilePath);
				return true;
			}
			return false;
		}
		for (File f : files) {
			if (f.getName().endsWith(LocalBufferFile.BUFFER_FILE_EXTENSION) && f.length() != 0) {
				return false;
			}
		}
		Msg.debug(this, "CachedDB is not empty but contains no *.gbf files: " + entry.itemName +
			", " + entry.packedDbFilePath);
		return true;
	}

	private void writeCacheList(List<CachedDB> list) throws IOException {
		FileOutputStream out = new FileOutputStream(mapFile);

		PrintWriter w = new PrintWriter(out);
		for (CachedDB entry : list) {
			w.println(entry.getMapEntry());
		}

		try {
			out.getFD().sync();
		}
		catch (SyncFailedException e) {
			// Sync not supported - we tried our best
		}

		w.close();
	}

	private void addCacheMapEntry(CachedDB cachedDb) throws IOException {

		FileOutputStream out = new FileOutputStream(mapFile, true);

		PrintWriter w = new PrintWriter(out);
		w.println(cachedDb.getMapEntry());

		try {
			out.getFD().sync();
		}
		catch (SyncFailedException e) {
			// Sync not supported - we tried our best
		}

		w.close();
	}

	private CachedDB createCachedDb(ResourceFile packedDbFile) throws IOException {
		File dbDir = createCachedDir();
		ItemDeserializer itemDeserializer = null;
		boolean success = false;
		try {
			long dbTime = packedDbFile.lastModified();
			if (dbTime == 0 || !packedDbFile.isFile()) {
				throw new FileNotFoundException("File not found: " + packedDbFile);
			}
			itemDeserializer = new ItemDeserializer(packedDbFile);
			if (itemDeserializer.getFileType() != FolderItem.DATABASE_FILE_TYPE) {
				throw new IOException("Incorrect file type");
			}
			String contentType = itemDeserializer.getContentType();
			String itemName = itemDeserializer.getItemName();
			CachedDB cachedDb = new CachedDB(packedDbFile, dbDir, contentType, itemName, 0, true);
			success = true;
			return cachedDb;
		}
		finally {
			if (itemDeserializer != null) {
				itemDeserializer.dispose();
			}
			if (!success) {
				FileUtilities.deleteDir(dbDir);
			}
		}
	}

	private File createCachedDir() throws IOException {
		int tries = 0;
		while (tries++ < 10) {
			File dir = new File(cacheDir, PDB_PREFIX + PackedDatabase.getRandomString());
			if (dir.mkdir()) {
				return dir;
			}
		}
		throw new IOException("Unable to create cached database");
	}

	CachedDB getCachedDBEntry(ResourceFile packedDbFile) throws IOException {
		if (!isEnabled()) {
			throw new IOException("Cache disabled");
		}
		if (!lock.createLock(PackedDatabase.LOCK_TIMEOUT, true)) {
			throw new IOException("Packed database cache timeout");
		}
		try {
			String packedFilePath = packedDbFile.getCanonicalPath();
			List<CachedDB> list = readCache();
			for (CachedDB entry : list) {
				if (packedFilePath.equals(entry.packedDbFilePath)) {
					return entry;
				}
			}
		}
		finally {
			lock.removeLock();
		}
		return null;
	}

	void purgeFromCache(ResourceFile packedDbFile) throws IOException {
		if (!lock.createLock(PackedDatabase.LOCK_TIMEOUT, true)) {
			throw new IOException("Packed database cache timeout");
		}
		try {
			String packedFilePath = packedDbFile.getCanonicalPath();
			List<CachedDB> list = readCache();
			for (CachedDB entry : list) {
				if (packedFilePath.equals(entry.packedDbFilePath)) {
					entry.lastAccessTime = 0;
					writeCacheList(list);
					FileUtilities.deleteDir(entry.dbDir);
					break;
				}
			}
		}
		finally {
			lock.removeLock();
		}
	}

	boolean isInCache(ResourceFile packedDbFile) throws IOException {
		if (!lock.createLock(PackedDatabase.LOCK_TIMEOUT, true)) {
			throw new IOException("Packed database cache timeout");
		}
		try {
			String packedFilePath = packedDbFile.getCanonicalPath();
			List<CachedDB> list = readCache();
			for (CachedDB entry : list) {
				if (packedFilePath.equals(entry.packedDbFilePath) && entry.dbDir.isDirectory()) {
					return true;
				}
			}
		}
		finally {
			lock.removeLock();
		}
		return false;
	}

	/**
	 * Get cached packed database
	 * @param packedDbFile
	 * @param isReadOnly
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 * @throws IOException
	 */
	PackedDatabase getCachedDB(ResourceFile packedDbFile, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (!isEnabled()) {
			throw new IOException("Cache disabled");
		}
		if (!lock.createLock(PackedDatabase.LOCK_TIMEOUT, true)) {
			throw new IOException("Packed database cache timeout");
		}
		try {
			boolean isReadOnly =
				PackedDatabase.isReadOnlyPDBDirectory(packedDbFile.getParentFile());

			LockFile packedDbLock = null;
			if (!isReadOnly) {
				packedDbLock = PackedDatabase.getFileLock(packedDbFile.getFile(false));
				PackedDatabase.lock(packedDbLock, true, true);
			}
			try {
				String packedFilePath = packedDbFile.getCanonicalPath();
				long now = (new Date()).getTime();
				CachedDB cachedDb = null;
				List<CachedDB> list = readCache();
				for (CachedDB entry : list) {
					if (packedFilePath.equals(entry.packedDbFilePath)) {
						if (!entry.dbDir.canExecute() || !entry.dbDir.canWrite()) {
							throw new IOException("Permssion denied: " + entry.dbDir);
						}
						entry.lastAccessTime = now;
						writeCacheList(list);
						cachedDb = entry;
						break;
					}
				}
				if (cachedDb == null) {
					cachedDb = createCachedDb(packedDbFile);
					cachedDb.lastAccessTime = now;
					addCacheMapEntry(cachedDb);
					Msg.debug(this, "Caching packed database: " + cachedDb.packedDbFilePath);
				}
				else {
					Msg.debug(this, "Using cached packed database: " + cachedDb.packedDbFilePath);
				}
				return new PackedDatabase(packedDbFile, packedDbLock, cachedDb, monitor);
			}
			finally {
				if (packedDbLock != null && packedDbLock.haveLock()) {
					// packed database lock may have been removed if disposed on error
					packedDbLock.removeLock();
				}
			}
		}
		finally {
			lock.removeLock();
		}
	}

	void updateLastModified(ResourceFile packedDbFile, long modTime) throws IOException {
		if (!isEnabled()) {
			throw new IOException("Cache disabled");
		}
		if (!lock.createLock(PackedDatabase.LOCK_TIMEOUT, true)) {
			throw new IOException("Packed database cache timeout");
		}
		try {
			String packedFilePath = packedDbFile.getCanonicalPath();
			long now = (new Date()).getTime();
			List<CachedDB> list = readCache();
			for (CachedDB entry : list) {
				if (packedFilePath.equals(entry.packedDbFilePath)) {
					entry.lastAccessTime = now;
					entry.lastModifiedTime = modTime;
					writeCacheList(list);
					Msg.debug(this, "Cache update completed: " + packedFilePath);
					return;
				}
			}
			Msg.debug(this, "Cache entry not found for: " + packedFilePath);
		}
		finally {
			lock.removeLock();
		}
	}

	class CachedDB {

		public final String packedDbFilePath;
		public final String itemName;
		public final String contentType;
		public final File dbDir;

		private ResourceFile packedDbFile;
		private boolean refreshRequired; // signal PackedDatabase to unpack

		private long lastModifiedTime;
		private long lastAccessTime;

		CachedDB(ResourceFile packedDbFile, File dbDir, String contentType, String itemName,
				long lastModifiedTime, boolean refreshRequired) throws IOException {
			this.packedDbFile = packedDbFile;
			this.packedDbFilePath = packedDbFile.getCanonicalPath();
			this.dbDir = dbDir;
			this.contentType = contentType;
			this.itemName = itemName;
			this.lastModifiedTime = lastModifiedTime;
			this.refreshRequired = refreshRequired;
		}

		CachedDB(String mapEntry) {
			String[] split = splitEntry(mapEntry);
			packedDbFilePath = split[0];
			dbDir = new File(cacheDir, split[1]);
			lastModifiedTime = Long.parseUnsignedLong(split[2], 16);
			contentType = split[3];
			itemName = split[4];

			try {
				packedDbFile = new ResourceFile(packedDbFilePath);
				refreshRequired = lastModifiedTime != packedDbFile.lastModified();
			}
			catch (Exception e) {
				// ignore - treat as non-existing file
			}

			lastAccessTime = Long.parseUnsignedLong(split[5], 16);
		}

		String[] splitEntry(String mapEntry) {
			String[] split = new String[6];
			int lastIndex = mapEntry.length();
			for (int i = 5; i > 0; i--) {
				int index = mapEntry.lastIndexOf(MAP_SEPARATOR, lastIndex - 1);
				if (index <= 0 || (lastIndex - index) == 1) {
					throw new IllegalArgumentException("Invalid cache map entry");
				}
				split[i] = mapEntry.substring(index + 1, lastIndex);
				lastIndex = index;
			}
			split[0] = mapEntry.substring(0, lastIndex);
			return split;
		}

		boolean refreshRequired() {
			return refreshRequired;
		}

		long getLastModified() {
			return lastModifiedTime;
		}

		boolean originalPackedDBExists() {
			return packedDbFile != null && packedDbFile.isFile();
		}

		String getMapEntry() {
			StringBuffer buf = new StringBuffer();
			buf.append(packedDbFilePath);
			buf.append(MAP_SEPARATOR);
			buf.append(dbDir.getName());
			buf.append(MAP_SEPARATOR);
			buf.append(Long.toHexString(lastModifiedTime));
			buf.append(MAP_SEPARATOR);
			buf.append(contentType);
			buf.append(MAP_SEPARATOR);
			buf.append(itemName);
			buf.append(MAP_SEPARATOR);
			buf.append(Long.toHexString(lastAccessTime));
			return buf.toString();
		}

	}

}
