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
package ghidra.formats.gfilesystem;

import java.io.*;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Pattern;

import org.apache.commons.collections4.map.ReferenceMap;

import ghidra.app.util.bin.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * File caching implementation.
 * <p>
 * Caches files based on a hash of the contents of the file.<br>
 * Files are retrieved using the hash string.<br>
 * Cached files are stored in a file with a name that is the hex encoded value of the hash.<br>
 * Cached files are obfuscated/de-obfuscated when written/read to/from disk.  See 
 * {@link ObfuscatedFileByteProvider}, {@link ObfuscatedInputStream}, 
 * {@link ObfuscatedOutputStream}.<br>
 * Cached files are organized into a nested directory structure to prevent
 * overwhelming a single directory with thousands of files.
 * <p>
 * Nested directory structure is based on the file's name:<br>
 * <pre>   File: AABBCCDDEEFF... &rarr; AA/AABBCCDDEEFF...</pre>
 * <p>
 * Cache size is not bounded.
 * <p>
 * Cache maintenance is done during startup if interval since last maintenance has been exceeded.
 * <p>
 * Files are not removed from the cache after being added, except during startup maintenance.
 *
 */
public class FileCache {
	/**
	 * Max size of a file that will be kept in {@link #memCache} (2Mb)  
	 */
	public static final int MAX_INMEM_FILESIZE = 2 * 1024 * 1024; // 2mb
	private static final long FREESPACE_RESERVE_BYTES = 50 * 1024 * 1024; // 50mb
	private static final Pattern NESTING_DIR_NAME_REGEX = Pattern.compile("[0-9a-fA-F][0-9a-fA-F]");
	private static final Pattern FILENAME_REGEX = Pattern.compile("[0-9a-fA-F]{32}");

	private static final int MD5_BYTE_LEN = 16;
	public static final int MD5_HEXSTR_LEN = MD5_BYTE_LEN * 2;
	private static final long MAX_FILE_AGE_MS = DateUtils.MS_PER_DAY;
	private static final long MAINT_INTERVAL_MS = DateUtils.MS_PER_DAY * 2;

	private final File cacheDir;
	private final FileStore cacheDirFileStore;
	private final File newDir;
	private FileCacheMaintenanceDaemon cleanDaemon;
	private ReferenceMap<String, FileCacheEntry> memCache = new ReferenceMap<>();

	/**
	 * Backwards compatible with previous cache directories to age off the files located
	 * therein.
	 * 
	 * @param oldCacheDir the old 2-level cache directory
	 * @deprecated Marked as deprecated to ensure this is removed in a few versions after most
	 * user's old-style cache dirs have been cleaned up.
	 */
	@Deprecated(forRemoval = true, since = "10.1")
	public static void performCacheMaintOnOldDirIfNeeded(File oldCacheDir) {
		if (oldCacheDir.isDirectory()) {
			performCacheMaintIfNeeded(oldCacheDir, 2 /* old nesting level */);
		}
	}

	/**
	 * Creates a new {@link FileCache} instance where files are stored under the specified
	 * {@code cacheDir}
	 * <p>
	 * @param cacheDir where to store the files
	 * @throws IOException if there was a problem creating subdirectories under cacheDir or
	 * when pruning expired files.
	 */
	public FileCache(File cacheDir) throws IOException {
		this.cacheDir = cacheDir;
		this.newDir = new File(cacheDir, "new");

		if ((!cacheDir.exists() && !cacheDir.mkdirs()) || (!newDir.exists() && !newDir.mkdirs())) {
			throw new IOException("Unable to initialize cache dir " + cacheDir);
		}

		cacheDirFileStore = Files.getFileStore(cacheDir.toPath());
		cleanDaemon = performCacheMaintIfNeeded(cacheDir, 1 /* current nesting level */);
	}

	/**
	 * Deletes all stored files from this file cache that are under a "NN" two hex digit
	 * nesting dir.
	 * <p>
	 * Will cause other processes which are accessing or updating the cache to error.
	 */
	public synchronized void purge() {
		for (File f : cacheDir.listFiles()) {
			String name = f.getName();
			if (f.isDirectory() && NESTING_DIR_NAME_REGEX.matcher(name).matches()) {
				FileUtilities.deleteDir(f);
			}
		}
		memCache.clear();
	}

	synchronized boolean hasEntry(String md5) {
		FileCacheEntry fce = memCache.get(md5);
		if (fce == null) {
			fce = getFileByMD5(md5);
		}
		return fce != null;
	}

	private void ensureAvailableSpace(long sizeHint) throws IOException {
		if ( sizeHint > MAX_INMEM_FILESIZE ) {
			long usableSpace = cacheDirFileStore.getUsableSpace();
			if (usableSpace >= 0 && usableSpace < sizeHint + FREESPACE_RESERVE_BYTES) {
				throw new IOException("Not enough storage available in " + cacheDir +
					" to store file sized: " + sizeHint);
			}
		}
		
	}

	/**
	 * Returns a {@link FileCacheEntry} for the matching file, based on its MD5, or
	 * NULL if there is no matching file.
	 * <p>
	 * Tweaks the file's last modified time to implement a LRU.
	 *
	 * @param md5 md5 string.
	 * @return {@link FileCacheEntry} with a File and it's md5 string or {@code null} if no
	 * matching file exists in cache.
	 */
	synchronized FileCacheEntry getFileCacheEntry(String md5) {
		if (md5 == null) {
			return null;
		}
		FileCacheEntry fce = memCache.get(md5);
		if (fce == null) {
			fce = getFileByMD5(md5);
			if (fce != null) {
				fce.file.setLastModified(System.currentTimeMillis());
			}
		}
		return fce;
	}

	synchronized void releaseFileCacheEntry(String md5) {
		FileCacheEntry fce = memCache.get(md5);
		if (fce != null) {
			memCache.remove(md5);
			Msg.debug(this, "Releasing memCache entry: " + fce.md5 + ", " + fce.bytes.length);
		}
	}

	/**
	 * Get a file (by md5) from the cache, returns NULL if not found.
	 * <p>
	 * @param md5 file md5 string.
	 * @return File or null if not found.
	 */
	private FileCacheEntry getFileByMD5(String md5) {
		File f = new File(cacheDir, getCacheRelPath(md5));
		return f.exists() ? new FileCacheEntry(f, md5) : null;
	}

	/**
	 * Creates a randomly generated file name in the temp directory.
	 * 
	 * @return randomly generated file name in the cache's temp directory
	 */
	private File createTempFile() {
		return new File(newDir, UUID.randomUUID().toString());
	}

	/**
	 * Creates a new {@link FileCacheEntryBuilder} that will accept bytes written to it
	 * (via its {@link OutputStream} methods).  When finished writing, the {@link FileCacheEntryBuilder}
	 * will give the caller a {@link FileCacheEntry}.
	 * 
	 * @param sizeHint a hint about the size of the file being added.  Use -1 if unsure or unknown
	 * @return new {@link FileCacheEntryBuilder}
	 * @throws IOException if error
	 */
	FileCacheEntryBuilder createCacheEntryBuilder(long sizeHint) throws IOException {
		ensureAvailableSpace(sizeHint);
		return new FileCacheEntryBuilder(sizeHint);
	}


	/**
	 * Adds a plaintext file to this cache, consuming it.
	 * <p>
	 * @param file plaintext file
	 * @param monitor {@link TaskMonitor}
	 * @return a {@link FileCacheEntry} that controls the contents of the newly added file
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	FileCacheEntry giveFile(File file, TaskMonitor monitor) throws IOException, CancelledException {
		try (InputStream fis = new FileInputStream(file);
				FileCacheEntryBuilder fceBuilder = createCacheEntryBuilder(file.length())) {
			FSUtilities.streamCopy(fis, fceBuilder, monitor);
			return fceBuilder.finish();
		}
		finally {
			if (!file.delete()) {
				Msg.warn(this, "Failed to delete temporary file: " + file);
			}
		}
	}

	/**
	 * Adds an already obfuscated File to this cache, consuming the file.
	 * <p>
	 * This method makes some assumptions:
	 * <p>
	 * 1) Directories are never removed - when ensuring that a nested directory exists
	 * before placing a new file into that directory, there is no locking mechanism
	 * and if another process removed the directory between the check for the directory's
	 * existence and the attempt to place the file into the directory.  Solution: no
	 * process may remove a nested directory after it has been created.
	 * 2) The source file is co-located with the cache directory to ensure its on the
	 * same physical filesystem volume, and is already obfuscated.
	 * <p>
	 * @param tmpFile the File to add to the cache
	 * @param md5 hex string md5 of the file
	 * @return a new {@link FileCacheEntry} with the File's location and its md5
	 * @throws IOException if an file error occurs
	 */
	private FileCacheEntry addTmpFileToCache(File tmpFile, String md5) throws IOException {
		String relPath = getCacheRelPath(md5);

		File destCacheFile = new File(cacheDir, relPath);
		File destCacheFileDir = destCacheFile.getParentFile();

		if (!destCacheFileDir.exists() && !FileUtilities.mkdirs(destCacheFileDir)) {
			throw new IOException("Failed to create cache dir " + destCacheFileDir);
		}

		try {
			tmpFile.renameTo(destCacheFile);
		}
		finally {
			tmpFile.delete();
			if (!destCacheFile.exists()) {
				throw new IOException("Failed to move " + tmpFile + " to " + destCacheFile);
			}
		}
		destCacheFile.setLastModified(System.currentTimeMillis());
		return new FileCacheEntry(destCacheFile, md5);
	}

	private String getCacheRelPath(String md5) {
		return String.format("%s/%s",
			md5.substring(0, 2),
			md5);
	}

	@Override
	public String toString() {
		return "FileCache [cacheDir=" + cacheDir + "]";
	}

	/**
	 * Returns true if the background thread has been created to clean old cache files and the
	 * thread is still working
	 * @return true if removing expired cache files
	 */
	boolean isCleaning() {
		return cleanDaemon != null && cleanDaemon.isAlive();
	}

	/**
	 * Prunes cache if interval since last maintenance exceeds {@link #MAINT_INTERVAL_MS}
	 * <p>
	 * Only called during construction, and the only known multi-process conflict that can occur
	 * is when re-writing the "lastMaint" timestamp file, which isn't a problem as its the
	 * approximate timestamp of that file that is important, not the contents.
	 * 
	 * @param cacheDir cache directory location 
	 * @param nestingLevel the depth of directory nesting, 2 for old style, 1 for newer style
	 * @return {@link FileCacheMaintenanceDaemon} instance if started, null otherwise
	 */
	private static FileCacheMaintenanceDaemon performCacheMaintIfNeeded(File cacheDir,
			int nestingLevel) {
		File lastMaintFile = new File(cacheDir, ".lastmaint");
		long lastMaintTS = lastMaintFile.isFile() ? lastMaintFile.lastModified() : 0;
		if (lastMaintTS + MAINT_INTERVAL_MS > System.currentTimeMillis()) {
			return null;
		}

		FileCacheMaintenanceDaemon cleanDaemon =
			new FileCacheMaintenanceDaemon(cacheDir, lastMaintFile, nestingLevel);
		cleanDaemon.start();
		return cleanDaemon;
	}

	private static class FileCacheMaintenanceDaemon extends Thread {
		private File lastMaintFile;
		private File cacheDir;
		private long storageEstimateBytes;
		private int nestingLevel;

		FileCacheMaintenanceDaemon(File cacheDir, File lastMaintFile, int nestingLevel) {
			setDaemon(true);
			setName("FileCacheMaintenanceDaemon for " + cacheDir.getName());
			this.cacheDir = cacheDir;
			this.lastMaintFile = lastMaintFile;
			this.nestingLevel = nestingLevel;
		}

		@Override
		public void run() {
			Msg.info(this, "Starting cache cleanup: " + cacheDir);
			cacheMaintForDir(cacheDir, 0);
			Msg.info(this,
				"Finished cache cleanup, estimated storage used: " + storageEstimateBytes);

			// stamp the file after we finish, in case the VM stopped this daemon thread
			try {
				FileUtilities.writeStringToFile(lastMaintFile, "Last maint run at " + (new Date()));
			}
			catch (IOException e) {
				Msg.error(this, "Unable to write file cache maintenance file: " + lastMaintFile, e);
			}
		}

		private void cacheMaintForDir(File dir, int dirLevel) {
			if (dirLevel < nestingLevel) {
				for (File f : dir.listFiles()) {
					String name = f.getName();
					if (f.isDirectory() && NESTING_DIR_NAME_REGEX.matcher(name).matches()) {
						cacheMaintForDir(f, dirLevel + 1);
					}
				}
			}
			else if (dirLevel == nestingLevel) {
				cacheMaintForLeafDir(dir);
			}
		}

		private void cacheMaintForLeafDir(File dir) {
			long cutoffMS = System.currentTimeMillis() - MAX_FILE_AGE_MS;

			for (File f : dir.listFiles()) {
				if (f.isFile() && isCacheFileName(f.getName())) {
					if (f.lastModified() < cutoffMS) {
						if (f.delete()) {
							Msg.debug(this, "Expired cache file " + f);
							continue;
						}
						Msg.error(this, "Failed to delete cache file " + f);
					}
					storageEstimateBytes += f.length();
				}
			}
		}

		private boolean isCacheFileName(String s) {
			return FILENAME_REGEX.matcher(s).matches();
		}

	}

	/**
	 * Helper class, keeps a FileCacheEntry pinned while the ByteProvider is alive.  When
	 * the ByteProvider is closed, the FileCacheEntry is allowed to be garbage collected
	 * if there is enough memory pressure to also remove its entry from the {@link FileCache#memCache}
	 * map.
	 */
	private static class RefPinningByteArrayProvider extends ByteArrayProvider {
		@SuppressWarnings("unused")
		private FileCacheEntry fce;	// its just here to be pinned in memory

		public RefPinningByteArrayProvider(FileCacheEntry fce, FSRL fsrl) {
			super(fce.bytes, fsrl);

			this.fce = fce;
		}

		@Override
		public void close() {
			fce = null;
			super.hardClose();
		}
	}

	/**
	 * Allows creating {@link FileCacheEntry file cache entries} at the caller's convenience.
	 * <p>
	 */
	public class FileCacheEntryBuilder extends OutputStream {

		private OutputStream delegate;
		private HashingOutputStream hos;
		private FileCacheEntry fce;
		private long delegateLength;
		private File tmpFile;

		private FileCacheEntryBuilder(long sizeHint) throws IOException {
			sizeHint = sizeHint <= 0 ? 512 : sizeHint;
			if (sizeHint < MAX_INMEM_FILESIZE) {
				delegate = new ByteArrayOutputStream((int) sizeHint);
			}
			else {
				tmpFile = createTempFile();
				delegate = new ObfuscatedOutputStream(new FileOutputStream(tmpFile));
			}
			initHashingOutputStream();
		}

		@Override
		protected void finalize() throws Throwable {
			if (hos != null) {
				Msg.warn(this, "FAIL TO CLOSE FileCacheEntryBuilder, currentSize=" +
					delegateLength + ", file=" + (tmpFile != null ? tmpFile : "not set"));
			}
		}

		@Override
		public void write(int b) throws IOException {
			switchToTempFileIfNecessary(1);
			hos.write(b);
		}

		@Override
		public void write(byte[] b) throws IOException {
			switchToTempFileIfNecessary(b.length);
			hos.write(b);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			switchToTempFileIfNecessary(len);
			hos.write(b, off, len);
		}

		@Override
		public void flush() throws IOException {
			hos.flush();
		}

		@Override
		public void close() throws IOException {
			finish();
		}

		private void initHashingOutputStream() throws IOException {
			try {
				hos = new HashingOutputStream(delegate, HashUtilities.MD5_ALGORITHM);
			}
			catch (NoSuchAlgorithmException e) {
				throw new IOException("Error getting MD5 algo", e);
			}
		}

		private void switchToTempFileIfNecessary(int bytesToAdd) throws IOException {
			delegateLength += bytesToAdd;
			if (tmpFile == null && delegateLength > MAX_INMEM_FILESIZE) {
				tmpFile = createTempFile();
				byte[] bytes = ((ByteArrayOutputStream) delegate).toByteArray();
				delegate = new ObfuscatedOutputStream(new FileOutputStream(tmpFile));
				initHashingOutputStream();
				// send the old bytes through the new hasher and to the tmp file
				hos.write(bytes);
			}
		}

		/**
		 * Finalizes this builder, pushing the bytes that have been written to it into
		 * the FileCache.
		 * <p>
		 * @return new {@link FileCacheEntry}
		 * @throws IOException if error
		 */
		public FileCacheEntry finish() throws IOException {
			if (hos != null) {
				hos.close();
				String md5 = NumericUtilities.convertBytesToString(hos.getDigest());
				if (tmpFile != null) {
					fce = addTmpFileToCache(tmpFile, md5);
				}
				else {
					ByteArrayOutputStream baos = (ByteArrayOutputStream) delegate;
					byte[] bytes = baos.toByteArray();
					fce = new FileCacheEntry(bytes, md5);
					synchronized (FileCache.this) {
						memCache.put(md5, fce);
					}
				}
				hos = null;
				delegate = null;
			}
			return fce;
		}

	}

	/**
	 * Represents a cached file.  It may be an actual file if {@link FileCacheEntry#file file}
	 * is set, or if smaller than {@link FileCache#MAX_INMEM_FILESIZE 2Mb'ish} just an 
	 * in-memory byte array that is weakly pinned in the {@link FileCache#memCache} map.
	 */
	public static class FileCacheEntry {

		final String md5;
		final File file;
		final byte[] bytes;

		private FileCacheEntry(File file, String md5) {
			this.file = file;
			this.bytes = null;
			this.md5 = md5;
		}

		private FileCacheEntry(byte[] bytes, String md5) {
			this.file = null;
			this.bytes = bytes;
			this.md5 = md5;
		}

		/**
		 * Returns the contents of this cache entry as a {@link ByteProvider}, using the specified
		 * {@link FSRL}.
		 * <p>
		 * @param fsrl {@link FSRL} that the returned {@link ByteProvider} should have as its
		 * identity
		 * @return new {@link ByteProvider} containing the contents of this cache entry, caller is
		 * responsible for {@link ByteProvider#close() closing}
		 * @throws IOException if error
		 */
		public ByteProvider asByteProvider(FSRL fsrl) throws IOException {
			if (fsrl.getMD5() == null) {
				fsrl = fsrl.withMD5(md5);
			}
			if (file != null) {
				file.setLastModified(System.currentTimeMillis());
			}
			return (bytes != null)
					? new RefPinningByteArrayProvider(this, fsrl)
					: new ObfuscatedFileByteProvider(file, fsrl, AccessMode.READ);
		}

		/**
		 * Returns the MD5 of this cache entry.
		 * 
		 * @return the MD5 (as a string) of this cache entry
		 */
		public String getMD5() {
			return md5;
		}

		public long length() {
			return bytes != null ? bytes.length : file.length();
		}

		@Override
		public int hashCode() {
			return Objects.hash(md5);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			FileCacheEntry other = (FileCacheEntry) obj;
			return Objects.equals(md5, other.md5);
		}

	}
}
