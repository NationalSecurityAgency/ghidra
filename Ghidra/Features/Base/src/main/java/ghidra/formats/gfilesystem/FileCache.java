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
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.UUID;
import java.util.regex.Pattern;

import ghidra.formats.gfilesystem.FSUtilities.StreamCopyResult;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * File caching implementation.
 * <p>
 * Caches files based on a hash of the contents of the file.<br>
 * Files are retrieved using the hash string.<p>
 * Cached files are stored in a file with a name that is the hex encoded value of the hash.
 * Cached files are organized into a nested directory structure to prevent
 * overwhelming a single directory with thousands of files.
 * <p>
 * Nested directory structure is based on the file's name:
 *   File: AABBCCDDEEFF...
 *   Directory (2 level nesting): AA/BB/AABBCCDDEEFF...
 * <p>
 * Cache size is not bounded.
 * <p>
 * Cache maint is done during startup if interval since last maint has been exceeded
 * <p>
 * No file data is maintained in memory.
 * <p>
 * No file is moved or removed from the cache after being added (except during startup)
 * as there is no use count or reference tracking of the files.
 *
 */
public class FileCache {

	private static final Pattern NESTING_DIR_NAME_REGEX = Pattern.compile("[0-9a-fA-F][0-9a-fA-F]");

	private static final int MD5_BYTE_LEN = 16;
	public static final int MD5_HEXSTR_LEN = MD5_BYTE_LEN * 2;
	private static final int NESTING_LEVEL = 2;
	private static final long MAX_FILE_AGE_MS = DateUtils.MS_PER_DAY;
	private static final long MAINT_INTERVAL_MS = DateUtils.MS_PER_DAY * 2;

	private final File cacheDir;
	private final File newDir;
	private final File lastMaintFile;
	private FileCacheMaintenanceDaemon cleanDaemon;

	private int fileAddCount;
	private int fileReUseCount;
	private long storageEstimateBytes;
	private long lastMaintTS;

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
		this.lastMaintFile = new File(cacheDir, ".lastmaint");

		if ((!cacheDir.exists() && !cacheDir.mkdirs()) || (!newDir.exists() && !newDir.mkdirs())) {
			throw new IOException("Unable to initialize cache dir " + cacheDir);
		}
		performCacheMaintIfNeeded();
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
	}

	/**
	 * Adds a {@link File} to the cache, returning a {@link FileCacheEntry}.
	 *
	 * @param f {@link File} to add to cache.
	 * @param monitor {@link TaskMonitor} to monitor for cancel and to update progress.
	 * @return {@link FileCacheEntry} with new File and md5.
	 * @throws IOException if error
	 * @throws CancelledException if canceled
	 */
	public FileCacheEntry addFile(File f, TaskMonitor monitor)
			throws IOException, CancelledException {
		try (FileInputStream fis = new FileInputStream(f)) {
			return addStream(fis, monitor);
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
	public FileCacheEntry getFile(String md5) {
		FileCacheEntry cfi = getFileByMD5(md5);
		if (cfi != null) {
			cfi.file.setLastModified(System.currentTimeMillis());
		}
		return cfi;
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
	 * Prunes cache if interval since last maintenance exceeds {@link #MAINT_INTERVAL_MS}
	 * <p>
	 * Only called during construction, and the only known multi-process conflict that can occur
	 * is when re-writing the "lastMaint" timestamp file, which isn't a problem as its the
	 * approximate timestamp of that file that is important, not the contents.
	 *
	 * @throws IOException if error when writing metadata file.
	 */
	private void performCacheMaintIfNeeded() throws IOException {
		lastMaintTS = (lastMaintTS == 0) ? lastMaintFile.lastModified() : lastMaintTS;
		if (lastMaintTS + MAINT_INTERVAL_MS > System.currentTimeMillis()) {
			return;
		}

		cleanDaemon = new FileCacheMaintenanceDaemon();
		cleanDaemon.start();
	}

	/**
	 * Prunes files in cache if they are old, calculates space used by cache.
	 */
	private void performCacheMaint() {
		storageEstimateBytes = 0;
		Msg.info(this, "Starting cache cleanup: " + cacheDir);
		// TODO: add check for orphan files in ./new
		cacheMaintForDir(cacheDir, 0);
		Msg.info(this, "Finished cache cleanup, estimated storage used: " + storageEstimateBytes);
	}

	private void cacheMaintForDir(File dir, int nestingLevel) {
		if (nestingLevel < NESTING_LEVEL) {
			for (File f : dir.listFiles()) {
				String name = f.getName();
				if (f.isDirectory() && NESTING_DIR_NAME_REGEX.matcher(name).matches()) {
					cacheMaintForDir(f, nestingLevel + 1);
				}
			}
		}
		else if (nestingLevel == NESTING_LEVEL) {
			cacheMaintForLeafDir(dir);
		}
	}

	private void cacheMaintForLeafDir(File dir) {
		long cutoffMS = System.currentTimeMillis() - MAX_FILE_AGE_MS;

		for (File f : dir.listFiles()) {
			if (f.isFile() && isCacheFileName(f.getName())) {
				if (f.lastModified() < cutoffMS) {
					if (!f.delete()) {
						Msg.error(this, "Failed to delete cache file " + f);
					}
					else {
						Msg.info(this, "Expired cache file " + f);
						continue;
					}
				}
				storageEstimateBytes += f.length();
			}
		}
	}

	private boolean isCacheFileName(String s) {
		try {
			byte[] bytes = NumericUtilities.convertStringToBytes(s);
			return (bytes != null) && bytes.length == MD5_BYTE_LEN;
		}
		catch (IllegalArgumentException e) {
			return false;
		}
	}

	/**
	 * Adds a contents of a stream to the cache, returning the md5 identifier of the stream.
	 * <p>
	 * The stream is copied into a temp file in the cacheDir/new directory while its md5
	 * is calculated.  The temp file is then moved into its final location
	 * based on the md5 of the stream: AA/BB/AABBCCDDEEFF....
	 * <p>
	 * The monitor progress is updated with the number of bytes that are being copied.  No
	 * message or maximum is set.
	 * <p>
	 * @param is {@link InputStream} to add to the cache.  Not closed when done.
	 * @param monitor {@link TaskMonitor} that will be checked for canceling and updating progress.
	 * @return {@link FileCacheEntry} with file info and md5, never null.
	 * @throws IOException if error
	 * @throws CancelledException if canceled
	 */
	public FileCacheEntry addStream(InputStream is, TaskMonitor monitor)
			throws IOException, CancelledException {
		File tmpFile = new File(newDir, UUID.randomUUID().toString());
		try (FileOutputStream fos = new FileOutputStream(tmpFile)) {
			StreamCopyResult copyResults = FSUtilities.streamCopy(is, fos, monitor);

			// Close the fos so the tmpFile can be moved even though
			// the try(){} will attempt to close it as well.
			fos.close();

			String md5 = NumericUtilities.convertBytesToString(copyResults.md5);

			return addTmpFileToCache(tmpFile, md5, copyResults.bytesCopied);
		}
		finally {
			if (tmpFile.exists()) {
				Msg.debug(this, "Removing left-over temp file " + tmpFile);
				tmpFile.delete();
			}
		}
	}

	/**
	 * Adds a file to the cache, using a 'pusher' strategy where the producer is given a
	 * {@link OutputStream} to write to.
	 * <p>
	 * Unbeknownst to the producer, but knownst to us, the outputstream is really a
	 * {@link HashingOutputStream} that will allow us to get the MD5 hash when the producer
	 * is finished pushing.
	 *
	 * @param pusher functional callback that will accept an {@link OutputStream} and write
	 * to it.
	 * <pre> (os) -&gt; { os.write(.....); }</pre>
	 * @param monitor {@link TaskMonitor} that will be checked for cancel and updated with
	 * file io progress.
	 * @return a new {@link FileCacheEntry} with the newly added cache file's File and MD5,
	 * never null.
	 * @throws IOException if an IO error
	 * @throws CancelledException if the user cancels
	 */
	public FileCacheEntry pushStream(DerivedFilePushProducer pusher, TaskMonitor monitor)
			throws IOException, CancelledException {
		File tmpFile = new File(newDir, UUID.randomUUID().toString());
		try (HashingOutputStream hos =
			new HashingOutputStream(new FileOutputStream(tmpFile), "MD5")) {
			pusher.push(hos);
			// early hos.close() so it can be renamed/moved on the filesystem
			hos.close();

			String md5 = NumericUtilities.convertBytesToString(hos.getDigest());
			long fileSize = tmpFile.length();

			return addTmpFileToCache(tmpFile, md5, fileSize);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IOException("Error getting MD5 algo", e);
		}
		catch (Throwable th) {
			throw new IOException("Error while pushing stream into cache", th);
		}
		finally {
			if (tmpFile.exists()) {
				Msg.debug(this, "Removing left-over temp file " + tmpFile);
				tmpFile.delete();
			}
		}

	}

	/**
	 * Adds a File to this cache, consuming the file.
	 * <p>
	 * This method makes some assumptions:
	 * <p>
	 * 1) Directories are never removed - when ensuring that a nested directory exists
	 * before placing a new file into that directory, there is no locking mechanism
	 * and if another process removed the directory between the check for the directory's
	 * existence and the attempt to place the file into the directory.  Solution: no
	 * process may remove a nested directory after it has been created.
	 * 2) The source file is co-located with the cache directory to ensure its on the
	 * same physical filesystem volume.
	 * <p>
	 * @param tmpFile the File to add to the cache
	 * @param md5 hex string md5 of the file
	 * @param fileLen the length in bytes of the file being added
	 * @return a new {@link FileCacheEntry} with the File's location and its md5
	 * @throws IOException if an file error occurs
	 */
	private FileCacheEntry addTmpFileToCache(File tmpFile, String md5, long fileLen)
			throws IOException {
		String relPath = getCacheRelPath(md5);

		File destCacheFile = new File(cacheDir, relPath);
		File destCacheFileDir = destCacheFile.getParentFile();

		if (!destCacheFileDir.exists() && !FileUtilities.mkdirs(destCacheFileDir)) {
			throw new IOException("Failed to create cache dir " + destCacheFileDir);
		}

		boolean moved = false;
		boolean reused = false;
		if (destCacheFile.exists()) {
			reused = true;
		}
		else {
			moved = tmpFile.renameTo(destCacheFile);

			// test again to see if another process was racing us if the rename failed
			reused = !moved && destCacheFile.exists();
		}
		if (!moved && reused) {
			//Msg.info(this, "File already exists in cache, reusing: " + destCacheFile);
			tmpFile.delete();
		}
		else if (!moved) {
			throw new IOException("Failed to move " + tmpFile + " to " + destCacheFile);
		}

		synchronized (this) {
			fileAddCount++;
			if (reused) {
				fileReUseCount++;
				destCacheFile.setLastModified(System.currentTimeMillis());
			}
			else {
				storageEstimateBytes += fileLen;
			}
		}

		return new FileCacheEntry(destCacheFile, md5);
	}

	private String getCacheRelPath(String md5) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < NESTING_LEVEL; i++) {
			sb.append(md5.substring(i * 2, (i + 1) * 2));
			sb.append('/');
		}
		sb.append(md5);
		return sb.toString();
	}

	@Override
	public String toString() {
		return "FileCache [cacheDir=" + cacheDir + ", fileAddCount=" + fileAddCount +
			", storageEstimateBytes=" + storageEstimateBytes + ", lastMaintTS=" + lastMaintTS + "]";
	}

	/**
	 * Number of files added to this cache.
	 *
	 * @return Number of files added to this cache
	 */
	public int getFileAddCount() {
		return fileAddCount;
	}

	/**
	 * Number of times a file-add was a no-op and the contents were already present
	 * in the cache.
	 *
	 * @return Number of times a file-add was a no-op and the contents were already present
	 * in the cache.
	 */
	public int getFileReUseCount() {
		return fileReUseCount;
	}

	/**
	 * Estimate of the number of bytes in the cache.
	 *
	 * @return estimate of the number of bytes in the cache - could be very wrong
	 */
	public long getStorageEstimateBytes() {
		return storageEstimateBytes;
	}

	/**
	 * How old (in milliseconds) files must be before being aged-off during cache maintenance.
	 *
	 * @return Max cache file age in milliseconds.
	 */
	public long getMaxFileAgeMS() {
		return MAX_FILE_AGE_MS;
	}

	/**
	 * Returns true if the background thread has been created to clean old cache files and the
	 * thread is still working
	 * @return true if removing expired cache files
	 */
	boolean isCleaning() {
		return cleanDaemon != null && cleanDaemon.isAlive();
	}

	private class FileCacheMaintenanceDaemon extends Thread {

		FileCacheMaintenanceDaemon() {
			setDaemon(true);
		}

		@Override
		public void run() {

			performCacheMaint();

			// stamp the file after we finish, in case the VM stopped this daemon thread
			lastMaintTS = System.currentTimeMillis();
			try {
				FileUtilities.writeStringToFile(lastMaintFile, "Last maint run at " + (new Date()));
			}
			catch (IOException e) {
				Msg.error(this, "Unable to write file cache maintenance file: " + lastMaintFile, e);
			}
		}
	}
}
