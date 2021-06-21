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
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.FileSystemFactoryMgr;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.timer.GTimer;

/**
 * Provides methods for dealing with GFilesystem files and {@link GFileSystem filesystems}.
 * <p>
 * Most methods take {@link FSRL} references to files as a way to decouple dependencies and
 * reduce forced filesystem instantiation.
 * <p>
 * (ie. a {@link GFile} instance is only valid if its {@link GFileSystem} is open, which
 * means that its parent probably also has to be open, recursively, etc, whereas a FSRL
 * is always valid and does not force the instantiation of parent objects)
 * <p>
 * {@link GFileSystem Filesystems} should be used via {@link FileSystemRef filesystem ref}
 * handles that ensure the filesystem is pinned in memory and won't be closed while
 * you are using it.
 * <p>
 * If you are working with {@link GFile} instances, you should have a
 * {@link FileSystemRef fs ref} that you are using to pin the filesystem.
 * <p>
 * Thread-safe.
 * <p>
 *
 * <pre>{@literal
 * TODO list:
 *
 * Refactor fileInfo -> needs dialog to show properties
 * Refactor GFile.getInfo() to return Map<> instead of String.
 * Persistent filesystem - when reopen tool, filesystems should auto-reopen.
 * Unify GhidraFileChooser with GFileSystem.
 * Add "Mounted Filesystems" button to show currently opened GFilesystems?
 * Dockable filesystem browser in FrontEnd.
 * Reorg filesystem browser right-click popup menu to be more Eclipse action-like
 * 	Show In -> Project tree
 *             Tool [CodeBrowser name]
 *  Import
 *  Open With -> Text Viewer
 *               Image Viewer
 *  Export -> To Project dir
 *            To Home dir
 *            To Dir
 *            To Eclipse Project
 *            Decompiled source
 * ProgramMappingService - more robust, precache when open project.
 * Make BatchImportDialog modeless, drag-and-drop to src list
 *
 * Testing:
 *
 * More format tests
 * Large test binary support
 * }</pre>
 */
public class FileSystemService {
	private static int FSRL_INTERN_SIZE = 1000;

	private static FileSystemService instance;

	public static synchronized FileSystemService getInstance() {
		if (instance == null) {
			instance = new FileSystemService();
		}
		return instance;
	}

	/**
	 * Returns true if this service has been loaded
	 * @return true if this service has been loaded
	 */
	public static synchronized boolean isInitialized() {
		return instance != null;
	}

	private final LocalFileSystem localFS = LocalFileSystem.makeGlobalRootFS();
	private final FSRLRoot localFSRL = localFS.getFSRL();
	private final FileSystemFactoryMgr fsFactoryMgr = FileSystemFactoryMgr.getInstance();
	private FileCache fileCache;
	private FileSystemCache filesystemCache = new FileSystemCache(localFS);
	private FileCacheNameIndex fileCacheNameIndex = new FileCacheNameIndex();
	private FileFingerprintCache fileFingerprintCache = new FileFingerprintCache();
	private long fsCacheMaintIntervalMS = 10 * 1000;

	/**
	 * LRU hashmap, limited in size to FSRL_INTERN_SIZE.
	 */
	private FixedSizeHashMap<FSRLRoot, FSRLRoot> fsrlInternMap =
		new FixedSizeHashMap<>(FSRL_INTERN_SIZE, FSRL_INTERN_SIZE);

	/**
	 * Creates a FilesystemService instance, using the {@link Application}'s default value
	 * for {@link Application#getUserCacheDirectory() user cache directory} as the
	 * cache directory.
	 */
	public FileSystemService() {
		this(new File(Application.getUserCacheDirectory(), "fscache"));
	}

	/**
	 * Creates a FilesystemService instance, using the supplied directory as its file caching
	 * root directory.
	 *
	 * @param fscacheDir {@link File Root dir} to use to store files placed into cache.
	 */
	public FileSystemService(File fscacheDir) {
		try {
			fileCache = new FileCache(fscacheDir);
			GTimer.scheduleRepeatingRunnable(fsCacheMaintIntervalMS, fsCacheMaintIntervalMS,
				() -> filesystemCache.cacheMaint());
		}
		catch (IOException e) {
			throw new RuntimeException("Failed to init global cache " + fscacheDir, e);
		}
	}

	/**
	 * Forcefully closes all open filesystems and clears caches.
	 */
	public void clear() {
		synchronized (filesystemCache) {
			filesystemCache.clear();
			fsrlInternMap.clear();
			fileCacheNameIndex.clear();
		}
	}

	/**
	 * Close unused filesystems.
	 */
	public void closeUnusedFileSystems() {
		filesystemCache.closeAllUnused();
	}

	/**
	 * Returns a direct reference to a filesystem that represents the local filesystem.
	 *
	 * @return {@link GFileSystem} that represents the local filesystem.
	 */
	public GFileSystem getLocalFS() {
		return localFS;
	}

	/**
	 * Returns true of there is a {@link GFileSystem filesystem} mounted at the requested
	 * {@link FSRL} location.
	 *
	 * @param fsrl {@link FSRL} container to query for mounted filesystem
	 * @return boolean true if filesystem mounted at location.
	 */
	public boolean isFilesystemMountedAt(FSRL fsrl) {
		return filesystemCache.isFilesystemMountedAt(fsrl);
	}

	/**
	 * Returns the {@link GFile} pointed to by the FSRL, along with a {@link FileSystemRef}
	 * that the caller is responsible for releasing (either explicitly via
	 * {@code result.fsRef.close()} or via the {@link RefdFile#close()}).
	 *
	 * @param fsrl {@link FSRL} of the desired file
	 * @param monitor {@link TaskMonitor} so the user can cancel
	 * @return a {@link RefdFile} which contains the resultant {@link GFile} and a
	 * {@link FileSystemRef} that needs to be closed, or {@code null} if the filesystem
	 * does not have the requested file.
	 *
	 * @throws CancelledException if the user cancels
	 * @throws IOException if there was a file io problem
	 */
	public RefdFile getRefdFile(FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		FSRLRoot fsRoot = fsrl.getFS();
		FileSystemRef ref = getFilesystem(fsRoot, monitor);
		try {
			GFile gfile = ref.getFilesystem().lookup(fsrl.getPath());
			if (gfile == null) {
				throw new IOException("File [" + fsrl + "] not found in filesystem [" +
					ref.getFilesystem().getFSRL() + "]");
			}
			RefdFile result = new RefdFile(ref, gfile);
			ref = null;
			return result;
		}
		finally {
			if (ref != null) {
				ref.close();
			}
		}
	}

	/**
	 * Return a {@link FileCacheEntry} with information about the requested file specified
	 * by the FSRL, forcing a read/cache add of the file is it is missing from the cache.
	 * <p>
	 * Never returns NULL, instead throws IOException.
	 *
	 * @param fsrl {@link FSRL} of the desired file.
	 * @param monitor {@link TaskMonitor} to watch and update with progress.
	 * @return new {@link FileCacheEntry} with info about the cached file.
	 * @throws IOException if IO error when getting file.
	 * @throws CancelledException if user canceled.
	 */
	private FileCacheEntry getCacheFile(FSRL fsrl, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (fsrl.getPath() == null) {
			throw new IOException("Invalid FSRL specified: " + fsrl);
		}
		String md5 = fsrl.getMD5();
		if (md5 == null && fsrl.getNestingDepth() == 1) {
			// if this is a real file on the local file system, and the FSRL doesn't specify
			// its MD5, try to fetch the MD5 from the fingerprint cache based on its
			// size and lastmod time, which will help us locate the file in the cache
			File f = localFS.getLocalFile(fsrl);
			if (f.isFile()) {
				md5 = fileFingerprintCache.getMD5(f.getPath(), f.lastModified(), f.length());
			}
		}
		FSRLRoot fsRoot = fsrl.getFS();

		FileCacheEntry result = (md5 != null) ? fileCache.getFile(md5) : null;
		if (result == null) {
			try (FileSystemRef ref = getFilesystem(fsRoot, monitor)) {
				GFileSystem fs = ref.getFilesystem();
				GFile gfile = fs.lookup(fsrl.getPath());
				if (gfile == null) {
					throw new IOException(
						"File [" + fsrl + "] not found in filesystem [" + fs.getFSRL() + "]");
				}

				// Its possible the filesystem added the file to the cache when it was mounted,
				// or that we now have a better FSRL with a MD5 value that we can use to
				// search the file cache.
				if (gfile.getFSRL().getMD5() != null) {
					result = fileCache.getFile(gfile.getFSRL().getMD5());
					if (result != null) {
						return result;
					}
				}

				try (InputStream dataStream = fs.getInputStream(gfile, monitor)) {
					if (dataStream == null) {
						throw new IOException("Unable to get datastream for " + fsrl);
					}
					monitor.setMessage("Caching " + gfile.getName());
					monitor.initialize(gfile.getLength());
					result = fileCache.addStream(dataStream, monitor);
					if (md5 != null && !md5.equals(result.md5)) {
						throw new IOException("Error reading file, MD5 has changed: " + fsrl +
							", md5 now " + result.md5);
					}
				}
				if (fsrl.getNestingDepth() == 1) {
					// if this is a real file on the local filesystem, now that we have its
					// MD5, save it in the fingerprint cache so it can be found later
					File f = localFS.getLocalFile(fsrl);
					if (f.isFile()) {
						fileFingerprintCache.add(f.getPath(), result.md5, f.lastModified(),
							f.length());
					}
				}

			}
		}

		return result;
	}

	/**
	 * Returns a filesystem instance for the requested {@link FSRLRoot}, either from an already
	 * loaded instance in the global fscache, or by instantiating the requested filesystem
	 * from its container file (in a possibly recursive manner, depending on the depth
	 * of the FSLR)
	 * <p>
	 * Never returns NULL, instead throws IOException if there is a problem.
	 * <p>
	 * The caller is responsible for releasing the {@link FileSystemRef}.
	 * <p>
	 * @param fsFSRL {@link FSRLRoot} of file system you want a reference to.
	 * @param monitor {@link TaskMonitor} to allow the user to cancel.
	 * @return a new {@link FileSystemRef} that the caller is responsible for closing when
	 * no longer needed, never {@code null}.
	 * @throws IOException if there was an io problem.
	 * @throws CancelledException if the user cancels.
	 */
	public FileSystemRef getFilesystem(FSRLRoot fsFSRL, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (filesystemCache) {
			FileSystemRef ref = filesystemCache.getRef(fsFSRL);
			if (ref == null) {
				if (!fsFSRL.hasContainer()) {
					throw new IOException("Bad FSRL " + fsFSRL);
				}

				fsFSRL = intern(fsFSRL);
				FSRL containerFSRL = fsFSRL.getContainer();
				FileCacheEntry cfi = getCacheFile(containerFSRL, monitor);
				if (containerFSRL.getMD5() == null) {
					containerFSRL = containerFSRL.withMD5(cfi.md5);
				}
				GFileSystem fs = FileSystemFactoryMgr.getInstance()
						.mountFileSystem(
							fsFSRL.getProtocol(), containerFSRL, cfi.file, this, monitor);
				ref = fs.getRefManager().create();
				filesystemCache.add(fs);
			}
			return ref;
		}
	}

	/**
	 * Adds a {@link GFile file}'s stream's contents to the file cache, returning its MD5 hash.
	 *
	 * @param file {@link GFile} not really used currently
	 * @param is {@link InputStream} to add to the cache.
	 * @param monitor {@link TaskMonitor} to monitor and update.
	 * @return string with new file's md5.
	 * @throws IOException if IO error
	 * @throws CancelledException if user canceled.
	 */
	public FileCacheEntry addFileToCache(GFile file, InputStream is, TaskMonitor monitor)
			throws IOException, CancelledException {
		FileCacheEntry fce = fileCache.addStream(is, monitor);
		return fce;
	}

	/**
	 * Stores a stream in the file cache.
	 * <p>
	 * @param is {@link InputStream} to store in the cache.
	 * @param monitor {@link TaskMonitor} to watch and update.
	 * @return {@link File} location of the new file.
	 * @throws IOException if IO error
	 * @throws CancelledException if the user cancels.
	 */
	public FileCacheEntry addStreamToCache(InputStream is, TaskMonitor monitor)
			throws IOException, CancelledException {
		FileCacheEntry fce = fileCache.addStream(is, monitor);
		return fce;
	}

	/**
	 * Returns a {@link File java.io.file} with the data from the requested FSRL.
	 * Simple local files will be returned directly, and files nested in containers
	 * will be located in the file cache directory and have a 'random' name.
	 * <p>
	 * Never returns nulls, throws IOException if not found or error.
	 *
	 * @param fsrl {@link FSRL} of the desired file.
	 * @param monitor {@link TaskMonitor} to watch and update.
	 * @return {@link File} of the desired file in the cache, never null.
	 * @throws CancelledException if user cancels.
	 * @throws IOException if IO problem.
	 */
	public File getFile(FSRL fsrl, TaskMonitor monitor) throws CancelledException, IOException {
		if (fsrl.getNestingDepth() == 1) {
			// If this is a real files on the local filesystem, verify any
			// MD5 embedded in the FSRL before returning the live local file
			// as the result.
			File f = localFS.getLocalFile(fsrl);
			if (f.isFile() && fsrl.getMD5() != null) {
				if (!fileFingerprintCache.contains(f.getPath(), fsrl.getMD5(), f.lastModified(),
					f.length())) {
					String fileMD5 = FSUtilities.getFileMD5(f, monitor);
					if (!fsrl.getMD5().equals(fileMD5)) {
						throw new IOException("Exact file no longer exists: " + f.getPath() +
							" contents have changed, old md5: " + fsrl.getMD5() + ", new md5: " +
							fileMD5);
					}
					fileFingerprintCache.add(f.getPath(), fileMD5, f.lastModified(), f.length());
				}
			}
			return f;
		}
		FileCacheEntry fce = getCacheFile(fsrl, monitor);
		return fce.file;
	}

	private String getMD5(FSRL fsrl, TaskMonitor monitor) throws CancelledException, IOException {
		if (fsrl.getNestingDepth() == 1) {
			File f = localFS.getLocalFile(fsrl);
			if (!f.isFile()) {
				return null;
			}
			String md5 = fileFingerprintCache.getMD5(f.getPath(), f.lastModified(), f.length());
			if (md5 == null) {
				md5 = FSUtilities.getFileMD5(f, monitor);
				fileFingerprintCache.add(f.getPath(), md5, f.lastModified(), f.length());
			}
			return md5;
		}
		FileCacheEntry fce = getCacheFile(fsrl, monitor);
		return fce.md5;
	}

	/**
	 * Builds a {@link FSRL} of a {@link File file} located on the local filesystem.
	 *
	 * @param f {@link File} on the local filesystem
	 * @return {@link FSRL} pointing to the same file, never null
	 */
	public FSRL getLocalFSRL(File f) {
		return localFS.getFSRL()
				.withPath(
					FSUtilities.appendPath("/", FilenameUtils.separatorsToUnix(f.getPath())));
	}

	/**
	 * Converts a java {@link File} instance into a GFilesystem {@link GFile} hosted on the
	 * {@link #getLocalFS() local filesystem}.
	 * <p>
	 * @param f {@link File} on the local filesystem
	 * @return {@link GFile} representing the same file or {@code null} if there was a problem
	 * with the file path.
	 */
	public GFile getLocalGFile(File f) {
		try {
			return localFS.lookup(f.getPath());
		}
		catch (IOException e) {
			// the LocalFileSystem impl doesn't check the validity of the path so this
			// exception should never happen.  If it does, fall thru and return null.
		}
		return null;
	}

	/**
	 * Returns a {@link ByteProvider} with the contents of the requested {@link GFile file}
	 * (in the Global file cache directory).
	 * <p>
	 * Never returns null, throws IOException if there was a problem.
	 * <p>
	 * Caller is responsible for {@link ByteProvider#close() closing()} the ByteProvider
	 * when finished.
	 *
	 * @param fsrl {@link FSRL} file to wrap
	 * @param monitor {@link TaskMonitor} to watch and update.
	 * @return new {@link ByteProvider}
	 * @throws CancelledException if user cancels
	 * @throws IOException if IO problem.
	 */
	public ByteProvider getByteProvider(FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		File file = getFile(fsrl, monitor);
		RandomAccessByteProvider rabp = new RandomAccessByteProvider(file, fsrl);
		return rabp;
	}

	/**
	 * Returns a reference to a file in the FileCache that contains the
	 * derived (ie. decompressed or decrypted) contents of a source file, as well as
	 * its md5.
	 * <p>
	 * If the file was not present in the cache, the {@link DerivedFileProducer producer}
	 * lambda will be called and it will be responsible for returning an {@link InputStream}
	 * which has the derived contents, which will be added to the file cache for next time.
	 * <p>
	 * @param fsrl {@link FSRL} of the source (or container) file that this derived file is based on
	 * @param derivedName a unique string identifying the derived file inside the source (or container) file
	 * @param producer a {@link DerivedFileProducer callback or lambda} that returns an
	 * {@link InputStream} that will be streamed into a file and placed into the file cache.
	 * Example:{@code (file) -> { return new XYZDecryptorInputStream(file); }}
	 * @param monitor {@link TaskMonitor} that will be monitor for cancel requests and updated
	 * with file io progress
	 * @return {@link FileCacheEntry} with file and md5 fields
	 * @throws CancelledException if the user cancels
	 * @throws IOException if there was an io error
	 */
	public FileCacheEntry getDerivedFile(FSRL fsrl, String derivedName,
			DerivedFileProducer producer, TaskMonitor monitor)
			throws CancelledException, IOException {

		// fileCacheNameIndex is queried and updated in separate steps,
		// which could be a race issue with another thread, but in this
		// case should be okay as the only bad result will be extra
		// work being performed recreating the contents of the same derived file a second
		// time.
		FileCacheEntry cacheEntry = getCacheFile(fsrl, monitor);
		String derivedMD5 = fileCacheNameIndex.get(cacheEntry.md5, derivedName);
		FileCacheEntry derivedFile = (derivedMD5 != null) ? fileCache.getFile(derivedMD5) : null;
		if (derivedFile == null) {
			monitor.setMessage(derivedName + " " + fsrl.getName());
			try (InputStream is = producer.produceDerivedStream(cacheEntry.file)) {
				derivedFile = fileCache.addStream(is, monitor);
				fileCacheNameIndex.add(cacheEntry.md5, derivedName, derivedFile.md5);
			}
		}
		return derivedFile;
	}

	/**
	 * Returns a reference to a file in the FileCache that contains the
	 * derived (ie. decompressed or decrypted) contents of a source file, as well as
	 * its md5.
	 * <p>
	 * If the file was not present in the cache, the {@link DerivedFilePushProducer push producer}
	 * lambda will be called and it will be responsible for producing and writing the derived
	 * file's bytes to a {@link OutputStream}, which will be added to the file cache for next time.
	 * <p>
	 * @param fsrl {@link FSRL} of the source (or container) file that this derived file is based on
	 * @param derivedName a unique string identifying the derived file inside the source (or container) file
	 * @param pusher a {@link DerivedFilePushProducer callback or lambda} that recieves a {@link OutputStream}.
	 * Example:{@code (os) -> { ...write to outputstream os here...; }}
	 * @param monitor {@link TaskMonitor} that will be monitor for cancel requests and updated
	 * with file io progress
	 * @return {@link FileCacheEntry} with file and md5 fields
	 * @throws CancelledException if the user cancels
	 * @throws IOException if there was an io error
	 */
	public FileCacheEntry getDerivedFilePush(FSRL fsrl, String derivedName,
			DerivedFilePushProducer pusher, TaskMonitor monitor)
			throws CancelledException, IOException {

		// fileCacheNameIndex is queried and updated in separate steps,
		// which could be a race issue with another thread, but in this
		// case should be okay as the only bad result will be extra
		// work being performed recreating the contents of the same derived file a second
		// time.
		FileCacheEntry cacheEntry = getCacheFile(fsrl, monitor);
		String derivedMD5 = fileCacheNameIndex.get(cacheEntry.md5, derivedName);
		FileCacheEntry derivedFile = (derivedMD5 != null) ? fileCache.getFile(derivedMD5) : null;
		if (derivedFile == null) {
			monitor.setMessage("Caching " + fsrl.getName() + " " + derivedName);
			derivedFile = fileCache.pushStream(pusher, monitor);
			fileCacheNameIndex.add(cacheEntry.md5, derivedName, derivedFile.md5);
		}
		return derivedFile;
	}

	/**
	 * Returns true if the specified derived file exists in the file cache.
	 * 
	 * @param fsrl {@link FSRL} of the container
	 * @param derivedName name of the derived file inside of the container
	 * @param monitor {@link TaskMonitor}
	 * @return boolean true if file exists at time of query, false if file is not in cache
	 * @throws CancelledException if user cancels
	 * @throws IOException if other IO error
	 */
	public boolean hasDerivedFile(FSRL fsrl, String derivedName, TaskMonitor monitor)
			throws CancelledException, IOException {
		FileCacheEntry cacheEntry = getCacheFile(fsrl, monitor);
		String derivedMD5 = fileCacheNameIndex.get(cacheEntry.md5, derivedName);
		return derivedMD5 != null;
	}

	/**
	 * Returns true if the container file probably holds one of the currently supported
	 * filesystem types.
	 * <p>
	 * @param containerFSRL {@link FSRL} of the file being queried.
	 * @param monitor {@link TaskMonitor} to watch and update progress.
	 * @return boolean true if the file probably is a container, false otherwise.
	 * @throws CancelledException if user cancels.
	 * @throws IOException if IO problem.
	 */
	public boolean isFileFilesystemContainer(FSRL containerFSRL, TaskMonitor monitor)
			throws CancelledException, IOException {
		File containerFile = getFile(containerFSRL, monitor);
		return fsFactoryMgr.test(containerFSRL, containerFile, this, monitor);
	}

	/**
	 * Auto-detects a filesystem in the container file pointed to by the FSRL.
	 * <p>
	 * Returns a filesystem instance for the requested container file, either from an already
	 * loaded instance in the Global fs cache, or by probing for a filesystem in the container
	 * file using the {@link FileSystemFactoryMgr}.
	 * <p>
	 * Returns null if no filesystem implementation was found that could handle the container
	 * file.
	 *
	 * @param containerFSRL {@link FSRL} of the file container
	 * @param monitor {@link TaskMonitor} to watch and update progress.
	 * @param conflictResolver {@link FileSystemProbeConflictResolver} to handle choosing
	 * the correct file system type among multiple results, or null if you want
	 * {@link FileSystemProbeConflictResolver#CHOOSEFIRST} .
	 * @return new {@link FileSystemRef} or null
	 * @throws CancelledException if user cancels.
	 * @throws IOException if IO problem.
	 */
	public FileSystemRef probeFileForFilesystem(FSRL containerFSRL, TaskMonitor monitor,
			FileSystemProbeConflictResolver conflictResolver)
			throws CancelledException, IOException {
		return probeFileForFilesystem(containerFSRL, monitor, conflictResolver,
			FileSystemInfo.PRIORITY_LOWEST);
	}

	/**
	 * Auto-detects a filesystem in the container file pointed to by the FSRL.
	 * <p>
	 * Returns a filesystem instance for the requested container file, either from an already
	 * loaded instance in the Global fs cache, or by probing for a filesystem in the container
	 * file using a {@link FileSystemFactoryMgr}.
	 * <p>
	 * Returns null if no filesystem implementation was found that could handle the container
	 * file.
	 *
	 * @param containerFSRL {@link FSRL} of the file container
	 * @param monitor {@link TaskMonitor} to watch and update progress.
	 * @param conflictResolver {@link FileSystemProbeConflictResolver} to handle choosing
	 * the correct file system type among multiple results, or null if you want
	 * {@link FileSystemProbeConflictResolver#CHOOSEFIRST} .
	 * @param priorityFilter minimum filesystem {@link FileSystemInfo#priority()} to allow
	 * when using file system factories to probe the container.
	 * @return new {@link FileSystemRef} or null
	 * @throws CancelledException if user cancels.
	 * @throws IOException if IO problem.
	 */
	public FileSystemRef probeFileForFilesystem(FSRL containerFSRL, TaskMonitor monitor,
			FileSystemProbeConflictResolver conflictResolver, int priorityFilter)
			throws CancelledException, IOException {

		// Fix up FSRL first before querying
		containerFSRL = getFullyQualifiedFSRL(containerFSRL, monitor);

		synchronized (filesystemCache) {
			containerFSRL = intern(containerFSRL);
			FileSystemRef ref = filesystemCache.getFilesystemRefMountedAt(containerFSRL);
			if (ref != null) {
				return ref;
			}

			// Special case when the container is really a local filesystem directory.
			// Return a LocalFilesystem subfs instance.
			if (localFS.isLocalSubdir(containerFSRL)) {
				try {
					File localDir = new File(containerFSRL.getPath());
					GFileSystem fs = new LocalFileSystemSub(localDir, getLocalFS());
					ref = fs.getRefManager().create();
					filesystemCache.add(fs);
					return ref;
				}
				catch (IOException e) {
					Msg.error(this, "Problem when probing for local directory: ", e);
				}
				return null;
			}
		}

		// Normal case, probe the container file and create a filesystem instance.
		// Do this outside of the sync lock so if any swing stuff happens in the conflictResolver
		// it doesn't deadlock us.
		File containerFile = getFile(containerFSRL, monitor);
		try {
			GFileSystem fs = fsFactoryMgr.probe(containerFSRL, containerFile, this,
				conflictResolver, priorityFilter, monitor);
			if (fs != null) {
				synchronized (filesystemCache) {
					FileSystemRef fsRef = filesystemCache.getFilesystemRefMountedAt(fs.getFSRL());
					if (fsRef != null) {
						// race condition between sync block at top of this func and here.
						// Throw away our new FS instance and use instance already in
						// cache.
						fs.close();
						return fsRef;
					}

					filesystemCache.add(fs);
					return fs.getRefManager().create();
				}
			}
		}
		catch (IOException ioe) {
			Msg.trace(this, "Probe exception", ioe);
			throw ioe;
		}
		return null;
	}

	/**
	 * Mount a specific file system (by class) using a specified container file.
	 * <p>
	 * The newly constructed / mounted file system is not managed by this FileSystemService
	 * or controlled with {@link FileSystemRef}s.
	 * <p>
	 * The caller is responsible for closing the resultant file system instance when it is
	 * no longer needed.
	 * <p>
	 * @param containerFSRL a reference to the file that contains the file system image
	 * @param fsClass the GFileSystem derived class that implements the specific file system
	 * @param monitor {@link TaskMonitor} to allow the user to cancel
	 * @return new {@link GFileSystem} instance, caller is responsible for closing() when done.
	 * @throws CancelledException if user cancels
	 * @throws IOException if file io error or wrong file system type.
	 */
	public <FSTYPE extends GFileSystem> FSTYPE mountSpecificFileSystem(FSRL containerFSRL,
			Class<FSTYPE> fsClass, TaskMonitor monitor) throws CancelledException, IOException {

		containerFSRL = getFullyQualifiedFSRL(containerFSRL, monitor);
		File containerFile = getFile(containerFSRL, monitor);
		String fsType = fsFactoryMgr.getFileSystemType(fsClass);
		if (fsType == null) {
			Msg.error(this, "Specific file system implemention " + fsClass.getName() +
				" not registered correctly in file system factory.");
			return null;
		}
		GFileSystem fs =
			fsFactoryMgr.mountFileSystem(fsType, containerFSRL, containerFile, this, monitor);
		Class<?> producedClass = fs.getClass();
		if (!fsClass.isAssignableFrom(fs.getClass())) {
			fs.close();
			throw new IOException("Bad file system type returned by factory. Expecting " +
				fsClass.getName() + " but factory produced " + producedClass.getName());
		}
		return fsClass.cast(fs);
	}

	/**
	 * Open the file system contained at the specified location.
	 * <p>
	 * The newly constructed / mounted file system is not managed by this FileSystemService
	 * or controlled with {@link FileSystemRef}s.
	 * <p>
	 * The caller is responsible for closing the resultant file system instance when it is
	 * no longer needed.
	 * <p>
	 * @param containerFSRL a reference to the file that contains the file system image
	 * @param monitor {@link TaskMonitor} to allow the user to cancel
	 * @return new {@link GFileSystem} instance, caller is responsible for closing() when done.
	 * @throws CancelledException if user cancels
	 * @throws IOException if file io error or wrong file system type.
	 */
	public GFileSystem openFileSystemContainer(FSRL containerFSRL, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (localFS.isLocalSubdir(containerFSRL)) {
			File localDir = localFS.getLocalFile(containerFSRL);
			return new LocalFileSystemSub(localDir, localFS);
		}

		File containerFile = getFile(containerFSRL, monitor);
		return fsFactoryMgr.probe(containerFSRL, containerFile, this, null,
			FileSystemInfo.PRIORITY_LOWEST, monitor);
	}

	/**
	 * Returns a cloned copy of the {@code FSRL} that should have MD5 values specified.
	 * (excluding GFile objects that don't have data streams)
	 * <p>
	 * Also implements a best-effort caching of non-root filesystem FSRL's MD5 values.
	 * (ie. the md5 values of files inside of containers are cached.  The md5 value of
	 * files on the real OS filesystem are not cached)
	 * <p>
	 * @param fsrl {@link FSRL} of the file that should be forced to have a MD5
	 * @param monitor {@link TaskMonitor} to watch and update with progress.
	 * @return possibly new {@link FSRL} instance with a MD5 value.
	 * @throws CancelledException if user cancels.
	 * @throws IOException if IO problem.
	 */
	public FSRL getFullyQualifiedFSRL(FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (fsrl == null) {
			return null;
		}

		FSRL fqParentContainer = getFullyQualifiedFSRL(fsrl.getFS().getContainer(), monitor);

		FSRL resultFSRL = (fqParentContainer != fsrl.getFS().getContainer())
				? FSRLRoot.nestedFS(fqParentContainer, fsrl.getFS()).withPath(fsrl)
				: fsrl;

		if (resultFSRL.getMD5() == null) {
			String md5 = null;
			if (fqParentContainer != null) {
				md5 = fileCacheNameIndex.get(fqParentContainer.getMD5(), resultFSRL.getPath());
			}
			if (md5 == null) {
				try {
					md5 = getMD5(resultFSRL, monitor);
					if (fqParentContainer != null) {
						fileCacheNameIndex.add(fqParentContainer.getMD5(), resultFSRL.getPath(),
							md5);
					}
				}
				catch (IOException ioe) {
					// ignore, default to no MD5 value
				}
			}
			if (md5 != null) {
				resultFSRL = resultFSRL.withMD5(md5);
			}
		}

		return resultFSRL;
	}

	/**
	 * Returns true if the specified file is on the local computer's
	 * filesystem.
	 *
	 * @param gfile file to query
	 * @return true if local, false if the path points to an embedded file in a container.
	 */
	public boolean isLocal(GFile gfile) {
		return gfile.getFSRL().getFS().hasContainer() == false;
	}

	/**
	 * Returns true if the specified location is a path on the local computer's
	 * filesystem.
	 *
	 * @param fsrl {@link FSRL} path to query
	 * @return true if local, false if the path points to an embedded file in a container.
	 */
	public boolean isLocal(FSRL fsrl) {
		return fsrl.getFS().hasContainer() == false;
	}

	public String getFileHash(GFile gfile, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (isLocal(gfile)) {
			File f = localFS.getLocalFile(gfile.getFSRL());
			if (f.isFile()) {
				return FSUtilities.getFileMD5(f, monitor);
			}
		}
		else {
			try (InputStream dataStream = gfile.getFilesystem().getInputStream(gfile, monitor)) {
				if (dataStream == null) {
					throw new IOException("Unable to get datastream for " + gfile.getFSRL());
				}
				monitor.setMessage("Caching " + gfile.getName());
				monitor.initialize(gfile.getLength());
				FileCacheEntry cfi = fileCache.addStream(dataStream, monitor);
				return cfi.md5;
			}
		}
		return null;
	}

	/**
	 * Returns a list of all detected GFilesystem filesystem names.
	 * <p>
	 * See {@link FileSystemFactoryMgr#getAllFilesystemNames()}.
	 *
	 * @return {@link List} of strings.
	 */
	public List<String> getAllFilesystemNames() {
		return FileSystemFactoryMgr.getInstance().getAllFilesystemNames();
	}

	/**
	 * Returns a list of all currently mounted filesystems.
	 * <p>
	 * As a FSRL is returned, there is no guarantee that the filesystem will still be
	 * mounted when you later use values from the list.
	 * <p>
	 * @return {@link List} of {@link FSRLRoot} of currently mounted filesystems.
	 */
	public List<FSRLRoot> getMountedFilesystems() {
		synchronized (filesystemCache) {
			return filesystemCache.getMountedFilesystems();
		}
	}

	/**
	 * Returns a new FilesystemRef handle to an already mounted filesystem.
	 * <p>
	 * The caller is responsible for releasing the ref.
	 * <p>
	 * Returns null if there is no filesystem mounted at {@code fsFSRL}.
	 *
	 * @param fsFSRL {@link FSRLRoot} of file system to get a {@link FileSystemRef} to.
	 * @return new {@link FileSystemRef} or null if requested file system not mounted.
	 */
	public FileSystemRef getMountedFilesystem(FSRLRoot fsFSRL) {
		synchronized (filesystemCache) {
			return filesystemCache.getRef(fsFSRL);
		}

	}

	/**
	 * Interns the FSRLRoot so that its parent parts are shared with already interned instances.
	 * <p>
	 * Caller needs to hold sync mutex
	 *
	 * @param fsrl {@link FSRLRoot} to intern-alize.
	 * @return possibly different {@link FSRLRoot} instance that has shared parent references
	 * instead of unique bespoke instances.
	 */
	private FSRLRoot intern(FSRLRoot fsrl) {
		if (localFSRL.equals(fsrl)) {
			return localFSRL;
		}

		FSRL container = fsrl.getContainer();
		if (container != null) {
			FSRLRoot parentFSRL = intern(container.getFS());
			if (parentFSRL != container.getFS()) {
				FSRL internedContainer = parentFSRL.withPath(container);
				fsrl = FSRLRoot.nestedFS(internedContainer, fsrl);
			}
		}
		FSRLRoot existing = fsrlInternMap.get(fsrl);
		if (existing == null) {
			fsrlInternMap.put(fsrl, fsrl);
			existing = fsrl;
		}

		return existing;
	}

	/**
	 * Interns the FSRL so that its parent parts are shared with already interned instances.
	 * <p>
	 * Caller needs to hold sync mutex.
	 * <p>
	 * Only {@link FSRLRoot} instances are cached in the intern map, {@link FSRL} instances
	 * are not.
	 *
	 * @param fsrl {@link FSRL} to intern-alize.
	 * @return possibly different {@link FSRL} instance that has shared parent references
	 * instead of unique bespoke instances.
	 */
	private FSRL intern(FSRL fsrl) {
		FSRLRoot internedRoot = intern(fsrl.getFS());
		return internedRoot == fsrl.getFS() ? fsrl : internedRoot.withPath(fsrl);
	}

}
