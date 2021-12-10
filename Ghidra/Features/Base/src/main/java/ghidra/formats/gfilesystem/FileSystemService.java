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

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntry;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.crypto.*;
import ghidra.formats.gfilesystem.factory.FileSystemFactoryMgr;
import ghidra.framework.Application;
import ghidra.util.Msg;
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
 * Files written to the {@code fscache} directory are obfuscated to prevent interference from
 * virus scanners.  See {@link ObfuscatedInputStream} or {@link ObfuscatedOutputStream} or 
 * {@link ObfuscatedFileByteProvider}.
 * <p> 
 * Thread-safe.
 * <p>
 */
public class FileSystemService {

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

	/**
	 * Used by {@link FileSystemService#getDerivedByteProvider(FSRL, FSRL, String, long, DerivedStreamProducer, TaskMonitor) getDerivedByteProvider()}
	 * to produce a derivative stream from a source file.
	 * <p>
	 * The {@link InputStream} returned from the method needs to supply the bytes of the derived file
	 * and will be closed by the caller.
	 * <p>
	 * Example:
	 * <p>
	 * <pre>fsService.getDerivedByteProvider(
	 *     containerFSRL, 
	 *     null,
	 *     "the_derived_file",
	 *     -1,
	 *     () -> new MySpecialtyInputstream(),
	 *     monitor);</pre>
	 * <p>
	 * See {@link #produceDerivedStream()}.   
	 */
	public interface DerivedStreamProducer {

		/**
		 * Callback method intended to be implemented by the caller to
		 * {@link FileSystemService#getDerivedByteProvider(FSRL, FSRL, String, long, DerivedStreamProducer, TaskMonitor)}
		 * <p>
		 * The implementation needs to return an {@link InputStream} that contains the bytes
		 * of the derived file.
		 * <p>
		 * @return a new {@link InputStream} that will produce all the bytes of the derived file
		 * @throws IOException if there is a problem while producing the InputStream
		 * @throws CancelledException if the user canceled
		 */
		InputStream produceDerivedStream() throws IOException, CancelledException;
	}

	/**
	 * Used by {@link FileSystemService#getDerivedByteProviderPush(FSRL, FSRL, String, long, DerivedStreamPushProducer, TaskMonitor) getDerivedByteProviderPush()}
	 * to produce a derivative stream from a source file.
	 * <p>
	 * The implementation needs to write bytes to the supplied {@link OutputStream}.
	 * <p>
	 * Example:
	 * <p>
	 * <pre>fsService.getDerivedByteProviderPush(
	 *     containerFSRL, 
	 *     null,
	 *     "the_derived_file",
	 *     -1,
	 *     os -> FileUtilities.copyStream(my_input_stream, os),
	 *     monitor);</pre>
	 * <p>
	 * See {@link #push(OutputStream)}.   
	 * 
	 */
	public interface DerivedStreamPushProducer {
		/**
		 * Callback method intended to be implemented by the caller to
		 * {@link FileSystemService#getDerivedByteProviderPush(FSRL, FSRL, String, long, DerivedStreamPushProducer, TaskMonitor) getDerivedByteProviderPush()}
		 * <p>
		 * @param os {@link OutputStream} that the implementor should write the bytes to.  Do
		 * not close the stream when done
		 * @throws IOException if there is a problem while writing to the OutputStream
		 * @throws CancelledException if the user canceled
		 */
		void push(OutputStream os) throws IOException, CancelledException;
	}

	private final LocalFileSystem localFS = LocalFileSystem.makeGlobalRootFS();
	private final FileSystemFactoryMgr fsFactoryMgr = FileSystemFactoryMgr.getInstance();
	private final FSRLRoot cacheFSRL = FSRLRoot.makeRoot("cache");
	private final FileCache fileCache;
	private final FileSystemInstanceManager fsInstanceManager =
		new FileSystemInstanceManager(localFS);
	private final FileCacheNameIndex fileCacheNameIndex = new FileCacheNameIndex();
	private long fsCacheMaintIntervalMS = 10 * 1000;
	private CryptoSession currentCryptoSession;

	/**
	 * Creates a FilesystemService instance, using the {@link Application}'s default value
	 * for {@link Application#getUserCacheDirectory() user cache directory} as the
	 * cache directory.
	 */
	public FileSystemService() {
		this(new File(Application.getUserCacheDirectory(), "fscache2"));

		// age off files in old cache dir.  Remove this after a few versions
		FileCache.performCacheMaintOnOldDirIfNeeded(
			new File(Application.getUserCacheDirectory(), "fscache"));
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
				() -> fsInstanceManager.cacheMaint());
		}
		catch (IOException e) {
			throw new RuntimeException("Failed to init global cache " + fscacheDir, e);
		}
	}

	/**
	 * Forcefully closes all open filesystems and clears caches.
	 */
	public void clear() {
		synchronized (fsInstanceManager) {
			fsInstanceManager.clear();
			fileCacheNameIndex.clear();
		}
	}

	/**
	 * Close unused filesystems.
	 */
	public void closeUnusedFileSystems() {
		fsInstanceManager.closeAllUnused();
	}

	/**
	 * Releases the specified {@link FileSystemRef}, and if no other references remain, removes 
	 * it from the shared cache of file system instances.
	 * 
	 * @param fsRef the ref to release
	 */
	public void releaseFileSystemImmediate(FileSystemRef fsRef) {
		if (fsRef != null && !fsRef.isClosed()) {
			fsInstanceManager.releaseImmediate(fsRef);
		}
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
	 * Returns true if the specified location is a path on the local computer's
	 * filesystem.
	 *
	 * @param fsrl {@link FSRL} path to query
	 * @return true if local, false if the path points to an embedded file in a container.
	 */
	public boolean isLocal(FSRL fsrl) {
		return localFS.isSameFS(fsrl);
	}

	/**
	 * Builds a {@link FSRL} of a {@link File file} located on the local filesystem.
	 *
	 * @param f {@link File} on the local filesystem
	 * @return {@link FSRL} pointing to the same file, never null
	 */
	public FSRL getLocalFSRL(File f) {
		return localFS.getLocalFSRL(f);
	}

	/**
	 * Returns true of there is a {@link GFileSystem filesystem} mounted at the requested
	 * {@link FSRL} location.
	 *
	 * @param fsrl {@link FSRL} container to query for mounted filesystem
	 * @return boolean true if filesystem mounted at location.
	 */
	public boolean isFilesystemMountedAt(FSRL fsrl) {
		return fsInstanceManager.isFilesystemMountedAt(fsrl);
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
		FileSystemRef ref = getFilesystem(fsrl.getFS(), monitor);
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
		synchronized (fsInstanceManager) {
			FileSystemRef ref = fsInstanceManager.getRef(fsFSRL);
			if (ref == null) {
				if (!fsFSRL.hasContainer()) {
					throw new IOException("Bad FSRL " + fsFSRL);
				}

				ByteProvider containerByteProvider = getByteProvider(fsFSRL.getContainer(), true, monitor);
				GFileSystem fs =
					fsFactoryMgr.mountFileSystem(fsFSRL.getProtocol(), containerByteProvider, this, monitor);
				ref = fs.getRefManager().create();
				fsInstanceManager.add(fs);
			}
			return ref;
		}
	}

	/**
	 * Returns a {@link ByteProvider} with the contents of the requested {@link GFile file}.
	 * <p>
	 * Never returns null, throws IOException if there was a problem.
	 * <p>
	 * Caller is responsible for {@link ByteProvider#close() closing()} the ByteProvider
	 * when finished.
	 *
	 * @param fsrl {@link FSRL} file to wrap
	 * @param fullyQualifiedFSRL if true, the returned ByteProvider's FSRL will always have a MD5
	 * hash
	 * @param monitor {@link TaskMonitor} to watch and update
	 * @return new {@link ByteProvider}
	 * @throws CancelledException if user cancels
	 * @throws IOException if IO problem
	 */
	public ByteProvider getByteProvider(FSRL fsrl, boolean fullyQualifiedFSRL, TaskMonitor monitor)
			throws CancelledException, IOException {

		if ( fsrl.getMD5() != null ) {
			FileCacheEntry fce = fileCache.getFileCacheEntry(fsrl.getMD5());
			if ( fce != null ) {
				return fce.asByteProvider(fsrl);
			}
		}

		try ( FileSystemRef fsRef = getFilesystem(fsrl.getFS(), monitor) ) {
			GFileSystem fs = fsRef.getFilesystem();
			GFile file = fs.lookup(fsrl.getPath());
			if (file == null) {
				throw new IOException("File not found: " + fsrl);
			}
			if (file.getFSRL().getMD5() != null) {
				fsrl = file.getFSRL();
				// try again to fetch cached file if we now have a md5
				FileCacheEntry fce = fileCache.getFileCacheEntry(fsrl.getMD5());
				if (fce != null) {
					return fce.asByteProvider(fsrl);
				}
			}
			ByteProvider provider = fs.getByteProvider(file, monitor);
			if (provider == null) {
				throw new IOException("Unable to get ByteProvider for " + fsrl);
			}

			// use the returned provider's FSRL as it may have more info
			FSRL resultFSRL = provider.getFSRL();
			if (resultFSRL.getMD5() == null && (fsrl.getMD5() != null || fullyQualifiedFSRL)) {
				String md5 = (fs instanceof GFileHashProvider)
						? ((GFileHashProvider) fs).getMD5Hash(file, true, monitor)
						: FSUtilities.getMD5(provider, monitor);
				resultFSRL = resultFSRL.withMD5(md5);
			}
			if (fsrl.getMD5() != null) {
				if (!fsrl.isMD5Equal(resultFSRL.getMD5())) {
					throw new IOException("Unable to retrieve requested file, hash has changed: " +
						fsrl + ", new hash: " + resultFSRL.getMD5());
				}
			}
			return new RefdByteProvider(fsRef.dup(), provider, resultFSRL);
		}
	}

	/**
	 * Returns a {@link ByteProvider} that contains the
	 * derived (ie. decompressed or decrypted) contents of the requested file.
	 * <p>
	 * The resulting ByteProvider will be a cached file, either written to a 
	 * temporary file, or a in-memory buffer if small enough (see {@link FileCache#MAX_INMEM_FILESIZE}).
	 * <p> 
	 * If the file was not present in the cache, the {@link DerivedStreamProducer producer}
	 * will be called and it will be responsible for returning an {@link InputStream}
	 * which has the derived contents, which will be added to the file cache for next time.
	 * <p>
	 * @param containerFSRL {@link FSRL} w/hash of the source (or container) file that this 
	 * derived file is based on
	 * @param derivedFSRL (optional) {@link FSRL} to assign to the resulting ByteProvider
	 * @param derivedName a unique string identifying the derived file inside the source (or container) file
	 * @param sizeHint the expected size of the resulting ByteProvider, or -1 if unknown
	 * @param producer supplies an InputStream if needed.  See {@link DerivedStreamProducer}
	 * @param monitor {@link TaskMonitor} that will be monitor for cancel requests and updated
	 * with file io progress
	 * @return a {@link ByteProvider} containing the bytes of the requested file, that has the 
	 * specified derivedFSRL, or a pseudo FSRL if not specified.  Never null
	 * @throws CancelledException if the user cancels
	 * @throws IOException if there was an io error
	 */
	public ByteProvider getDerivedByteProvider(FSRL containerFSRL, FSRL derivedFSRL,
			String derivedName, long sizeHint, DerivedStreamProducer producer,
			TaskMonitor monitor) throws CancelledException, IOException {

		// fileCacheNameIndex is queried and updated in separate steps,
		// which could be a race issue with another thread, but in this
		// case should be okay as the only bad result will be extra
		// work being performed recreating the contents of the same derived file a second
		// time.
		assertFullyQualifiedFSRL(containerFSRL);
		String containerMD5 = containerFSRL.getMD5();
		String derivedMD5 = fileCacheNameIndex.get(containerMD5, derivedName);
		FileCacheEntry derivedFile = fileCache.getFileCacheEntry(derivedMD5);
		if (derivedFile == null) {
			monitor.setMessage("Caching " + containerFSRL.getName() + " " + derivedName);
			if (sizeHint > 0) {
				monitor.initialize(sizeHint);
			}
			try (InputStream is = producer.produceDerivedStream();
					FileCacheEntryBuilder fceBuilder =
						fileCache.createCacheEntryBuilder(sizeHint)) {
				FSUtilities.streamCopy(is, fceBuilder, monitor);
				derivedFile = fceBuilder.finish();
				fileCacheNameIndex.add(containerMD5, derivedName, derivedFile.getMD5());
			}
		}
		derivedFSRL = (derivedFSRL != null)
				? derivedFSRL.withMD5(derivedFile.getMD5())
				: createCachedFileFSRL(derivedFile.getMD5());
		return derivedFile.asByteProvider(derivedFSRL);
	}

	/**
	 * Returns a {@link ByteProvider} that contains the
	 * derived (ie. decompressed or decrypted) contents of the requested file.
	 * <p>
	 * The resulting ByteProvider will be a cached file, either written to a 
	 * temporary file, or a in-memory buffer if small enough (see {@link FileCache#MAX_INMEM_FILESIZE}).
	 * <p> 
	 * If the file was not present in the cache, the {@link DerivedStreamPushProducer pusher}
	 * will be called and it will be responsible for producing and writing the derived
	 * file's bytes to a {@link OutputStream}, which will be added to the file cache for next time.
	 * <p>
	 * @param containerFSRL {@link FSRL} w/hash of the source (or container) file that this 
	 * derived file is based on
	 * @param derivedFSRL (optional) {@link FSRL} to assign to the resulting ByteProvider
	 * @param derivedName a unique string identifying the derived file inside the source (or container) file
	 * @param sizeHint the expected size of the resulting ByteProvider, or -1 if unknown
	 * @param pusher writes bytes to the supplied OutputStream.  See {@link DerivedStreamPushProducer}
	 * @param monitor {@link TaskMonitor} that will be monitor for cancel requests and updated
	 * with file io progress
	 * @return a {@link ByteProvider} containing the bytes of the requested file, that has the 
	 * specified derivedFSRL, or a pseudo FSRL if not specified.  Never null
	 * @throws CancelledException if the user cancels
	 * @throws IOException if there was an io error
	 */
	public ByteProvider getDerivedByteProviderPush(FSRL containerFSRL, FSRL derivedFSRL,
			String derivedName, long sizeHint, DerivedStreamPushProducer pusher, TaskMonitor monitor)
			throws CancelledException, IOException {

		// fileCacheNameIndex is queried and updated in separate steps,
		// which could be a race issue with another thread, but in this
		// case should be okay as the only bad result will be extra
		// work being performed recreating the contents of the same derived file a second
		// time.
		assertFullyQualifiedFSRL(containerFSRL);
		String containerMD5 = containerFSRL.getMD5();
		String derivedMD5 = fileCacheNameIndex.get(containerMD5, derivedName);
		FileCacheEntry derivedFile = fileCache.getFileCacheEntry(derivedMD5);
		if (derivedFile == null) {
			monitor.setMessage("Caching " + containerFSRL.getName() + " " + derivedName);
			if (sizeHint > 0) {
				monitor.initialize(sizeHint);
			}
			try (FileCacheEntryBuilder fceBuilder = fileCache.createCacheEntryBuilder(sizeHint)) {
				pusher.push(fceBuilder);
				derivedFile = fceBuilder.finish();
			}
			fileCacheNameIndex.add(containerMD5, derivedName, derivedFile.getMD5());
		}
		derivedFSRL = (derivedFSRL != null)
				? derivedFSRL.withMD5(derivedFile.getMD5())
				: createCachedFileFSRL(derivedFile.getMD5());
		return derivedFile.asByteProvider(derivedFSRL);
	}

	private FSRL createCachedFileFSRL(String md5) {
		return cacheFSRL.withPathMD5("/" + md5, md5);
	}

	/**
	 * Returns a {@link FileCacheEntryBuilder} that will allow the caller to
	 * write bytes to it.
	 * <p>
	 * After calling {@link FileCacheEntryBuilder#finish() finish()},
	 * the caller will have a {@link FileCacheEntry} that can provide access to a
	 * {@link ByteProvider}.
	 * <p>
	 * Temporary files that are written to disk are obfuscated to avoid interference from
	 * overzealous virus scanners.  See {@link ObfuscatedInputStream} / 
	 * {@link ObfuscatedOutputStream}.
	 * <p>
	 * @param sizeHint the expected size of the file, or -1 if unknown
	 * @return {@link FileCacheEntryBuilder} that must be finalized by calling 
	 * {@link FileCacheEntryBuilder#finish() finish()} 
	 * @throws IOException if error
	 */
	public FileCacheEntryBuilder createTempFile(long sizeHint) throws IOException {
		return fileCache.createCacheEntryBuilder(sizeHint);
	}

	/**
	 * Returns a {@link ByteProvider} for the specified {@link FileCacheEntry}, using the
	 * specified filename.
	 * <p>
	 * The returned ByteProvider's FSRL will be decorative and does not allow returning to
	 * the same ByteProvider at a later time.
	 *  
	 * @param tempFileCacheEntry {@link FileCacheEntry} (returned by {@link #createTempFile(long)})
	 * @param name desired name
	 * @return new {@link ByteProvider} with decorative {@link FSRL}
	 * @throws IOException if io error
	 */
	public ByteProvider getNamedTempFile(FileCacheEntry tempFileCacheEntry, String name)
			throws IOException {
		FSRL resultFSRL = FSRLRoot.makeRoot("tmp")
				.withPathMD5(FSUtilities.appendPath("/", name), tempFileCacheEntry.getMD5());
		return tempFileCacheEntry.asByteProvider(resultFSRL);
	}

	/**
	 * Allows the resources used by caching the specified file to be released.
	 * 
	 * @param fsrl {@link FSRL} file to release cache resources for 
	 */
	public void releaseFileCache(FSRL fsrl) {
		if (fsrl.getMD5() != null) {
			fileCache.releaseFileCacheEntry(fsrl.getMD5());
		}
	}

	/**
	 * Adds a plaintext (non-obfuscated) file to the cache, consuming it in the process, and returns
	 * a {@link ByteProvider} that contains the contents of the file.
	 * <p>
	 * NOTE: only use this if you have no other choice and are forced to deal with already
	 * existing files in the local filesystem.
	 * 
	 * @param file {@link File} to add
	 * @param fsrl {@link FSRL} of the file that is being added
	 * @param monitor {@link TaskMonitor}
	 * @return {@link ByteProvider} (hosted in the FileCache) that contains the bytes of the
	 * specified file
	 * @throws CancelledException if cancelled
	 * @throws IOException if error
	 */
	public ByteProvider pushFileToCache(File file, FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		FileCacheEntry fce = fileCache.giveFile(file, monitor);
		return fce.asByteProvider(fsrl);
	}

	/**
	 * Returns true if the specified derived file exists in the file cache.
	 * 
	 * @param containerFSRL {@link FSRL} w/hash of the container
	 * @param derivedName name of the derived file inside of the container
	 * @param monitor {@link TaskMonitor}
	 * @return boolean true if file exists at time of query, false if file is not in cache
	 * @throws CancelledException if user cancels
	 * @throws IOException if other IO error
	 */
	public boolean hasDerivedFile(FSRL containerFSRL, String derivedName, TaskMonitor monitor)
			throws CancelledException, IOException {
		assertFullyQualifiedFSRL(containerFSRL);
		String containerMD5 = containerFSRL.getMD5();
		String derivedMD5 = fileCacheNameIndex.get(containerMD5, derivedName);
		return derivedMD5 != null && fileCache.hasEntry(derivedMD5);
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
		try (ByteProvider byteProvider = getByteProvider(containerFSRL, false, monitor)) {
			return fsFactoryMgr.test(byteProvider, this, monitor);
		}
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

		synchronized (fsInstanceManager) {
			FileSystemRef ref = fsInstanceManager.getFilesystemRefMountedAt(containerFSRL);
			if (ref != null) {
				return ref;
			}

			GFileSystem subdirFS = probeForLocalSubDirFilesystem(containerFSRL);
			if (subdirFS != null) {
				ref = subdirFS.getRefManager().create();
				fsInstanceManager.add(subdirFS);
				return ref;
			}
		}

		// Normal case, probe the container file and create a filesystem instance.
		// Do this outside of the sync lock so if any swing stuff happens in the conflictResolver
		// it doesn't deadlock us.
		try {
			ByteProvider byteProvider = getByteProvider(containerFSRL, true, monitor);
			GFileSystem fs =
				fsFactoryMgr.probe(byteProvider, this, conflictResolver, priorityFilter, monitor);
			if (fs != null) {
				synchronized (fsInstanceManager) {
					FileSystemRef fsRef = fsInstanceManager.getFilesystemRefMountedAt(fs.getFSRL());
					if (fsRef != null) {
						// race condition between sync block at top of this func and here.
						// Throw away our new FS instance and use instance already in
						// cache.
						fs.close();
						return fsRef;
					}

					fsInstanceManager.add(fs);
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

	private GFileSystem probeForLocalSubDirFilesystem(FSRL containerFSRL) {
		if (localFS.isLocalSubdir(containerFSRL)) {
			try {
				return localFS.getSubFileSystem(containerFSRL);
			}
			catch (IOException e) {
				Msg.error(this, "Problem when probing for local directory: ", e);
			}
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

		String fsType = fsFactoryMgr.getFileSystemType(fsClass);
		if (fsType == null) {
			Msg.error(this, "Specific file system implemention " + fsClass.getName() +
				" not registered correctly in file system factory.");
			return null;
		}
		ByteProvider byteProvider = getByteProvider(containerFSRL, true, monitor);
		GFileSystem fs =
			fsFactoryMgr.mountFileSystem(fsType, byteProvider, this, monitor);
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

		GFileSystem subdirFS = probeForLocalSubDirFilesystem(containerFSRL);
		if (subdirFS != null) {
			return subdirFS;
		}

		ByteProvider byteProvider = getByteProvider(containerFSRL, true, monitor);
		return fsFactoryMgr.probe(byteProvider, this, null, FileSystemInfo.PRIORITY_LOWEST,
			monitor);
	}

	/**
	 * Returns a cloned copy of the {@code FSRL} that should have MD5 values specified.
	 * (excluding GFile objects that don't have data streams)
	 * <p>
	 * @param fsrl {@link FSRL} of the file that should be forced to have a MD5
	 * @param monitor {@link TaskMonitor} to watch and update with progress.
	 * @return possibly new {@link FSRL} instance with a MD5 value.
	 * @throws CancelledException if user cancels.
	 * @throws IOException if IO problem.
	 */
	public FSRL getFullyQualifiedFSRL(FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (fsrl == null || fsrl.getMD5() != null) {
			return fsrl;
		}
		try (FileSystemRef fsRef = getFilesystem(fsrl.getFS(), monitor)) {
			return getFullyQualifiedFSRL(fsRef.getFilesystem(), fsrl, monitor);
		}
	}

	private void assertFullyQualifiedFSRL(FSRL fsrl) throws IOException {
		if (fsrl.getMD5() == null) {
			throw new IOException("Bad FSRL, expected fully qualified: " + fsrl);
		}
	}

	private FSRL getFullyQualifiedFSRL(GFileSystem fs, FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (fsrl.getMD5() != null) {
			return fsrl;
		}
		GFile file = fs.lookup(fsrl.getPath());
		if (file == null) {
			throw new IOException("File not found: " + fsrl);
		}
		if (file.getFSRL().getMD5() != null || file.isDirectory()) {
			return file.getFSRL();
		}

		FSRL containerFSRL = fsrl.getFS().getContainer();
		if (containerFSRL != null && containerFSRL.getMD5() == null) {
			// re-home the fsrl to the parent container's fsrl since
			// filesystems will always have fully qualified fsrl
			containerFSRL = fs.getFSRL().getContainer();
			fsrl = FSRLRoot.nestedFS(containerFSRL, fsrl.getFS()).withPath(fsrl);
		}

		if (fs instanceof GFileHashProvider) {
			GFileHashProvider hashProvider = (GFileHashProvider) fs;
			return fsrl.withMD5(hashProvider.getMD5Hash(file, true, monitor));
		}

		String md5 = (containerFSRL != null)
				? fileCacheNameIndex.get(containerFSRL.getMD5(), fsrl.getPath())
				: null;
		if (md5 == null) {
			try (ByteProvider bp = fs.getByteProvider(file, monitor)) {
				if (bp == null) {
					throw new IOException("Unable to get bytes for " + fsrl);
				}
				md5 = (bp.getFSRL().getMD5() != null)
						? bp.getFSRL().getMD5()
						: FSUtilities.getMD5(bp, monitor);
			}
		}
		if (containerFSRL != null && fs.isStatic()) {
			fileCacheNameIndex.add(containerFSRL.getMD5(), fsrl.getPath(), md5);
		}
		return fsrl.withMD5(md5);
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
		synchronized (fsInstanceManager) {
			return fsInstanceManager.getMountedFilesystems();
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
		synchronized (fsInstanceManager) {
			return fsInstanceManager.getRef(fsFSRL);
		}
	}

	/**
	 * Returns a new {@link CryptoSession} that the caller can use to query for
	 * passwords and such.  Caller is responsible for closing the instance when done.
	 * <p>
	 * Later callers to this method will receive a nested CryptoSession that shares it's
	 * state with the initial CryptoSession, until the initial CryptoSession is closed(). 
	 * 
	 * @return new {@link CryptoSession} instance, never null
	 */
	public synchronized CryptoSession newCryptoSession() {
		if (currentCryptoSession == null || currentCryptoSession.isClosed()) {
			// If no this no current open cryptosession, return a new full/independent 
			// cryptosession, and use it as the parent for any subsequent sessions
			currentCryptoSession = CryptoProviders.getInstance().newSession();
			return currentCryptoSession;
		}

		// return a nested / dependent cryptosession
		return new CryptoProviderSessionChildImpl(currentCryptoSession);
	}

}
