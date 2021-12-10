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

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.util.Msg;

/**
 * A helper class used by GFilesystem implementors to track mappings between GFile
 * instances and the underlying container filesystem's native file objects.
 * <p>
 * Threadsafe (methods are synchronized).
 * <p>
 * This class also provides filename 'unique-ifying' (per directory) where an auto-incrementing
 * number will be added to a file's filename if it is not unique in the directory.
 * <p>
 * @param <METADATATYPE> the filesystem specific native file object that the user of this
 * class wants to be able to correlate with Ghidra {@link GFile} instances.
 */
public class FileSystemIndexHelper<METADATATYPE> {

	private GFile rootDir;
	
	static class FileData<METADATATYPE> {
		GFile file;
		METADATATYPE metaData;
		long fileIndex;
	}

	protected Map<GFile, FileData<METADATATYPE>> fileToEntryMap = new HashMap<>();
	protected Map<Long, FileData<METADATATYPE>> fileIndexToEntryMap = new HashMap<>();
	protected Map<GFile, Map<String, FileData<METADATATYPE>>> directoryToListing = new HashMap<>();

	/**
	 * Creates a new {@link FileSystemIndexHelper} for the specified {@link GFileSystem}.
	 * <p>
	 * A "root" directory GFile will be auto-created for the filesystem.
	 * <p>
	 * @param fs the {@link GFileSystem} that this index will be for.
	 * @param fsFSRL the {@link FSRLRoot fsrl} of the filesystem itself.
	 * (this parameter is explicitly passed here so there is no possibility of trying to call
	 * back to the fs's {@link GFileSystem#getFSRL()} on a half-constructed filesystem.)
	 */
	public FileSystemIndexHelper(GFileSystem fs, FSRLRoot fsFSRL) {
		this.rootDir = GFileImpl.fromFSRL(fs, null, fsFSRL.withPath("/"), true, -1);
		initRootDir(null);
	}

	private void initRootDir(METADATATYPE metadata) {
		FileData<METADATATYPE> fileData = new FileData<>();
		fileData.file = rootDir;
		fileData.fileIndex = -1;
		fileData.metaData = metadata;

		fileToEntryMap.put(rootDir, fileData);
		directoryToListing.put(rootDir, new HashMap<>());
	}

	/**
	 * Gets the root {@link GFile} object for this filesystem index.
	 *
	 * @return root {@link GFile} object.
	 */
	public GFile getRootDir() {
		return rootDir;
	}

	/**
	 * Removes all file info from this index.
	 */
	public synchronized void clear() {
		fileToEntryMap.clear();
		directoryToListing.clear();
	}

	/**
	 * Number of files in this index.
	 *
	 * @return number of file in this index
	 */
	public synchronized int getFileCount() {
		return fileToEntryMap.size();
	}

	/**
	 * Gets the opaque filesystem specific blob that was associated with the specified file.
	 *
	 * @param f {@link GFile} to look for
	 * @return Filesystem specific blob associated with the specified file, or null if not found
	 */
	public synchronized METADATATYPE getMetadata(GFile f) {
		FileData<METADATATYPE> fileData = fileToEntryMap.get(f);
		return fileData != null ? fileData.metaData : null;
	}

	/**
	 * Sets the associated metadata blob for the specified file.
	 * 
	 * @param f GFile to update
	 * @param metaData new metdata blob
	 * @throws IOException if unknown file
	 */
	public synchronized void setMetadata(GFile f, METADATATYPE metaData) throws IOException {
		FileData<METADATATYPE> fileData = fileToEntryMap.get(f);
		if ( fileData == null ) {
			throw new IOException("Unknown file: " + f);
		}
		fileData.metaData = metaData;
	}

	/**
	 * Gets the GFile instance that was associated with the filesystem file index.
	 * 
	 * @param fileIndex index of the file in its filesystem
	 * @return the associated GFile instance, or null if not found
	 */
	public synchronized GFile getFileByIndex(long fileIndex) {
		FileData<METADATATYPE> fileData = fileIndexToEntryMap.get(fileIndex);
		return (fileData != null) ? fileData.file : null;
	}

	/**
	 * Mirror's {@link GFileSystem#getListing(GFile)} interface.
	 *
	 * @param directory {@link GFile} directory to get the list of child files that have been
	 * added to this index, null means root directory
	 * @return {@link List} of GFile files that are in the specified directory, never null
	 */
	public synchronized List<GFile> getListing(GFile directory) {
		Map<String, FileData<METADATATYPE>> dirListing = getDirectoryContents(directory, false);
		if (dirListing == null) {
			return List.of();
		}
		return dirListing.values()
				.stream()
				.map(fd -> fd.file)
				.collect(Collectors.toList());
	}

	/**
	 * Mirror's {@link GFileSystem#lookup(String)} interface.
	 *
	 * @param path path and filename of a file to find
	 * @return {@link GFile} instance or null if no file was added to the index at that path
	 */
	public synchronized GFile lookup(String path) {
		String[] nameparts = (path != null ? path : "").split("/");
		GFile parent = lookupParent(nameparts);
		String name = (nameparts.length > 0) ? nameparts[nameparts.length - 1] : null;
		if (name == null || name.isEmpty()) {
			return parent;
		}

		Map<String, FileData<METADATATYPE>> dirListing = getDirectoryContents(parent, false);
		FileData<METADATATYPE> fileData = (dirListing != null) ? dirListing.get(name) : null;
		return (fileData != null) ? fileData.file : null;
	}

	/**
	 * Creates and stores a file entry into in-memory indexes.
	 * <p>
	 * The string path will be normalized to forward slashes before being split into
	 * directory components.
	 * <p>
	 * Filenames that are not unique in their directory will have a "[nnn]"
	 * suffix added to the resultant GFile name, where nnn is the file's
	 * order of occurrence in the container file.
	 * <p>
	 * 
	 * @param path string path and filename of the file being added to the index.  Back
	 * slashes are normalized to forward slashes
	 * @param fileIndex the filesystem specific unique index for this file, or -1
	 * if not available
	 * @param isDirectory boolean true if the new file is a directory
	 * @param length number of bytes in the file or -1 if not known or directory
	 * @param metadata opaque blob that will be stored and associated with the new
	 * GFile instance
	 * @return new GFile instance
	 */
	public synchronized GFile storeFile(String path, long fileIndex, boolean isDirectory,
			long length, METADATATYPE metadata) {

		String[] nameparts = path.replaceAll("[\\\\]", "/").split("/");
		GFile parent = lookupParent(nameparts);

		String lastpart = nameparts[nameparts.length - 1];
		FileData<METADATATYPE> fileData =
			doStoreFile(lastpart, parent, fileIndex, isDirectory, length, metadata);
		return fileData.file;
	}

	/**
	 * Creates and stores a file entry into in-memory indexes.
	 * <p>
	 * Use this when you already know the parent directory GFile object.
	 * <p>
	 * Filenames that are not unique in their directory will have a "[nnn]"
	 * suffix added to the resultant GFile name, where nnn is the file's
	 * order of occurrence in the container file.
	 * <p>
	 * 
	 * @param filename the new file's name
	 * @param parent the new file's parent directory
	 * @param fileIndex the filesystem specific unique index for this file, or -1
	 * if not available
	 * @param isDirectory boolean true if the new file is a directory
	 * @param length number of bytes in the file or -1 if not known or directory
	 * @param metadata opaque blob that will be stored and associated with the new
	 * GFile instance
	 * @return new GFile instance
	 */
	public synchronized GFile storeFileWithParent(String filename, GFile parent, long fileIndex,
			boolean isDirectory, long length, METADATATYPE metadata) {
		FileData<METADATATYPE> fileData =
			doStoreFile(filename, parent, fileIndex, isDirectory, length, metadata);
		return fileData.file;
	}

	private FileData<METADATATYPE> doStoreMissingDir(String filename, GFile parent) {
		parent = (parent == null) ? rootDir : parent;

		Map<String, FileData<METADATATYPE>> dirContents = getDirectoryContents(parent, true);
		GFile file = createNewFile(parent, filename, true, -1, null);

		FileData<METADATATYPE> fileData = new FileData<>();
		fileData.file = file;
		fileData.fileIndex = -1;
		fileToEntryMap.put(file, fileData);
		dirContents.put(filename, fileData);
		getDirectoryContents(file, true);

		return fileData;
	}

	private FileData<METADATATYPE> doStoreFile(String filename, GFile parent, long fileIndex,
			boolean isDirectory, long length, METADATATYPE metadata) {
		parent = (parent == null) ? rootDir : parent;
		long fileNum = (fileIndex != -1) ? fileIndex : fileToEntryMap.size();
		if (fileIndexToEntryMap.containsKey(fileNum)) {
			Msg.warn(this, "Duplicate fileNum for file " + parent.getPath() + "/" + filename);
		}

		Map<String, FileData<METADATATYPE>> dirContents = getDirectoryContents(parent, true);
		String uniqueName = makeUniqueFilename(dirContents.containsKey(filename) && !isDirectory,
			filename, fileNum);

		GFile file = createNewFile(parent, uniqueName, isDirectory, length, metadata);

		FileData<METADATATYPE> fileData = new FileData<>();
		fileData.file = file;
		fileData.fileIndex = fileNum;
		fileData.metaData = metadata;
		fileToEntryMap.put(file, fileData);
		fileIndexToEntryMap.put(fileNum, fileData);

		dirContents.put(uniqueName, fileData);
		if (isDirectory) {
			// side-effect of get will eagerly create the directorylisting entry 
			getDirectoryContents(file, true);
		}

		return fileData;
	}

	private String makeUniqueFilename(boolean wasNameCollision, String filename, long fileIndex) {
		return wasNameCollision
				? filename + "[" + Long.toString(fileIndex) + "]"
				: filename;
	}

	private Map<String, FileData<METADATATYPE>> getDirectoryContents(GFile directoryFile,
			boolean createIfMissing) {
		directoryFile = (directoryFile != null) ? directoryFile : rootDir;

		Map<String, FileData<METADATATYPE>> dirContents = directoryToListing.get(directoryFile);
		if (dirContents == null && createIfMissing) {
			dirContents = new HashMap<>();
			directoryToListing.put(directoryFile, dirContents);
		}

		return dirContents;
	}

	/**
	 * Walks a list of names of directories in nameparts (stopping prior to the last element)
	 * starting at the root of the filesystem and returns the final directory.
	 * <p>
	 * Directories in a path that have not been encountered before (ie. a file's path references a directory
	 * that hasn't been mentioned yet as its own file entry) will have a stub entry GFile created for them.
	 * <p>
	 * Superfluous slashes in the original filename (ie. name/sub//subafter_extra_slash) will
	 * be represented as empty string elements in the nameparts array and will be skipped
	 * as if they were not there.
	 * <p>
	 * @param nameparts
	 * @return
	 */
	protected GFile lookupParent(String[] nameparts) {

		GFile currentDir = rootDir;
		for (int i = 0; i < nameparts.length - 1; i++) {
			Map<String, FileData<METADATATYPE>> currentDirContents =
				getDirectoryContents(currentDir, true);
			String name = nameparts[i];
			if (name.isEmpty()) {
				continue;
			}
			FileData<METADATATYPE> fileData = currentDirContents.get(name);
			if (fileData == null) {
				fileData = doStoreMissingDir(name, currentDir);
			}
			currentDir = fileData.file;
		}

		return currentDir;
	}

	/**
	 * Creates a new GFile instance, using per-filesystem custom logic.
	 * <p>
	 *
	 * @param parentFile the parent file of the new instance.  Never null.
	 * @param name the name of the file
	 * @param isDirectory is this is file or directory?
	 * @param size length of the file data
	 * @param metadata filesystem specific BLOB that may have data that this method needs to
	 * create the new GFile instance.  Can be null if this method is being called to create
	 * a missing directory that was referenced in a filename.
	 *
	 * @return new GFileImpl instance
	 */
	protected GFileImpl createNewFile(GFile parentFile, String name, boolean isDirectory, long size,
			METADATATYPE metadata) {
		FSRL newFileFSRL = parentFile.getFSRL().appendPath(name);
		return GFileImpl.fromFSRL(rootDir.getFilesystem(), parentFile, newFileFSRL, isDirectory,
			size);
	}

	/**
	 * Updates the FSRL of a file already in the index.
	 * 
	 * @param file current {@link GFile}
	 * @param newFSRL the new FSRL the new file will be given
	 */
	public synchronized void updateFSRL(GFile file, FSRL newFSRL) {
		GFileImpl newFile = GFileImpl.fromFSRL(rootDir.getFilesystem(), file.getParentFile(),
			newFSRL, file.isDirectory(), file.getLength());

		FileData<METADATATYPE> fileData = fileToEntryMap.get(file);
		if (fileData != null) {
			fileToEntryMap.remove(file);
			fileIndexToEntryMap.remove(fileData.fileIndex);
			
			fileData.file = newFile;
			
			fileToEntryMap.put(newFile, fileData);
			if (fileData.fileIndex != -1) {
				fileIndexToEntryMap.put(fileData.fileIndex, fileData);
			}
		}

		Map<String, FileData<METADATATYPE>> dirListing = directoryToListing.get(file);
		if ( dirListing != null) {
			// typically this shouldn't ever happen as directory entries don't have MD5s and won't need to be updated
			// after the fact
			directoryToListing.remove(file);
			directoryToListing.put(newFile, dirListing);
		}
	}

	@Override
	public String toString() {
		return "FileSystemIndexHelper for " + rootDir.getFilesystem();
	}

}
