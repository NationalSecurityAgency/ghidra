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

import ghidra.util.Msg;

/**
 * A helper class used by GFilesystem implementors to track mappings between GFile
 * instances and the underlying container filesystem's native file objects.
 * <p>
 * Threadsafe (methods are synchronized).
 * <p>
 * This class also provides filename 'unique-ifying' (per directory) where an auto-incrementing
 * number will be added to a file's filename if it is not unique in the directory.
 * 
 * @param <METADATATYPE> the filesystem specific native file object that the user of this
 * class wants to be able to correlate with Ghidra {@link GFile} instances.
 */
public class FileSystemIndexHelper<METADATATYPE> {

	private static final int MAX_SYMLINK_RECURSE_DEPTH = 10;
	private FileData<METADATATYPE> rootDir;
	
	static class FileData<METADATATYPE> {
		GFile file;
		METADATATYPE metaData;
		final long fileIndex;
		final String symlinkPath;
		
		FileData(GFile file, METADATATYPE metaData, long fileIndex) {
			this(file, metaData, fileIndex, null);
		}

		FileData(GFile file, METADATATYPE metaData, long fileIndex, String symlinkPath) {
			this.file = file;
			this.metaData = metaData;
			this.fileIndex = fileIndex;
			this.symlinkPath = symlinkPath;
		}
	}

	protected Map<GFile, FileData<METADATATYPE>> fileToEntryMap = new HashMap<>();
	protected Map<Long, FileData<METADATATYPE>> fileIndexToEntryMap = new HashMap<>();
	protected Map<GFile, Map<String, FileData<METADATATYPE>>> directoryToListing = new HashMap<>();

	/**
	 * Creates a new {@link FileSystemIndexHelper} for the specified {@link GFileSystem}.
	 * <p>
	 * A "root" directory GFile will be auto-created for the filesystem.
	 * 
	 * @param fs the {@link GFileSystem} that this index will be for.
	 * @param fsFSRL the {@link FSRLRoot fsrl} of the filesystem itself.
	 * (this parameter is explicitly passed here so there is no possibility of trying to call
	 * back to the fs's {@link GFileSystem#getFSRL()} on a half-constructed filesystem.)
	 */
	public FileSystemIndexHelper(GFileSystem fs, FSRLRoot fsFSRL) {
		GFile rootGFile = GFileImpl.fromFSRL(fs, null, fsFSRL.withPath("/"), true, -1);
		rootDir = new FileData<>(rootGFile, null, -1);
		fileToEntryMap.put(rootDir.file, rootDir);
		directoryToListing.put(rootDir.file, new HashMap<>());
	}

	/**
	 * Gets the root {@link GFile} object for this filesystem index.
	 *
	 * @return root {@link GFile} object.
	 */
	public GFile getRootDir() {
		return rootDir.file;
	}

	/**
	 * Removes all file info from this index.
	 */
	public synchronized void clear() {
		fileToEntryMap.clear();
		directoryToListing.clear();
		fileIndexToEntryMap.clear();
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
	 * @param metaData new metadata blob
	 * @throws IOException if unknown file
	 */
	public synchronized void setMetadata(GFile f, METADATATYPE metaData) throws IOException {
		FileData<METADATATYPE> fileData = getFileData(f);
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
	 * Mirrors {@link GFileSystem#getListing(GFile)} interface.
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
				.toList();
	}

	/**
	 * Mirrors {@link GFileSystem#lookup(String)} interface.
	 *
	 * @param path path and filename of a file to find
	 * @return {@link GFile} instance or null if no file was added to the index at that path
	 */
	public synchronized GFile lookup(String path) {
		return lookup(null, path, null);
	}

	/**
	 * Mirrors {@link GFileSystem#lookup(String)} interface, with additional parameters to
	 * control the lookup.
	 * 
	 * @param baseDir optional starting directory to perform lookup
	 * @param path path and filename of a file to find
	 * @param nameComp optional {@link Comparator} that compares file names.  Suggested values are 
	 * {@code String::compareTo} or {@code String::compareToIgnoreCase} or {@code null} (also exact).
	 * @return {@link GFile} instance or null if no file was added to the index at that path
	 */
	public synchronized GFile lookup(GFile baseDir, String path, Comparator<String> nameComp) {
		try {
			FileData<METADATATYPE> baseDirData = getFileData(baseDir);
			FileData<METADATATYPE> fileData =
				lookup(baseDirData, splitPath(path), -1, false, nameComp);
			return (fileData != null) ? fileData.file : null;
		}
		catch (IOException e) {
			// shouldn't happen, fall thru
		}
		return null;
	}

	protected FileData<METADATATYPE> lookup(FileData<METADATATYPE> baseDir, String[] nameparts,
			int maxpart, boolean createIfMissing, Comparator<String> nameComp) {
		maxpart = maxpart < 0 ? nameparts.length : maxpart;

		FileData<METADATATYPE> currentFile = Objects.requireNonNullElse(baseDir, rootDir);
		for (int i = 0; i < maxpart && currentFile != null; i++) {
			String name = nameparts[i];
			if (name.isEmpty()) {
				continue;
			}

			Map<String, FileData<METADATATYPE>> currentDirContents =
				getDirectoryContents(currentFile.file, createIfMissing);
			FileData<METADATATYPE> next = lookupFileInDir(currentDirContents, name, nameComp);
			if (next == null && createIfMissing) {
				next = doStoreMissingDir(name, currentFile.file);
			}
			currentFile = next;
		}

		return currentFile;
	}

	protected FileData<METADATATYPE> resolveSymlinkPath(FileData<METADATATYPE> baseDir, String path,
			int depth, StringBuilder symlinkPathDebug, Comparator<String> nameComp)
			throws IOException {
		symlinkPathDebug = Objects.requireNonNullElseGet(symlinkPathDebug, StringBuilder::new);

		if (depth > MAX_SYMLINK_RECURSE_DEPTH) {
			throw new IOException("Too many symlinks: %s, %s".formatted(symlinkPathDebug, path));
		}

		symlinkPathDebug.append("[");
		FileData<METADATATYPE> currentFile = Objects.requireNonNullElse(baseDir, rootDir);
		String[] pathparts = splitPath(path);
		for (int i = 0; i < pathparts.length && currentFile != null; i++) {
			String name = pathparts[i];
			symlinkPathDebug.append(i != 0 ? "," : "").append(name);
			if (i == 0 && name.isEmpty()) {
				// leading '/' was present in the path, it overrides the current location
				currentFile = rootDir;
				continue;
			}
			if (name.isEmpty() || ".".equals(name)) {
				continue;
			}
			if ("..".equals(name)) {
				currentFile = getParentFileData(currentFile);
				continue;
			}

			Map<String, FileData<METADATATYPE>> currentDirContents =
				getDirectoryContents(currentFile.file, false);
			FileData<METADATATYPE> next = lookupFileInDir(currentDirContents, name, nameComp);
			if (next != null && next.symlinkPath != null) {
				next = resolveSymlinkPath(currentFile, next.symlinkPath, depth + 1,
					symlinkPathDebug, nameComp);
			}
			currentFile = next;
		}

		symlinkPathDebug.append("]");
		return currentFile;
	}

	/**
	 * If supplied file is a symlink, converts the supplied file into the targeted file, otherwise
	 * just returns the original file.
	 *   
	 * @param file {@link GFile} to convert
	 * @return symlink targeted {@link GFile}, or original file it not a symlink, or null if
	 * symlink path was invalid or reached outside the bounds of this file system
	 * @throws IOException if symlinks are nested too deeply
	 */
	public synchronized GFile resolveSymlinks(GFile file) throws IOException {
		FileData<METADATATYPE> fd = getFileData(file);
		if (fd.symlinkPath != null) {
			fd = resolveSymlinkPath(getParentFileData(fd), fd.symlinkPath, 0, null, null);
		}
		return fd != null ? fd.file : null;
	}

	private FileData<METADATATYPE> getFileData(GFile f) throws IOException {
		if (f == null) {
			return rootDir;
		}
		FileData<METADATATYPE> fd = fileToEntryMap.get(f);
		if (fd == null) {
			throw new IOException("Unknown file: %s".formatted(f));
		}
		return fd;
	}

	private FileData<METADATATYPE> getParentFileData(FileData<METADATATYPE> file) {
		GFile parentGFile = file.file.getParentFile();
		return parentGFile != null ? fileToEntryMap.get(parentGFile) : null;
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

		String[] nameparts = splitPath(path);
		if (nameparts.length == 0) {
			return rootDir.file;
		}

		GFile parent = lookupParent(nameparts, null);
		String lastpart = nameparts[nameparts.length - 1];
		FileData<METADATATYPE> fileData =
			doStoreFile(lastpart, parent, fileIndex, isDirectory, length, null, metadata);
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
			doStoreFile(filename, parent, fileIndex, isDirectory, length, null, metadata);
		return fileData.file;
	}

	/**
	 * Creates and stores a file entry that is a symlink into in-memory indexes.
	 * <p>
	 * The string path will be normalized to forward slashes before being split into
	 * directory components.
	 * <p>
	 * Filenames that are not unique in their directory will have a "[nnn]"
	 * suffix added to the resultant GFile name, where nnn is the file's
	 * order of occurrence in the container file.
	 * 
	 * @param path string path and filename of the file being added to the index.  Back
	 * slashes are normalized to forward slashes
	 * @param fileIndex the filesystem specific unique index for this file, or -1
	 * if not available
	 * @param symlinkPath destination of the symlink
	 * @param length number of bytes in the file or -1 if not known or directory
	 * @param metadata opaque blob that will be stored and associated with the new
	 * GFile instance
	 * @return new GFile instance
	 */
	public synchronized GFile storeSymlink(String path, long fileIndex, String symlinkPath,
			long length, METADATATYPE metadata) {
		String[] nameparts = splitPath(path);
		if (nameparts.length == 0) {
			Msg.warn(this,
				"Unable to create invalid symlink file [%s] -> [%s]".formatted(path, symlinkPath));
			return rootDir.file;
		}
		length = length != 0 ? length : symlinkPath.length();
		GFile parent = lookupParent(nameparts, null);

		String lastpart = nameparts[nameparts.length - 1];
		FileData<METADATATYPE> fileData =
			doStoreFile(lastpart, parent, fileIndex, false, length, symlinkPath, metadata);
		return fileData.file;

	}

	/**
	 * Creates and stores a file entry that is a symlink into in-memory indexes.
	 * <p>
	 * Use this when you already know the parent directory GFile object.
	 * <p>
	 * Filenames that are not unique in their directory will have a "[nnn]"
	 * suffix added to the resultant GFile name, where nnn is the file's
	 * order of occurrence in the container file.
	 * 
	 * @param filename the new file's name
	 * @param parent the new file's parent directory
	 * @param fileIndex the filesystem specific unique index for this file, or -1
	 * if not available
	 * @param symlinkPath destination of the symlink
	 * @param length number of bytes in the file or -1 if not known or directory
	 * @param metadata opaque blob that will be stored and associated with the new
	 * GFile instance
	 * @return new GFile instance
	 */
	public synchronized GFile storeSymlinkWithParent(String filename, GFile parent, long fileIndex,
			String symlinkPath, long length, METADATATYPE metadata) {
		length = length != 0 ? length : symlinkPath.length();
		FileData<METADATATYPE> fileData =
			doStoreFile(filename, parent, fileIndex, false, length, symlinkPath, metadata);
		return fileData.file;
	}

	private FileData<METADATATYPE> doStoreMissingDir(String filename, GFile parent) {
		parent = (parent == null) ? rootDir.file : parent;

		Map<String, FileData<METADATATYPE>> dirContents = getDirectoryContents(parent, true);
		GFile file = createNewFile(parent, filename, true, -1, null);

		FileData<METADATATYPE> fileData = new FileData<>(file, null, -1);
		fileToEntryMap.put(file, fileData);
		dirContents.put(filename, fileData);
		getDirectoryContents(file, true);

		return fileData;
	}

	private FileData<METADATATYPE> doStoreFile(String filename, GFile parent, long fileIndex,
			boolean isDirectory, long length, String symlinkPath, METADATATYPE metadata) {
		parent = (parent == null) ? rootDir.file : parent;
		long fileNum = (fileIndex != -1) ? fileIndex : fileToEntryMap.size();
		if (fileIndexToEntryMap.containsKey(fileNum)) {
			Msg.warn(this, "Duplicate fileNum %d for file %s/%s".formatted(fileNum,
				parent.getPath(), filename));
		}

		Map<String, FileData<METADATATYPE>> dirContents = getDirectoryContents(parent, true);
		String uniqueName = makeUniqueFilename(dirContents.containsKey(filename) && !isDirectory,
			filename, fileNum);

		GFile file = createNewFile(parent, uniqueName, isDirectory, length, metadata);

		FileData<METADATATYPE> fileData = new FileData<>(file, metadata, fileNum, symlinkPath);
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
				? filename + "[%d]".formatted(fileIndex)
				: filename;
	}

	private Map<String, FileData<METADATATYPE>> getDirectoryContents(GFile directoryFile,
			boolean createIfMissing) {
		directoryFile = (directoryFile != null) ? directoryFile : rootDir.file;

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
	 * Directories in a path that have not been encountered before (ie. a file's path references 
	 * a directory that hasn't been mentioned yet as its own file entry) will have a stub entry 
	 * GFile created for them if createIfMissing is true.
	 * <p>
	 * Superfluous slashes in the original filename (ie. name/sub//subafter_extra_slash) will
	 * be represented as empty string elements in the nameparts array and will be skipped
	 * as if they were not there.
	 * 
	 * @param nameparts String[] containing the elements of a path
	 * for them
	 * @param nameComp optional comparator that will compare names, usually case-sensitive vs case
	 * insensitive
	 * @return GFile that represents the parent directory
	 */
	protected GFile lookupParent(String[] nameparts, Comparator<String> nameComp) {

		FileData<METADATATYPE> parent =
			lookup(rootDir, nameparts, nameparts.length - 1, true, nameComp);
		return parent.file;
	}

	protected String[] splitPath(String path) {
		return Objects.requireNonNullElse(path, "").replace('\\', '/').split("/");
	}

	protected FileData<METADATATYPE> lookupFileInDir(
			Map<String, FileData<METADATATYPE>> dirContents, String filename,
			Comparator<String> nameComp) {
		if (dirContents == null) {
			return null;
		}
		if (nameComp == null) {
			// exact match
			return dirContents.get(filename);
		}
		List<FileData<METADATATYPE>> candidateFiles = new ArrayList<>();
		for (FileData<METADATATYPE> fd : dirContents.values()) {
			if (nameComp.compare(filename, fd.file.getName()) == 0) {
				if (fd.file.getName().equals(filename)) {
					return fd;
				}
				candidateFiles.add(fd);
			}
		}
		Collections.sort(candidateFiles,
			(f1, f2) -> f1.file.getName().compareTo(f2.file.getName()));
		return !candidateFiles.isEmpty() ? candidateFiles.get(0) : null;
	}

	/**
	 * Creates a new GFile instance, using per-filesystem custom logic.
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
		return GFileImpl.fromFSRL(rootDir.file.getFilesystem(), parentFile, newFileFSRL,
			isDirectory, size);
	}

	/**
	 * Updates the FSRL of a file already in the index.
	 * 
	 * @param file current {@link GFile}
	 * @param newFSRL the new FSRL the new file will be given
	 */
	public synchronized void updateFSRL(GFile file, FSRL newFSRL) {
		GFileImpl newFile = GFileImpl.fromFSRL(rootDir.file.getFilesystem(), file.getParentFile(),
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
		return "FileSystemIndexHelper for " + rootDir.file.getFilesystem();
	}

}
