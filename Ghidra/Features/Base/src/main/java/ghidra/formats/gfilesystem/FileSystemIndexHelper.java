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

import java.util.*;

/**
 * A helper class used by GFilesystem implementors to track mappings between GFile
 * instances and the underlying container filesystem's native file objects.
 * <p>
 * Threadsafe after initial use of {@link #storeFile(String, int, boolean, long, Object) storeFile()}
 * by the owning filesystem.
 * <p>
 * This class also provides filename 'unique-ifying' (per directory) where an auto-incrementing
 * number will be added to a file's filename if it is not unique in the directory.
 * <p>
 * @param <METADATATYPE> the filesystem specific native file object that the user of this
 * class wants to be able to correlate with Ghidra {@link GFile} instances.
 */
public class FileSystemIndexHelper<METADATATYPE> {

	private GFile rootDir;

	protected Map<GFile, METADATATYPE> fileToEntryMap = new HashMap<>();
	protected Map<GFile, Map<String, GFile>> directoryToListing = new HashMap<>();

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
	public void clear() {
		fileToEntryMap.clear();
		directoryToListing.clear();
	}

	/**
	 * Number of files in this index.
	 *
	 * @return number of file in this index.
	 */
	public int getFileCount() {
		return fileToEntryMap.size();
	}

	/**
	 * Gets the opaque filesystem specific blob that was associated with the specified file.
	 *
	 * @param f {@link GFile} to look for.
	 * @return Filesystem specific blob associated with the specified file, or null if not found.
	 */
	public METADATATYPE getMetadata(GFile f) {
		return fileToEntryMap.get(f);
	}

	/**
	 * Mirror's {@link GFileSystem#getListing(GFile)} interface.
	 *
	 * @param directory {@link GFile} directory to get the list of child files that have been
	 * added to this index, null means root directory.
	 * @return {@link List} of GFile files that are in the specified directory, never null.
	 */
	public List<GFile> getListing(GFile directory) {
		Map<String, GFile> dirListing = getDirectoryContents(directory, false);
		List<GFile> results =
			(dirListing != null) ? new ArrayList<>(dirListing.values()) : Collections.emptyList();
		return results;
	}

	/**
	 * Mirror's {@link GFileSystem#lookup(String)} interface.
	 *
	 * @param path path and filename of a file to find.
	 * @return {@link GFile} instance or null if no file was added to the index at that path.
	 */
	public GFile lookup(String path) {
		String[] nameparts = (path != null ? path : "").split("/");
		GFile parent = lookupParent(nameparts);
		if (nameparts.length == 0) {
			return parent;
		}

		String name = nameparts[nameparts.length - 1];
		if (name == null || name.isEmpty()) {
			return parent;
		}

		Map<String, GFile> dirListing = getDirectoryContents(parent, false);
		return (dirListing != null) ? dirListing.get(name) : null;
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
	 * @param path string path and filename of the file being added to the index.  Back
	 * slashes are normalized to forward slashes.
	 * @param fileIndex the filesystem specific unique index for this file, or -1
	 * if not available.
	 * @param isDirectory boolean true if the new file is a directory
	 * @param length number of bytes in the file or -1 if not known or directory.
	 * @param fileInfo opaque blob that will be stored and associated with the new
	 * GFile instance.
	 * @return new GFile instance.
	 */
	public GFileImpl storeFile(String path, int fileIndex, boolean isDirectory, long length,
			METADATATYPE fileInfo) {

		String[] nameparts = path.replaceAll("[\\\\]", "/").split("/");
		GFile parent = lookupParent(nameparts);

		int fileNum = (fileIndex != -1) ? fileIndex : fileToEntryMap.size();
		String lastpart = nameparts[nameparts.length - 1];
		Map<String, GFile> dirContents = getDirectoryContents(parent, true);
		String uniqueName = dirContents.containsKey(lastpart) && !isDirectory
				? lastpart + "[" + Integer.toString(fileNum) + "]"
				: lastpart;

		GFileImpl file = createNewFile(parent, uniqueName, isDirectory, length, fileInfo);

		dirContents.put(uniqueName, file);
		if (file.isDirectory()) {
			getDirectoryContents(file, true);
		}

		fileToEntryMap.put(file, fileInfo);
		return file;
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
	 * @param filename the new file's name
	 * @param parent the new file's parent directory
	 * @param fileIndex the filesystem specific unique index for this file, or -1
	 * if not available.
	 * @param isDirectory boolean true if the new file is a directory
	 * @param length number of bytes in the file or -1 if not known or directory.
	 * @param fileInfo opaque blob that will be stored and associated with the new
	 * GFile instance.
	 * @return new GFile instance.
	 */
	public GFile storeFileWithParent(String filename, GFile parent, int fileIndex,
			boolean isDirectory, long length, METADATATYPE fileInfo) {
		parent = (parent == null) ? rootDir : parent;
		int fileNum = (fileIndex != -1) ? fileIndex : fileToEntryMap.size();

		Map<String, GFile> dirContents = getDirectoryContents(parent, true);
		String uniqueName = dirContents.containsKey(filename) && !isDirectory
				? filename + "[" + Integer.toString(fileNum) + "]"
				: filename;

		GFile file = createNewFile(parent, uniqueName, isDirectory, length, fileInfo);

		dirContents.put(uniqueName, file);
		if (file.isDirectory()) {
			getDirectoryContents(file, true);
		}

		fileToEntryMap.put(file, fileInfo);
		return file;
	}

	/**
	 * Returns a string-&gt;GFile map that holds the contents of a single directory.
	 * @param directoryFile
	 * @return
	 */
	protected Map<String, GFile> getDirectoryContents(GFile directoryFile,
			boolean createIfMissing) {
		directoryFile = (directoryFile != null) ? directoryFile : rootDir;

		Map<String, GFile> dirContents = directoryToListing.get(directoryFile);
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
		GFile currentFile = rootDir;
		for (int i = 0; i < nameparts.length - 1; i++) {
			Map<String, GFile> currentDirContents = getDirectoryContents(currentDir, true);
			String name = nameparts[i];
			if (name.isEmpty()) {
				continue;
			}
			currentFile = currentDirContents.get(name);
			if (currentFile == null) {
				currentFile = createNewFile(currentDir, name, true, -1, null);
				currentDirContents.put(name, currentFile);
				getDirectoryContents(currentFile, true);
			}
			currentDir = currentFile;
		}

		return currentFile;
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

	@Override
	public String toString() {
		return "FileSystemIndexHelper for " + rootDir.getFilesystem();
	}

}
