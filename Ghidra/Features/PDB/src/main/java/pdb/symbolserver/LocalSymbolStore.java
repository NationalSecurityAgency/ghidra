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
package pdb.symbolserver;

import java.io.*;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Stores Pdb symbol files in a local directory.
 * <p>
 * This is both a {@link SymbolServer} and a {@link SymbolStore}
 * <p>
 */
public class LocalSymbolStore extends AbstractSymbolServer implements SymbolStore {
	private static final String ADMIN_DIRNAME = "000admin"; // per MS custom
	private static final Set<File> ALREADY_WARNED_ABOUT =
		Collections.synchronizedSet(new HashSet<>());

	/**
	 * Predicate that returns true if the location string is a LocalSymbolStore path
	 * 
	 * @param locationString symbol server location string
	 * @return boolean true if a LocalSymbolStore path
	 */
	public static boolean isLocalSymbolStoreLocation(String locationString) {
		if (locationString == null || locationString.isBlank()) {
			return false;
		}

		File dir = new File(locationString);
		return dir.isAbsolute() && dir.isDirectory();
	}

	/**
	 * Creates a (hopefully) MS-compatible symbol server directory location.
	 * <p>
	 * 
	 * @param rootDir    Directory location of the new symbol store
	 * @param indexLevel the 'level' of the storage directory. Typical directories
	 *                   are either level 1, with pdb files stored directly under
	 *                   the root directory, or level 2, using the first 2
	 *                   characters of the pdb filename as a bucket to place each
	 *                   pdb file-directory in. Level 0 indexLevel is a special
	 *                   Ghidra construct that is just a user-friendlier plain
	 *                   directory with a collection of Pdb files
	 * @throws IOException if error creating directory or admin files
	 */
	public static void create(File rootDir, int indexLevel) throws IOException {
		FileUtilities.checkedMkdirs(rootDir);
		switch (indexLevel) {
			case 0:
				// don't have to do anything
				break;
			case 2:
				File index2File = new File(rootDir, INDEX_TWO_FILENAME);
				if (!index2File.exists()) {
					FileUtilities.writeStringToFile(index2File,
						"created by Ghidra LocalSymbolStore " + new Date());
				}
				// fall thru to create pingme and admin dir
			case 1:
				File pingmeFile = new File(rootDir, PINGME_FILENAME);
				if (!pingmeFile.exists()) {
					FileUtilities.writeStringToFile(pingmeFile,
						"created by Ghidra LocalSymbolStore " + new Date());
				}
				File adminDir = new File(rootDir, ADMIN_DIRNAME);
				if (!adminDir.isDirectory()) {
					FileUtilities.checkedMkdir(adminDir);
				}
				break;
			default:
				throw new IOException("Unsupported storage index level: " + indexLevel);
		}
	}

	private final File rootDir;

	/**
	 * Creates an instance of LocalSymbolStore.
	 * 
	 * @param rootDir the root directory of the symbol storage
	 */
	public LocalSymbolStore(File rootDir) {
		this.rootDir = rootDir;
	}

	/**
	 * Returns the root directory of this symbol store.
	 * 
	 * @return root directory of this symbol store
	 */
	public File getRootDir() {
		return rootDir;
	}

	@Override
	public String getName() {
		return rootDir.getPath();
	}

	@Override
	public File getAdminDir() {
		return (storageLevel == 0) ? rootDir : new File(rootDir, ADMIN_DIRNAME);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		return isValid();
	}

	/**
	 * Non-task monitor variant of {@link #isValid(TaskMonitor)}.
	 * 
	 * @return boolean true if this is a valid symbol store
	 */
	public boolean isValid() {
		return rootDir.isDirectory();
	}

	@Override
	public boolean exists(String filename, TaskMonitor monitor) {
		File f = new File(rootDir, filename);
		return f.isFile();
	}

	@Override
	protected int detectStorageLevel(TaskMonitor monitor) {
		// if the PINGME files exists, it means this directory was initialized as
		// a real symbol server. If not, its probably just a normal directory
		// that contains files.
		File pingMeFile = new File(rootDir, PINGME_FILENAME);
		File adminDir = new File(rootDir, ADMIN_DIRNAME);
		if (pingMeFile.isFile() && adminDir.isDirectory()) {
			return super.detectStorageLevel(monitor);
		}
		return doHackyStorageLevelDetection(monitor);
	}

	private int doHackyStorageLevelDetection(TaskMonitor monitor) {
		// dig through the files in the rootDir and see if there is anything
		// that looks like a level1 or level2 directory.
		if (containsPdbSymbolDirsWithFiles(rootDir)) {
			if (ALREADY_WARNED_ABOUT.add(rootDir)) {
				Msg.warn(this,
					"Symbol directory missing control files, guessing storage scheme as level 1: " +
						rootDir);
			}
			return 1;
		}
		File[] possibleLevel2SymbolDirs =
			list(rootDir, f -> f.isDirectory() && f.getName().length() == 2);
		for (File dir : possibleLevel2SymbolDirs) {
			if (containsPdbSymbolDirsWithFiles(dir)) {
				if (ALREADY_WARNED_ABOUT.add(rootDir)) {
					Msg.warn(this,
						"Symbol directory missing control files, guessing storage scheme as level 2: " +
							rootDir);
				}
				return 2;
			}
		}
		return 0;
	}

	private boolean containsPdbSymbolDirsWithFiles(File testDir) {
		File[] possibleLevel1SymbolDirs =
			list(testDir, f -> f.isDirectory() && f.getName().toLowerCase().endsWith(".pdb"));
		for (File dir : possibleLevel1SymbolDirs) {
			if (list(dir, f -> f.isDirectory() &&
				SymbolFileInfo.fromSubdirectoryPath("doesntmatter", f.getName()) != null &&
				new File(f, dir.getName()).isFile()).length > 0) {
				Msg.debug(this, "Detected symbol file directory: " + dir);
				return true;
			}
		}
		return false;
	}

	@Override
	public List<SymbolFileLocation> find(SymbolFileInfo symbolFileInfo, Set<FindOption> options,
			TaskMonitor monitor) {

		initStorageLevelIfNeeded(monitor);

		List<SymbolFileLocation> matches = new ArrayList<>();

		if (storageLevel != 0) {
			// search for exact matches using the built-in logic in AbstractSymbolServer
			matches.addAll(super.find(symbolFileInfo, options, monitor));

			if (options.contains(FindOption.ANY_AGE) || options.contains(FindOption.ANY_ID)) {
				try {
					searchLevelN(symbolFileInfo, options, matches, monitor);
				}
				catch (IOException ioe) {
					Msg.warn(this,
						"Error searching for " + symbolFileInfo.getName() + " in " + rootDir, ioe);
				}
			}
		}
		else {
			searchLevel0(rootDir, this, symbolFileInfo, options, matches, monitor);
		}

		return matches;
	}

	static void searchLevel0(File rootDir, SymbolStore symbolStore, SymbolFileInfo symbolFileInfo,
			Set<FindOption> options, List<SymbolFileLocation> matches, TaskMonitor monitor) {

		File f = new File(rootDir, symbolFileInfo.getName());
		if (!f.isFile()) {
			return;
		}
		SymbolFileInfo fileInfo = SymbolFileInfo.fromFile(f, monitor);
		if (fileInfo != null) {
			if (hasSymbolFileInfoMatch(symbolFileInfo, fileInfo, options)) {
				matches.add(new SymbolFileLocation(f.getName(), symbolStore, fileInfo));
			}
		}
	}

	private void searchLevelN(SymbolFileInfo symbolFileInfo, Set<FindOption> options,
			List<SymbolFileLocation> matches,
			TaskMonitor monitor) throws IOException {

		// enbiggen the search by grubing through our subdirectories.
		// "ke/kernelstuff.pdb/" or just "kernelstuff.pdb/"
		String fileDir = getFileDir(symbolFileInfo.getName());

		// since its a normal 1 or 2 level, we can get UID and AGE info from the subpath
		// without opening the symbol file
		for (File subDir : list(new File(rootDir, fileDir), File::isDirectory)) {
			if (monitor.isCancelled()) {
				break;
			}
			searchSubDir(subDir, symbolFileInfo, fileDir, options, matches);
		}
	}

	private void searchSubDir(File subDir, SymbolFileInfo symbolFileInfo, String relativeFileDir,
			Set<FindOption> options, List<SymbolFileLocation> results) {

		String symbolFileName = symbolFileInfo.getName();
		SymbolFileInfo subDirSymbolFileInfo =
			SymbolFileInfo.fromSubdirectoryPath(symbolFileName, subDir.getName());

		if (subDirSymbolFileInfo != null && !symbolFileInfo.isExactMatch(subDirSymbolFileInfo)) {
			// don't examine this subfolder if its fingerprints indicate its an exact match,
			// since exact matches will already have been added to the results

			// "ke/kernelstuff.pdb/112233440/"
			String uniqueDir = relativeFileDir + subDir.getName() + "/";

			if (hasSymbolFileInfoMatch(symbolFileInfo, subDirSymbolFileInfo, options)) {
				String matchingFile = getFirstExists(uniqueDir, null, symbolFileName,
					getCompressedFilename(symbolFileName));

				if (matchingFile != null) {
					results.add(new SymbolFileLocation(matchingFile, this, subDirSymbolFileInfo));
				}
			}
		}
	}

	@Override
	public String getFileLocation(String filename) {
		return getFile(filename).getPath();
	}

	@Override
	public File getFile(String path) {
		return new File(rootDir, path);
	}

	@Override
	public String giveFile(SymbolFileInfo symbolFileInfo, File file, String filename,
			TaskMonitor monitor) throws IOException {
		initStorageLevelIfNeeded(monitor);
		filename = FilenameUtils.getName(filename); // make sure no relative path shenanigans
		String relativeDestinationFilename = getUniqueFileDir(symbolFileInfo) + filename;
		File destinationFile = new File(rootDir, relativeDestinationFilename);
		FileUtilities.checkedMkdirs(destinationFile.getParentFile());
		if (destinationFile.isFile()) {
			Msg.info(this, logPrefix() + ": File already exists: " + destinationFile);
			if (!file.delete()) {
				Msg.warn(this, logPrefix() + ": Unable to delete source file: " + file);
			}
			return relativeDestinationFilename;
		}
		monitor.setMessage("Storing " + filename + " in local symbol store ");
		if (!file.renameTo(destinationFile)) {
			throw new IOException("Could not move " + file + " to " + destinationFile);
		}

		return relativeDestinationFilename;
	}

	@Override
	public String putStream(SymbolFileInfo symbolFileInfo,
			SymbolServerInputStream symbolServerInputStream, String filename, TaskMonitor monitor)
			throws IOException {
		initStorageLevelIfNeeded(monitor);
		filename = FilenameUtils.getName(filename); // make sure no relative path shenanigans
		String relativeDestinationFilename = getUniqueFileDir(symbolFileInfo) + filename;
		File destinationFile = new File(rootDir, relativeDestinationFilename);
		FileUtilities.checkedMkdirs(destinationFile.getParentFile());
		if (destinationFile.isFile()) {
			Msg.info(this, logPrefix() + ": File already exists: " + destinationFile);
			return relativeDestinationFilename;
		}
		if (destinationFile.isDirectory()) {
			Msg.error(this, logPrefix() + ": File's location already exists and is a directory: " +
				destinationFile);
			Msg.error(this, logPrefix() + ": Possible symbol storage directory misconfiguration!");
			return relativeDestinationFilename;
		}

		File destinationFileTmp = new File(rootDir, relativeDestinationFilename + ".tmp");
		destinationFileTmp.delete();

		long expectedLength = symbolServerInputStream.getExpectedLength();
		String expectedLenMsg =
			expectedLength >= 0 ? (" (" + FileUtilities.formatLength(expectedLength) + ")") : "";
		monitor.setIndeterminate(expectedLength < 0);
		monitor.initialize(expectedLength);
		monitor.setMessage("Storing " + filename + " in local symbol store" + expectedLenMsg);
		try (InputStream is = symbolServerInputStream.getInputStream()) {
			long bytesCopied =
				FileUtilities.copyStreamToFile(is, destinationFileTmp, false, monitor);
			if (symbolServerInputStream.getExpectedLength() >= 0 &&
				bytesCopied != symbolServerInputStream.getExpectedLength()) {
				throw new IOException("Copy length mismatch, expected " +
					symbolServerInputStream.getExpectedLength() + " bytes, got " + bytesCopied);
			}
			if (!destinationFileTmp.renameTo(destinationFile)) {
				throw new IOException(
					"Error renaming temp file " + destinationFileTmp + " to " + destinationFile);
			}
			return relativeDestinationFilename;
		}
		finally {
			destinationFileTmp.delete();
		}
	}

	@Override
	public SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException {
		File file = new File(rootDir, filename);
		return new SymbolServerInputStream(new FileInputStream(file), file.length());
	}

	@Override
	public boolean isLocal() {
		return true;
	}

	@Override
	public String toString() {
		return String.format("LocalSymbolStore: [ rootDir: %s, storageLevel: %d]",
			rootDir.getPath(), storageLevel);
	}

	private String logPrefix() {
		return getClass().getSimpleName() + "[" + rootDir + "]";
	}

	// -----------------------------------------------------------------------------------
	// Static helpers

	static File[] list(File dir, FileFilter filter) {
		File[] files = dir.listFiles(filter);
		return files != null ? files : new File[] {};
	}

	static boolean hasSymbolFileInfoMatch(SymbolFileInfo symbolFileInfo,
			SymbolFileInfo otherSymbolFileInfo, Set<FindOption> options) {
		boolean idMatches =
			symbolFileInfo.getUniqueName().equalsIgnoreCase(otherSymbolFileInfo.getUniqueName());
		boolean ageMatches = symbolFileInfo.getIdentifiers()
				.getAge() == otherSymbolFileInfo.getIdentifiers().getAge();

		if (!options.contains(FindOption.ANY_ID)) {
			return idMatches && (ageMatches || options.contains(FindOption.ANY_AGE));
		}
		return true;
	}

}
