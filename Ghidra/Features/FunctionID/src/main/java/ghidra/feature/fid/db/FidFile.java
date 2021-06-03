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
package ghidra.feature.fid.db;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;

/**
 * This class manages a file that contains a Fid database.  We support two types of Fid
 * databases.  One type is a read-only raw buffer file, that is the type we distribute with
 * Ghidra.  The other is for user-added FidFiles. These are packed database files that can
 * be opened for update.  The down-side is that these files must be unpacked before they are
 * used and are susceptible to leaving large temporary files if Ghidra crashes or is killed
 * hard.
 *
 * FidFiles are used to open Fid databases.  User-added (packed) files can also be opened
 * for update.  In this case, the FidFile will maintain a handle to the open, updateable
 * FidDB.  If a second request comes in to open the Fid database for update, the currently
 * open fid database will be return, with its "open count" incremented.  As users close
 * fidDBs, its "open count" is decremented until it reaches 0 and then it is acutally closed.
 */

public class FidFile implements Comparable<FidFile> {
	public static final String FID_PACKED_DATABASE_FILE_EXTENSION = ".fidb";
	public static final String FID_RAW_DATABASE_FILE_EXTENSION = ".fidbf";

	private final File file;
	private final boolean isInstalled;
	private boolean isActive = true;
	private FidFileManager fidFileManager;
	private Set<LanguageDescription> supportedLanguages;
	private FidDB openUpdateableFidDB;

	FidFile(FidFileManager fidFileManager, File file, boolean isInstalled) {
		this.fidFileManager = fidFileManager;
		this.file = file;
		this.isInstalled = isInstalled;
	}

	boolean isValidFile() {
		try (FidDB fidDB = getFidDB(false)) {
			// do nothing - just checking
			return true;
		}
		catch (VersionException e) {
			// Version upgrades are not supported - call showError() to let the user know
			Msg.showError(this, null, "Failed to open FidDb",
				"Failed to open incompatible FidDb (may need to regenerate with this version of Ghidra): " +
					file.getAbsolutePath());
		}
		catch (IOException e) {
			// Not calling showError() here; simply return false and log the message
			Msg.error(this, "Failed to open FidDb: " + file.getAbsolutePath(), e);
		}
		return false;
	}

	/**
	 * Sets the active state of the FidFile. FidFiles that are not active will not be used
	 * when Function ID analysis is performed.
	 * @param b the active state to set it to.
	 */
	public void setActive(boolean b) {
		this.isActive = b;
		fidFileManager.activeStateChanged(this);
	}

	/**
	 * Opens the FidDB for this FidFile.
	 * @param openForUpdate if true, the database will be opened for update, otherwise it
	 * will be read-only.
	 * @return The open FidDB.
	 * @throws VersionException if the FidFile is not the currently supported database schema version.
	 * @throws IOException if a general I/O access error.
	 */
	public synchronized FidDB getFidDB(boolean openForUpdate) throws VersionException, IOException {
		if (openForUpdate && openUpdateableFidDB != null) {
			openUpdateableFidDB.incrementOpenCount();
			return openUpdateableFidDB;
		}
		FidDB fidDB = new FidDB(this, openForUpdate);
		if (openForUpdate) {
			openUpdateableFidDB = fidDB;
		}
		if (supportedLanguages == null) {
			supportedLanguages = getSupportedLanguages(fidDB);
		}
		return fidDB;
	}

	File getFile() {
		return file;
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Returns true if this is a read-only raw database file.
	 * @return true if this is a read-only raw database file.
	 */
	public boolean isInstalled() {
		return isInstalled;
	}

	/**
	 * Returns true if this FidFile will be included when anayslis runs.
	 * @return true if this FidFile will be included when anayslis runs.
	 */
	public boolean isActive() {
		return isActive;
	}

	@Override
	public int hashCode() {
		return file.hashCode();
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
		FidFile other = (FidFile) obj;
		return file.equals(other.file);
	}

	public String getPath() {
		return file.getAbsolutePath();
	}

	@Override
	public int compareTo(FidFile o) {
		return file.compareTo(o.file);
	}

	/**
	 * Returns the name of this FidFile (included extension)
	 * @return  the name of this FidFile (included extension)
	 */
	public String getName() {
		return file.getName();
	}

	/**
	 * Returns the name of this FidFile (without extension)
	 * @return the name of this FidFile (without extension)
	 */
	public String getBaseName() {
		return FilenameUtils.removeExtension(file.getName());
	}

	/**
	 * Tests if the Fid database for this FidFile supports the given language.
	 * @param language the language to test.
	 * @return true if this Fid Database supports the given language.
	 */
	public boolean canProcessLanguage(Language language) {
		if (supportedLanguages == null) {
			supportedLanguages = getSupportedLanguages();
		}
		return supportedLanguages.contains(language.getLanguageDescription());
	}

	private Set<LanguageDescription> getSupportedLanguages(FidDB fidDB) {

		Set<LanguageDescription> languages = new TreeSet<>(new ProcessorSizeComparator());
		LanguageService languageService = DefaultLanguageService.getLanguageService();

		List<LibraryRecord> allLibraries = fidDB.getAllLibraries();
		for (LibraryRecord libraryRecord : allLibraries) {
			LanguageID ghidraLanguageID = libraryRecord.getGhidraLanguageID();
			try {
				LanguageDescription languageDescription =
					languageService.getLanguageDescription(ghidraLanguageID);
				languages.add(languageDescription);
			}
			catch (LanguageNotFoundException e) {
				// ignore language
			}
		}
		return languages;
	}

	private Set<LanguageDescription> getSupportedLanguages() {
		if (supportedLanguages != null) {
			return supportedLanguages;
		}
		if (isValidFile() && supportedLanguages != null) {
			return supportedLanguages;
		}
		supportedLanguages = new TreeSet<>(new ProcessorSizeComparator());
		return supportedLanguages;
	}

	void closingFidDB(FidDB fidDB) {
		if (fidDB == openUpdateableFidDB) {
			openUpdateableFidDB = null;
		}
	}

	/**
	 *  Comparator for deciding if a target language "matches" an architecture for a library
	 *  We want processor family, endianness and "size" to match, but variant can be different
	 */
	private static class ProcessorSizeComparator implements Comparator<LanguageDescription> {

		@Override
		public int compare(LanguageDescription o1, LanguageDescription o2) {
			int res = o1.getProcessor().compareTo(o2.getProcessor());
			if (res != 0) {
				return res;
			}
			if (o1.getSize() != o2.getSize()) {
				return (o1.getSize() < o2.getSize()) ? -1 : 1;
			}
			if (o1.getInstructionEndian() != o2.getInstructionEndian()) {
				return o1.getInstructionEndian().isBigEndian() ? -1 : 1;
			}
			return 0;
		}

	}
}
