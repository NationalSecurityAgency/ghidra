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

import org.apache.commons.io.FilenameUtils;

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
	private FidDB openUpdateableFidDB;
	private FidFilter supportedLanguages;

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
			supportedLanguages = new FidFilter(fidDB);
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
	 * Tests if the database for this FidFile supports the given language, compiler, and source.
	 * LanguageDescription maps to the set of CompilerSpecID that are supported for that language.
	 * If there is no matching LanguageDescription in the map, the Program is not supported.
	 * If the mapped Set<CompilerSpecID> is empty, then all specs are supported for the language.
	 * If the mapped Set<CompilerSpecID> is not empty but there is no matching CompilerSpecID,
	 * then the Program is not supported.
	 * If the compilerSpec parameter is null, then the user wants to apply this
	 * file even if the Program's compiler spec doesn't match.
	 * If a set of supported source languages is present, then at least one provided source
	 * language must match or the Program is not supported.
	 * If the sourceSet parameter is null, then the user wants to apply this file even if
	 * the Program's source languages don't match.
	 * @param programID the program features to test
	 * @return true if this Fid Database supports the given Program.
	 */
	public boolean canProcess(FidProgramID programID) {
		if (supportedLanguages == null) {
			supportedLanguages = getSupportedLanguages();
		}
		return supportedLanguages.test(programID);
	}

	private FidFilter getSupportedLanguages() {
		if (supportedLanguages != null) {
			return supportedLanguages;
		}
		if (isValidFile() && supportedLanguages != null) {
			return supportedLanguages;
		}
		supportedLanguages = new FidFilter();
		return supportedLanguages;
	}

	void closingFidDB(FidDB fidDB) {
		if (fidDB == openUpdateableFidDB) {
			openUpdateableFidDB = null;
		}
	}
}
