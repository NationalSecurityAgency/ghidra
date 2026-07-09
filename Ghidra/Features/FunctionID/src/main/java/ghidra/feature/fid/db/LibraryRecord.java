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

import static ghidra.feature.fid.db.LibrariesTable.*;

import db.DBRecord;
import ghidra.program.model.lang.LanguageID;

/**
 * Represents a library record in the FID database.
 */
public class LibraryRecord {
	/**
	 * The record is stored, no memoization is performed.
	 */
	final DBRecord record;

	/**
	 * Creates a new library record.
	 * @param record the database record on which to base this library
	 */
	public LibraryRecord(DBRecord record) {
		if (record == null) {
			throw new IllegalArgumentException("null record");
		}
		this.record = record;
	}

	/**
	 * Returns the library primary key.
	 * @return the library primary key
	 */
	public long getLibraryID() {
		return record.getKey();
	}

	/**
	 * Returns the library family name.
	 * @return the library family name
	 */
	public String getLibraryFamilyName() {
		return record.getString(LIBRARY_FAMILY_NAME_COL);
	}

	/**
	 * Returns the library version string.
	 * @return the library version string
	 */
	public String getLibraryVersion() {
		return record.getString(LIBRARY_VERSION_COL);
	}

	/**
	 * Returns the library variant string.
	 * @return the library variant string
	 */
	public String getLibraryVariant() {
		return record.getString(LIBRARY_VARIANT_COL);
	}

	/**
	 * Returns the Ghidra version string (used to create the library).
	 * @return the Ghidra version string
	 */
	public String getGhidraVersion() {
		return record.getString(GHIDRA_VERSION_COL);
	}

	/**
	 * Returns the Ghidra LanguageID (used to create the library).
	 * @return the Ghidra LanguageID
	 */
	public LanguageID getGhidraLanguageID() {
		return new LanguageID(record.getString(GHIDRA_LANGUAGE_ID_COL));
	}

	/**
	 * Returns the Ghidra language version (used to create the library).
	 * @return the Ghidra language version
	 */
	public int getGhidraLanguageVersion() {
		return record.getIntValue(GHIDRA_LANGUAGE_VERSION_COL);
	}

	/**
	 * Returns the Ghidra language minor version (used to create the library).
	 * @return the Ghidra language minor version
	 */
	public int getGhidraLanguageMinorVersion() {
		return record.getIntValue(GHIDRA_LANGUAGE_MINOR_VERSION_COL);
	}

	/**
	 * Returns a list of CompilerSpecIDs (used to create the library)
	 * as a string of comma separated names.
	 * A null value indicates that all CompilerSpecIDs are allowed.
	 * @return a list of CompilerSpecIDs or null
	 */
	public String getGhidraCompilerSpecID() {
		String rawString = record.getString(LIBRARY_METADATA_COL);
		if (rawString == null) {
			return null;
		}
		int pos = rawString.indexOf(':');
		if (pos >= 0) {
			rawString = rawString.substring(0, pos);
		}
		if (rawString.length() == 0) {
			return null;
		}
		return rawString;
	}

	/**
	 * Returns a list of SourceLanguageIDs (used to create the library)
	 * as a string of comma separated names.
	 * A null value means that all SourceLanguageIDs are allowed.
	 * @return a list of SourceLanguageIDs or null
	 */
	public String getGhidraSourceLanguageID() {
		String rawString = record.getString(LIBRARY_METADATA_COL);
		if (rawString == null) {
			return null;
		}
		int pos = rawString.indexOf(':');
		if (pos < 0) {
			return null;
		}
		rawString = rawString.substring(pos + 1);
		if (rawString.length() == 0) {
			return null;
		}
		return rawString;
	}

	/**
	 * Overridden toString for pretty printing the library whilst debugging.
	 */
	@Override
	public String toString() {
		return getLibraryFamilyName() + " " + getLibraryVersion() + " " + getLibraryVariant();
	}
}
