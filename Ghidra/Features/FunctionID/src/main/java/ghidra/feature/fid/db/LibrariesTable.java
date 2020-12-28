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

import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.VersionException;

/**
 * The libraries table for FID.  Note that all entries associated with a single library must have the same
 * LanguageID and CompilerSpecID.  If supporting multiple architectures, simply create multiple libraries
 * in the same database file.
 */
public class LibrariesTable {
	static final String LIBRARIES_TABLE = "Libraries Table";
	/**
	 * NOTE!  There is no way to upgrade databases right now!  If you increment this number
	 * due to a schema change, you must recreate all the databases we distribute with Ghidra,
	 * and ALL customers EVERYWHERE will have to recreate their databases upon upgrading
	 * as well!!!  DANGER!
	 */
	static final int VERSION = 6;

	static final int LIBRARY_FAMILY_NAME_COL = 0;
	static final int LIBRARY_VERSION_COL = 1;
	static final int LIBRARY_VARIANT_COL = 2;
	static final int GHIDRA_VERSION_COL = 3;
	static final int GHIDRA_LANGUAGE_ID_COL = 4;
	static final int GHIDRA_LANGUAGE_VERSION_COL = 5;
	static final int GHIDRA_LANGUAGE_MINOR_VERSION_COL = 6;
	static final int GHIDRA_COMPILER_SPEC_ID_COL = 7;

	// @formatter:off
	static final Schema SCHEMA = new Schema(VERSION, "Library ID", new Field[] {
			StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
			StringField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE,
			StringField.INSTANCE
		}, new String[] {
			"Library Family Name", "Library Version", "Library Variant",
			"Ghidra Version", "Ghidra Language ID", "Ghidra Language Version", "Ghidra Language Minor Version",
			"Ghidra Compiler Spec ID"
		});
	// @formatter:on

	static int[] INDEXED_COLUMNS = new int[] { LIBRARY_FAMILY_NAME_COL, LIBRARY_VERSION_COL };

	Table table;

	/**
	 * Creates or attaches a libraries table.
	 * @param handle database handle
	 * @param create whether to create or just attach
	 * @throws IOException if create fails
	 * @throws VersionException if the saved database version is incompatible with this software
	 */
	public LibrariesTable(DBHandle handle) throws IOException, VersionException {
		table = handle.getTable(LIBRARIES_TABLE);
		checkVersion();
	}

	public static void createTable(DBHandle handle) throws IOException {
		handle.createTable(LIBRARIES_TABLE, SCHEMA, INDEXED_COLUMNS);
	}

	/**
	 * Checks the saved database version versus our current software version.
	 * @throws VersionException if the version is different
	 * @throws IOException if the version can't be read from the database
	 */
	private void checkVersion() throws VersionException, IOException {
		int libraryVersion = table.getSchema().getVersion();
		if (libraryVersion != VERSION) {
			String msg = "Expected version " + VERSION + " for table " + LIBRARIES_TABLE +
				" but got " + table.getSchema().getVersion();
			throw new VersionException(msg,
				libraryVersion < VERSION ? VersionException.OLDER_VERSION
						: VersionException.NEWER_VERSION,
				false);
		}
	}

	/**
	 * Creates a new library record using the parameters.
	 * @param libraryFamilyName the family name of the library
	 * @param libraryVersion the version string for the library
	 * @param libraryVariant the variant name for the library
	 * @param ghidraVersion the version of Ghidra used in creating the library
	 * @param languageID the LanguageID of the language in this library
	 * @param languageVersion the version of the language
	 * @param languageMinorVersion the minor version of the language
	 * @param compilerSpecID the CompilerSpecID in this library
	 * @return the new library record
	 * @throws IOException if the database create fails
	 */
	public DBRecord createLibrary(String libraryFamilyName, String libraryVersion,
			String libraryVariant, String ghidraVersion, LanguageID languageID, int languageVersion,
			int languageMinorVersion, CompilerSpecID compilerSpecID) throws IOException {
		DBRecord record = SCHEMA.createRecord(UniversalIdGenerator.nextID().getValue());
		record.setString(LIBRARY_FAMILY_NAME_COL, libraryFamilyName);
		record.setString(LIBRARY_VERSION_COL, libraryVersion);
		record.setString(LIBRARY_VARIANT_COL, libraryVariant);
		record.setString(GHIDRA_VERSION_COL, ghidraVersion);
		record.setString(GHIDRA_LANGUAGE_ID_COL, languageID.getIdAsString());
		record.setIntValue(GHIDRA_LANGUAGE_VERSION_COL, languageVersion);
		record.setIntValue(GHIDRA_LANGUAGE_MINOR_VERSION_COL, languageMinorVersion);
		record.setString(GHIDRA_COMPILER_SPEC_ID_COL, compilerSpecID.getIdAsString());
		table.putRecord(record);
		return record;
	}

	/**
	 * Returns all libraries in this database.
	 * @return all libraries in this database
	 * @throws IOException if database iteration encounters an error
	 */
	public List<LibraryRecord> getLibraries() throws IOException {
		RecordIterator iterator = table.iterator();
		if (!iterator.hasNext()) {
			return Collections.emptyList();
		}
		ArrayList<LibraryRecord> list = new ArrayList<LibraryRecord>();
		while (iterator.hasNext()) {
			list.add(new LibraryRecord(iterator.next()));
		}
		return list;
	}

	/**
	 * Return libraries by name
	 *   Restrict by version if -version- is non-null
	 *   Restrict by variant if -variant- is non-null
	 * @param name is the family name of the library (must not be null)
	 * @param version is the optional version string
	 * @param variant is the optional variant string
	 * @return matching list of libraries
	 * @throws IOException
	 */
	public List<LibraryRecord> getLibrariesByName(String name, String version, String variant)
			throws IOException {
		StringField hashField = new StringField(name);
		DBFieldIterator iterator =
			table.indexKeyIterator(LIBRARY_FAMILY_NAME_COL, hashField, hashField, true);
		if (!iterator.hasNext()) {
			return Collections.emptyList();
		}
		List<LibraryRecord> list = new ArrayList<LibraryRecord>();
		while (iterator.hasNext()) {
			Field key = iterator.next();
			DBRecord record = table.getRecord(key);
			LibraryRecord libraryRecord = new LibraryRecord(record);
			if (version != null) {
				if (!libraryRecord.getLibraryVersion().equals(version)) {
					continue;
				}
			}
			if (variant != null) {
				if (!libraryRecord.getLibraryVariant().equals(variant)) {
					continue;
				}
			}
			list.add(libraryRecord);
		}
		return list;
	}

	/**
	 * Returns a specific library by primary key id, or null if it doesn't exist.
	 * @param id the library primary key
	 * @return the library or null if not found
	 * @throws IOException if database seek encounters an error
	 */
	public DBRecord getLibraryByID(long id) throws IOException {
		DBRecord record = table.getRecord(id);
		return record;
	}
}
