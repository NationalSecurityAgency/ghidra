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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.database.DBObjectCache;
import ghidra.util.UniversalIdGenerator;

/**
 * Class to manage the FID functions table.
 */
public class FunctionsTable {
	static final String FUNCTIONS_TABLE = "Functions Table";

	static final int CODE_UNIT_SIZE_COL = 0;
	static final int FULL_HASH_COL = 1;
	static final int SPECIFIC_HASH_ADDITIONAL_SIZE_COL = 2;
	static final int SPECIFIC_HASH_COL = 3;
	static final int LIBRARY_ID_COL = 4;
	static final int NAME_ID_COL = 5;
	static final int ENTRY_POINT_COL = 6;
	static final int DOMAIN_PATH_ID_COL = 7;
	static final int FLAGS_COL = 8;

	static final int CACHE_SIZE = 10000;

	// @formatter:off
	static final Schema SCHEMA = new Schema(LibrariesTable.VERSION, "Function ID", new Field[] {
			ShortField.INSTANCE, LongField.INSTANCE,
			ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			ByteField.INSTANCE
		}, new String[] {
			"Code Unit Size", "Full Hash",
			"Specific Hash Additional Size", "Specific Hash", "Library ID",
			"Name ID", "Entry Point", "Domain Path ID",
			"Flags"
		});
	// @formatter:on

	static int[] INDEXED_COLUMNS = new int[] { FULL_HASH_COL, NAME_ID_COL };

	Table table;
	FidDB fidDb;
	StringsTable stringsTable;
	DBObjectCache<FunctionRecord> functionCache;

	/**
	 * Creates or attaches a functions table.
	 * @param handle database handle
	 * @param stringsTable strings table (must be created first!)
	 * @param create whether to create or just attach
	 * @throws IOException if create fails
	 */
	public FunctionsTable(FidDB fid, DBHandle handle) throws IOException {
		table = handle.getTable(FUNCTIONS_TABLE);
		this.fidDb = fid;
		this.stringsTable = fid.getStringsTable();
		functionCache = new DBObjectCache<>(CACHE_SIZE);
	}

	public static void createTable(DBHandle handle) throws IOException {
		handle.createTable(FUNCTIONS_TABLE, SCHEMA, INDEXED_COLUMNS);
	}

	/**
	 * Returns the first full hash value in the table that is greater than or
	 * equal to the provided argument.  Useful for iterating over all the function
	 * records in (arbitrarily, but deterministically) sorted full hash order.
	 * @param value the minimum hash value to seek
	 * @return the lowest hash in the database greater than or equal to value, or null if no such hash
	 * @throws IOException if database iteration encounters an error
	 */
	public Long getFullHashValueAtOrAfter(long value) throws IOException {
		LongField hashField = new LongField(value);
		DBFieldIterator indexFieldIterator =
			table.indexFieldIterator(hashField, null, true, FULL_HASH_COL);
		if (indexFieldIterator.hasNext()) {
			Field next = indexFieldIterator.next();
			return next.getLongValue();
		}
		return null;
	}

	/**
	 * Returns all the function records that have the provided specific hash.
	 * This is implemented without an index, so it is inefficient.
	 * @param hash the hash value
	 * @return a list of function records that match the hash value
	 * @throws IOException if database iteration encounters an error
	 */
	public List<FunctionRecord> getFunctionRecordsBySpecificHash(long hash) throws IOException {
		RecordIterator iterator = table.iterator();
		List<FunctionRecord> list = new ArrayList<>();
		while (iterator.hasNext()) {
			DBRecord record = iterator.next();
			if (record.getLongValue(SPECIFIC_HASH_COL) != hash) {
				continue;
			}
			FunctionRecord functionRecord = functionCache.get(record);
			if (functionRecord == null) {
				functionRecord = new FunctionRecord(fidDb, functionCache, record);
			}
			list.add(functionRecord);
		}
		return list;
	}

	/**
	 * Returns all the function records that have the provided full hash.
	 * @param hash the hash value
	 * @return a list of function records that match the hash value
	 * @throws IOException if database iteration encounters an error
	 */
	public List<FunctionRecord> getFunctionRecordsByFullHash(long hash) throws IOException {
		LongField hashField = new LongField(hash);
		DBFieldIterator iterator =
			table.indexKeyIterator(FULL_HASH_COL, hashField, hashField, true);
		if (!iterator.hasNext()) {
			return Collections.emptyList();
		}
		List<FunctionRecord> list = new ArrayList<>();
		while (iterator.hasNext()) {
			Field key = iterator.next();
			FunctionRecord functionRecord = functionCache.get(key.getLongValue());
			if (functionRecord == null) {
				DBRecord record = table.getRecord(key);
				functionRecord = new FunctionRecord(fidDb, functionCache, record);
			}
			list.add(functionRecord);
		}
		return list;
	}

	/**
	 * Creates a function record with the given parameters.
	 * @param libraryID the library record primary key
	 * @param hashQuad the quad containing the hash values
	 * @param name the name of the function
	 * @param entryPoint the entry point (address) of the function as found in the library
	 * @param domainPath the domain path of the domain object of the function in the library
	 * @param hasTerminator whether the function contained a terminator in the flow of its function body
	 * @return the newly created function record
	 * @throws IOException if the database create record operation fails
	 */
	public FunctionRecord createFunctionRecord(long libraryID, FidHashQuad hashQuad, String name,
			long entryPoint, String domainPath, boolean hasTerminator) throws IOException {
		DBRecord record = SCHEMA.createRecord(UniversalIdGenerator.nextID().getValue());
		record.setShortValue(CODE_UNIT_SIZE_COL, hashQuad.getCodeUnitSize());
		record.setLongValue(FULL_HASH_COL, hashQuad.getFullHash());
		record.setByteValue(SPECIFIC_HASH_ADDITIONAL_SIZE_COL,
			hashQuad.getSpecificHashAdditionalSize());
		record.setLongValue(SPECIFIC_HASH_COL, hashQuad.getSpecificHash());
		record.setLongValue(LIBRARY_ID_COL, libraryID);
		long stringID = stringsTable.obtainStringID(name);
		record.setLongValue(NAME_ID_COL, stringID);
		record.setLongValue(ENTRY_POINT_COL, entryPoint);
		stringID = stringsTable.obtainStringID(domainPath);
		record.setLongValue(DOMAIN_PATH_ID_COL, stringID);
		byte flags = (byte) (hasTerminator ? FunctionRecord.HAS_TERMINATOR_FLAG : 0);
		record.setByteValue(FLAGS_COL, flags);
		table.putRecord(record);
		FunctionRecord functionRecord = new FunctionRecord(fidDb, functionCache, record);
		return functionRecord;
	}

	/**
	 * Modify a flag on a function record.  Should be accompanied by clearCache().
	 * @param functionID is the id of the function record to modify
	 * @param flagMask is the bit to modify
	 * @param value is true to set, false to clear
	 * @throws IOException
	 */
	void modifyFlags(long functionID, int flagMask, boolean value) throws IOException {
		DBRecord record = table.getRecord(functionID);
		if (record == null) {
			throw new IOException("Function record does not exist");
		}
		byte flags = record.getByteValue(FLAGS_COL);
		if (value) {
			flags |= flagMask;
		}
		else {
			flags &= ~flagMask;
		}
		record.setByteValue(FLAGS_COL, flags);
		table.putRecord(record);
		functionCache.delete(functionID); // Remove any cached record
	}

	/**
	 * Performs a SLOW search of all function records, looking for functions whose name contain
	 * the substring provided as an argument.  Note that empty string will return ALL function
	 * records in the database!
	 * @param nameSearch the name substring to seek
	 * @return a list of the matching function records
	 * @throws IOException if database iteration encounters an error
	 */
	public List<FunctionRecord> getFunctionRecordsByNameSubstring(String nameSearch)
			throws IOException {
		DBFieldIterator iterator = table.indexKeyIterator(NAME_ID_COL);

		if (!iterator.hasNext()) {
			return Collections.emptyList();
		}
		List<FunctionRecord> list = new ArrayList<>();
		while (iterator.hasNext()) {
			Field key = iterator.next();
			FunctionRecord functionRecord = functionCache.get(key.getLongValue());
			if (functionRecord == null) {
				DBRecord record = table.getRecord(key);
				long nameID = record.getLongValue(NAME_ID_COL);
				StringRecord nameRecord = stringsTable.lookupString(nameID);
				String name = nameRecord.getValue();
				if (name.contains(nameSearch)) {
					functionRecord = new FunctionRecord(fidDb, functionCache, record);
				}
			}
			else {
				if (!functionRecord.getName().contains(nameSearch)) {
					functionRecord = null;
				}
			}
			if (functionRecord != null) {
				list.add(functionRecord);
			}
		}
		return list;
	}

	/**
	 * Performs a SLOW search of all function records, looking for functions whose name matches
	 * the regular expression provided as an argument.
	 * @param regex the regular expression to match
	 * @return a list of the matching function records
	 * @throws IOException if database iteration encounters an error
	 */
	public List<FunctionRecord> getFunctionRecordsByNameRegex(String regex) throws IOException {
		Matcher matcher = Pattern.compile(regex).matcher("");
		DBFieldIterator iterator = table.indexKeyIterator(NAME_ID_COL);

		if (!iterator.hasNext()) {
			return Collections.emptyList();
		}
		List<FunctionRecord> list = new ArrayList<>();
		while (iterator.hasNext()) {
			Field key = iterator.next();
			FunctionRecord functionRecord = functionCache.get(key.getLongValue());
			if (functionRecord == null) {
				DBRecord record = table.getRecord(key);
				long nameID = record.getLongValue(NAME_ID_COL);
				StringRecord nameRecord = stringsTable.lookupString(nameID);
				String name = nameRecord.getValue();
				matcher.reset(name);
				if (matcher.matches()) {
					functionRecord = new FunctionRecord(fidDb, functionCache, record);
				}
			}
			else {
				matcher.reset(functionRecord.getName());
				if (!matcher.matches()) {
					functionRecord = null;
				}
			}
			if (functionRecord != null) {
				list.add(functionRecord);
			}
		}
		return list;
	}

	/**
	 * Returns a single function record given its id, or null if no such record exists.
	 * @param functionID the function record primary key id
	 * @return the function record or null if non-existent
	 * @throws IOException if database seek encounters an error
	 */
	public FunctionRecord getFunctionByID(long functionID) throws IOException {
		FunctionRecord functionRecord = functionCache.get(functionID);
		if (functionRecord == null) {
			DBRecord record = table.getRecord(functionID);
			if (record != null) {
				functionRecord = new FunctionRecord(fidDb, functionCache, record);
			}
		}
		return functionRecord;
	}

	/**
	 * Performs a SLOW search of all function records, looking for functions whose domain path contain
	 * the substring provided as an argument.  Note that empty string will return ALL function
	 * records in the database!
	 * @param domainPathSearch the domain name substring to seek
	 * @return a list of the matching function records
	 * @throws IOException if database iteration encounters an error
	 */
	public List<FunctionRecord> getFunctionRecordsByDomainPathSubstring(String domainPathSearch)
			throws IOException {
		RecordIterator iterator = table.iterator();
		List<FunctionRecord> list = new ArrayList<>();
		while (iterator.hasNext()) {
			DBRecord record = iterator.next();
			long domainPathID = record.getLongValue(DOMAIN_PATH_ID_COL);
			StringRecord domainPathRecord = stringsTable.lookupString(domainPathID);
			String domainPath = domainPathRecord.getValue();
			if (domainPath.contains(domainPathSearch)) {
				FunctionRecord functionRecord = functionCache.get(record);
				if (functionRecord == null) {
					functionRecord = new FunctionRecord(fidDb, functionCache, record);
				}
				list.add(functionRecord);
			}
		}
		return list;
	}

	/**
	 * Performs a library-restricted search for functions by name.
	 * @param library the library to restrict the search to
	 * @param name the name of the function to seek
	 * @return a list of all functions in that library having that name
	 * @throws IOException if database iteration encounters an error
	 */
	public List<FunctionRecord> getFunctionRecordsByLibraryAndName(LibraryRecord library,
			String name) throws IOException {
		Long stringID = stringsTable.lookupStringID(name);
		if (stringID == null) {
			// no records with that name
			return Collections.emptyList();
		}
		LongField field = new LongField(stringID);
		DBFieldIterator iterator = table.indexKeyIterator(NAME_ID_COL, field, field, true);
		if (!iterator.hasNext()) {
			return Collections.emptyList();
		}
		final long libraryKey = library.getLibraryID();
		List<FunctionRecord> list = new ArrayList<>();
		while (iterator.hasNext()) {
			Field key = iterator.next();
			FunctionRecord functionRecord = functionCache.get(key.getLongValue());
			if (functionRecord == null) {
				DBRecord record = table.getRecord(key);
				if (record.getLongValue(LIBRARY_ID_COL) == libraryKey) {
					functionRecord = new FunctionRecord(fidDb, functionCache, record);
					list.add(functionRecord);
				}
			}
			else {
				if (functionRecord.getLibraryID() == libraryKey) {
					list.add(functionRecord);
				}
			}
		}
		return list;
	}
}
