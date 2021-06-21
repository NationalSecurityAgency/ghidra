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

import java.io.*;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import db.DBHandle;
import db.DBRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class FidDB implements Closeable {
	private static final String FID_CONTENT_TYPE = "Function ID Database";

	private static final String[] OLD_V1_FID_TABLES =
		new String[] { "Relations Table", "Functions Table", "Strings Table", "Libraries Table" };

	private final FidFile fidFile;
	private final DBHandle handle;
	private LibrariesTable librariesTable;
	private StringsTable stringsTable;
	private FunctionsTable functionsTable;
	private RelationsTable relationsTable;
	private long openTransaction;

	private boolean openForUpdate;
	private AtomicInteger openCount = new AtomicInteger(); // how many have this open?

	/**
	 * @param service the FID database service
	 * @param installationFile the installation file, if this database is in the installation
	 * @param dbFile the database file, if this database is not in the installation
	 * @throws VersionException
	 */
	FidDB(FidFile fidFile, boolean openForUpdate) throws IOException, VersionException {
		this.fidFile = fidFile;
		this.openForUpdate = openForUpdate;
		openCount.set(1);
		if (fidFile.isInstalled()) {
			handle = openRawDatabaseFile();
		}
		else {
			handle = openPackedDatabase();
		}
		getTables();
		if (openForUpdate) {
			openTransaction = handle.startTransaction();
		}
	}

	/**
	 * Creates a new empty Fid database and saves it to the give file.
	 * @param file the file to create
	 * @throws IOException
	 */
	static void createNewFidDatabase(File file) throws IOException {
		if (file.exists()) {
			throw new DuplicateFileException("File already exists: " + file.getAbsolutePath());
		}
		PackedDBHandle packedDBHandle = new PackedDBHandle(FID_CONTENT_TYPE);
		try {
			long txId = packedDBHandle.startTransaction();
			LibrariesTable.createTable(packedDBHandle);
			StringsTable.createTable(packedDBHandle);
			FunctionsTable.createTable(packedDBHandle);
			RelationsTable.createTables(packedDBHandle);
			packedDBHandle.endTransaction(txId, true);

			String name = file.getName();
			packedDBHandle.saveAs(name, file.getParentFile(), name, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen since we used a dummy
		}
		finally {
			packedDBHandle.close();
		}
	}

	/**
	 * Saves this FidDB to a raw database file
	 * @param file the file to save to.
	 * @param monitor the monitor for progress.
	 * @throws CancelledException if the monitor is cancelled
	 * @throws IOException if the file can't be written.
	 */
	public void saveRawDatabaseFile(File file, TaskMonitor monitor)
			throws CancelledException, IOException {
		handle.saveAs(file, false, monitor);
	}

	/**
	 * Opens a FidDb using a raw read-only database file (included with Ghidra in the installation).
	 * @return the database handle for the open database.
	 * @throws IOException
	 */
	private DBHandle openRawDatabaseFile() throws IOException {
		openForUpdate = false; // can't open raw database files for update.
		return new DBHandle(fidFile.getFile());
	}

	/**
	 * Opens a FidDB from a packed database files.  These are FidDb that are not in the installation
	 * and can be modified.
	 * @return the database handle for the open database.
	 * @throws IOException
	 */
	private DBHandle openPackedDatabase() throws IOException {
		try {
			PackedDatabase pdb = PackedDatabase.getPackedDatabase(fidFile.getFile(), false,
				TaskMonitorAdapter.DUMMY_MONITOR);
			if (openForUpdate) {
				return pdb.openForUpdate(TaskMonitorAdapter.DUMMY_MONITOR);
			}
			return pdb.open(TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// using dummy monitor - can't happen
		}
		throw new AssertException("Can't happen!");
	}

	private void getTables() throws IOException, VersionException {
		librariesTable = new LibrariesTable(handle);
		stringsTable = new StringsTable(handle);
		functionsTable = new FunctionsTable(this, handle);
		relationsTable = new RelationsTable(handle);
	}

	/**
	 * @return name of underlying FidFile.
	 */
	public String getName() {
		return fidFile.getName();
	}

	/**
	 * @return full file path of underlying FidFile.
	 */
	public String getPath() {
		return fidFile.getPath();
	}

	/**
	 * Overridden toString to pretty print object for debug.
	 */
	@Override
	public String toString() {
		return "FidDB: " + fidFile.getFile().getAbsolutePath();
	}

	/**
	 * Used to indicated an addition user wants to keep the database open.  The database will
	 * be closed only when all the users have called the close.  After the original open, the
	 * openCount will be one.
	 */
	public void incrementOpenCount() {
		openCount.incrementAndGet();
	}

	/**
	 * Indicates the the user of this FidDB no longer needs it open.  This will decrement the
	 * "open count" and if the "open count is 0, the database will be closed.
	 */
	@Override
	public void close() {
		if (openCount.decrementAndGet() == 0) {
			fidFile.closingFidDB(this);

			try {
				if (openForUpdate) {
					handle.endTransaction(openTransaction, true);
				}
				handle.close();
			}
			catch (IOException e) {
				Msg.error(this, "Error closing " + this, e);
			}
			librariesTable = null;
			stringsTable = null;
			functionsTable = null;
			relationsTable = null;
		}
	}

	/**
	 * Returns the string specific table of the databaes
	 * @return the StringsTable object
	 */
	StringsTable getStringsTable() {
		return stringsTable;
	}

	/**
	 * Returns all libraries that exist in this FID database.
	 * @return all libraries that exist in this FID database
	 */
	public List<LibraryRecord> getAllLibraries() {
		List<LibraryRecord> libraries;
		try {
			if (librariesTable == null) {
				libraries = Collections.emptyList();
			}
			else {
				libraries = librariesTable.getLibraries();
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error in FID database", e);
			libraries = Collections.emptyList();
		}
		return libraries;
	}

	/**
	 * Searches this database for functions given a specific library and exact name.
	 * @param library the library to search
	 * @param name the exact name of the function
	 * @return the functions matching the search (or empty)
	 */
	public List<FunctionRecord> findFunctionsByLibraryAndName(LibraryRecord library, String name) {
		try {
			List<FunctionRecord> list =
				functionsTable.getFunctionRecordsByLibraryAndName(library, name);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem searching for FID Functions by name and namespace", e);
		}
		return null;
	}

	/**
	 * Searches this database for functions that match a name substring.
	 * @param name the name substring
	 * @return the functions matching the search (or empty)
	 */
	public List<FunctionRecord> findFunctionsByNameSubstring(String name) {
		try {
			List<FunctionRecord> list = functionsTable.getFunctionRecordsByNameSubstring(name);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem searching for FID Functions by name substring", e);
		}
		return null;
	}

	/**
	 * Searches this database for functions whose name matches the given regular expression
	 * @param regex the regular expression to match
	 * @return the functions matching the search (or empty)
	 */
	public List<FunctionRecord> findFunctionsByNameRegex(String regex) {
		try {
			List<FunctionRecord> list = functionsTable.getFunctionRecordsByNameRegex(regex);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem search for FID Functions by regular expression", e);
		}
		return null;
	}

	/**
	 * Searches this database for functions that match a domain path substring.
	 * @param domainPath the domain path substring
	 * @return the functions matching the search (or empty)
	 */
	public List<FunctionRecord> findFunctionsByDomainPathSubstring(String domainPath) {
		try {
			List<FunctionRecord> list =
				functionsTable.getFunctionRecordsByDomainPathSubstring(domainPath);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem searching for FID Functions by domain path", e);
		}
		return null;
	}

	/**
	 * Returns the first full hash value in the database that is greater than or
	 * equal to the provided argument.  Useful for iterating over all the function
	 * records in (arbitrarily, but deterministically) sorted full hash order.
	 * @param value the minimum hash value to seek
	 * @return the lowest hash in the database greater than or equal to value, or null if no such hash
	 */
	public Long findFullHashValueAtOrAfter(long value) {
		try {
			Long search = functionsTable.getFullHashValueAtOrAfter(value);
			return search;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem searching for full hash values", e);
		}
		return null;
	}

	/**
	 * Returns all the function records that have the provided specific hash.
	 * @param hash the hash value
	 * @return a list of function records that match the hash value
	 */
	public List<FunctionRecord> findFunctionsBySpecificHash(long specificHash) {
		try {
			List<FunctionRecord> list =
				functionsTable.getFunctionRecordsBySpecificHash(specificHash);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem searching for FID Functions by specific hash", e);
		}
		return null;
	}

	/**
	 * Returns all the function records that have the provided full hash.
	 * @param hash the hash value
	 * @return a list of function records that match the hash value
	 */
	public List<FunctionRecord> findFunctionsByFullHash(long fullHash) {
		try {
			List<FunctionRecord> list = functionsTable.getFunctionRecordsByFullHash(fullHash);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem searching for FID Functions by full hash", e);
		}
		return null;
	}

	/**
	 * Return libraries by name
	 *   Restrict by version if -version- is non-null
	 *   Restrict by variant if -variant- is non-null
	 * @param family is the family name of the library (must not be null)
	 * @param version is the optional version string
	 * @param variant is the optional variant string
	 * @return matching list of libraries
	 */
	public List<LibraryRecord> findLibrariesByName(String family, String version, String variant) {
		try {
			List<LibraryRecord> list = librariesTable.getLibrariesByName(family, version, variant);
			return list;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem search for FID Libraries by name", e);
		}
		return null;
	}

	/**
	 * Returns true if the relation exists, between a superior (caller) function and a
	 * full hash representing the inferior (callee) function.
	 * @param superiorFunction the caller function
	 * @param inferiorFunction a hash representing the callee function
	 * @return true if the relation exists
	 */
	public boolean getSuperiorFullRelation(FunctionRecord superiorFunction,
			FidHashQuad inferiorFunction) {
		try {
			DBRecord libraryByID = librariesTable.getLibraryByID(superiorFunction.getLibraryID());
			if (libraryByID != null) {
				return relationsTable.getSuperiorFullRelation(superiorFunction, inferiorFunction);
			}
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem in getSuperiorFullRelation", e);
		}
		return false;
	}

	/**
	 * Returns true if the relation exists, between an inferior (callee) function and a
	 * full hash representing the superior (caller) function.
	 * @param superiorFunction a hash representing the caller function
	 * @param inferiorFunction the callee function
	 * @return true if the relation exists
	 */
	public boolean getInferiorFullRelation(FidHashQuad superiorFunction,
			FunctionRecord inferiorFunction) {
		try {
			DBRecord libraryByID = librariesTable.getLibraryByID(inferiorFunction.getLibraryID());
			if (libraryByID != null) {
				return relationsTable.getInferiorFullRelation(superiorFunction, inferiorFunction);
			}
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem in getInferiorFullRelation", e);
		}
		return false;
	}

	/**
	 * Returns a single function record given its id, or null if no such record exists.
	 * @param functionID the function record primary key id
	 * @return the function record or null if non-existent
	 */
	public FunctionRecord getFunctionByID(long functionID) {
		try {
			FunctionRecord functionRecord = functionsTable.getFunctionByID(functionID);
			return functionRecord;
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem finding Function record by ID", e);
		}
		return null;
	}

	/**
	 * Returns the library record in which the provided function record resides.
	 * @param functionRecord the function record
	 * @return the library record for that function
	 */
	public LibraryRecord getLibraryForFunction(FunctionRecord functionRecord) {
		try {
			DBRecord record = librariesTable.getLibraryByID(functionRecord.getLibraryID());
			if (record == null) {
				return null;
			}
			return new LibraryRecord(record);
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem finding Library for function", e);
		}
		return null;
	}

	public DBHandle getDBHandle() {
		return handle;
	}

	/**
	 * Creates a new library using the parameters supplied.
	 * @param libraryFamilyName the library family name
	 * @param libraryVersion the library version
	 * @param libraryVariant the library variant
	 * @param ghidraVersion the Ghidra version
	 * @param languageID the language id
	 * @param languageVersion the language version
	 * @param languageMinorVersion the language minor version
	 * @param compilerSpecID the compiler spec id
	 * @return the newly created library record
	 */
	public LibraryRecord createNewLibrary(String libraryFamilyName, String libraryVersion,
			String libraryVariant, String ghidraVersion, LanguageID languageID, int languageVersion,
			int languageMinorVersion, CompilerSpecID compilerSpecID) {

		try {
			checkUpdateAllowed();
			DBRecord record = librariesTable.createLibrary(libraryFamilyName, libraryVersion,
				libraryVariant, ghidraVersion, languageID, languageVersion, languageMinorVersion,
				compilerSpecID);
			return new LibraryRecord(record);
		}
		catch (ReadOnlyException e) {
			Msg.error(this, e);
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem creating FID Library record", e);
		}
		return null;
	}

	private void checkUpdateAllowed() throws ReadOnlyException {
		if (!openForUpdate) {
			throw new ReadOnlyException(
				"Attempted to modify Fid Database that is not open for update: " + this);
		}
	}

	/**
	 * Creates a new function record in a specific library in this FID database.
	 * @param library the library in which to create the function
	 * @param hashQuad the hash quad
	 * @param name the name of the function
	 * @param entryPoint the entry point of the function in the library
	 * @param domainPath the domain path of the domain object containing the function
	 * @param hasTerminator whether a terminating flow was found in the function body
	 * @return the newly created function record
	 */
	public FunctionRecord createNewFunction(LibraryRecord library, FidHashQuad hashQuad,
			String name, long entryPoint, String domainPath, boolean hasTerminator) {

		try {
			checkUpdateAllowed();
			FunctionRecord functionRecord = functionsTable.createFunctionRecord(
				library.getLibraryID(), hashQuad, name, entryPoint, domainPath, hasTerminator);
			return functionRecord;
		}
		catch (ReadOnlyException e) {
			Msg.error(this, e);
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem creating FID Function record", e);
		}
		return null;
	}

	/**
	 * Creates a new relation record between a superior (caller) and inferior (callee)
	 * function.
	 * @param superiorFunction the caller function
	 * @param inferiorFunction the callee function
	 * @param relationType the relation type
	 */
	public void createRelation(FunctionRecord superiorFunction, FunctionRecord inferiorFunction,
			RelationType relationType) {

		try {
			checkUpdateAllowed();
			relationsTable.createRelation(superiorFunction, inferiorFunction, relationType);
		}
		catch (ReadOnlyException e) {
			Msg.error(this, e);
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem creating FID Relation record", e);
		}
	}

	/**
	 * Creates only an inferior relation, used for special distinguishing parent relationships with
	 * common functions
	 * @param superiorFunction is the parent function
	 * @param inferiorFunction is the common function
	 */
	public void createInferiorRelation(FunctionRecord superiorFunction,
			FunctionRecord inferiorFunction) {
		try {
			checkUpdateAllowed();
			relationsTable.createInferiorRelation(superiorFunction, inferiorFunction);
		}
		catch (ReadOnlyException e) {
			Msg.error(this, e);
		}
		catch (IOException e) {
			Msg.error(this, "Serious problem creating FID Inferior Relation record", e);
		}
	}

	/**
	 * Modify a single flag to a specific value across a list of functions
	 * @param funcList is the list of functions
	 * @param flagMask is the flag to be modified
	 * @param value is true to set, false to clear
	 * @throws IOException
	 */
	private void modifyFlags(List<FunctionRecord> funcList, int flagMask, boolean value)
			throws IOException {

		for (FunctionRecord funcRec : funcList) {
			functionsTable.modifyFlags(funcRec.getID(), flagMask, value);
		}
	}

	/**
	 * Modify a flag of a FunctionRecord in the database, and return a modified record
	 * @param funcRec the original record to be modified
	 * @param flagMask mask indicating which flag to modify
	 * @param value new value of the flag
	 * @return a new FunctionRecord reflecting the change
	 * @throws IOException
	 */
	private FunctionRecord modifyFunctionFlag(FunctionRecord funcRec, int flagMask, boolean value)
			throws IOException {

		if (funcRec.getFidDb() != this) {
			throw new IOException("Mismatched FunctionRecord and FidDb");
		}
		long key = funcRec.getID();
		functionsTable.modifyFlags(key, flagMask, value);
		FunctionRecord res = functionsTable.getFunctionByID(key);
		if (res == null) {
			throw new IOException("Could not recover modified FunctionRecord");
		}
		return res;
	}

	/**
	 * Change the auto-pass property for all functions with given full hash
	 * @param hash is the full hash to match
	 * @param value is true to set auto-pass, false to clear
	 * @throws IOException
	 */
	public void setAutoPassByFullHash(long hash, boolean value) throws IOException {

		checkUpdateAllowed();

		List<FunctionRecord> funcList = findFunctionsByFullHash(hash);
		modifyFlags(funcList, FunctionRecord.AUTO_PASS_FLAG, value);
	}

	/**
	 * Change the auto-fail property for all functions with given full hash
	 * @param hash is the full hash to match
	 * @param value is true to set auto-fail, false to clear
	 * @throws IOException
	 */
	public void setAutoFailByFullHash(long hash, boolean value) throws IOException {

		checkUpdateAllowed();

		List<FunctionRecord> funcList = findFunctionsByFullHash(hash);
		modifyFlags(funcList, FunctionRecord.AUTO_FAIL_FLAG, value);
	}

	/**
	 * Change the force-specific property for all functions with given full hash
	 * @param hash is the full hash to match
	 * @param value is true to set force-specific, false to clear
	 * @throws IOException
	 */
	public void setForceSpecificByFullHash(long hash, boolean value) throws IOException {

		checkUpdateAllowed();

		List<FunctionRecord> funcList = findFunctionsByFullHash(hash);
		modifyFlags(funcList, FunctionRecord.FORCE_SPECIFIC_FLAG, value);
	}

	/**
	 * Change the force-relation property for all function with given full hash
	 * @param hash is the full hash to match
	 * @param value is true to set force-relation, false to clear
	 * @throws IOException
	 */
	public void setForceRelationByFullHash(long hash, boolean value) throws IOException {
		checkUpdateAllowed();

		List<FunctionRecord> funcList = findFunctionsByFullHash(hash);
		modifyFlags(funcList, FunctionRecord.FORCE_RELATION_FLAG, value);
	}

	/**Change the value of the auto-pass property on the given FunctionRecord
	 * @param funcRec is the record to change
	 * @param value is the new value to set
	 * @return a new FunctionRecord reflecting the change
	 * @throws IOException
	 */
	public FunctionRecord setAutoPassOnFunction(FunctionRecord funcRec, boolean value)
			throws IOException {

		checkUpdateAllowed();

		return modifyFunctionFlag(funcRec, FunctionRecord.AUTO_PASS_FLAG, value);
	}

	/**Change the value of the auto-fail property on the given FunctionRecord
	 * @param funcRec is the record to change
	 * @param value is the new value to set
	 * @return a new FunctionRecord reflecting the change
	 * @throws IOException
	 */
	public FunctionRecord setAutoFailOnFunction(FunctionRecord funcRec, boolean value)
			throws IOException {

		checkUpdateAllowed();

		return modifyFunctionFlag(funcRec, FunctionRecord.AUTO_FAIL_FLAG, value);
	}

	/**Change the value of the force-specific property on the given FunctionRecord
	 * @param funcRec is the record to change
	 * @param value is the new value to set
	 * @return a new FunctionRecord reflecting the change
	 * @throws IOException
	 */
	public FunctionRecord setForceSpecificOnFunction(FunctionRecord funcRec, boolean value)
			throws IOException {

		checkUpdateAllowed();

		return modifyFunctionFlag(funcRec, FunctionRecord.FORCE_SPECIFIC_FLAG, value);
	}

	/**Change the value of the force-relation property on the given FunctionRecord
	 * @param funcRec is the record to change
	 * @param value is the new value to set
	 * @return a new FunctionRecord reflecting the change
	 * @throws IOException
	 */
	public FunctionRecord setForceRelationOnFunction(FunctionRecord funcRec, boolean value)
			throws IOException {

		checkUpdateAllowed();

		return modifyFunctionFlag(funcRec, FunctionRecord.FORCE_RELATION_FLAG, value);
	}

	/**
	 * Change the auto-pass property for all functions with given name
	 * @param library is the name of the library containing the function
	 * @param version is the (optional may be null) library version
	 * @param variant is the (optional may be null) library variant
	 * @param functionName is the name of the function
	 * @param value is true to set auto-pass, false to clear
	 * @throws IOException
	 */
	public void setAutoPassByName(String library, String version, String variant,
			String functionName, boolean value) throws IOException {

		checkUpdateAllowed();

		List<LibraryRecord> libraryList = findLibrariesByName(library, version, variant);
		for (LibraryRecord libRec : libraryList) {
			List<FunctionRecord> funcList = findFunctionsByLibraryAndName(libRec, functionName);
			modifyFlags(funcList, FunctionRecord.AUTO_PASS_FLAG, value);
		}
	}

	/**
	 * Change the auto-fail property for all functions with given name
	 * @param library is the name of the library containing the function
	 * @param version is the (optional may be null) library version
	 * @param variant is the (optional may be null) library variant
	 * @param functionName is the name of the function
	 * @param value is true to set auto-fail, false to clear
	 * @throws IOException
	 */
	public void setAutoFailByName(String library, String version, String variant,
			String functionName, boolean value) throws IOException {

		checkUpdateAllowed();

		List<LibraryRecord> libraryList = findLibrariesByName(library, version, variant);
		for (LibraryRecord libRec : libraryList) {
			List<FunctionRecord> funcList = findFunctionsByLibraryAndName(libRec, functionName);
			modifyFlags(funcList, FunctionRecord.AUTO_FAIL_FLAG, value);
		}
	}

	/**
	 * Change the force-specific property for all functions with given name
	 * @param library is the name of the library containing the function
	 * @param version is the (optional may be null) library version
	 * @param variant is the (optional may be null) library variant
	 * @param functionName is the name of the function
	 * @param value is true to set force-specific, false to clear
	 * @throws IOException
	 */
	public void setForceSpecificByName(String library, String version, String variant,
			String functionName, boolean value) throws IOException {

		checkUpdateAllowed();

		List<LibraryRecord> libraryList = findLibrariesByName(library, version, variant);
		for (LibraryRecord libRec : libraryList) {
			List<FunctionRecord> funcList = findFunctionsByLibraryAndName(libRec, functionName);
			modifyFlags(funcList, FunctionRecord.FORCE_SPECIFIC_FLAG, value);
		}
	}

	/**
	 * Change the force-relation property for all functions with given name
	 * @param library is the name of the library containing the function
	 * @param version is the (optional may be null) library version
	 * @param variant is the (optional may be null) library variant
	 * @param functionName is the name of the function
	 * @param value is true to set force-relation, false to clear
	 * @throws IOException
	 */
	public void setForceRelationByName(String library, String version, String variant,
			String functionName, boolean value) throws IOException {

		checkUpdateAllowed();

		List<LibraryRecord> libraryList = findLibrariesByName(library, version, variant);
		for (LibraryRecord libRec : libraryList) {
			List<FunctionRecord> funcList = findFunctionsByLibraryAndName(libRec, functionName);
			modifyFlags(funcList, FunctionRecord.FORCE_RELATION_FLAG, value);
		}
	}

	/**
	 * Saves the database.  This MUST be called after one or more transactions, and before
	 * Ghidra exits...otherwise all changes in the database will be lost!
	 * @param comment the save comment
	 * @param monitor a task monitor
	 * @throws IOException if a database error occurs
	 * @throws CancelledException if the user cancels
	 */
	public void saveDatabase(String comment, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (!openForUpdate) {
			return;
		}

		handle.endTransaction(openTransaction, true);
		handle.save(comment, null, monitor);
		openTransaction = handle.startTransaction();
	}

}
