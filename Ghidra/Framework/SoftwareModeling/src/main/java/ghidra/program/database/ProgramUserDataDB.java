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
package ghidra.program.database;

import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.LockException;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.database.properties.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.Saveable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <code>ProgramUserDataDB</code> stores user data associated with a specific program.
 * A ContentHandler should not be created for this class since it must never be stored
 * within a DomainFolder.
 */
class ProgramUserDataDB extends DomainObjectAdapterDB implements ProgramUserData {

// TODO: WARNING! This implementation does not properly handle undo/redo in terms of cache invalidation

	/**
	 * DB_VERSION should be incremented any time a change is made to the overall
	 * database schema associated with any of the managers.
	 * 
	 * NOTE: 19-Jun-2020 Corrections to DB index tables should have no impact on user data 
	 *                   PropertyMaps which are not indexed.                   
	 */
	static final int DB_VERSION = 1;

	/**
	 * UPGRADE_REQUIRED_BFORE_VERSION should be changed to DB_VERSION any time the
	 * latest version requires a forced upgrade (i.e., Read-only mode not supported
	 * until upgrade is performed).  It is assumed that read-only mode is supported
	 * if the data's version is &gt;= UPGRADE_REQUIRED_BEFORE_VERSION and &lt;= DB_VERSION.
	 */
	private static final int UPGRADE_REQUIRED_BEFORE_VERSION = 1;

	private static final String TABLE_NAME = "ProgramUserData";
	private final static Field[] COL_FIELDS = new Field[] { StringField.INSTANCE };
	private final static String[] COL_NAMES = new String[] { "Value" };
	private final static Schema SCHEMA =
		new Schema(0, StringField.INSTANCE, "Key", COL_FIELDS, COL_NAMES);
	private static final int VALUE_COL = 0;

	private static final String STORED_DB_VERSION = "DB Version";
	private static final String LANGUAGE_VERSION = "Language Version";
	private static final String LANGUAGE_ID = "Language ID";

	private static final String REGISTRY_TABLE_NAME = "PropertyRegistry";
	private final static Field[] REGISTRY_COL_FIELDS = new Field[] { StringField.INSTANCE,
		StringField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE };
	private final static String[] REGISTRY_COL_NAMES =
		new String[] { "Owner", "PropertyName", "PropertyType", "SaveableClass" };
	private final static Schema REGISTRY_SCHEMA =
		new Schema(0, "ID", REGISTRY_COL_FIELDS, REGISTRY_COL_NAMES);
	private static final int PROPERTY_OWNER_COL = 0;
	private static final int PROPERTY_NAME_COL = 1;
	private static final int PROPERTY_TYPE_COL = 2;
	private static final int PROPERTY_CLASS_COL = 3;

	private static final int PROPERTY_TYPE_STRING = 0;
	private static final int PROPERTY_TYPE_LONG = 1;
	private static final int PROPERTY_TYPE_INT = 2;
	private static final int PROPERTY_TYPE_BOOLEAN = 3;
	private static final int PROPERTY_TYPE_SAVEABLE = 4;

	private static final String[] PROPERTY_TYPES =
		new String[] { "String", "Long", "Int", "Boolean", "Object" };

	private ProgramDB program;
	private Table table;
	private Table registryTable;
	private AddressMapDB addressMap;
	private LanguageID languageID;
	private int languageVersion;
	private Language language;
	private LanguageTranslator languageUpgradeTranslator;
	private AddressFactory addressFactory;
	private HashMap<Long, PropertyMap> propertyMaps = new HashMap<Long, PropertyMap>();
	private HashSet<String> propertyMapOwners = null;

	private final ChangeManager changeMgr = new ChangeManagerAdapter() {
		@Override
		public void setPropertyChanged(String propertyName, Address codeUnitAddr, Object oldValue,
				Object newValue) {
			changed = true;
			program.userDataChanged(propertyName, codeUnitAddr, oldValue, newValue);
		}
	};

	private static String getName(ProgramDB program) {
		return program.getName() + "_UserData";
	}

	public ProgramUserDataDB(ProgramDB program) throws IOException {
		super(new DBHandle(), getName(program), 500, 1000, program);
		this.program = program;
		this.language = program.getLanguage();
		languageID = language.getLanguageID();
		languageVersion = language.getVersion();

		addressFactory = language.getAddressFactory();

		setEventsEnabled(false); // events not support

		boolean success = false;
		try {
			int id = startTransaction("create user data");

			createDatabase();
			if (createManagers(CREATE, program, TaskMonitorAdapter.DUMMY_MONITOR) != null) {
				throw new AssertException("Unexpected version exception on create");
			}
			//initManagers(CREATE, TaskMonitorAdapter.DUMMY_MONITOR);

			endTransaction(id, true);
			changed = false;
			clearUndo(false);
			success = true;
		}
		catch (CancelledException e) {
			throw new AssertException();
		}
		finally {
			dbh.closeScratchPad();
			if (!success) {
				release(program);
				dbh.close();
			}
		}
	}

	public ProgramUserDataDB(DBHandle dbh, ProgramDB program, TaskMonitor monitor)
			throws IOException, VersionException, LanguageNotFoundException, CancelledException {

		super(dbh, getName(program), 500, 1000, program);
		this.program = program;
		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		setEventsEnabled(false); // events not support

		boolean success = false;
		try {
			int id = startTransaction("create user data");

			// check DB version and read name, languageName, languageVersion and languageMinorVersion
			VersionException dbVersionExc = initializeDatabase();

			VersionException languageVersionExc = null;
			try {
				language = DefaultLanguageService.getLanguageService().getLanguage(languageID);
				languageVersionExc = checkLanguageVersion();
			}
			catch (LanguageNotFoundException e) {
				languageVersionExc = checkForLanguageChange(e);
			}

			addressFactory = language.getAddressFactory();

			VersionException versionExc = createManagers(UPGRADE, program, monitor);
			if (dbVersionExc != null) {
				versionExc = dbVersionExc.combine(versionExc);
			}

			if (versionExc != null) {
				throw versionExc;
			}

			//initManagers(UPGRADE, monitor);

			upgradeDatabase();

			if (languageVersionExc != null) {
				try {
					setLanguage(languageUpgradeTranslator, monitor);
					addressMap.memoryMapChanged((MemoryMapDB) program.getMemory());
				}
				catch (IllegalStateException e) {
					if (e.getCause() instanceof CancelledException) {
						throw (CancelledException) e.getCause();
					}
					throw e;
				}
				catch (LockException e) {
					throw new AssertException("Upgrade mode requires exclusive access", e);
				}
			}

			endTransaction(id, true);
			changed = false;
			clearUndo(false);
			success = true;
		}
		finally {
			dbh.closeScratchPad();
			if (!success) {
				release(program);
			}
		}
	}

	/**
	 * Language corresponding to languageId was found.  Check language version
	 * for language upgrade situation.
	 * @throws LanguageNotFoundException
	 * @return VersionException if language upgrade required
	 */
	private VersionException checkLanguageVersion() throws LanguageNotFoundException {

		if (language.getVersion() > languageVersion) {

			Language newLanguage = language;

			Language oldLanguage = OldLanguageFactory.getOldLanguageFactory().getOldLanguage(
				languageID, languageVersion);
			if (oldLanguage == null) {
				// Assume minor version behavior - old language does not exist for current major version
				Msg.error(this, "Old language specification not found: " + languageID +
					" (Version " + languageVersion + ")");
				return new VersionException(true);
			}

			// Ensure that we can upgrade the language
			languageUpgradeTranslator =
				LanguageTranslatorFactory.getLanguageTranslatorFactory().getLanguageTranslator(
					oldLanguage, newLanguage);
			if (languageUpgradeTranslator == null) {
				throw new LanguageNotFoundException(language.getLanguageID(),
					"(Ver " + languageVersion + ".x" + " -> " + newLanguage.getVersion() + "." +
						newLanguage.getMinorVersion() +
						") language version translation not supported");
			}
			language = oldLanguage;
			return new VersionException(true);
		}
		else if (language.getVersion() != languageVersion) {
			throw new LanguageNotFoundException(language.getLanguageID(), languageVersion, 0);
		}
		return null;
	}

	/**
	 * Language specified by languageName was not found.  Check for
	 * valid language translation/migration.  Old langauge version specified by
	 * languageVersion.
	 * @param openMode one of:
	 * 		READ_ONLY: the original database will not be modified
	 * 		UPDATE: the database can be written to.
	 * 		UPGRADE: the database is upgraded to the lastest schema as it is opened.
	 * @return true if language upgrade required
	 * @throws LanguageNotFoundException if a suitable replacement language not found
	 */
	private VersionException checkForLanguageChange(LanguageNotFoundException e)
			throws LanguageNotFoundException {

		languageUpgradeTranslator =
			LanguageTranslatorFactory.getLanguageTranslatorFactory().getLanguageTranslator(
				languageID, languageVersion);
		if (languageUpgradeTranslator == null) {
			throw e;
		}

		language = languageUpgradeTranslator.getOldLanguage();
		languageID = language.getLanguageID();

		VersionException ve = new VersionException(true);
		LanguageID oldLangName = languageUpgradeTranslator.getOldLanguage().getLanguageID();
		LanguageID newLangName = languageUpgradeTranslator.getNewLanguage().getLanguageID();
		String message;
		if (oldLangName.equals(newLangName)) {
			message = "Program User Data requires a processor language version change";
		}
		else {
			message = "Program User Data requires a processor language change to:\n" + newLangName;
		}
		ve.setDetailMessage(message);
		return ve;
	}

	@Override
	public String getDescription() {
		return "Program User Data";
	}

	@Override
	public boolean isChangeable() {
		return true;
	}

	private void createDatabase() throws IOException {

		table = dbh.createTable(TABLE_NAME, SCHEMA);
		registryTable =
			dbh.createTable(REGISTRY_TABLE_NAME, REGISTRY_SCHEMA, new int[] { PROPERTY_OWNER_COL });

		DBRecord record = SCHEMA.createRecord(new StringField(LANGUAGE_ID));
		record.setString(VALUE_COL, languageID.getIdAsString());
		table.putRecord(record);

		record = SCHEMA.createRecord(new StringField(LANGUAGE_VERSION));
		record.setString(VALUE_COL, Integer.toString(languageVersion));
		table.putRecord(record);

		record = SCHEMA.createRecord(new StringField(STORED_DB_VERSION));
		record.setString(VALUE_COL, Integer.toString(DB_VERSION));
		table.putRecord(record);
	}

	private VersionException initializeDatabase()
			throws IOException, VersionException, LanguageNotFoundException {
		boolean requiresUpgrade = false;

		table = dbh.getTable(TABLE_NAME);
		registryTable = dbh.getTable(REGISTRY_TABLE_NAME);
		if (table == null || registryTable == null) {
			throw new IOException("Unsupported User Data File Content");
		}

		DBRecord record = table.getRecord(new StringField(LANGUAGE_ID));
		languageID = new LanguageID(record.getString(VALUE_COL));

		record = table.getRecord(new StringField(LANGUAGE_VERSION));
		languageVersion = 1;
		try {
			languageVersion = Integer.parseInt(record.getString(VALUE_COL));
		}
		catch (Exception e) {
			// Ignore
		}

		int storedVersion = 1;
		record = table.getRecord(new StringField(STORED_DB_VERSION));
		try {
			storedVersion = Integer.parseInt(record.getString(VALUE_COL));
		}
		catch (NumberFormatException e) {
		}
		if (storedVersion > DB_VERSION) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
		if (storedVersion < UPGRADE_REQUIRED_BEFORE_VERSION) {
			requiresUpgrade = true;
		}
		return requiresUpgrade ? new VersionException(true) : null;
	}

	private void upgradeDatabase() throws IOException {
		table = dbh.getTable(TABLE_NAME);
		DBRecord record = SCHEMA.createRecord(new StringField(STORED_DB_VERSION));
		record.setString(VALUE_COL, Integer.toString(DB_VERSION));
		table.putRecord(record);
	}

	private VersionException createManagers(int openMode, ProgramDB program1, TaskMonitor monitor)
			throws CancelledException, IOException {

		VersionException versionExc = null;

		monitor.checkCanceled();

		// the memoryManager should always be created first because it is needed to resolve
		// segmented addresses from longs that other manages may need while upgrading.
		long baseImageOffset = program1.getImageBase().getOffset();
		try {
			addressMap = new AddressMapDB(dbh, openMode, addressFactory, baseImageOffset, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
			try {
				addressMap =
					new AddressMapDB(dbh, READ_ONLY, addressFactory, baseImageOffset, monitor);
			}
			catch (VersionException e1) {
				if (e1.isUpgradable()) {
					Msg.error(this,
						"AddressMapDB is upgradeable but failed to support READ-ONLY mode!");
				}
				// Unable to proceed without addrMap !
				return versionExc;
			}
		}
		addressMap.memoryMapChanged((MemoryMapDB) program1.getMemory());
		monitor.checkCanceled();

		return versionExc;
	}

	/**
	 * Translate language
	 * @param translator language translator, if null only re-disassembly will occur.
	 * @param monitor
	 * @throws LockException
	 */
	private void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws LockException {
		lock.acquire();
		try {
			//setEventsEnabled(false);
			try {

				language = translator.getNewLanguage();
				languageID = language.getLanguageID();
				languageVersion = language.getVersion();

				addressFactory = language.getAddressFactory();
				addressMap.setLanguage(language, addressFactory, translator);

				clearCache(true);

				DBRecord record = SCHEMA.createRecord(new StringField(LANGUAGE_ID));
				record.setString(VALUE_COL, languageID.getIdAsString());
				table.putRecord(record);

				setChanged(true);
				clearCache(true);

				//invalidate();

			}
			catch (Throwable t) {
				throw new IllegalStateException(
					"Set language aborted - program user data is now in an unusable state!", t);
			}
//			finally {
//				setEventsEnabled(true);
//			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public synchronized boolean canSave() {
		return dbh.canUpdate();
	}

	private PropertyMap getPropertyMap(String owner, String propertyName, int propertyType,
			Class<?> saveableClass, boolean create) throws PropertyTypeMismatchException {

		try {
			for (Field key : registryTable.findRecords(new StringField(owner),
				PROPERTY_OWNER_COL)) {
				DBRecord rec = registryTable.getRecord(key);
				if (propertyName.equals(rec.getString(PROPERTY_NAME_COL))) {
					int type = rec.getIntValue(PROPERTY_TYPE_COL);
					if (propertyType != type) {
						throw new PropertyTypeMismatchException(
							"'" + propertyName + "' is type " + PROPERTY_TYPES[type]);
					}
					if (propertyType == PROPERTY_TYPE_SAVEABLE) {
						String className = rec.getString(PROPERTY_CLASS_COL);
						if (!className.equals(saveableClass.getName())) {
							throw new PropertyTypeMismatchException(
								"'" + propertyName + "' is class " + className);
						}
					}
					return getPropertyMap(rec);
				}
			}

			if (!create) {
				return null;
			}

			long key = registryTable.getKey();
			DBRecord rec = REGISTRY_SCHEMA.createRecord(key);
			rec.setString(PROPERTY_OWNER_COL, owner);
			rec.setString(PROPERTY_NAME_COL, propertyName);
			rec.setIntValue(PROPERTY_TYPE_COL, propertyType);
			if (saveableClass != null) {
				rec.setString(PROPERTY_CLASS_COL, saveableClass.getName());
			}
			PropertyMap map = null;
			boolean success = false;
			try {
				map = getPropertyMap(rec);
				registryTable.putRecord(rec);
				if (propertyMapOwners != null) {
					propertyMapOwners.add(owner);
				}
				success = true;
			}
			finally {
				if (!success && map != null) {
					propertyMaps.remove(key);
				}
			}
			return map;

		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	private PropertyMap getPropertyMap(DBRecord rec) throws IOException {
		try {
			PropertyMap map;
			int type = rec.getIntValue(PROPERTY_TYPE_COL);
			switch (type) {
				case PROPERTY_TYPE_STRING:
					map = new StringPropertyMapDB(dbh, DBConstants.UPGRADE, this, changeMgr,
						addressMap, rec.getString(PROPERTY_NAME_COL),
						TaskMonitorAdapter.DUMMY_MONITOR);
					break;
				case PROPERTY_TYPE_LONG:
					map =
						new LongPropertyMapDB(dbh, DBConstants.UPGRADE, this, changeMgr, addressMap,
							rec.getString(PROPERTY_NAME_COL), TaskMonitorAdapter.DUMMY_MONITOR);
					break;
				case PROPERTY_TYPE_INT:
					map =
						new IntPropertyMapDB(dbh, DBConstants.UPGRADE, this, changeMgr, addressMap,
							rec.getString(PROPERTY_NAME_COL), TaskMonitorAdapter.DUMMY_MONITOR);
					break;
				case PROPERTY_TYPE_BOOLEAN:
					map =
						new VoidPropertyMapDB(dbh, DBConstants.UPGRADE, this, changeMgr, addressMap,
							rec.getString(PROPERTY_NAME_COL), TaskMonitorAdapter.DUMMY_MONITOR);
					break;
				case PROPERTY_TYPE_SAVEABLE:
					String className = rec.getString(PROPERTY_CLASS_COL);
					Class<? extends Saveable> c =
						ObjectPropertyMapDB.getSaveableClassForName(className);
					return new ObjectPropertyMapDB(dbh, DBConstants.UPGRADE, this, changeMgr,
						addressMap, rec.getString(PROPERTY_NAME_COL), c,
						TaskMonitorAdapter.DUMMY_MONITOR, true);
				default:
					throw new IllegalArgumentException("Unsupported property type: " + type);
			}
			propertyMaps.put(rec.getKey(), map);
			return map;
		}
		catch (CancelledException e) {
			throw new AssertException("Unexpected Error", e);
		}
		catch (VersionException e) {
			throw new IOException("Incompatable property data for '" +
				rec.getString(PROPERTY_NAME_COL) + "': " + e.getMessage());
		}
	}

	@Override
	public synchronized List<PropertyMap> getProperties(String owner) {
		List<PropertyMap> list = new ArrayList<PropertyMap>();
		try {
			for (Field key : registryTable.findRecords(new StringField(owner),
				PROPERTY_OWNER_COL)) {
				DBRecord rec = registryTable.getRecord(key);
				list.add(getPropertyMap(rec));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return list;
	}

	@Override
	public synchronized List<String> getPropertyOwners() {
		if (propertyMapOwners == null) {
			try {
				propertyMapOwners = new HashSet<String>();
				RecordIterator recIter = registryTable.iterator();
				while (recIter.hasNext()) {
					DBRecord rec = recIter.next();
					propertyMapOwners.add(rec.getString(PROPERTY_OWNER_COL));
				}
			}
			catch (IOException e) {
				propertyMapOwners = null;
				dbError(e);
			}
		}
		return new ArrayList<String>(propertyMapOwners);
	}

	@Override
	public synchronized StringPropertyMap getStringProperty(String owner, String propertyName,
			boolean create) throws PropertyTypeMismatchException {
		return (StringPropertyMap) getPropertyMap(owner, propertyName, PROPERTY_TYPE_STRING, null,
			create);
	}

	@Override
	public synchronized LongPropertyMap getLongProperty(String owner, String propertyName,
			boolean create) throws PropertyTypeMismatchException {
		return (LongPropertyMap) getPropertyMap(owner, propertyName, PROPERTY_TYPE_LONG, null,
			create);
	}

	@Override
	public synchronized IntPropertyMap getIntProperty(String owner, String propertyName,
			boolean create) throws PropertyTypeMismatchException {
		return (IntPropertyMap) getPropertyMap(owner, propertyName, PROPERTY_TYPE_INT, null,
			create);
	}

	@Override
	public synchronized VoidPropertyMap getBooleanProperty(String owner, String propertyName,
			boolean create) throws PropertyTypeMismatchException {
		return (VoidPropertyMap) getPropertyMap(owner, propertyName, PROPERTY_TYPE_BOOLEAN, null,
			create);
	}

	@Override
	public synchronized ObjectPropertyMap getObjectProperty(String owner, String propertyName,
			Class<? extends Saveable> saveableObjectClass, boolean create)
			throws PropertyTypeMismatchException {
		return (ObjectPropertyMap) getPropertyMap(owner, propertyName, PROPERTY_TYPE_SAVEABLE,
			saveableObjectClass, create);
	}

	@Override
	protected boolean propertyChanged(String propertyName, Object oldValue, Object newValue) {
		changed = true;
		program.userDataChanged(propertyName, oldValue, newValue);
		return true;
	}

	@Override
	public int startTransaction() {
		return startTransaction("Property Change");
	}

	@Override
	public void endTransaction(int transactionID) {
		super.endTransaction(transactionID, true);
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {

		synchronized (this) {
			if (dbh.canUpdate()) {
				if (changed) {
					dbh.save(comment, null, monitor);
					setChanged(false);
				}
			}
			else {
				FileSystem userfs = program.getAssociatedUserFilesystem();
				if (userfs != null) {
					ContentHandler contentHandler = getContentHandler(program);
					if (contentHandler != null) {
						contentHandler.saveUserDataFile(program, dbh, userfs, monitor);
					}
					setChanged(false);
				}
			}
		}

		// fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_SAVED));
	}

}
