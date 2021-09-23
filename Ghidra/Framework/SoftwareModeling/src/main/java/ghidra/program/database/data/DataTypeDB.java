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
package ghidra.program.database.data;

import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.List;

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotYetImplementedException;

/**
 * Base class for data types that are Database objects.
 *
 *
 */
abstract class DataTypeDB extends DatabaseObject implements DataType {

	protected DBRecord record;
	protected final DataTypeManagerDB dataMgr;
	private volatile Settings defaultSettings;
	private final static SettingsDefinition[] EMPTY_DEFINITIONS = new SettingsDefinition[0];
	protected boolean resolving;
	protected boolean pointerPostResolveRequired;
	protected Lock lock;
	private volatile String name;
	private volatile Category category;

	protected DataTypeDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			DBRecord record) {
		super(cache, record.getKey());
		this.dataMgr = dataMgr;
		this.record = record;
		this.lock = dataMgr.lock;
		refreshName();
	}

	protected void refreshName() {
		name = doGetName();
	}

	/**
	 * Subclasses implement this to either read the name from the database record or compute if it
	 * is a derived name such as a pointer or array. Implementers can assume that the database lock
	 * will be acquired when this method is called.
	 */
	protected abstract String doGetName();

	/**
	 * Subclasses implement this to read the category path from the database record.Implementers can
	 * assume that the database lock will be acquired when this method is called.
	 */
	protected abstract long doGetCategoryID();

	/**
	 * Subclasses implement this to update the category path ID to the database. Implementers can
	 * assume that the database lock will be acquired when this method is called.
	 */
	protected abstract void doSetCategoryPathRecord(long categoryID) throws IOException;

	/**
	 * Subclasses implement this to update the to the database. Implementers can assume that the
	 * database lock will be acquired when this method is called.
	 * 
	 * @param newName new data type name
	 */
	protected abstract void doSetNameRecord(String newName)
			throws IOException, InvalidNameException;

	/**
	 * Subclasses implement this to read the source archive id from the record. Implementers can
	 * assume that the database lock will be acquired when this method is called.
	 */
	protected abstract UniversalID getSourceArchiveID();

	/**
	 * Subclasses implement this to update the source archive id from the record. Implementers can
	 * assume that the database lock will be acquired when this method is called.
	 */
	protected abstract void setSourceArchiveID(UniversalID id);

	@Override
	public final DataOrganization getDataOrganization() {
		return dataMgr.getDataOrganization();
	}

	@Override
	protected boolean refresh() {
		category = null;
		defaultSettings = null;
		refreshName();
		return true;
	}

	@Override
	public boolean isNotYetDefined() {
		return false;
	}

	@Override
	public boolean isZeroLength() {
		return false;
	}

	@Override
	public String getDisplayName() {
		return getName();
	}

	@Override
	public String toString() {
		return getDisplayName();
	}

	@Override
	public final String getName() {
		validate(lock);
		return name;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return null;
	}

	/**
	 * Get the current name without refresh. This is intended to be used for event generation when
	 * an old-name is needed.
	 * 
	 * @return old name
	 */
	protected final String getOldName() {
		return name;
	}

	@Override
	public Settings getDefaultSettings() {
		Settings localDefaultSettings = defaultSettings;
		if (localDefaultSettings != null && !isInvalid()) {
			return localDefaultSettings;
		}
		lock.acquire();
		try {
			checkIsValid();
			if (defaultSettings == null) {
				defaultSettings = new SettingsDBManager(dataMgr, this, key);
			}
			return defaultSettings;
		}
		finally {
			lock.release();
		}

	}

	@Override
	public URL getDocs() {
		return null;
	}

	/**
	 * Set the data in the form of the appropriate Object for this DataType.
	 *
	 * @param buf the data buffer.
	 * @param settings the display settings for the current value.
	 * @param length the number of bytes to set the value from.
	 * @param value the new value to set object
	 */

	public void setValue(MemBuffer buf, Settings settings, int length, Object value) {
		throw new NotYetImplementedException("setValue() not implemented");
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return EMPTY_DEFINITIONS;
	}

	@Override
	public boolean isDeleted() {
		return isDeleted(lock);
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// do nothing
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		// do nothing
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dataMgr;
	}

	@Override
	public void setDefaultSettings(Settings settings) {
		checkIsValid();
		defaultSettings = settings;
	}

	@Override
	public int getAlignment() {
		int length = getLength();
		if (length < 0) {
			return 1;
		}
		DataOrganization dataOrganization = dataMgr.getDataOrganization();
		return dataOrganization.getAlignment(this);
	}

	@Override
	public String getPathName() {
		return getDataTypePath().getPath();
	}

	protected void checkValidName(String newName) throws InvalidNameException {
		if (!DataUtilities.isValidDataTypeName(newName)) {
			throw new InvalidNameException();
		}
	}

	protected DataType resolve(DataType dt) {
		// complex types should keep equivalence checks to a minimum while resolving
		// and when post-resolve required for pointers
		resolving = true;
		try {
			dt = dataMgr.resolve(dt, dataMgr.getDependencyConflictHandler());
		}
		finally {
			resolving = false;
		}
		return dt;
	}

	protected void postPointerResolve(DataType definitionDt, DataTypeConflictHandler handler) {
		throw new UnsupportedOperationException("post-resolve of pointers not implemented");
	}

	@Override
	public CategoryPath getCategoryPath() {
		Category cat = category;
		if (cat != null && !isInvalid()) {
			return cat.getCategoryPath();
		}
		lock.acquire();
		try {
			checkIsValid();
			if (category == null) {
				category = dataMgr.getCategory(doGetCategoryID());
			}
			if (category == null) {
				category = dataMgr.getRootCategory();
			}
			return category.getCategoryPath();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypePath getDataTypePath() {
		return new DataTypePath(getCategoryPath(), getName());
	}

	@Override
	public void setName(String name) throws InvalidNameException, DuplicateNameException {
		lock.acquire();
		try {
			checkDeleted();
			CategoryPath categoryPath = getCategoryPath();
			if (dataMgr.getDataType(categoryPath, name) != null) {
				throw new DuplicateNameException("DataType named " + name +
					" already exists in category " + categoryPath.getPath());
			}
			doSetName(name);
		}
		finally {
			lock.release();
		}
	}

	private final void doSetName(String newName) throws InvalidNameException {
		String oldName = getName();
		if (newName.equals(oldName)) {
			return;
		}
		checkValidName(newName);
		try {
			doSetNameRecord(newName);
			this.name = newName;
			notifyNameChanged(oldName);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}

	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		lock.acquire();
		try {
			checkDeleted();
			DataType type = dataMgr.getDataType(path, getName());
			if (type != null) {
				throw new DuplicateNameException("DataType named " + getDisplayName() +
					" already exists in category " + path.getPath());
			}
			doSetCategoryPath(path);
		}
		finally {
			lock.release();
		}
	}

	private void doSetCategoryPath(CategoryPath path) {
		CategoryPath myPath = getCategoryPath();
		if (path.equals(myPath)) {
			return;
		}

		long oldCatId = doGetCategoryID();
		Category cat = dataMgr.createCategory(path);
		try {
			doSetCategoryPathRecord(cat.getID());
			category = cat;
			dataMgr.dataTypeCategoryPathChanged(this, myPath, oldCatId);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		lock.acquire();
		try {
			checkDeleted();
			if (dataMgr.getDataType(path, name) != null) {
				throw new DuplicateNameException(
					"DataType named " + name + " already exists in category " + path.getPath());
			}

			// generate a name that would not cause a duplicate in either the current path
			// or
			// the new path. Use the new name if possible.
			String uniqueName = dataMgr.getUniqueName(path, getCategoryPath(), name);
			doSetName(uniqueName);

			// set the path - this is guaranteed to work since we make a name that won't
			// conflict
			doSetCategoryPath(path);

			// now, if necessary, rename it to the desired name - guaranteed to work since
			// we checked before we started changing things.
			if (!uniqueName.equals(name)) {
				doSetName(name);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Updates the path for this datatype
	 * 
	 * @param dt the dataType whose path has changed.
	 */
	protected void updatePath(DataTypeDB dt) {
		// no-op
	}

	@Override
	public void addParent(DataType dt) {
		if (dt instanceof DataTypeDB && dt.getDataTypeManager() == dataMgr) {
			dataMgr.addParentChildRecord(((DataTypeDB) dt).key, key);
		}
	}

	@Override
	public void removeParent(DataType dt) {
		if (dt instanceof DataTypeDB && dt.getDataTypeManager() == dataMgr) {
			dataMgr.removeParentChildRecord(((DataTypeDB) dt).key, key);
		}
	}

	/**
	 * Notify all parents that the size of this datatype has changed or other significant change
	 * that may affect a parent containing this datatype.
	 * 
	 * @param isAutoChange true if changes are in response to another datatype's change.
	 */
	protected void notifySizeChanged(boolean isAutoChange) {
		for (DataType dt : dataMgr.getParentDataTypes(key)) {
			dt.dataTypeSizeChanged(this);
		}
		dataMgr.dataTypeChanged(this, isAutoChange);
	}

	/**
	 * Notification that this composite data type's alignment has changed.
	 * 
	 * @param isAutoChange true if changes are in response to another datatype's change.
	 */
	protected void notifyAlignmentChanged(boolean isAutoChange) {
		for (DataType dt : dataMgr.getParentDataTypes(key)) {
			dt.dataTypeAlignmentChanged(this);
		}
		dataMgr.dataTypeChanged(this, isAutoChange);
	}

	protected void notifyNameChanged(String oldName) {
		for (DataType dt : dataMgr.getParentDataTypes(key)) {
			dt.dataTypeNameChanged(this, oldName);
		}
		dataMgr.dataTypeNameChanged(this, oldName);
	}

	protected void notifyDeleted() {
		for (DataType dt : dataMgr.getParentDataTypes(key)) {
			dt.dataTypeDeleted(this);
		}
	}

	@Override
	public DataType[] getParents() {
		List<DataType> parents = dataMgr.getParentDataTypes(key);
		DataType[] array = new DataType[parents.size()];
		return parents.toArray(array);
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return null;
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		return getDefaultLabelPrefix();
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return getDefaultLabelPrefix();
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		// By default we will do nothing different for offcut values
		return getDefaultLabelPrefix(buf, settings, len, options);
	}

	@Override
	public void setSourceArchive(SourceArchive archive) {
		archive = getDataTypeManager().resolveSourceArchive(archive);
		UniversalID id = archive == null ? DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID
				: archive.getSourceArchiveID();
		if (id.equals(getDataTypeManager().getUniversalID())) {
			id = DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
		}

		setSourceArchiveID(id);
	}

	@Override
	public SourceArchive getSourceArchive() {
		if (dataMgr == null) {
			return null;
		}
		return dataMgr.getSourceArchive(getSourceArchiveID());
	}

	@Override
	public void replaceWith(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Sets a String briefly describing this DataType. <br>
	 * If a data type that extends this class wants to allow the description to be changed, then it
	 * must override this method.
	 * 
	 * @param description a one-liner describing this DataType.
	 */
	@Override
	public void setDescription(String description) {
		// no-op
	}

	/**
	 * setUniversalID is a package level method that allows you to change a data type's universal
	 * ID. This is only intended to be used when transforming a newly parsed data type archive so
	 * that it can be used as a replacement of the archive from a previous software release.
	 * 
	 * @param oldUniversalID the old universal ID value that the user is already referencing with
	 *            their data types. This is the universal ID that we want the new data type to be
	 *            known by.
	 */
	abstract void setUniversalID(UniversalID oldUniversalID);

	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	@Override
	public final boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DataType)) {
			return false;
		}
		DataType otherDt = (DataType) obj;
		return otherDt.getDataTypeManager() == getDataTypeManager() &&
			getCategoryPath().equals(otherDt.getCategoryPath()) &&
			getName().equals(otherDt.getName()) && isEquivalent(otherDt);
	}

	@Override
	public boolean isEncodable() {
		return false;
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		throw new DataTypeEncodeException("Encoding not supported", value, this);
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		throw new DataTypeEncodeException("Encoding not supported", repr, this);
	}
}
