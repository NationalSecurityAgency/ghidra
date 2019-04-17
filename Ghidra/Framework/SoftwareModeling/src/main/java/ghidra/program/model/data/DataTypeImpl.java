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
package ghidra.program.model.data;

import java.io.Serializable;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.docking.settings.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.*;

/**
 * Base implementation for dataTypes.
 */
public abstract class DataTypeImpl implements DataType, ChangeListener, Serializable {
	private final static SettingsDefinition[] EMPTY_DEFINITIONS = new SettingsDefinition[0];
	protected Settings defaultSettings;
	protected String name;
	protected CategoryPath categoryPath;
	private ArrayList<DataType> parentList;
	private UniversalID universalID;
	private SourceArchive sourceArchive;
	private long lastChangeTime;
	private long lastChangeTimeInSourceArchive;
	private DataTypeManager dataMgr;

	protected DataTypeImpl(CategoryPath path, String name, DataTypeManager dataMgr) {
		this(path, name, null, null, System.currentTimeMillis(), NO_LAST_CHANGE_TIME, dataMgr);
	}

	DataTypeImpl(CategoryPath path, String name, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dataMgr) {
		if (path == null) {
			throw new IllegalArgumentException("Category Path is null!");
		}
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Name is null or empty!");
		}

		// allow spaces since derived types may have spaces (pointers for example: foo *32)
		if (!DataUtilities.isValidDataTypeName(name)) {
			throw new IllegalArgumentException("Invalid DataType name: " + name);
		}
		this.categoryPath = path;
		this.name = name;
		this.dataMgr = dataMgr;
		defaultSettings = new SettingsImpl(this, null);
		parentList = new ArrayList<>();
		this.universalID = universalID == null ? UniversalIdGenerator.nextID() : universalID;
		this.sourceArchive = sourceArchive;
		this.lastChangeTime = lastChangeTime;
		this.lastChangeTimeInSourceArchive = lastChangeTimeInSourceArchive;
	}

	/**
	 * Returns the DataOrganization associated with this
	 * data-types DataTypeManager
	 */
	protected final DataOrganization getDataOrganization() {
		DataOrganization dataOrganization = null;
		if (dataMgr != null) {
			dataOrganization = dataMgr.getDataOrganization();
		}
		if (dataOrganization == null) {
			dataOrganization = DataOrganizationImpl.getDefaultOrganization();
		}
		return dataOrganization;
	}

	@Override
	public boolean isNotYetDefined() {
		return false;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return null;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDefaultSettings()
	 */
	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getCategoryPath()
	 */
	@Override
	public CategoryPath getCategoryPath() {
		return categoryPath;
	}

	@Override
	public DataTypePath getDataTypePath() {
		return new DataTypePath(categoryPath, name);
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDocs()
	 */
	@Override
	public URL getDocs() {
		return null;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getSettingsDefinitions()
	 */
	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return EMPTY_DEFINITIONS;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getDisplayName()
	 */
	@Override
	public String getDisplayName() {
		return getName();
	}

	@Override
	public String toString() {
		return getDisplayName();
	}

	/**
	 * Check if the name is a valid name for a data type
	 * 
	 * @param checkedName name to check
	 * 
	 * @throws InvalidNameException if the name is invalid
	 */
	void checkValidName(String checkedName) throws InvalidNameException {
		if (!DataUtilities.isValidDataTypeName(checkedName)) {
			throw new InvalidNameException("Invalid Name: " + checkedName);
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#isDeleted()
	 */
	@Override
	public boolean isDeleted() {
		return false;
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		// don't care
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDataTypeManager()
	 */
	@Override
	public DataTypeManager getDataTypeManager() {
		return dataMgr;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#setDefaultSettings(ghidra.docking.settings.Settings)
	 */
	@Override
	public void setDefaultSettings(Settings settings) {
		defaultSettings = settings;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getPathName()
	 */
	@Override
	public String getPathName() {
		return getDataTypePath().getPath();
	}

	@Override
	public int getAlignment() {
		int length = getLength();
		if (length < 0) {
			return 1;
		}
		return getDataOrganization().getAlignment(this, length);
	}

	/**
	 * @see ghidra.program.model.data.DataType#addParent(ghidra.program.model.data.DataType)
	 */
	@Override
	public void addParent(DataType dt) {
		parentList.add(dt);
	}

	/**
	 * @see ghidra.program.model.data.DataType#removeParent(ghidra.program.model.data.DataType)
	 */
	@Override
	public void removeParent(DataType dt) {
		parentList.remove(dt);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getParents()
	 */
	@Override
	public DataType[] getParents() {
		DataType[] dts = new DataType[parentList.size()];
		return parentList.toArray(dts);

	}

	/**
	 * Notify any parent data types that my size has changed.
	 */
	protected void notifySizeChanged() {
		Iterator<DataType> it = parentList.iterator();
		while (it.hasNext()) {
			DataType dt = it.next();
			dt.dataTypeSizeChanged(this);
		}
	}

	/**
	 * Notify any parents that my name has changed.
	 * 
	 * @param oldName
	 */
	protected void notifyNameChanged(String oldName) {
		Iterator<DataType> it = parentList.iterator();
		while (it.hasNext()) {
			DataType dt = it.next();
			dt.dataTypeNameChanged(this, oldName);
		}
	}

	/**
	 * Notify any parents that I am deleted.
	 */
	protected void notifyDeleted() {
		Iterator<DataType> it = parentList.iterator();
		while (it.hasNext()) {
			DataType dt = it.next();
			dt.dataTypeDeleted(this);
		}
	}

	/**
	 * Notify any parents that I have been replaced.
	 * @param replacement replacement data type
	 */
	protected void notifyReplaced(DataType replacement) {
		Iterator<DataType> it = parentList.iterator();
		while (it.hasNext()) {
			DataType dt = it.next();
			dt.dataTypeReplaced(this, replacement);
		}
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
	public long getLastChangeTime() {
		return lastChangeTime;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return lastChangeTimeInSourceArchive;
	}

	@Override
	public SourceArchive getSourceArchive() {
		return sourceArchive;
	}

	@Override
	public void setSourceArchive(SourceArchive archive) {
		this.sourceArchive = archive;
	}

	@Override
	public UniversalID getUniversalID() {
		return universalID;
	}

	@Override
	public void replaceWith(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		this.lastChangeTime = lastChangeTime;
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		this.lastChangeTimeInSourceArchive = lastChangeTimeInSourceArchive;
	}

	/**
	 * Sets a String briefly describing this DataType.
	 * <br>If a data type that extends this class wants to allow the description to be changed,
	 * then it must override this method.
	 * @param description a one-liner describing this DataType.
	 * @throws UnsupportedOperationException if the description is not allowed to be set for this data type.
	 */
	@Override
	public void setDescription(String description) throws UnsupportedOperationException {
		throw new UnsupportedOperationException(
			getClass().getName() + " doesn't allow the description to be changed.");
	}

	@Override
	public int hashCode() {
		// Note: this works because the DTMs have to be equal and there can be only one DT with
		//       the same name and category path		
		return getName().hashCode();
	}

	@Override
	public final boolean equals(Object obj) {
		if (!(obj instanceof DataType)) {
			return false;
		}
		DataType otherDt = (DataType) obj;
		return otherDt.getDataTypeManager() == getDataTypeManager() &&
			categoryPath.equals(otherDt.getCategoryPath()) && name.equals(otherDt.getName()) &&
			isEquivalent(otherDt);
	}

}
