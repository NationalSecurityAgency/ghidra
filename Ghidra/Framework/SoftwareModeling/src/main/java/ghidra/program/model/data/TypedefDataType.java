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

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;

/**
 * 
 * Basic implementation for the typedef dataType
 */
public class TypedefDataType extends GenericDataType implements TypeDef {

	private DataType dataType;
	private boolean deleted = false;

	/**
	 * Construct a new typedef within the root category
	 * @param name name of this typedef
	 * @param dt data type that is being typedef'ed (may not be null)
	 */
	public TypedefDataType(String name, DataType dt) {
		this(CategoryPath.ROOT, name, dt, null);
	}

	/**
	 * Construct a new typedef.
	 * @param path category path for this datatype
	 * @param name name of this typedef
	 * @param dt data type that is being typedef'ed (may not be null)
	 */
	public TypedefDataType(CategoryPath path, String name, DataType dt) {
		this(path, name, dt, null);
	}

	/**
	 * Construct a new typedef.
	 * @param path category path for this datatype
	 * @param name name of this typedef
	 * @param dt data type that is being typedef'ed (may not be null)
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 */
	public TypedefDataType(CategoryPath path, String name, DataType dt, DataTypeManager dtm) {
		super(path, name, dtm);
		validate(dt);
		this.dataType = dt.clone(dtm);
		dt.addParent(this);
	}

	/**
	 * Construct a new typedef.
	 * @param path category path for this datatype
	 * @param name name of this typedef
	 * @param dt data type that is being typedef'ed (may not be null)
	 * @param universalID the id for the data type
	 * @param sourceArchive the source archive for this data type
	 * @param lastChangeTime the last time this data type was changed
	 * @param lastChangeTimeInSourceArchive the last time this data type was changed in
	 * its source archive.
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 */
	public TypedefDataType(CategoryPath path, String name, DataType dt, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		validate(dt);
		this.dataType = dt.clone(dtm);
		dt.addParent(this);
	}

	private void validate(DataType dt) {
		if (dt instanceof BitFieldDataType) {
			throw new IllegalArgumentException(
				"TypeDef data-type may not be a bitfield: " + dt.getName());
		}
		if (dt instanceof FactoryDataType) {
			throw new IllegalArgumentException(
				"TypeDef data-type may not be a Factory data-type: " + dt.getName());
		}
		if (dt instanceof Dynamic) {
			throw new IllegalArgumentException(
				"TypeDef data-type may not be a Dynamic data-type: " + dt.getName());
		}
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return dataType.hasLanguageDependantLength();
	}

	@Override
	public boolean isEquivalent(DataType obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj instanceof TypeDef) {
			TypeDef td = (TypeDef) obj;
			if (!DataTypeUtilities.equalsIgnoreConflict(name, td.getName())) {
				return false;
			}
			return DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), td.getDataType());
		}
		return false;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public String getDescription() {
		return dataType.getDescription();
	}

	@Override
	public boolean isZeroLength() {
		return dataType.isZeroLength();
	}

	@Override
	public int getLength() {
		return dataType.getLength();
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return dataType.getRepresentation(buf, settings, length);
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return dataType.getValue(buf, settings, length);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return dataType.getValueClass(settings);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (getDataTypeManager() == dtm) {
			return this;
		}
		return new TypedefDataType(categoryPath, name, dataType, getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return new TypedefDataType(categoryPath, name, dataType, dtm);
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (dt == dataType) {
			notifySizeChanged();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (dt == dataType) {
			notifyAlignmentChanged();
		}
	}

	@Override
	public DataType getBaseDataType() {
		if (dataType instanceof TypeDef) {
			return ((TypeDef) dataType).getBaseDataType();
		}
		return dataType;
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (dataType == dt) {
			notifyDeleted();
			deleted = true;
		}
	}

	@Override
	public boolean isDeleted() {
		return deleted;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return dataType.getSettingsDefinitions();
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		validate(newDt);
		if (oldDt == dataType) {
			dataType = newDt;
			oldDt.removeParent(this);
			newDt.addParent(this);
			if (oldDt.getLength() != newDt.getLength()) {
				notifySizeChanged();
			}
			else if (oldDt.getAlignment() != newDt.getAlignment()) {
				notifyAlignmentChanged();
			}
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// ignored
	}

	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt == dt || myDt.dependsOn(dt));
	}

	@Override
	public String toString() {
		return "typedef " + getName() + " " + dataType.getName();
	}

}
