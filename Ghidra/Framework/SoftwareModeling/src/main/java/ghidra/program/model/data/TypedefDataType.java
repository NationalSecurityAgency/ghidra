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

import ghidra.docking.settings.*;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;

/**
 * 
 * Basic implementation for the typedef dataType.
 * 
 * NOTE: Settings are immutable when a DataTypeManager has not been specified (i.e., null).
 */
public class TypedefDataType extends GenericDataType implements TypeDef {

	private DataType dataType;
	private SettingsDefinition[] settingsDef;
	private boolean isAutoNamed = false;
	private boolean deleted = false;

	/**
	 * Construct a new typedef within the root category
	 * @param name name of this typedef
	 * @param dt data type that is being typedef'ed (may not be null)
	 */
	public TypedefDataType(String name, DataType dt) {
		this(CategoryPath.ROOT, name, dt, dt.getDataTypeManager());
	}

	/**
	 * Construct a new typedef.
	 * @param path category path for this datatype
	 * @param name name of this typedef
	 * @param dt data type that is being typedef'ed (may not be null)
	 */
	public TypedefDataType(CategoryPath path, String name, DataType dt) {
		this(path, name, dt, dt.getDataTypeManager());
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
		defaultSettings = null; // use lazy initialization
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
		defaultSettings = null; // use lazy initialization
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
	public void enableAutoNaming() {
		if (isAutoNamed) {
			return;
		}
		isAutoNamed = true;
		notifyNameChanged(name);
	}

	@Override
	public boolean isAutoNamed() {
		return isAutoNamed;
	}

	@Override
	public String getDefaultLabelPrefix() {
		if (isAutoNamed()) {
			return getDataType().getDefaultLabelPrefix();
		}
		return getName();
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		if (isAutoNamed()) {
			return getDataType().getDefaultLabelPrefix(buf, settings, len, options);
		}
		return super.getDefaultLabelPrefix(buf, settings, len, options);
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		if (isAutoNamed()) {
			return getDataType().getDefaultAbbreviatedLabelPrefix();
		}
		return super.getDefaultAbbreviatedLabelPrefix();
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		if (isAutoNamed()) {
			return getDataType().getDefaultOffcutLabelPrefix(buf, settings, len, options,
				offcutLength);
		}
		return super.getDefaultOffcutLabelPrefix(buf, settings, len, options, offcutLength);
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
			if (isAutoNamed != td.isAutoNamed()) {
				return false;
			}
			if (!isAutoNamed && !DataTypeUtilities.equalsIgnoreConflict(getName(), td.getName())) {
				return false;
			}
			if (!hasSameTypeDefSettings(td)) {
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
	public int getAlignedLength() {
		return dataType.getAlignedLength();
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

	public static TypeDef clone(TypeDef typedef, DataTypeManager dtm) {
		if (typedef.getDataTypeManager() == dtm) {
			return typedef;
		}
		TypedefDataType newTypedef =
			new TypedefDataType(typedef.getCategoryPath(), typedef.getName(), typedef.getDataType(),
				typedef.getUniversalID(),
				typedef.getSourceArchive(), typedef.getLastChangeTime(),
				typedef.getLastChangeTimeInSourceArchive(), dtm);
		copyTypeDefSettings(typedef, newTypedef, false);
		newTypedef.isAutoNamed = typedef.isAutoNamed();
		return newTypedef;
	}

	public static TypedefDataType copy(TypeDef typedef, DataTypeManager dtm) {
		TypedefDataType newTypedef = new TypedefDataType(typedef.getCategoryPath(),
			typedef.getName(), typedef.getDataType(), dtm);
		copyTypeDefSettings(typedef, newTypedef, false);
		newTypedef.isAutoNamed = typedef.isAutoNamed();
		return newTypedef;
	}

	@Override
	public TypedefDataType clone(DataTypeManager dtm) {
		return (TypedefDataType) clone(this, dtm);
	}

	@Override
	public TypedefDataType copy(DataTypeManager dtm) {
		return copy(this, dtm);
	}

	@Override
	public String getName() {
		if (isAutoNamed()) {
			return generateTypedefName(this);
		}
		return super.getName();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		super.setName(name);
		isAutoNamed = false;
	}

	@Override
	public void setCategoryPath(CategoryPath path) {
		if (isAutoNamed()) {
			return; // ignore category change if auto-naming enabled
		}
		super.setCategoryPath(path);
	}

	@Override
	public CategoryPath getCategoryPath() {
		if (isAutoNamed()) {
			return getDataType().getCategoryPath();
		}
		return super.getCategoryPath();
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
		if (settingsDef == null) {
			DataType dt = getDataType();
			SettingsDefinition[] settingsDefinitions = dt.getSettingsDefinitions();
			TypeDefSettingsDefinition[] typeDefSettingsDefinitions =
				dt.getTypeDefSettingsDefinitions();
			settingsDef = new SettingsDefinition[settingsDefinitions.length +
				typeDefSettingsDefinitions.length];
			System.arraycopy(settingsDefinitions, 0, settingsDef, 0, settingsDefinitions.length);
			System.arraycopy(typeDefSettingsDefinitions, 0, settingsDef, settingsDefinitions.length,
				typeDefSettingsDefinitions.length);
		}
		return settingsDef;
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		return getDataType().getTypeDefSettingsDefinitions();
	}

	@Override
	public Settings getDefaultSettings() {
		// This class allows for lazy initialization of defaultSettings
		// Only applies if DataTypeManager has been specified
		if (defaultSettings == null) {
			DataType dt = getDataType();
			SettingsImpl settings;
			if (dt.getTypeDefSettingsDefinitions().length == 0) {
				// No viable settings - block changes to default settings
				settings = new SettingsImpl(true);
			}
			else {
				// Limit default settings changes to allowed definitions
				// which support resolve and equivalence checks
				settings = new SettingsImpl(n -> isAllowedSetting(n));
			}
			settings.setDefaultSettings(getDataType().getDefaultSettings());
			defaultSettings = settings;
		}
		return defaultSettings;
	}

	private boolean isAllowedSetting(String settingName) {
		// non-TypeDefSettingsDefinition settings are not permitted in Impl TypeDef
		// since they will be discarded during resolve and ignored for equivalence checks
		for (TypeDefSettingsDefinition def : getTypeDefSettingsDefinitions()) {
			if (def.getStorageKey().equals(settingName)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		validate(newDt);
		if (oldDt == dataType) {
			settingsDef = null;
			if (dataMgr != null) {
				defaultSettings = null;
			}
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
		if (isAutoNamed()) {
			return getName();
		}
		return "typedef " + getName() + " " + dataType.getName();
	}

	/**
	 * Copy all default settings , which correspond to a TypeDefSettingsDefinition,
	 * from the specified src TypeDef to the specified dest TypeDef.
	 * @param src settings source TypeDef
	 * @param dest settings destination TypeDef
	 * @param clearBeforeCopy if true dest default settings will be cleared before copy performed
	 */
	public static void copyTypeDefSettings(TypeDef src, TypeDef dest, boolean clearBeforeCopy) {
		if (clearBeforeCopy) {
			Settings settings = dest.getDefaultSettings();
			settings.clearAllSettings();
		}

		Settings otherSettings = src.getDefaultSettings();
		if (otherSettings.isEmpty()) {
			return;
		}

		Settings settings = dest.getDefaultSettings();
		for (TypeDefSettingsDefinition def : dest.getTypeDefSettingsDefinitions()) {
			def.copySetting(otherSettings, settings);
		}
	}

	/**
	 * Generate a name for the typedef based upon its current {@link TypeDefSettingsDefinition} settings.
	 * @param modelType model typedef from which name should be derived
	 * @return generated typedef auto-name with attribute specification
	 */
	public static String generateTypedefName(TypeDef modelType) {

		// Examples:
		//   string *32 __((relative))
		//   char *32 __((image-base-relative))
		//   char *16 __((space(data)))

		Settings settings = modelType.getDefaultSettings();
		StringBuilder attributesBuf = new StringBuilder();
		for (TypeDefSettingsDefinition def : modelType.getTypeDefSettingsDefinitions()) {
			String attribute = def.getAttributeSpecification(settings);
			if (attribute != null) {
				if (attributesBuf.length() != 0) {
					attributesBuf.append(',');
				}
				attributesBuf.append(attribute);
			}
		}
		StringBuilder buf = new StringBuilder(modelType.getDataType().getName());
		buf.append(' ');
		buf.append(DataType.TYPEDEF_ATTRIBUTE_PREFIX);
		buf.append(attributesBuf);
		buf.append(DataType.TYPEDEF_ATTRIBUTE_SUFFIX);
		return buf.toString();
	}

}
