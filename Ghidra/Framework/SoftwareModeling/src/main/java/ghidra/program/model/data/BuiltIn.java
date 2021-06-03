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

import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.lang.DecompilerLanguage;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE:  ALL DATATYPE CLASSES MUST END IN "DataType".  If not,
 * the ClassSearcher will not find them.
 * 
 * Base class for built-in Datatypes.  A built-in data type is
 * searched for in the classpath and added automatically to the available
 * data types in the data type manager.
 */
public abstract class BuiltIn extends DataTypeImpl implements BuiltInDataType {

	private static final SettingsDefinition[] STANDARD_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { MutabilitySettingsDefinition.DEF };

	private SettingsDefinition[] settingDefs;

	public BuiltIn(CategoryPath path, String name, DataTypeManager dataMgr) {
		// Change any category path so that it is under the built in category.
		super(path == null ? CategoryPath.ROOT : path, name, null, BuiltInSourceArchive.INSTANCE,
			NO_SOURCE_SYNC_TIME, NO_LAST_CHANGE_TIME, dataMgr);
	}

	/**
	 * Returns a clone of this built-in DataType
	 * @see ghidra.program.model.data.DataType#copy(ghidra.program.model.data.DataTypeManager)
	 */
	@Override
	public final DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	/**
	 * Gets a list of all the settingsDefinitions used by this datatype.
	 * @return a list of the settingsDefinitions used by this datatype.
	 */
	@Override
	public final SettingsDefinition[] getSettingsDefinitions() {
		if (settingDefs == null) {
			settingDefs = SettingsDefinition.concat(STANDARD_SETTINGS_DEFINITIONS,
				getBuiltInSettingsDefinitions());
		}
		return settingDefs;
	}

	/**
	 * Gets a list of all the settingsDefinitions used by this datatype.
	 * @return a list of the settingsDefinitions used by this datatype.
	 */
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return null;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null) {
			return false;
		}
		return getClass() == dt.getClass();
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// Default implementation does nothing.
	}

	@Override
	public final void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		// Default implementation does nothing.
	}

	@Override
	public final void setName(String name) throws InvalidNameException {
		// Default implementation does nothing.
	}

	@Override
	public final void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		// Default implementation does nothing.
	}

	@Override
	public final void addParent(DataType dt) {
		// Default implementation does nothing.
	}

	@Override
	public final void removeParent(DataType dt) {
		// Default implementation does nothing.
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// Default implementation does nothing.
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		// Default implementation does nothing.
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		// Default implementation does nothing.
	}

//	/* (non-Javadoc)
//	 * @see ghidra.program.model.data.BuiltInDataType#clone(ghidra.program.model.data.DataTypeManager)
//	 */
//	public BuiltInDataType clone(DataTypeManager dataManager) {
//		BuiltIn dt = (BuiltIn)copy(false);
//		dt.dataMgr = dataManager;
//		return dt;
//	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public UniversalID getUniversalID() {
		return null;
	}

	@Override
	public long getLastChangeTime() {
		return 0;
	}

	/**
	 * Return token used to represent this type in decompiler/source-code output
	 * @param language is the language being displayed
	 * @return the name string
	 */
	public String getDecompilerDisplayName(DecompilerLanguage language) {
		return name;
	}

	protected String getCTypeDeclaration(String typeName, String ctypeName, boolean useDefine) {
		return useDefine ? "#define " + typeName + "    " + ctypeName
				: "typedef " + ctypeName + "    " + typeName + ";";
	}

	protected String getCTypeDeclaration(String typeName, int typeLen, boolean signed,
			DataOrganization dataOrganization, boolean useDefine) {
		return getCTypeDeclaration(typeName,
			dataOrganization.getIntegerCTypeApproximation(typeLen, signed), useDefine);
	}

	protected String getCTypeDeclaration(BuiltIn dt, boolean signed,
			DataOrganization dataOrganization, boolean useDefine) {
		return getCTypeDeclaration(dt.getDecompilerDisplayName(DecompilerLanguage.C_LANGUAGE),
			dataOrganization.getIntegerCTypeApproximation(dt.getLength(), signed), useDefine);
	}

	/**
	 * Returns null for FactoryDataType (which should never be used) and Dynamic types which should
	 * generally be replaced by a primitive array (e.g., char[5]) or, a primitive pointer (e.g., char *).
	 * For other types an appropriately sized unsigned integer typedef is returned.
	 * @see ghidra.program.model.data.BuiltInDataType#getCTypeDeclaration(ghidra.program.model.data.DataOrganization)
	 */
	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		if ((this instanceof Dynamic) || (this instanceof FactoryDataType)) {
			return null;
		}
		return getCTypeDeclaration(this, false, dataOrganization, false);
	}

}
