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
package ghidra.app.plugin.core.data;

import ghidra.docking.settings.*;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;

public class DataTypeSettingsDialog extends AbstractSettingsDialog {

	private DataType dataType;			// not set for data selection mode		
	private DataTypeComponent dtc;		// Only set for single data-type component mode

	/**
	 * Construct for data type default settings
	 * @param dataType data type (must be resolved to program)
	 * @param settingsDefinitions settings definitions to be displayed (may be a restricted set)
	 */
	public DataTypeSettingsDialog(DataType dataType, SettingsDefinition[] settingsDefinitions) {
		super(constructTitle(null, dataType, true), settingsDefinitions,
			dataType.getDefaultSettings());
		checkDataType(dataType);
		this.dataType = dataType;
		setHelpLocation(new HelpLocation("DataPlugin", "Default_Settings"));
	}

	/**
	 * Construct for structure component default settings
	 * @param dtc data type component (must belong to program-resolved structure)
	 */
	DataTypeSettingsDialog(DataTypeComponent dtc) {
		super(constructTitle(dtc, dtc.getDataType(), true),
			DataSettingsDialog.getAllowedDataInstanceSettingsDefinitions(dtc.getDataType()),
			dtc.getDefaultSettings());
		// NOTE: component default settings currently use the same restricted set of definitions
		checkDataType(dtc.getParent());
		this.dtc = dtc;
		this.dataType = dtc.getDataType();
		setHelpLocation(new HelpLocation("DataPlugin", "SettingsOnStructureComponents"));
	}

	private static void checkDataType(DataType dt) {
		DataTypeManager dtm = dt.getDataTypeManager();
		if (dtm instanceof BuiltInDataTypeManager) {
			throw new IllegalArgumentException(
				"Unsupported use for datatype from BuiltInDataTypeManager");
		}
		if (dtm instanceof DataTypeManagerDB) {
			long id = dtm.getID(dt);
			if (id > 0) {
				// FIXME: this does not handle re-mapped BuiltIn datatypes
				// since multiple instances may be defined
				if (dt == dtm.getDataType(id)) {
					return; // valid original instance
				}
			}
		}
		throw new IllegalArgumentException("Invalid data type instance");
	}

	@Override
	public void dispose() {
		super.dispose();
		dataType = null;
		dtc = null;
	}

	static String constructTitle(DataTypeComponent dtc, DataType dataType, boolean isDefault) {
		// TODO: May need to truncate names which could be very long
		StringBuffer nameBuf = new StringBuffer();
		if (isDefault) {
			nameBuf.append("Default ");
		}
		String name = dataType.getDisplayName();
		// default array settings defer to base type
		if (dtc == null) {
			name = getSettingsBaseType(dataType).getDisplayName();
		}
		nameBuf.append(name);
		nameBuf.append(" Settings");
		if (dtc != null) {
			nameBuf.append(" (");
			nameBuf.append(dtc.getParent().getDisplayName());
			nameBuf.append('.');
			String fname = dtc.getFieldName();
			if (fname == null) {
				fname = dtc.getDefaultFieldName();
			}
			nameBuf.append(fname);
			nameBuf.append(')');
		}
		return nameBuf.toString();
	}

	/**
	 * Get base datatype associated with any array (include typedef of array)
	 * @param dt datatype
	 * @return base array datatype or specified dt if not an array type
	 */
	private static DataType getSettingsBaseType(DataType dt) {
		while (true) {
			if (dt instanceof TypeDef) {
				DataType baseDt = ((TypeDef) dt).getBaseDataType();
				if (baseDt instanceof Array) {
					dt = baseDt;
				}
				else {
					break;
				}
			}
			else if (dt instanceof Array) {
				dt = ((Array) dt).getDataType();
			}
			else {
				break;
			}
		}
		return dt;
	}

	private Settings getOriginalSettings() {
		if (dtc != null) {
			return dtc.getDefaultSettings();
		}
		return dataType.getDefaultSettings();
	}

	@Override
	String[] getSuggestedValues(StringSettingsDefinition settingsDefinition) {
		if (settingsDefinition.supportsSuggestedValues()) {
			return settingsDefinition.getSuggestedValues(getOriginalSettings());
		}
		return null;
	}

	protected void applySettings() {
		DataTypeManager dtm = dataType.getDataTypeManager();
		int txId = dtm.startTransaction(getTitle());
		try {
			Settings originalSettings = getOriginalSettings();
			Settings modifiedSettings = getSettings();
			for (SettingsDefinition settingsDef : getSettingsDefinitions()) {
				settingsDef.copySetting(modifiedSettings, originalSettings);
			}
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}
}
