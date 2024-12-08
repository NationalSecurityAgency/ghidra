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
package ghidra.app.plugin.core.codebrowser;

import docking.widgets.table.AbstractDynamicTableColumn;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.CodeUnitTableCellRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;

/**
 * A column for displaying a small window of {@link CodeUnit}s around a selected endpoint
 * of an {@link AddressRange} in an address range table
 */
public class AddressRangeCodeUnitTableColumn
		extends AbstractDynamicTableColumn<AddressRangeInfo, CodeUnitTableCellData, Program> {

	private static SettingsDefinition[] SETTINGS = { CodeUnitCountSettingsDefinition.DEF,
		CodeUnitOffsetSettingsDefinition.DEF, AddressRangeEndpointSettingsDefinition.DEF };

	private final CodeUnitTableCellRenderer renderer = new CodeUnitTableCellRenderer();
	private CodeUnitFormat codeUnitFormat;
	private static final String COLUMN_NAME = "Code Unit";

	/**
	 * Default constructor
	 */
	public AddressRangeCodeUnitTableColumn() {
	}

	@Override
	public String getColumnName() {
		return COLUMN_NAME;
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		StringBuilder sb =
			new StringBuilder(AddressRangeEndpointSettingsDefinition.DEF.getValueString(settings));
		sb.append(" ").append(COLUMN_NAME);
		int previewCnt = CodeUnitCountSettingsDefinition.DEF.getCount(settings);
		if (previewCnt != 1) {
			sb.append("[");
			sb.append(previewCnt);
			sb.append("]");
		}
		String offset = CodeUnitOffsetSettingsDefinition.DEF.getDisplayValue(settings);
		if (!"0".equals(offset)) {
			sb.append(offset);
		}
		return sb.toString();
	}

	@Override
	public CodeUnitTableCellData getValue(AddressRangeInfo rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
		int choice = AddressRangeEndpointSettingsDefinition.DEF.getChoice(settings);
		Address base =
			choice == AddressRangeEndpointSettingsDefinition.BEGIN_CHOICE_INDEX ? rowObject.min()
					: rowObject.max();
		ProgramLocation location = new ProgramLocation(program, base);
		return new CodeUnitTableCellData(location, getCodeUnitFormat(serviceProvider),
			CodeUnitOffsetSettingsDefinition.DEF.getOffset(settings),
			CodeUnitCountSettingsDefinition.DEF.getCount(settings));
	}

	@Override
	public GColumnRenderer<CodeUnitTableCellData> getColumnRenderer() {
		return renderer;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return SETTINGS;
	}

	@Override
	public int getMaxLines(Settings settings) {
		return CodeUnitCountSettingsDefinition.DEF.getCount(settings);
	}

	private CodeUnitFormat getCodeUnitFormat(ServiceProvider serviceProvider) {
		if (codeUnitFormat == null) {
			codeUnitFormat = new BrowserCodeUnitFormat(serviceProvider);
		}
		return codeUnitFormat;
	}

}
