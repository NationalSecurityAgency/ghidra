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
package ghidra.util.table.field;

import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.CodeUnitTableCellRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * Table column to display {@link CodeUnit}s
 */
public class CodeUnitTableColumn
		extends ProgramLocationTableColumnExtensionPoint<ProgramLocation, CodeUnitTableCellData> {

	private static final CodeUnitCountSettingsDefinition CODE_UNIT_COUNT =
		CodeUnitCountSettingsDefinition.DEF;
	private static final CodeUnitOffsetSettingsDefinition CODE_UNIT_OFFSET =
		CodeUnitOffsetSettingsDefinition.DEF;

	private static SettingsDefinition[] SETTINGS_DEFS = { CODE_UNIT_COUNT, CODE_UNIT_OFFSET };
	private BrowserCodeUnitFormat codeUnitFormat;
	private CodeUnitTableCellRenderer renderer = new CodeUnitTableCellRenderer();

	@Override
	public String getColumnName() {
		return "Code Unit";
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		String name = getColumnName();
		int previewCnt = CODE_UNIT_COUNT.getCount(settings);
		if (previewCnt != 1) {
			name += "[" + previewCnt + "]";
		}
		String offset = CODE_UNIT_OFFSET.getDisplayValue(settings);
		if (!"0".equals(offset)) {
			name += offset;
		}
		return name;
	}

	@Override
	public CodeUnitTableCellData getValue(ProgramLocation rowObject, Settings settings,
			Program data, ServiceProvider serviceProvider) throws IllegalArgumentException {
		ProgramLocation loc = rowObject;
		return new CodeUnitTableCellData(loc, getCodeUnitFormat(serviceProvider),
			CODE_UNIT_OFFSET.getOffset(settings), CODE_UNIT_COUNT.getCount(settings));
	}

	private CodeUnitFormat getCodeUnitFormat(ServiceProvider serviceProvider) {
		if (codeUnitFormat == null) {
			codeUnitFormat = new BrowserCodeUnitFormat(serviceProvider);
		}
		return codeUnitFormat;
	}

	@Override
	public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		return rowObject;
	}

	@Override
	public GColumnRenderer<CodeUnitTableCellData> getColumnRenderer() {
		return renderer;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	@Override
	public int getMaxLines(Settings settings) {
		return CODE_UNIT_COUNT.getCount(settings);
	}
}
