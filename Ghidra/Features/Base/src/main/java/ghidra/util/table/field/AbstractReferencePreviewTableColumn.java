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

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.PreviewTableCellData;
import ghidra.util.table.column.GColumnRenderer;

/**
 * This table field displays the preview of the code unit at the ToAddress 
 * for the reference or possible reference address pair
 * associated with a row in the table.
 */
public abstract class AbstractReferencePreviewTableColumn extends
		ProgramLocationTableColumnExtensionPoint<ReferenceAddressPair, PreviewTableCellData> {

	private PreviewTableColumn previewTableColumn;

	public AbstractReferencePreviewTableColumn() {
		previewTableColumn = new PreviewTableColumn();
	}

	abstract Address getAddress(ReferenceAddressPair pair);

	abstract String getColumnNamePrefix();

	@Override
	public PreviewTableCellData getValue(ReferenceAddressPair rowObject, Settings settings,
			Program pgm, ServiceProvider serviceProvider) throws IllegalArgumentException {
		Address address = getAddress(rowObject);
		ProgramLocation programLocation = new ProgramLocation(pgm, address);
		return previewTableColumn.getValue(programLocation, settings, pgm, serviceProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(ReferenceAddressPair rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		Address address = getAddress(rowObject);
		ProgramLocation programLocation = new ProgramLocation(program, address);
		return previewTableColumn.getProgramLocation(programLocation, settings, program,
			serviceProvider);
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnNamePrefix() + previewTableColumn.getColumnDisplayName(settings);
	}

	@Override
	public int getMaxLines(Settings settings) {
		return previewTableColumn.getMaxLines(settings);
	}

	@Override
	public GColumnRenderer<PreviewTableCellData> getColumnRenderer() {
		return previewTableColumn.getColumnRenderer();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return previewTableColumn.getSettingsDefinitions();
	}
}
