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
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.PreviewDataTableCellRenderer;
import ghidra.util.table.PreviewTableCellData;
import ghidra.util.table.column.GColumnRenderer;

/**
 * This table column displays a preview of the {@link ProgramLocation} with a row in the table.
 * The actual content displayed will vary, depending upon the location.  Further, the preview is
 * meant to mimic what the user will see displayed in the Listing display window.
 */
public class PreviewTableColumn
		extends ProgramLocationTableColumnExtensionPoint<ProgramLocation, PreviewTableCellData> {

	private CodeUnitFormat codeUnitFormat;
	private PreviewDataTableCellRenderer previewRenderer = new PreviewDataTableCellRenderer();

	@Override
	public String getColumnName() {
		return "Preview";
	}

	@Override
	public PreviewTableCellData getValue(ProgramLocation rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
		ProgramLocation loc = rowObject;
		return new PreviewTableCellData(loc, getCodeUnitFormat(serviceProvider));
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
	public GColumnRenderer<PreviewTableCellData> getColumnRenderer() {
		return previewRenderer;
	}
}
