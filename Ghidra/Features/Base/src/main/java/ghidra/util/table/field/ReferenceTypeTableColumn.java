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

import java.awt.Component;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * This table field displays the reference type for the reference 
 * associated with a row in the table.
 */
public class ReferenceTypeTableColumn
		extends ProgramLocationTableColumnExtensionPoint<Reference, RefType> {

	private ReferenceTypeTableCellRenderer reftypeRenderer = new ReferenceTypeTableCellRenderer();

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnName();
	}

	@Override
	public String getColumnName() {
		return "Ref Type";
	}

	@Override
	public RefType getValue(Reference rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return rowObject.getReferenceType();
	}

	@Override
	public ProgramLocation getProgramLocation(Reference rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		return null;
	}

	@Override
	public GColumnRenderer<RefType> getColumnRenderer() {
		return reftypeRenderer;
	}

	private class ReferenceTypeTableCellRenderer extends AbstractGhidraColumnRenderer<RefType> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);

			RefType value = (RefType) data.getValue();

			label.setText(value.getName());

			return label;
		}

		@Override
		public String getFilterString(RefType t, Settings settings) {
			return t.getName();
		}
	}
}
