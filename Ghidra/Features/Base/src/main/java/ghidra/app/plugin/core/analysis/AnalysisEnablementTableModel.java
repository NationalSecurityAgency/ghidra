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
package ghidra.app.plugin.core.analysis;

import java.awt.Color;
import java.awt.Component;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JTable;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.ColorUtils;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * Table model for analyzer enablement state.
 */
public class AnalysisEnablementTableModel
		extends GDynamicColumnTableModel<AnalyzerEnablementState, Object> {

	private static Color BG_COLOR_NOT_DEFAULT_ENABLEMENT = new Color(255, 255, 200);
	private static Color BG_COLOR_NOT_DEFAULT_ENABLEMENT_SELECTED = new Color(177, 212, 236);

	private List<AnalyzerEnablementState> analyzerStates;
	private AnalysisPanel panel;

	public AnalysisEnablementTableModel(AnalysisPanel panel,
			List<AnalyzerEnablementState> analyzerStates) {
		super(new ServiceProviderStub());
		this.panel = panel;
		this.analyzerStates = analyzerStates;
		setDefaultTableSortState(TableSortState.createUnsortedSortState());
	}

	public void setData(List<AnalyzerEnablementState> analyzerStates) {
		this.analyzerStates = analyzerStates;
		fireTableDataChanged();
	}

	@Override
	public String getName() {
		return "Analysis Enablement";
	}

	@Override
	public List<AnalyzerEnablementState> getModelData() {
		return analyzerStates;
	}

	@Override
	protected TableColumnDescriptor<AnalyzerEnablementState> createTableColumnDescriptor() {
		TableColumnDescriptor<AnalyzerEnablementState> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new AnalyzerEnabledColumn());
		descriptor.addVisibleColumn(new AnalyzerNameColumn());

		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return columnIndex == 0;
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		if (columnIndex == AnalysisPanel.COLUMN_ANALYZER_IS_ENABLED) {
			Boolean enabled = (Boolean) value;
			analyzerStates.get(rowIndex).setEnabled(enabled);
			String analyzerName = analyzerStates.get(rowIndex).getName();
			panel.setAnalyzerEnabled(analyzerName, enabled, true);
			fireTableRowsUpdated(rowIndex, rowIndex);
		}
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return false;
	}

	private void setToolTip(Component c, String text) {
		if (c instanceof JComponent) {
			((JComponent) c).setToolTipText(text);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class AnalyzerEnabledColumn
			extends AbstractDynamicTableColumn<AnalyzerEnablementState, Boolean, Object> {
		EnabledColumnTableCellRenderer renderer = new EnabledColumnTableCellRenderer();

		@Override
		public String getColumnName() {
			return "Enabled";
		}

		@Override
		public Boolean getValue(AnalyzerEnablementState state, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return state.isEnabled();
		}

		@Override
		public GColumnRenderer<Boolean> getColumnRenderer() {
			return renderer;
		}
	}

	private class AnalyzerNameColumn
			extends AbstractDynamicTableColumn<AnalyzerEnablementState, String, Object> {
		AnalyzerNameTableCellRenderer renderer = new AnalyzerNameTableCellRenderer();

		@Override
		public String getColumnName() {
			return "Analyzer";
		}

		@Override
		public String getValue(AnalyzerEnablementState state, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			String value = state.getName();
			if (state.isPrototype()) {
				value += " (Prototype)";
			}
			return value;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	private class EnabledColumnTableCellRenderer implements GColumnRenderer<Boolean> {
		GBooleanCellRenderer booleanRenderer = new GBooleanCellRenderer();

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			Component component = booleanRenderer.getTableCellRendererComponent(table, value,
				isSelected, hasFocus, row, column);

			AnalyzerEnablementState state = getRowObject(row);
			if (state.isDefaultEnablement()) {
				setToolTip(component, null);
				return component;
			}

			// not the default enablement
			if (isSelected) {
				component.setBackground(BG_COLOR_NOT_DEFAULT_ENABLEMENT_SELECTED);
			}
			else {
				component.setBackground(BG_COLOR_NOT_DEFAULT_ENABLEMENT);
			}

			setToolTip(component, "This option differs from the default");

			return component;
		}

		@Override
		public String getFilterString(Boolean t, Settings settings) {
			return "";
		}
	}

	private class AnalyzerNameTableCellRenderer extends AbstractGColumnRenderer<String> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component component = super.getTableCellRendererComponent(data);
			Object value = data.getValue();

			if (value == null) {
				return component;
			}

			String analyzerName = (String) value;

			if (analyzerName.endsWith(AnalysisPanel.PROTOTYPE)) {
				component.setForeground(
					ColorUtils.deriveForeground(component.getBackground(), ColorUtils.HUE_RED));
			}

			AnalyzerEnablementState state = (AnalyzerEnablementState) data.getRowObject();
			if (state.isDefaultEnablement()) {
				setToolTip(component, null);
				return component;
			}

			// not the default enablement			
			if (data.isSelected()) {
				component.setBackground(BG_COLOR_NOT_DEFAULT_ENABLEMENT_SELECTED);
				component.setForeground(Color.BLACK);
			}
			else {
				component.setBackground(BG_COLOR_NOT_DEFAULT_ENABLEMENT);
			}

			setToolTip(component, "This option differs from the default");
			return component;
		}

		@Override
		public String getFilterString(String value, Settings settings) {
			return value;
		}
	}

}
