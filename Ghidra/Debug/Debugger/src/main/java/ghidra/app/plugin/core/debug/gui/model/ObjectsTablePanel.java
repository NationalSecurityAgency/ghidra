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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.Component;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.TableColumn;

import docking.widgets.table.GTableColumnModel;
import docking.widgets.table.GTableTextCellEditor;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class ObjectsTablePanel extends AbstractQueryTablePanel<ValueRow, ObjectTableModel> {

	private static final String DEFAULT_PREF_KEY = "DEFAULT";

	private static class PropertyEditor extends GTableTextCellEditor {
		private final JTextField textField;

		public PropertyEditor() {
			super(new JTextField());
			textField = (JTextField) getComponent();
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {
			super.getTableCellEditorComponent(table, value, isSelected, row, column);
			if (value instanceof ValueProperty<?> property) {
				textField.setText(property.getDisplay());
			}
			else {
				textField.setText(value.toString());
			}
			return textField;
		}

		@Override
		public Object getCellEditorValue() {
			Object value = super.getCellEditorValue();
			return new ValueFixedProperty<>(value);
		}
	}

	public ObjectsTablePanel(Plugin plugin) {
		super(plugin);
		table.setDefaultEditor(ValueProperty.class, new PropertyEditor());
	}

	@Override
	protected ObjectTableModel createModel() {
		return new ObjectTableModel(plugin);
	}

	public boolean trySelectAncestor(TraceObject successor) {
		ValueRow row = tableModel.findTraceObjectAncestor(successor);
		if (row == null) {
			return false;
		}
		setSelectedItem(row);
		return true;
	}

	protected String computePreferenceKey() {
		Trace trace = tableModel.getTrace();
		if (trace == null) {
			return DEFAULT_PREF_KEY;
		}
		ModelQuery query = tableModel.getQuery();
		if (query == null) {
			return DEFAULT_PREF_KEY;
		}
		List<TargetObjectSchema> schemas = query.computeSchemas(trace);
		if (schemas.isEmpty()) {
			return DEFAULT_PREF_KEY;
		}
		TargetObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return DEFAULT_PREF_KEY;
		}
		return rootSchema.getName() + ":" + schemas
				.stream()
				.map(s -> s.getName().toString())
				.collect(Collectors.joining(",")) +
			":" + (isShowHidden() ? "show" : "hide");
	}

	protected void showHiddenColumns(boolean show) {
		if (table.getColumnModel() instanceof GTableColumnModel columnModel) {
			for (TableColumn tCol : columnModel.getAllColumns()) {
				int modelIndex = tCol.getModelIndex();
				if (tableModel
						.getColumn(modelIndex) instanceof AutoAttributeColumn<?> attrCol) {
					if (attrCol.isHidden()) {
						columnModel.setVisible(tCol, show);
					}
				}
			}
		}
	}

	protected void reloadPreferences() {
		String prefKey = computePreferenceKey();
		if (!prefKey.equals(table.getPreferenceKey())) {
			table.setPreferenceKey(prefKey);
		}
	}

	protected void resyncAttributeVisibility() {
		showHiddenColumns(isShowHidden());
	}

	@Override
	protected void coordinatesChanged() {
		super.coordinatesChanged();
		reloadPreferences();
	}

	@Override
	protected void queryChanged() {
		super.queryChanged();
		reloadPreferences();
	}

	@Override
	protected void showHiddenChanged() {
		super.showHiddenChanged();
		resyncAttributeVisibility();
	}
}
