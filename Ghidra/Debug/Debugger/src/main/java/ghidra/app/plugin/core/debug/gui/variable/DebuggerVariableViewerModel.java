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
package ghidra.app.plugin.core.debug.gui.variable;

import javax.swing.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.*;
import java.util.stream.Collectors;

import db.Transaction;
import docking.Tool;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import generic.theme.GColor;
import ghidra.app.services.DataTypeManagerService;
import ghidra.base.widgets.table.AbstractDataTypeTableCellEditor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

import static docking.widgets.table.CustomToStringCellRenderer.CustomFont.MONOSPACED;

public class DebuggerVariableViewerModel
		extends ThreadedTableModelStub<AbstractDebuggerVariableViewerVarValue> {
	private static class DataTypeEditor extends AbstractDataTypeTableCellEditor {
		@Override
		protected DataTypeManagerService getService(TableModel model) {
			if (!(model instanceof final DebuggerVariableViewerModel dvvModel)) {
				return null;
			}
			return dvvModel.tool.getService(DataTypeManagerService.class);
		}

		@Override
		protected DataType resolveSelection(DataType dataType, TableModel model) {
			if ((dataType == null) ||
					!(model instanceof final DebuggerVariableViewerModel dvvModel)) {
				return null;
			}
			final Trace trace = dvvModel.trace;
			if (trace == null) {
				return dataType;
			}
			try (Transaction ignored = trace.openTransaction("Resolve DataType")) {
				return trace.getDataTypeManager().resolve(dataType, null);
			}
		}
	}

	private static class VariableValueOrReprCellEditor<T> extends AbstractCellEditor
			implements TableCellEditor {
		private final Function<AbstractDebuggerVariableViewerVarValue, T> getter;
		private final JTextField jTextField;

		public VariableValueOrReprCellEditor(
				Function<AbstractDebuggerVariableViewerVarValue, T> getter) {
			this.getter = getter;
			jTextField = new JTextField();
		}

		@Override
		public Object getCellEditorValue() {
			return jTextField.getText();
		}

		@Override
		public boolean isCellEditable(EventObject e) {
			if (e instanceof MouseEvent me) {
				return me.getClickCount() >= 2;
			}
			return true;
		}

		@Override
		public Component getTableCellEditorComponent(final JTable table, Object value,
				boolean isSelected, int row, int column) {
			AbstractDebuggerVariableViewerVarValue rowData =
					(AbstractDebuggerVariableViewerVarValue) value;
			jTextField.setText(getter.apply(rowData).toString());
			return jTextField;
		}
	}

	private static class VariableMemoryStateCellRenderer
			extends CustomToStringCellRenderer<AbstractDebuggerVariableViewerVarValue> {
		private static final Color COLOR_FOREGROUND_STALE =
				new GColor("color.debugger.plugin.resources.watch.stale");
		private static final Color COLOR_FOREGROUND_STALE_SEL =
				new GColor("color.debugger.plugin.resources.watch.stale.selected");
		private static final Color COLOR_FOREGROUND_CHANGED =
				new GColor("color.debugger.plugin.resources.watch.changed");
		private static final Color COLOR_FOREGROUND_CHANGED_SEL =
				new GColor("color.debugger.plugin.resources.watch.changed.selected");

		public VariableMemoryStateCellRenderer(
				BiFunction<AbstractDebuggerVariableViewerVarValue, Settings, String> toString) {
			super(MONOSPACED, AbstractDebuggerVariableViewerVarValue.class, toString, false);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			AbstractDebuggerVariableViewerVarValue row =
					(AbstractDebuggerVariableViewerVarValue) data.getRowObject();
			if (!row.isKnown()) {
				if (data.isSelected()) {
					setForeground(COLOR_FOREGROUND_STALE_SEL);
				}
				else {
					setForeground(COLOR_FOREGROUND_STALE);
				}
			}
			else if (row.isChanged()) {
				if (data.isSelected()) {
					setForeground(COLOR_FOREGROUND_CHANGED_SEL);
				}
				else {
					setForeground(COLOR_FOREGROUND_CHANGED);
				}
			}
			return this;
		}
	}

	private static class AbstractDebuggerVariableColumn<T, V>
			extends AbstractDynamicTableColumn<AbstractDebuggerVariableViewerVarValue, T, Object> {
		private final Function<AbstractDebuggerVariableViewerVarValue, T> getter;
		private final BiConsumer<AbstractDebuggerVariableViewerVarValue, V> setter;
		private final Class<V> clazz;
		private final String columnName;

		AbstractDebuggerVariableColumn(String columnName,
				Function<AbstractDebuggerVariableViewerVarValue, T> getter,
				BiConsumer<AbstractDebuggerVariableViewerVarValue, V> setter, Class<V> clazz) {
			this.columnName = columnName;
			this.getter = getter;
			this.setter = setter;
			this.clazz = clazz;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public T getValue(AbstractDebuggerVariableViewerVarValue rowObject, Settings settings,
				Object data, ServiceProvider services) throws IllegalArgumentException {
			return getter.apply(rowObject);
		}

		public void setValue(AbstractDebuggerVariableViewerVarValue rowObject, Object data) {
			setter.accept(rowObject, clazz.cast(data));
		}

		public boolean isEditable() {
			return true;
		}
	}

	private static class AbstractDebuggerVariableColumnNoSetter<T>
			extends AbstractDebuggerVariableColumn<T, Void> {
		AbstractDebuggerVariableColumnNoSetter(String columnName,
				Function<AbstractDebuggerVariableViewerVarValue, T> getter) {
			super(columnName, getter, null, null);
		}

		@Override
		public void setValue(AbstractDebuggerVariableViewerVarValue rowObject, Object data) {
			// Ignore set value as there is no setter
		}

		@Override
		public boolean isEditable() {
			return false;
		}
	}

	private static class VariableValueOrReprColumn
			extends AbstractDebuggerVariableColumn<AbstractDebuggerVariableViewerVarValue,
			String> {

		private final VariableMemoryStateCellRenderer cellRenderer;
		private final VariableValueOrReprCellEditor<String> cellEditor;

		VariableValueOrReprColumn(String columnName,
				Function<AbstractDebuggerVariableViewerVarValue, String> getter,
				BiConsumer<AbstractDebuggerVariableViewerVarValue, String> setter) {
			super(columnName, v -> v, setter, String.class);
			cellRenderer = new VariableMemoryStateCellRenderer((v, s) -> getter.apply(v));
			cellEditor = new VariableValueOrReprCellEditor<>(getter);
		}

		@Override
		public GColumnRenderer<AbstractDebuggerVariableViewerVarValue> getColumnRenderer() {
			return cellRenderer;
		}

		@Override
		public TableCellEditor getColumnEditor() {
			return cellEditor;
		}

	}

	private static class SourceColumn extends AbstractDebuggerVariableColumnNoSetter<String> {
		SourceColumn() {
			super("Source", AbstractDebuggerVariableViewerVarValue::getSource);
		}
	}

	private static class StorageColumn
			extends AbstractDebuggerVariableColumnNoSetter<AbstractDebuggerVariableViewerVarValue> {

		private static final CustomToStringCellRenderer<AbstractDebuggerVariableViewerVarValue>
				ADDRESS_RENDERER = new CustomToStringCellRenderer<>(MONOSPACED,
				AbstractDebuggerVariableViewerVarValue.class, (v, s) -> {
			if (v.getAddress() == Address.NO_ADDRESS) {
				return "??";
			}
			else if (v.getAddress().isRegisterAddress()) {
				Register register = v.getLanguage().getRegister(v.getAddress(), v.value.length);
				if (register != null) {
					return register.getName();
				}
			}
			return v.getAddress().toString();
		}, false);

		StorageColumn() {
			super("Storage", v -> v);
		}

		@Override
		public GColumnRenderer<AbstractDebuggerVariableViewerVarValue> getColumnRenderer() {
			return ADDRESS_RENDERER;
		}

	}

	private static class ReprColumn extends VariableValueOrReprColumn {
		ReprColumn() {
			super("Repr", AbstractDebuggerVariableViewerVarValue::getRepr,
					AbstractDebuggerVariableViewerVarValue::setRepr);
		}
	}

	private static class SymbolColumn extends AbstractDebuggerVariableColumn<String, String> {
		SymbolColumn() {
			super("Symbol", AbstractDebuggerVariableViewerVarValue::getSymbol,
					AbstractDebuggerVariableViewerVarValue::setSymbol, String.class);
		}
	}

	private static class TypeColumn extends AbstractDebuggerVariableColumn<DataType, DataType> {
		private static final DataTypeEditor TYPE_EDITOR = new DataTypeEditor();

		TypeColumn() {
			super("Type", AbstractDebuggerVariableViewerVarValue::getDataType,
					AbstractDebuggerVariableViewerVarValue::setDataType, DataType.class);
		}

		@Override
		public TableCellEditor getColumnEditor() {
			return TYPE_EDITOR;
		}
	}

	private static class ValueColumn extends VariableValueOrReprColumn {
		ValueColumn() {
			super("Value", AbstractDebuggerVariableViewerVarValue::getValue,
					AbstractDebuggerVariableViewerVarValue::setValue);
		}
	}

	private static class ErrorColumn extends AbstractDebuggerVariableColumnNoSetter<String> {
		ErrorColumn() {
			super("Error", AbstractDebuggerVariableViewerVarValue::getError);
		}
	}

	private final List<AbstractDebuggerVariableViewerVarValue> vars;
	private final Tool tool;
	private final DebuggerVariableViewerProvider provider;
	private Trace trace;

	public DebuggerVariableViewerModel(Tool tool, DebuggerVariableViewerProvider provider) {
		super("Variable Model", null);
		vars = new LinkedList<>();
		this.tool = tool;
		this.provider = provider;
	}

	@Override
	protected TableColumnDescriptor<AbstractDebuggerVariableViewerVarValue> createTableColumnDescriptor() {
		final TableColumnDescriptor<AbstractDebuggerVariableViewerVarValue> descriptor =
				new TableColumnDescriptor<>();
		descriptor.addHiddenColumn(new SourceColumn());
		descriptor.addVisibleColumn(new StorageColumn());
		descriptor.addVisibleColumn(new SymbolColumn());
		descriptor.addVisibleColumn(new ValueColumn());
		descriptor.addVisibleColumn(new TypeColumn());
		descriptor.addVisibleColumn(new ReprColumn());
		descriptor.addVisibleColumn(new ErrorColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<AbstractDebuggerVariableViewerVarValue> accumulator,
			TaskMonitor monitor) {

		if (provider != null) {
			Map<String, AbstractDebuggerVariableViewerVarValue> varValueMap = vars.stream()
					.sorted(Comparator.comparing(AbstractDebuggerVariableViewerVarValue::getSource))
					.filter(v -> switch (provider.actionShowVariables.getCurrentState()
							.getUserData()) {
						case LISTING -> v instanceof DebuggerVariableViewerVarValue;
						case DECOMPILER -> v instanceof DebuggerVariableViewerHighVarValue;
						case BOTH -> true;
					})
					.collect(Collectors.toMap(AbstractDebuggerVariableViewerVarValue::getSymbol,
							Function.identity(), (existing, replacement) -> existing));

			for (AbstractDebuggerVariableViewerVarValue varValue : varValueMap.values()) {
				accumulator.add(varValue);
			}
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (getColumn(
				columnIndex) instanceof AbstractDebuggerVariableColumn<?, ?> abstractDebuggerVariableColumn) {
			return provider.actionEnableEdits.isSelected() &&
					abstractDebuggerVariableColumn.isEditable() && getRowObject(rowIndex).canEdit();
		}
		return false;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		final AbstractDebuggerVariableViewerVarValue value = getRowObject(rowIndex);
		if (getColumn(columnIndex) instanceof final AbstractDebuggerVariableColumn<?, ?> advCol) {
			advCol.setValue(value, aValue);
			provider.rebuildTable();
		}
	}

	public void setModelData(List<AbstractDebuggerVariableViewerVarValue> result) {
		for (AbstractDebuggerVariableViewerVarValue newValue : result) {
			for (AbstractDebuggerVariableViewerVarValue oldValue : vars) {
				if (oldValue.getAddress().equals(newValue.getAddress()) &&
						Objects.equals(oldValue.getSymbol(), newValue.getSymbol()) &&
						oldValue.getDataType().equals(newValue.getDataType())) {
					newValue.setOldValue(oldValue.value);
				}
			}
		}
		vars.clear();
		vars.addAll(result);
		reload();
	}

	public void setTrace(Trace trace) {
		this.trace = trace;
	}
}
