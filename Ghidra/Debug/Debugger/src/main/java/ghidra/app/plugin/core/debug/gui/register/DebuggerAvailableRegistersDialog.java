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
package ghidra.app.plugin.core.debug.gui.register;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerAvailableRegistersDialog extends DialogComponentProvider {

	protected enum AvailableRegisterTableColumns
		implements EnumeratedTableColumn<AvailableRegisterTableColumns, AvailableRegisterRow> {
		SELECTED("", Boolean.class, AvailableRegisterRow::isSelected, AvailableRegisterRow::setSelected, true),
		NUMBER("#", Integer.class, AvailableRegisterRow::getNumber, true),
		NAME("Name", String.class, AvailableRegisterRow::getName, true),
		BITS("Bits", Integer.class, AvailableRegisterRow::getBits, true),
		KNOWN("Known", Boolean.class, AvailableRegisterRow::isKnown, true),
		GROUP("Group", String.class, AvailableRegisterRow::getGroup, true),
		CONTAINS("Contains", String.class, AvailableRegisterRow::getContains, true),
		PARENT("Parent", String.class, AvailableRegisterRow::getParentName, true);

		private final String header;
		private final Function<AvailableRegisterRow, ?> getter;
		private final BiConsumer<AvailableRegisterRow, Object> setter;
		private final boolean sortable;
		private final Class<?> cls;

		<T> AvailableRegisterTableColumns(String header, Class<T> cls,
				Function<AvailableRegisterRow, T> getter, boolean sortable) {
			this(header, cls, getter, null, sortable);
		}

		@SuppressWarnings("unchecked")
		<T> AvailableRegisterTableColumns(String header, Class<T> cls,
				Function<AvailableRegisterRow, T> getter,
				BiConsumer<AvailableRegisterRow, T> setter,
				boolean sortable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<AvailableRegisterRow, Object>) setter;
			this.sortable = sortable;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(AvailableRegisterRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(AvailableRegisterRow row) {
			return setter != null;
		}

		@Override
		public boolean isSortable() {
			return sortable;
		}

		@Override
		public void setValueOf(AvailableRegisterRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class AvailableRegistersTableModel extends
			DefaultEnumeratedColumnTableModel<AvailableRegisterTableColumns, AvailableRegisterRow> {
		public AvailableRegistersTableModel() {
			super("Available Registers", AvailableRegisterTableColumns.class);
		}

		@Override
		public List<AvailableRegisterTableColumns> defaultSortOrder() {
			return List.of(AvailableRegisterTableColumns.NUMBER);
		}
	}

	private final DebuggerRegistersProvider provider;

	private Language language;

	/* testing */ final AvailableRegistersTableModel availableTableModel =
		new AvailableRegistersTableModel();
	private final Map<Register, AvailableRegisterRow> regMap = new HashMap<>();

	private GTable availableTable;
	private GhidraTableFilterPanel<AvailableRegisterRow> availableFilterPanel;

	ActionContext myActionContext;

	DockingAction actionAdd;
	DockingAction actionRemove;

	protected DebuggerAvailableRegistersDialog(DebuggerRegistersProvider provider) {
		super(DebuggerResources.SelectRegistersAction.NAME, true, true, true, false);
		this.provider = provider;

		populateComponents();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		availableTable = new GTable(availableTableModel);
		// Selection is actually via checkboxes
		availableTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		panel.add(new JScrollPane(availableTable));
		availableTable.setAutoLookupColumn(AvailableRegisterTableColumns.NAME.ordinal());

		availableFilterPanel = new GhidraTableFilterPanel<>(availableTable, availableTableModel);
		panel.add(availableFilterPanel, BorderLayout.SOUTH);

		addWorkPanel(panel);

		TableColumnModel columnModel = availableTable.getColumnModel();
		TableColumn numCol = columnModel.getColumn(AvailableRegisterTableColumns.NUMBER.ordinal());
		numCol.setPreferredWidth(1);
		TableColumn selCol =
			columnModel.getColumn(AvailableRegisterTableColumns.SELECTED.ordinal());
		selCol.setPreferredWidth(20);
		TableColumn nameCol = columnModel.getColumn(AvailableRegisterTableColumns.NAME.ordinal());
		nameCol.setPreferredWidth(40);
		TableColumn bitsCol = columnModel.getColumn(AvailableRegisterTableColumns.BITS.ordinal());
		bitsCol.setPreferredWidth(30);
		TableColumn knownCol = columnModel.getColumn(AvailableRegisterTableColumns.KNOWN.ordinal());
		knownCol.setPreferredWidth(20);
		TableColumn groupCol = columnModel.getColumn(AvailableRegisterTableColumns.GROUP.ordinal());
		groupCol.setPreferredWidth(40);
		TableColumn containsCol =
			columnModel.getColumn(AvailableRegisterTableColumns.CONTAINS.ordinal());
		containsCol.setPreferredWidth(20);
		TableColumn parentCol =
			columnModel.getColumn(AvailableRegisterTableColumns.PARENT.ordinal());
		parentCol.setPreferredWidth(30);

		addOKButton();
		addCancelButton();

		createActions();

		availableTable.getSelectionModel().addListSelectionListener(evt -> updateActionContext());
	}

	protected void updateActionContext() {
		List<AvailableRegisterRow> sel = availableFilterPanel.getSelectedItems();
		if (sel == null || sel.isEmpty()) {
			myActionContext = null;
		}
		else {
			myActionContext = new DebuggerAvailableRegistersActionContext(sel);
		}
		notifyContextChanged();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected void createActions() {
		addAction(actionAdd = createActionAdd());
		addAction(actionRemove = createActionRemove());
		notifyContextChanged();
	}

	private DockingAction createActionAdd() {
		return DebuggerResources.AddAction.builder(provider.plugin)
				.withContext(DebuggerAvailableRegistersActionContext.class)
				.enabledWhen(ctx -> !ctx.getSelection().isEmpty())
				.onAction(ctx -> addSelection(ctx.getSelection()))
				.build();
	}

	private DockingAction createActionRemove() {
		return DebuggerResources.RemoveAction.builder(provider.plugin)
				.withContext(DebuggerAvailableRegistersActionContext.class)
				.enabledWhen(ctx -> !ctx.getSelection().isEmpty())
				.onAction(ctx -> removeSelection(ctx.getSelection()))
				.build();
	}

	protected void setAvailable(List<Register> regs) {
		regMap.clear();
		availableTableModel.clear();
		for (int i = 0; i < regs.size(); i++) {
			Register reg = regs.get(i);
			AvailableRegisterRow ar = new AvailableRegisterRow(i, reg);
			regMap.put(reg, ar);
			availableTableModel.add(ar);
		}
	}

	public void setLanguage(Language language) {
		if (this.language == language) {
			return;
		}
		this.language = language;
		if (language == null) {
			setAvailable(List.of());
		}
		else {
			setAvailable(language.getRegisters());
		}
	}

	protected void clearKnown() {
		for (AvailableRegisterRow ar : regMap.values()) {
			ar.setKnown(false);
		}
	}

	public void setKnown(Collection<Register> known) {
		clearKnown();
		if (known == null) {
			availableTableModel.fireTableDataChanged();
			return;
		}
		for (Register reg : known) {
			AvailableRegisterRow ar = regMap.get(reg);
			if (ar == null) {
				throw new IllegalArgumentException(
					"Register " + reg + " is not in current language");
			}
			ar.setKnown(true);
		}
		availableTableModel.fireTableDataChanged();
	}

	protected void clearSelection() {
		for (AvailableRegisterRow ar : regMap.values()) {
			ar.setSelected(false);
		}
	}

	public void setSelection(Collection<Register> selection) {
		clearSelection();
		if (selection == null) {
			availableTableModel.fireTableDataChanged();
			return;
		}
		for (Register reg : selection) {
			AvailableRegisterRow ar = regMap.get(reg);
			if (ar == null) {
				throw new IllegalArgumentException(
					"Register " + reg + " is not in current language");
			}
			ar.setSelected(true);
		}
		availableTableModel.fireTableDataChanged();
	}

	protected void addSelection(Collection<AvailableRegisterRow> selection) {
		if (selection == null) {
			return;
		}
		for (AvailableRegisterRow ar : selection) {
			ar.setSelected(true);
		}
		availableTableModel.fireTableDataChanged();
	}

	protected void removeSelection(Collection<AvailableRegisterRow> selection) {
		if (selection == null) {
			return;
		}
		for (AvailableRegisterRow ar : selection) {
			ar.setSelected(false);
		}
		availableTableModel.fireTableDataChanged();
	}

	@Override
	protected void okCallback() {
		LinkedHashSet<Register> selected = new LinkedHashSet<>();
		for (AvailableRegisterRow row : availableTableModel.getModelData()) {
			if (!row.isSelected()) {
				continue;
			}
			selected.add(row.getRegister());
		}
		provider.setSelectedRegistersAndLoad(selected);
		close();
	}
}
