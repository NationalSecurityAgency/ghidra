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

import docking.ActionContext;
import docking.ReusableDialogComponentProvider;
import docking.action.DockingAction;
import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerAvailableRegistersDialog extends ReusableDialogComponentProvider {

	protected enum AvailableRegisterTableColumns
		implements EnumeratedTableColumn<AvailableRegisterTableColumns, AvailableRegisterRow> {
		SELECTED("", Boolean.class, AvailableRegisterRow::isSelected,
				AvailableRegisterRow::setSelected) {
			@Override
			public int getMaxWidth() {
				return 30;
			}

			@Override
			public int getMinWidth() {
				return 30;
			}
		},
		NUMBER("#", Integer.class, AvailableRegisterRow::getNumber) {
			@Override
			public int getPreferredWidth() {
				return 1;
			}
		},
		NAME("Name", String.class, AvailableRegisterRow::getName) {
			@Override
			public int getPreferredWidth() {
				return 40;
			}
		},
		BITS("Bits", Integer.class, AvailableRegisterRow::getBits) {
			@Override
			public int getPreferredWidth() {
				return 30;
			}
		},
		KNOWN("Known", Boolean.class, AvailableRegisterRow::isKnown) {
			@Override
			public int getPreferredWidth() {
				return 20;
			}
		},
		GROUP("Group", String.class, AvailableRegisterRow::getGroup) {
			@Override
			public int getPreferredWidth() {
				return 40;
			}
		},
		CONTAINS("Contains", String.class, AvailableRegisterRow::getContains) {
			@Override
			public int getPreferredWidth() {
				return 20;
			}
		},
		PARENT("Parent", String.class, AvailableRegisterRow::getParentName) {
			@Override
			public int getPreferredWidth() {
				return 30;
			}
		};

		private final String header;
		private final Class<?> cls;
		private final Function<AvailableRegisterRow, ?> getter;
		private final BiConsumer<AvailableRegisterRow, Object> setter;

		<T> AvailableRegisterTableColumns(String header, Class<T> cls,
				Function<AvailableRegisterRow, T> getter) {
			this(header, cls, getter, null);
		}

		@SuppressWarnings("unchecked")
		<T> AvailableRegisterTableColumns(String header, Class<T> cls,
				Function<AvailableRegisterRow, T> getter,
				BiConsumer<AvailableRegisterRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<AvailableRegisterRow, Object>) setter;
		}

		@Override
		public String getHeader() {
			return header;
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
		public boolean isEditable(AvailableRegisterRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(AvailableRegisterRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class AvailableRegistersTableModel extends
			DefaultEnumeratedColumnTableModel<AvailableRegisterTableColumns, AvailableRegisterRow> {
		public AvailableRegistersTableModel(PluginTool tool) {
			super(tool, "Available Registers", AvailableRegisterTableColumns.class);
		}

		@Override
		public List<AvailableRegisterTableColumns> defaultSortOrder() {
			return List.of(AvailableRegisterTableColumns.NUMBER);
		}
	}

	private final DebuggerRegistersProvider provider;

	private Language language;

	/* testing */ final AvailableRegistersTableModel availableTableModel;
	private final Map<Register, AvailableRegisterRow> regMap = new HashMap<>();

	private GTable availableTable;
	private GhidraTableFilterPanel<AvailableRegisterRow> availableFilterPanel;

	ActionContext myActionContext;

	DockingAction actionAdd;
	DockingAction actionRemove;

	protected DebuggerAvailableRegistersDialog(DebuggerRegistersProvider provider) {
		super(DebuggerResources.SelectRegistersAction.NAME, true, true, true, false);
		this.provider = provider;

		availableTableModel = new AvailableRegistersTableModel(provider.getTool());
		populateComponents();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		availableTable = new GTable(availableTableModel);
		// Selection is actually via checkboxes
		availableTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		availableTable.getAccessibleContext().setAccessibleName("Selection Choices");
		panel.add(new JScrollPane(availableTable));
		availableTable.setAutoLookupColumn(AvailableRegisterTableColumns.NAME.ordinal());

		availableFilterPanel = new GhidraTableFilterPanel<>(availableTable, availableTableModel);
		availableFilterPanel.getAccessibleContext().setAccessibleName("Available Filters");
		panel.add(availableFilterPanel, BorderLayout.SOUTH);
		panel.getAccessibleContext().setAccessibleName("Available Debugger Registers");
		addWorkPanel(panel);

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
