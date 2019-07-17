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
package ghidra.app.plugin.core.data;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GComboBox;
import docking.widgets.dialogs.StringChoices;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import ghidra.docking.settings.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.*;
import ghidra.program.util.InteriorSelection;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.*;

public class DataSettingsDialog extends DialogComponentProvider {

	private final static int WIDTH = 350;
	private final static int HEIGHT = 150;

	private static String[] BOOLEAN_CHOICES = { "yes", "no" };
	private static String NO_CHOICE = "";

	private String name;
	private Data data;					// Only set for single data unit mode
	private ProgramSelection selection; // Only set for data selection mode
	private DataType dataType;			// not set for data selection mode		
	private DataTypeComponent dtc;		// Only set for single data-type component mode
	private SettingsDefinition[] settingsDefs; // required
	private Settings defaultSettings;	// not set for data selection mode
	private SettingsImpl settings;		// required
	private boolean editingDefaults;

	private SettingsTableModel settingsTableModel;
	private GTable settingsTable;
	private boolean appliedSettings;
	private Program program;

	public DataSettingsDialog(Program program, ProgramSelection sel) throws CancelledException {
		super("Data Settings", true, false, true, false);
		this.program = program;
		this.selection = sel;

		settingsDefs = getCommonSettings();
		settings = new SettingsImpl();

		setHelpLocation(new HelpLocation("DataPlugin", "Data_Settings_OnSelection"));

		buildPanel();
	}

	public DataSettingsDialog(Program program, Data data) {
		super("Data Settings", true, false, true, false);
		this.data = data;
		this.program = program;
		dataType = data.getDataType();
		settingsDefs = dataType.getSettingsDefinitions();
		Data pdata = data.getParent();
		if (pdata != null) {
			DataType pdt = pdata.getBaseDataType();
			if (pdt instanceof Composite) {
				Composite comp = (Composite) pdt;
				this.dtc = comp.getComponent(data.getComponentIndex());
				setHelpLocation(new HelpLocation("DataPlugin", "SettingsOnStructureComponents"));
			}
		}
		if (dtc == null) {
			setHelpLocation(new HelpLocation("DataPlugin", "Data_Settings"));
		}

		settings = new SettingsImpl(data);
		defaultSettings = data.getDefaultSettings();
		settings.setDefaultSettings(defaultSettings);
		buildPanel();
	}

	public DataSettingsDialog(Program program, DataType dataType) {
		super("Data Settings", true, false, true, false);
		this.dataType = dataType;
		this.program = program;
		editingDefaults = true;
		settingsDefs = dataType.getSettingsDefinitions();
		settings = new SettingsImpl(dataType.getDefaultSettings());
		defaultSettings = dataType.getDefaultSettings();
		buildPanel();
		setHelpLocation(new HelpLocation("DataPlugin", "Default_Data_Settings"));
	}

	DataSettingsDialog(Program program, DataTypeComponent dtc) {
		super("Data Settings", true, false, true, false);
		this.dtc = dtc;
		this.program = program;
		editingDefaults = true;
		settingsDefs = dtc.getDataType().getSettingsDefinitions();
		settings = new SettingsImpl(dtc.getDefaultSettings());
		defaultSettings = dtc.getDefaultSettings();
		buildPanel();
		setHelpLocation(new HelpLocation("DataPlugin", "SettingsOnStructureComponents"));
	}

	GTable getSettingsTable() {
		return settingsTable;
	}

	SettingsTableModel getSettingsTableModel() {
		return settingsTableModel;
	}

	public void dispose() {
		close();
		program = null;
		data = null;
		dataType = null;
		dtc = null;
		settingsDefs = null;
		defaultSettings = null;
		settings = null;
	}

	boolean hasSettings() {
		return settingsDefs.length != 0;
	}

	private String constructTitle() {
		if (selection != null) {
			return "Common Settings for Selected Data";
		}
		StringBuffer nameBuf = new StringBuffer();
		if (data == null) {
			nameBuf.append("Default ");
		}
		if (dtc != null) {
			nameBuf.append(dtc.getDataType().getDisplayName());
			nameBuf.append(" Settings (");
			nameBuf.append(dtc.getParent().getDisplayName());
			nameBuf.append('.');
			String fname = dtc.getFieldName();
			if (fname == null) {
				fname = dtc.getDefaultFieldName();
			}
			nameBuf.append(fname);
			nameBuf.append(')');
		}
		else {
			nameBuf.append(dataType.getDisplayName());
			nameBuf.append(" Settings");
		}
		if (data != null) {
			nameBuf.append(" at ");
			nameBuf.append(data.getMinAddress().toString());
		}
		return nameBuf.toString();
	}

	private void buildPanel() {

		name = constructTitle();
		setTitle(name);
		addWorkPanel(buildWorkPanel());
		addButtons();
	}

	private void addButtons() {

		addOKButton();

		JButton newApplyButton = new JButton("Apply");
		newApplyButton.addActionListener(e -> applySettings());
		addButton(newApplyButton);

		addCancelButton();
	}

	private JPanel buildWorkPanel() {
		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		settingsTableModel = new SettingsTableModel(settingsDefs);
		settingsTableModel.addTableModelListener(e -> appliedSettings = false);
		settingsTable = new GhidraTable(settingsTableModel);
		settingsTable.setAutoscrolls(true);
		settingsTable.setRowSelectionAllowed(false);
		settingsTable.setColumnSelectionAllowed(false);

		// disable user sorting and column adding (we don't expect enough data to require sort
		// changes)
		settingsTable.getTableHeader().setReorderingAllowed(false);
		settingsTable.setColumnHeaderPopupEnabled(false);
		settingsTable.setUserSortingEnabled(false);

		settingsTable.setDefaultRenderer(Settings.class, new DefaultTableCellRenderer());
		settingsTable.setDefaultEditor(Settings.class, new SettingsEditor());

		JScrollPane scrollpane = new JScrollPane(settingsTable);
		scrollpane.setPreferredSize(new Dimension(WIDTH, HEIGHT));

		workPanel.add(scrollpane, BorderLayout.CENTER);

		return workPanel;
	}

	@Override
	protected void cancelCallback() {
		close();
		dispose();
	}

	@Override
	protected void okCallback() {
		applySettings();
		close();
		dispose();
	}

	/**
	 * Build an array of SettingsDefinitions which are shared across
	 * all defined data constrained by an address set.
	 *
	 * The presence of an instruction will result in the selectionContainsInstruction
	 * flag being set.
	 *
	 */
	private class CommonSettingsAccumulator extends Task {

		boolean cancelled = false;
		SettingsDefinition[] defsArray = new SettingsDefinition[0];

		CommonSettingsAccumulator() {
			super("Accumulating Data Settings", true, false, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			InteriorSelection interiorSelection = selection.getInteriorSelection();
			if (interiorSelection != null) {
				accumulateInteriorSettingsDefinitions(interiorSelection, monitor);
			}
			else {
				accumulateDataSettingsDefinitions(monitor);
			}
		}

		private void accumulateDataSettingsDefinitions(TaskMonitor monitor) {

			List<Class<? extends SettingsDefinition>> defClasses = new ArrayList<>();
			List<SettingsDefinition> defs = new ArrayList<>();

			Listing listing = program.getListing();
			DataIterator definedData = listing.getDefinedData(selection, true);
			if (!definedData.hasNext()) {
				return;
			}
			Data d = definedData.next();
			for (SettingsDefinition def : d.getDataType().getSettingsDefinitions()) {
				defs.add(def);
				defClasses.add(def.getClass());
			}

			while (!defClasses.isEmpty() && definedData.hasNext()) {
				if (monitor.isCancelled()) {
					cancelled = true;
					return;
				}
				d = definedData.next();
				removeMissingDefinitions(defClasses, defs,
					d.getDataType().getSettingsDefinitions());
			}
			defsArray = new SettingsDefinition[defs.size()];
			defs.toArray(defsArray);
		}

		private void accumulateInteriorSettingsDefinitions(InteriorSelection interiorSelection,
				TaskMonitor monitor) {

			List<Class<? extends SettingsDefinition>> defClasses = null;
			List<SettingsDefinition> defs = null;

			int[] from = interiorSelection.getFrom().getComponentPath();
			int[] to = interiorSelection.getTo().getComponentPath();

			Data dataComp = DataPlugin.getDataUnit(program, selection.getMinAddress(), from);
			if (dataComp == null || from.length != to.length) {
				return;
			}
			Data parent = dataComp.getParent();
			int fromIndex = from[from.length - 1];
			int toIndex = to[to.length - 1];
			for (int i = fromIndex; i <= toIndex; i++) {
				dataComp = parent.getComponent(i);
				if (dataComp == null) {
					break;
				}
				DataType dt = dataComp.getDataType();
				if (dt == DataType.DEFAULT) {
					continue;
				}
				SettingsDefinition[] settingsDefinitions = dt.getSettingsDefinitions();
				if (settingsDefinitions.length == 0) {
					return;
				}
				if (defClasses == null) {
					defClasses = new ArrayList<>();
					defs = new ArrayList<>();
					for (SettingsDefinition def : settingsDefinitions) {
						defs.add(def);
						defClasses.add(def.getClass());
					}
				}
				else {
					removeMissingDefinitions(defClasses, defs, settingsDefinitions);
				}
			}
			defsArray = new SettingsDefinition[defs.size()];
			defs.toArray(defsArray);
		}
	}

	private SettingsDefinition[] getCommonSettings() throws CancelledException {

		CommonSettingsAccumulator myTask = new CommonSettingsAccumulator();

		new TaskLauncher(myTask, getComponent());

		if (myTask.cancelled) {
			throw new CancelledException();
		}
		return myTask.defsArray;
	}

	private static void removeMissingDefinitions(
			List<Class<? extends SettingsDefinition>> defClasses, List<SettingsDefinition> defs,
			SettingsDefinition[] checkDefs) {

		for (int i = defClasses.size() - 1; i >= 0; i--) {
			Class<? extends SettingsDefinition> c = defClasses.get(i);
			boolean found = false;
			for (SettingsDefinition checkDef : checkDefs) {
				if (c.isAssignableFrom(checkDef.getClass())) {
					found = true;
					break;
				}
			}
			if (!found) {
				defClasses.remove(i);
				defs.remove(i);
			}
		}
	}

	private void applyCommonSettings() {

		// TODO: Use task since this could be big and slow

		InteriorSelection interiorSelection = selection.getInteriorSelection();
		if (interiorSelection == null) {
			CodeUnitIterator codeUnits = program.getListing().getCodeUnits(selection, true);
			while (codeUnits.hasNext()) {
				// TODO: check monitor
				CodeUnit cu = codeUnits.next();
				if ((cu instanceof Data) && ((Data) cu).isDefined()) {
					applySettingsToData((Data) cu);
				}
			}
			return;
		}

		int[] from = interiorSelection.getFrom().getComponentPath();
		int[] to = interiorSelection.getTo().getComponentPath();

		Data dataComp = DataPlugin.getDataUnit(program, selection.getMinAddress(), from);
		if (dataComp == null) {
			return;
		}
		Data parent = dataComp.getParent();
		int fromIndex = from[from.length - 1];
		int toIndex = to[to.length - 1];
		for (int i = fromIndex; i <= toIndex; i++) {
			dataComp = parent.getComponent(i);
			if (dataComp == null) {
				break;
			}
			DataType dt = dataComp.getDataType();
			if (dt == DataType.DEFAULT) {
				continue;
			}
			applySettingsToData(dataComp);
		}
	}

	private void applySettingsToData(Data dataTarget) {
		if (appliedSettings) {
			return;
		}
		for (SettingsDefinition settingsDef : settingsDefs) {
			if (selection != null && settings.getValue(settingsDef.getName()) == null) {
				continue; // No-Choice
			}

			if (settingsDef instanceof EnumSettingsDefinition) {
				EnumSettingsDefinition def = (EnumSettingsDefinition) settingsDef;

				int s = def.getChoice(settings);
				if (defaultSettings != null && s == def.getChoice(defaultSettings)) {
					def.clear(dataTarget);
				}
				else {
					def.setChoice(dataTarget, s);
				}
			}
			else if (settingsDef instanceof BooleanSettingsDefinition) {
				BooleanSettingsDefinition def = (BooleanSettingsDefinition) settingsDef;
				boolean s = def.getValue(settings);
				if (defaultSettings != null && s == def.getValue(defaultSettings)) {
					def.clear(dataTarget);
				}
				else {
					def.setValue(dataTarget, s);
				}
			}
			else {
				throw new AssertException();
			}
		}
	}

	private void applySettings() {
		int txId = program.startTransaction(name);
		boolean success = true;
		try {
			if (selection != null) {
				applyCommonSettings();
				appliedSettings = true;
			}
			else if (data != null) {
				applySettingsToData(data);
				appliedSettings = true;
			}
			else {
				Settings origDefSettings = null;
				if (dataType != null) {
					origDefSettings = dataType.getDefaultSettings();
				}
				else {
					origDefSettings = dtc.getDefaultSettings();
				}
//				String[] names = settings.getNames();
//				for (int i=0; i<names.length; i++) {
//					origDefSettings.setValue(names[i],
//									settings.getValue(names[i]));
//				}
				for (SettingsDefinition settingsDef : settingsDefs) {
					settingsDef.copySetting(settings, origDefSettings);
				}
			}
			success = true;
		}
		finally {
			program.endTransaction(txId, success);
		}
	}

	private StringChoices getChoices(EnumSettingsDefinition def) {
		String[] choices = def.getDisplayChoices(settings);
		int currentChoice = def.getChoice(settings);
		if (selection != null) {
			choices = addNoChoice(choices);
			if (settings.getValue(def.getName()) == null) {
				currentChoice = 0;
			}
			else {
				++currentChoice; // account for presence of No-Choice
			}
		}
		StringChoices choicesEnum = new StringChoices(choices);
		choicesEnum.setSelectedValue(currentChoice);
		return choicesEnum;
	}

	private StringChoices getChoices(BooleanSettingsDefinition def) {
		String[] choices = BOOLEAN_CHOICES;
		int currentChoice = def.getValue(settings) ? 0 : 1;
		if (selection != null) {
			choices = addNoChoice(choices);
			if (settings.getValue(def.getName()) == null) {
				currentChoice = 0;
			}
			else {
				++currentChoice; // account for presence of No-Choice
			}
		}
		StringChoices choicesEnum = new StringChoices(choices);
		choicesEnum.setSelectedValue(currentChoice);
		return choicesEnum;
	}

	private void setChoice(Object value, EnumSettingsDefinition def) {
		StringChoices choices = (StringChoices) value;
		int selectedChoice = choices.getSelectedValueIndex();
		if (selection != null) {
			if (selectedChoice == 0) {
				settings.clearSetting(def.getName());
				return;
			}
			--selectedChoice;  // account for presence of No-Choice
		}
		def.setChoice(settings, selectedChoice);

		// For selection case we must ensure that settings has a non-null value even for defaults
		if (selection != null && settings.getValue(def.getName()) == null) {
			settings.setValue(def.getName(), Long.valueOf(def.getChoice(settings)));
		}
	}

	private void setChoice(Object value, BooleanSettingsDefinition def) {
		StringChoices choices = (StringChoices) value;
		int selectedChoice = choices.getSelectedValueIndex();
		if (selection != null) {
			if (selectedChoice == 0) {
				settings.clearSetting(def.getName());
				return;
			}
			--selectedChoice;  // account for presence of No-Choice
		}
		def.setValue(settings, selectedChoice == 0);

		// For selection case we must ensure that settings has a non-null value even for defaults
		if (selection != null && settings.getValue(def.getName()) == null) {
			settings.setValue(def.getName(), def.getValue(settings));
		}
	}

	private String[] addNoChoice(String[] choices) {
		String[] newChoices = new String[choices.length + 1];
		newChoices[0] = NO_CHOICE;
		System.arraycopy(choices, 0, newChoices, 1, choices.length);
		return newChoices;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class SettingsRowObject {

		private SettingsDefinition definition;

		SettingsRowObject(SettingsDefinition definition) {
			this.definition = definition;
		}

		public String getName() {
			return definition.getName();
		}

		Object getSettingsChoices() {
			if (definition instanceof EnumSettingsDefinition) {
				StringChoices choices = getChoices((EnumSettingsDefinition) definition);
				return choices;
			}
			else if (definition instanceof BooleanSettingsDefinition) {
				StringChoices choices = getChoices((BooleanSettingsDefinition) definition);
				return choices;
			}
			return "<Unsupported>";
		}

		boolean useDefault() {
			if (definition instanceof EnumSettingsDefinition) {
				EnumSettingsDefinition def = (EnumSettingsDefinition) definition;
				return def.getChoice(settings) == def.getChoice(defaultSettings);
			}
			else if (definition instanceof BooleanSettingsDefinition) {
				BooleanSettingsDefinition def = (BooleanSettingsDefinition) definition;
				return def.getValue(settings) == def.getValue(defaultSettings);
			}
			return false;
		}

		boolean setSettingsChoice(Object value) {
			if (definition instanceof EnumSettingsDefinition) {
				setChoice(value, (EnumSettingsDefinition) definition);
				return true;
			}
			else if (definition instanceof BooleanSettingsDefinition) {
				setChoice(value, (BooleanSettingsDefinition) definition);
				return true;
			}
			return false;
		}

		void clear(SettingsImpl s) {
			definition.clear(s);
		}
	}

	private class SettingsTableModel extends AbstractSortedTableModel<SettingsRowObject> {

		private List<SettingsRowObject> rows = new ArrayList<>();

		SettingsTableModel(SettingsDefinition[] settingsDefs) {
			for (SettingsDefinition sd : settingsDefs) {
				rows.add(new SettingsRowObject(sd));
			}
		}

		@Override
		public List<SettingsRowObject> getModelData() {
			return rows;
		}

		@Override
		public String getName() {
			return "Settings Definition Model";
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return columnIndex == 0;
		}

		@Override
		public boolean isCellEditable(int row, int col) {
			return col != 0;
		}

		@Override
		public int getColumnCount() {
			return (selection != null || editingDefaults) ? 2 : 3;
		}

		@Override
		public String getColumnName(int col) {
			switch (col) {
				case 0:
					return "Name";
				case 1:
					return "Settings";
				case 2:
					return "Use Default";
			}
			return null;
		}

		// override this to force the correct cell editors to be used
		@Override
		public Class<?> getColumnClass(int col) {
			switch (col) {
				case 0:
					return String.class;
				case 1:
					return Settings.class;
				case 2:
					return Boolean.class;
			}
			return null;
		}

		@Override
		public Object getColumnValueForRow(SettingsRowObject t, int columnIndex) {
			switch (columnIndex) {
				case 0:
					return t.getName();
				case 1:
					return t.getSettingsChoices();
				case 2:
					return t.useDefault();
			}
			return null;
		}

		@Override
		public void setValueAt(Object value, int row, int col) {
			SettingsRowObject rowObject = rows.get(row);
			switch (col) {
				case 1:
					if (rowObject.setSettingsChoice(value)) {
						fireTableDataChanged();
					}
					break;
				case 2:
					if (((Boolean) value).booleanValue()) {
						rowObject.clear(settings);
						fireTableDataChanged();
					}
					break;
			}
		}
	}

	class SettingsEditor extends AbstractCellEditor implements TableCellEditor {

		final static int ENUM = 0;
		final static int BOOLEAN = 1;

		private int mode;
		private GComboBox<String> comboBox = new GComboBox<>();

		SettingsEditor() {
			comboBox.addItemListener(e -> fireEditingStopped());
		}

		GComboBox<String> getComboBox() {
			return comboBox;
		}

		@Override
		public Object getCellEditorValue() {
			switch (mode) {
				case ENUM:
					return getComboBoxEnum();
				case BOOLEAN:
					return getComboBoxEnum();
			}
			throw new AssertException();
		}

		private StringChoices getComboBoxEnum() {
			String[] items = new String[comboBox.getItemCount()];
			for (int i = 0; i < items.length; i++) {
				items[i] = comboBox.getItemAt(i);
			}
			StringChoices enuum = new StringChoices(items);
			enuum.setSelectedValue(comboBox.getSelectedIndex());
			return enuum;
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {
			if (value instanceof StringChoices || value instanceof Boolean) {
				initComboBox((StringChoices) value);
				return comboBox;
			}
			throw new AssertException(
				"SettingsEditor: " + value.getClass().getName() + " not supported");
		}

		private void initComboBox(StringChoices enuum) {
			mode = ENUM;
			comboBox.removeAllItems();
			String[] items = enuum.getValues();
			for (String item : items) {
				comboBox.addItem(item);
			}
			comboBox.setSelectedIndex(enuum.getSelectedValueIndex());
		}

	}
}
