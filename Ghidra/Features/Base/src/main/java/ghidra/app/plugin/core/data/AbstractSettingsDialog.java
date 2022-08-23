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
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GComboBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.StringChoices;
import docking.widgets.table.*;
import docking.widgets.textfield.IntegerTextField;
import ghidra.docking.settings.*;
import ghidra.framework.preferences.Preferences;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;

public abstract class AbstractSettingsDialog extends DialogComponentProvider {

	private final static int WIDTH = 400;
	private final static int HEIGHT = 150;

	private static String[] BOOLEAN_CHOICES = { "yes", "no" };
	private static String NO_CHOICE = "";

	private SettingsDefinition[] settingsDefinitions;
	private Settings defaultSettings;	// may be null
	private SettingsImpl settings;		// holder for setting edits

	private SettingsTableModel settingsTableModel;
	private SettingsTable settingsTable;

	private Map<String, Boolean> intHexModeMap; // used to track/cache integer hex mode preference per setting
	private boolean appliedSettings;

	/**
	 * Construct a Settings dialog.  If original settings are null, all initial settings
	 * values will be blank and no default specified.
	 * @param title dialog title
	 * @param settingDefinitions settings definitions to be displayed
	 * @param originalSettings original settings to be modified may (may be null)
	 */
	protected AbstractSettingsDialog(String title, SettingsDefinition[] settingDefinitions,
			Settings originalSettings) {
		super(title, true, false, true, false);
		this.settingsDefinitions = settingDefinitions;
		settings = new SettingsImpl(originalSettings) {
			public boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
				return originalSettings == null ||
					originalSettings.isChangeAllowed(settingsDefinition);
			}
		};
		defaultSettings = settings.getDefaultSettings();
		if (originalSettings != null && defaultSettings == null) {
			// ensure we have defaults to facilitate revert to default
			defaultSettings = new SettingsImpl();
			settings.setDefaultSettings(defaultSettings);
		}
		buildPanel();
	}

	/**
	 * Get settings definitions specified with dialog construction
	 * @return settings definitions
	 */
	protected SettingsDefinition[] getSettingsDefinitions() {
		return settingsDefinitions;
	}

	/**
	 * Get settings which contain modifications which may be applied to
	 * original settings.
	 * @return settings
	 */
	protected Settings getSettings() {
		return settings;
	}

	/**
	 * Get default setting specified with dialog construction
	 * @return settings or null if not specified
	 */
	protected Settings getDefaultSettings() {
		return defaultSettings;
	}

	GTable getSettingsTable() {
		return settingsTable;
	}

	SettingsTableModel getSettingsTableModel() {
		return settingsTableModel;
	}

	@Override
	public void dispose() {
		close();
		settingsDefinitions = null;
		defaultSettings = null;
		settings = null;
	}

	boolean hasSettings() {
		return settingsDefinitions.length != 0;
	}

	private void buildPanel() {
		addWorkPanel(buildWorkPanel());
		addButtons();
	}

	private void addButtons() {

		addOKButton();

		JButton newApplyButton = new JButton("Apply");
		newApplyButton.addActionListener(e -> apply());
		addButton(newApplyButton);

		addCancelButton();
	}

	private String getHexModePropertyName(SettingsDefinition settingsDef) {
		return settingsDef.getClass().getSimpleName() + ".hexMode";
	}

	private void readHexModePreferences() {
		intHexModeMap = new HashMap<>();
		for (int i = 0; i < settingsDefinitions.length; i++) {
			if (settingsDefinitions[i] instanceof NumberSettingsDefinition) {
				String propertyName = getHexModePropertyName(settingsDefinitions[i]);
				boolean hexMode = Boolean
						.valueOf(
					Preferences.getProperty(propertyName, Boolean.FALSE.toString()));
				intHexModeMap.put(settingsDefinitions[i].getName(), hexMode);
			}
		}
	}

	private void writeHexModePreferences() {
		boolean save = false;
		for (int i = 0; i < settingsDefinitions.length; i++) {
			if (settingsDefinitions[i] instanceof NumberSettingsDefinition) {
				boolean hexMode = intHexModeMap.get(settingsDefinitions[i].getName());
				String propertyName = getHexModePropertyName(settingsDefinitions[i]);
				if (hexMode != Boolean
						.valueOf(Preferences.getProperty(propertyName, Boolean.FALSE.toString()))) {
					Preferences.setProperty(propertyName, Boolean.toString(hexMode));
					save = true;
				}
			}
		}
		if (save) {
			Preferences.store();
		}
	}

	private boolean isHexModeEnabled(SettingsDefinition settingsDef) {
		return intHexModeMap.get(settingsDef.getName());
	}

	private JPanel buildWorkPanel() {
		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		readHexModePreferences();

		settingsTableModel = new SettingsTableModel(settingsDefinitions);
		settingsTableModel.addTableModelListener(e -> appliedSettings = false);
		settingsTable = new SettingsTable(settingsTableModel);
		settingsTable.setAutoscrolls(true);
		settingsTable.setRowSelectionAllowed(false);
		settingsTable.setColumnSelectionAllowed(false);

		// make the rows a bit taller to allow the integer text field editor to render correctly
		settingsTable.setRowHeight(22);

		// disable user sorting and column adding (we don't expect enough data to require sorting)
		settingsTable.getTableHeader().setReorderingAllowed(false);
		settingsTable.setColumnHeaderPopupEnabled(false);
		settingsTable.setUserSortingEnabled(false);

		settingsTable.setDefaultRenderer(Settings.class, new SettingsRenderer());
		settingsTable.setDefaultEditor(Settings.class, new SettingsEditor());

		JScrollPane scrollpane = new JScrollPane(settingsTable);
		scrollpane.setPreferredSize(new Dimension(WIDTH, HEIGHT));

		workPanel.add(scrollpane, BorderLayout.CENTER);

		boolean hasImmutableSettings = false;
		for (SettingsDefinition def : settingsDefinitions) {
			if (!settings.isChangeAllowed(def)) {
				hasImmutableSettings = true;
				break;
			}
		}
		if (hasImmutableSettings) {
			workPanel.add(new JLabel("* Immutable setting"), BorderLayout.SOUTH);
		}

		return workPanel;
	}

	@Override
	protected void cancelCallback() {
		settingsTable.editingStopped(null);
		close();
		dispose();
	}

	@Override
	protected void okCallback() {
		settingsTable.editingStopped(null);
		apply();
		close();
		dispose();
	}

	private void apply() {
		settingsTable.editingStopped(null);
		try {
			applySettings();
		}
		catch (CancelledException e) {
			return;
		}
		writeHexModePreferences();
		appliedSettings = true;
	}

	/**
	 * Get suggested string setting values from the original settings container.
	 * @param settingsDefinition string settings definition
	 * @return suggested string value (may be empty array or null)
	 */
	protected abstract String[] getSuggestedValues(StringSettingsDefinition settingsDefinition);

	/**
	 * Apply changes to settings.  This method must be ov
	 * @throws CancelledException thrown if apply operation cancelled
	 */
	protected abstract void applySettings() throws CancelledException;

	protected boolean isSettingsApplied() {
		return appliedSettings;
	}

	protected StringChoices getChoices(EnumSettingsDefinition def) {
		String[] choices = def.getDisplayChoices(settings);
		int currentChoice = def.getChoice(settings);
		if (defaultSettings == null) {
			choices = addNoChoice(choices);
			if (!def.hasValue(settings)) {
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

	protected StringChoices getChoices(BooleanSettingsDefinition def) {
		String[] choices = BOOLEAN_CHOICES;
		int currentChoice = def.getValue(settings) ? 0 : 1;
		if (defaultSettings == null) {
			choices = addNoChoice(choices);
			if (!def.hasValue(settings)) {
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

	protected void setChoice(Object value, EnumSettingsDefinition def) {
		StringChoices choices = (StringChoices) value;
		int selectedChoice = choices.getSelectedValueIndex();
		if (defaultSettings == null) {
			if (selectedChoice == 0) { // blank choosen
				settings.clearSetting(def.getName());
				return;
			}
			--selectedChoice;  // account for presence of No-Choice
		}
		def.setChoice(settings, selectedChoice);
	}

	protected void setChoice(Object value, BooleanSettingsDefinition def) {
		StringChoices choices = (StringChoices) value;
		int selectedChoice = choices.getSelectedValueIndex();
		if (defaultSettings == null) {
			if (selectedChoice == 0) { // blank choosen
				settings.clearSetting(def.getName());
				return;
			}
			--selectedChoice;  // account for presence of No-Choice
		}
		def.setValue(settings, selectedChoice == 0);
	}

	protected void setValue(Number value, NumberSettingsDefinition def) {
		if (value == null) {
			def.clear(settings);
		}
		else {
			def.setValue(settings, value.longValue());
		}
	}

	protected void setValue(String value, StringSettingsDefinition def) {
		if (value == null) {
			def.clear(settings);
		}
		else {
			def.setValue(settings, value);
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

	class SettingsTable extends GhidraTable {

		public SettingsTable(SettingsTableModel settingsTableModel) {
			super(settingsTableModel);
		}

		@Override
		public String getToolTipText(MouseEvent evt) {
			int col = this.columnAtPoint(evt.getPoint());
			if (col != 0) {
				return super.getToolTipText();
			}
			int row = this.rowAtPoint(evt.getPoint());
			SettingsRowObject rowObject = settingsTableModel.getRowObject(row);
			String description = rowObject.definition.getDescription();
			if (!description.isEmpty()) {
				return "<html>" + HTMLUtilities.escapeHTML(description) + "</html>";
			}
			return null;
		}
	}

	class SettingsRowObject {

		private SettingsDefinition definition;

		SettingsRowObject(SettingsDefinition definition) {
			this.definition = definition;
		}

		public String getName() {
			return definition.getName();
		}

		boolean isEditable() {
			return settings.isChangeAllowed(definition);
		}

		Object getSettingsObject() {
			if (definition instanceof EnumSettingsDefinition) {
				StringChoices choices = getChoices((EnumSettingsDefinition) definition);
				return choices;
			}
			else if (definition instanceof BooleanSettingsDefinition) {
				StringChoices choices = getChoices((BooleanSettingsDefinition) definition);
				return choices;
			}
			else if (definition instanceof NumberSettingsDefinition) {
				NumberSettingsDefinition def = (NumberSettingsDefinition) definition;
				if (defaultSettings == null && !def.hasValue(settings)) {
					return new NumberWrapper(null); // show blank value
				}
				return new NumberWrapper(def.getValue(settings));
			}
			else if (definition instanceof StringSettingsDefinition) {
				StringSettingsDefinition def = (StringSettingsDefinition) definition;
				if (defaultSettings == null && !def.hasValue(settings)) {
					return new StringWrapper(def, null); // show blank value
				}
				return new StringWrapper(def, def.getValue(settings));
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
			else if (definition instanceof NumberSettingsDefinition) {
				NumberSettingsDefinition def = (NumberSettingsDefinition) definition;
				return def.getValue(settings) == def.getValue(defaultSettings);
			}
			else if (definition instanceof StringSettingsDefinition) {
				StringSettingsDefinition def = (StringSettingsDefinition) definition;
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
			else if (definition instanceof NumberSettingsDefinition) {
				setValue((Number) value, (NumberSettingsDefinition) definition);
				return true;
			}
			else if (definition instanceof StringSettingsDefinition) {
				setValue((String) value, (StringSettingsDefinition) definition);
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
			if (col == 0) {
				return false;
			}
			SettingsRowObject rowObject = rows.get(row);
			return rowObject.isEditable();
		}

		@Override
		public int getColumnCount() {
			return defaultSettings != null ? 3 : 2;
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
					String name = t.getName();
					if (!t.isEditable()) {
						name += "*"; // append immutable indicator
					}
					return name;
				case 1:
					return t.getSettingsObject();
				case 2:
					return t.useDefault();
			}
			return null;
		}

		@Override
		public void setValueAt(Object value, int row, int col) {
			if (settings == null) {
				return; // dialog has been disposed
			}
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

	private String getIntegerString(Number num, NumberSettingsDefinition settingsDef) {
		long value = num.longValue();
		boolean decimalMode = !settingsDef.isHexModePreferred() && !isHexModeEnabled(settingsDef);
		if (!settingsDef.allowNegativeValue()) {
			byte[] bytes = BigEndianDataConverter.INSTANCE.getBytes(value);
			BigInteger unsignedValue = new BigInteger(1, bytes);
			if (decimalMode) {
				return unsignedValue.toString();
			}
			return "0x" + unsignedValue.toString(16);
		}
		if (decimalMode) {
			return Long.toString(value); // signed decimal
		}
		BigInteger signedValue = BigInteger.valueOf(value);
		String sign = "";
		if (signedValue.signum() < 0) {
			sign = "-";
			signedValue = signedValue.negate();
		}
		return sign + "0x" + signedValue.toString(16);
	}


	private class SettingsRenderer extends GTableCellRenderer {

		private Font originalFont;

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData tableData) {
			JLabel renderer = (JLabel) super.getTableCellRendererComponent(tableData);
			renderer.setAlignmentX(Component.LEFT_ALIGNMENT);
			if (originalFont != null) {
				renderer.setFont(originalFont);
			}
			else {
				originalFont = renderer.getFont();
			}

			Object value = tableData.getValue();
			if (value instanceof NumberWrapper) {
				Number n = ((NumberWrapper) value).value;
				if (n != null) {
					// A Renderer that will show number values the same as the integer text field
					// based upon retained hex mode preference
					SettingsRowObject rowObject = (SettingsRowObject) tableData.getRowObject();
					String valString =
						getIntegerString(n, (NumberSettingsDefinition) rowObject.definition);
					renderer.setText(valString);
				}
			}
			else if (value instanceof StringWrapper) {
				String str = ((StringWrapper) value).value;
				if (str == null) {
					renderer.setText("--default--");
					renderer.setFont(originalFont.deriveFont(Font.ITALIC));
				}
			}
			return renderer;
		}
	}
	
	private class NumberWrapper {

		final Number value; // may be null

		NumberWrapper(Number value) {
			this.value = value;
		}

		@Override
		public String toString() {
			return value == null ? "" : Long.toString(value.longValue());
		}
	}

	private class StringWrapper {

		final StringSettingsDefinition settingsDefinition;
		final String value; // may be null

		StringWrapper(StringSettingsDefinition settingsDefinition, String value) {
			this.value = value;
			this.settingsDefinition = settingsDefinition;
		}

		@Override
		public String toString() {
			return value == null ? "" : value;
		}

		StringChoices getStringChoices() {
			String[] suggestedValues = getSuggestedValues(settingsDefinition);
			if (suggestedValues == null) {
				return null;
			}
			return suggestedValues.length == 0 ? null : new StringChoices(suggestedValues);
		}
	}

	class StringSettingsComboBox extends GComboBox<String> {
		StringSettingsComboBox() {
			super();
		}
	}

	class SettingsEditor extends AbstractCellEditor implements TableCellEditor {

		final static int ENUM = 0;
		final static int BOOLEAN = 1;
		final static int NUMBER = 2;
		final static int STRING = 3;
		final static int STRING_WITH_SUGGESTIONS = 4;

		private int mode;
		private GhidraComboBox<String> comboBox = new GhidraComboBox<>();
		private IntegerTextField intTextField = new IntegerTextField();
		private JTextField textField = new JTextField();

		private SettingsRowObject rowobject;

		SettingsEditor() {
			comboBox.setEnterKeyForwarding(false);
			comboBox.addActionListener(e -> fireEditingStopped());
			intTextField.addChangeListener(e -> updateHexMode());
		}

		GhidraComboBox<String> getComboBox() {
			return comboBox; // used for testing
		}
		
		@Override
		public Object getCellEditorValue() {
			switch (mode) {
				case ENUM:
					return getComboBoxEnum();
				case BOOLEAN:
					return getComboBoxEnum();
				case NUMBER:
					return getNumber();
				case STRING:
				case STRING_WITH_SUGGESTIONS:
					return getString();
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

		private void updateHexMode() {
			intHexModeMap.put(rowobject.definition.getName(), intTextField.isHexMode());
		}

		private Number getNumber() {
			BigInteger currentValue = intTextField.getValue();
			if (currentValue == null) {
				return null;
			}
			return currentValue.longValue();
		}

		private String getString() {
			if (mode == STRING_WITH_SUGGESTIONS) {
				return comboBox.getEditor().getItem().toString();
			}
			String value = textField.getText().trim();
			return value.length() == 0 ? null : value;
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {
			rowobject = settingsTableModel.getRowObject(row);
			if (value instanceof StringChoices || value instanceof Boolean) {
				initComboBox((StringChoices) value);
				return comboBox;
			}
			if (value instanceof NumberWrapper) {
				initIntField(((NumberWrapper) value).value);
				return intTextField.getComponent();
			}
			if (value instanceof StringWrapper) {
				StringWrapper strWrapper = (StringWrapper) value;
				StringChoices strWithChoices = strWrapper.getStringChoices();
				if (strWithChoices == null) {
					initTextField(strWrapper.value);
					return textField;
				}
				initEditableComboBox(strWithChoices, strWrapper.value);
				return comboBox;
			}
			throw new AssertException(
				"SettingsEditor: " + value.getClass().getName() + " not supported");
		}

		private void initComboBox(StringChoices enuum) {
			mode = ENUM;
			comboBox.removeAllItems();
			comboBox.setEditable(false);
			String[] items = enuum.getValues();
			for (String item : items) {
				comboBox.addItem(item);
			}
			comboBox.setSelectedIndex(enuum.getSelectedValueIndex());
		}

		private void initEditableComboBox(StringChoices strChoices, String value) {
			mode = STRING_WITH_SUGGESTIONS;
			comboBox.removeAllItems();
			comboBox.setEditable(true);
			String[] items = strChoices.getValues();
			for (String item : items) {
				comboBox.addItem(item);
			}
			comboBox.getEditor().setItem(value);
		}

		private void initIntField(Number value) {
			mode = NUMBER;
			NumberSettingsDefinition def = (NumberSettingsDefinition) rowobject.definition;
			if (def.isHexModePreferred() || isHexModeEnabled(def)) {
				intTextField.setHexMode();
			}
			else {
				intTextField.setDecimalMode();
			}

			intTextField.setMaxValue(def.getMaxValue());
			intTextField.setAllowNegativeValues(def.allowNegativeValue());

			if (value == null) {
				intTextField.setValue(null);
			}
			else if (def.allowNegativeValue()) {
				intTextField.setValue(value.longValue());
			}
			else {
				byte[] bytes = BigEndianDataConverter.INSTANCE.getBytes(value.longValue());
				intTextField.setValue(new BigInteger(1, bytes));
			}
		}

		private void initTextField(String str) {
			mode = STRING;
			textField.setText(str);
		}

	}
}
