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
package ghidra.app.util.bean;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumnModel;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filter.FilterListener;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.context.ListingActionContext;
/**
 * Dialog for Equate Plugin.
 * Allows the user to enter a name to be used for an equate at a location.
 * The dialog will present the user with a textfield to type in the new name. Additionally,
 * if other equates already exist for the value in question, they will be displayed in
 * a drop down comboBox. If the user types in an invalid equate name (the string is not
 * a valid name or the string is already associated with a different numeric value),
 * an error message will be displayed.  The user can choose whether to apply to current
 * cursor location only (default), or all scalars of the same value in a selection or
 * the entire program. Users also can indicate whether a setEquate should replace any
 * existing equates or only apply to new ones.
 */
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.ProgramSelection;
import ghidra.util.UniversalID;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.table.*;
import utility.function.Callback;

public class SetEquateDialog extends DialogComponentProvider {
	public static final int CANCELED = 0;
	public static final int OK = 1;

	public enum SelectionType {
		CURRENT_ADDRESS, SELECTION, ENTIRE_PROGRAM
	}

	private GhidraTable suggestedEquatesTable;
	private GhidraTableFilterPanel<EquateRowObject> filterPanel;
	private int result = CANCELED;
	private SetEquateTableModel model;
	private DataTypeManager dataTypeManager;
	private EquateTable equateTable;
	private JLabel titleLabel;
	private JRadioButton applyToCurrent;
	private JRadioButton applyToSelection;
	private JRadioButton applyToAll;
	private JCheckBox overwriteExistingEquates;

	private PluginTool tool;
	private Program program;
	private Scalar scalar;
	private EquateFilterListener filterListener = new EquateFilterListener();
	private EquateEnterListener enterListener = new EquateEnterListener();

	/**
	 * Constructor
	 *
	 * @param tool the EquatePlugin that launched this dialog(used to validate input)
	 * @param program the program the equate is located in.
	 * @param value the equate value to set.
	 */

	public SetEquateDialog(PluginTool tool, Program program, Scalar value) {
		super("Set Equate", true, true, true, false);
		this.tool = tool;
		this.program = program;
		this.scalar = value;
		this.dataTypeManager = program.getDataTypeManager();
		this.equateTable = program.getEquateTable();
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setRememberSize(false);
	}

	private void updateFilter() {
		suggestedEquatesTable.clearSelection();

		boolean isFiltered = filterPanel.isFiltered();
		int unfilteredSize = filterPanel.getUnfilteredRowCount();
		int filteredSize = filterPanel.getRowCount();

		if (isFiltered) {
			titleLabel.setText(
				"Possible matches (showing " + filteredSize + " of " + unfilteredSize + ")");
		}
		else {
			titleLabel.setText("Possible matches");
		}
	}

	private GhidraTableCellRenderer getRenderer() {
		// Colors everything in the table
		//
		// Blue entries are equates
		// Black entries are equates based off enums
		// Red entries are bad equates
		// Gray entries are suggestions that are not equates

		GhidraTableCellRenderer renderer = new GhidraTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				Component c = super.getTableCellRendererComponent(data);

				Object rowObject = data.getRowObject();
				boolean isSelected = data.isSelected();

				EquateRowObject eqRowObject = (EquateRowObject) rowObject;
				int refCount = eqRowObject.getRefCount();
				if (refCount > 0) {
					if (eqRowObject.getEntryName().contains(EquateManager.ERROR_TAG)) {
						c.setForeground(isSelected ? Color.WHITE : Color.RED);
					}
					else {
						Equate e = eqRowObject.getEquate();
						if (e != null && !e.isEnumBased()) {
							c.setForeground(isSelected ? Color.WHITE : Color.BLUE.brighter());
						}
					}
				}
				else {
					c.setForeground(isSelected ? Color.WHITE : Color.GRAY.darker());
				}
				return c;
			}
		};

		return renderer;
	}

	private List<EquateRowObject> getCurrentAndPotentialEquateNames() {
		// Creates a list of names, types, and reference counts.
		Set<EquateRowObject> entries = new HashSet<>();

		//
		// Adds the remaining equates with no Types associated with them.
		//
		// Note: This relies on Set to not add any entries that are equal() as we
		//       create them from the equate names.
		//

		entries.addAll(createEntriesFromEquateTable());
		entries.addAll(createEntriesFromDataTypeManager());

		return new ArrayList<>(entries);

	}

	private Set<EquateRowObject> createEntriesFromEquateTable() {
		List<Equate> allEquates = equateTable.getEquates(scalar.getValue());

		//@formatter:off
		return allEquates
			.stream()
			.filter(equate -> equate.isValidUUID())
			.map(equate -> new EquateRowObject(equate))
			.collect(Collectors.toSet());
		//@formatter:on
	}

	private Set<EquateRowObject> createEntriesFromDataTypeManager() {

		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		if (service == null) {
			return new HashSet<>();
		}

		Set<EquateRowObject> entries = new HashSet<>();

		//@formatter:off
		service.getSortedDataTypeList()
			.stream()
			.filter(dt -> dt instanceof Enum)
			.map(Enum.class::cast)
			.filter(enoom -> enoom.getName(scalar.getValue()) != null)
			.forEach(enoom -> {
				String name = enoom.getName(scalar.getValue());
				entries.add(new EquateRowObject(name, enoom));
			});
		//@formatter:on

		return entries;
	}

	/**
	 * Builds the main panel of the dialog and returns it.
	 */
	protected JPanel buildMainPanel() {

		titleLabel = new GDLabel("Possible Matches");
		titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

		//long value = scalar.getSignedValue();
		applyToCurrent = new GRadioButton("Current location", true);
		applyToCurrent.setName("applyToCurrent");
		applyToCurrent.setToolTipText("Apply to current scalar operand only");

		applyToSelection = new GRadioButton("Current selection", false);
		applyToSelection.setName("applyToSelection");
		applyToSelection.setToolTipText(
			"Apply to all matching, defined scalar code " + "units in current selection.");

		applyToAll = new GRadioButton("Entire program", false);
		applyToAll.setName("applyToAll");
		applyToAll.setToolTipText(
			"Apply to all matching, defined scalar code units " + "in entire program.");

		ButtonGroup group = new ButtonGroup();
		group.add(applyToCurrent);
		group.add(applyToSelection);
		group.add(applyToAll);

		overwriteExistingEquates = new GCheckBox("Overwrite existing equates", false);
		overwriteExistingEquates.setName("Overwrite");
		overwriteExistingEquates.setEnabled(false);
		overwriteExistingEquates.setToolTipText("If checked, apply equates to all unmarked " +
			"scalars and overwrite any existing equates of the same value in the " +
			"current selection or entire program depending on which option is selected. " +
			"If not checked, only apply equates to unmarked scalars.");

		applyToCurrent.addActionListener(evt -> {
			overwriteExistingEquates.setEnabled(!applyToCurrent.isSelected());
			if (applyToCurrent.isSelected()) {
				overwriteExistingEquates.setSelected(false);
			}
		});

		applyToSelection.addActionListener(
			evt -> overwriteExistingEquates.setEnabled(applyToSelection.isSelected()));

		applyToAll.addActionListener(
			evt -> overwriteExistingEquates.setEnabled(applyToAll.isSelected()));

		List<EquateRowObject> equateNames = getCurrentAndPotentialEquateNames();
		model = new SetEquateTableModel(tool, equateNames, program);
		suggestedEquatesTable = new GhidraTable(model);
		suggestedEquatesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		JPanel tablePanel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(suggestedEquatesTable);
		tablePanel.add(scrollPane);

		suggestedEquatesTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				int index = suggestedEquatesTable.columnAtPoint(e.getPoint());
				if (index >= 0) {
					if (e.getClickCount() == 2) {
						okCallback();
					}
				}
			}
		});
		tablePanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 5, 5));

		filterPanel =
			new GhidraTableFilterPanel<>(suggestedEquatesTable, model, " Equate String: ");
		model.addTableModelListener(evt -> updateFilter());

		GhidraTableCellRenderer renderer = getRenderer();
		TableColumnModel tcm = suggestedEquatesTable.getColumnModel();
		for (int i = 0; i < model.getColumnCount(); i++) {
			tcm.getColumn(i).setCellRenderer(renderer);
		}

		filterPanel.addFilterChagnedListener(filterListener);
		filterPanel.addEnterListener(enterListener);

		JPanel northPanel = new JPanel(new VerticalLayout(2));
		String labelText = "Scalar Value:  " + scalar.toString(16, false, true, "0x", "") + " (" +
			scalar.toString(10, false, true, "", "") + ")";
		JLabel label = new GLabel(labelText);
		label.setName("EquateField");
		label.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
		northPanel.add(label);
		northPanel.add(titleLabel);
		northPanel.add(filterPanel);
		northPanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 0, 5));

		JPanel scopePanel = new JPanel(new HorizontalLayout(2));
		scopePanel.setBorder(BorderFactory.createEmptyBorder(10, 5, 0, 5));

		scopePanel.add(new GLabel("Apply To: "));
		scopePanel.add(applyToCurrent);
		scopePanel.add(applyToSelection);
		scopePanel.add(applyToAll);

		JPanel optionsPanel = new JPanel(new HorizontalLayout(2));
		optionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));

		optionsPanel.add(new GLabel("Options: "));
		optionsPanel.add(overwriteExistingEquates);

		JPanel southPanel = new JPanel(new VerticalLayout(0));
		southPanel.add(scopePanel);
		southPanel.add(optionsPanel);

		JPanel mainPanel = new JPanel() {
			@Override
			public Dimension getPreferredSize() {
				return new Dimension(700, 400);
			}
		};
		mainPanel.setLayout(new BorderLayout());
		mainPanel.setSize(mainPanel.getPreferredSize());
		mainPanel.add(northPanel, BorderLayout.NORTH);
		mainPanel.add(tablePanel, BorderLayout.CENTER);
		mainPanel.add(southPanel, BorderLayout.SOUTH);

		return mainPanel;
	}

	/**
	 * Invoke the dialog.
	 * @return the exit condition of the dialog.  The return value can be one of:
	 * CANCELED - the user canceled the action.
	 * OK - the user pressed the "Ok" button or pressed the return key in the textfield.
	 */
	public int showSetDialog() {
		result = CANCELED;
		overwriteExistingEquates.setVisible(true);
		setTitle("Set Equate");
		tool.showDialog(this);
		return result;
	}

	/**
	 * Invoke the dialog.
	 *
	 * @return the exit condition of the dialog.  The return value can be one of:
	 * CANCELED - the user canceled the action.
	 * OK - the user pressed the "Ok" button or pressed the return key in the textfield.
	 */
	public int showRenameDialog() {
		result = CANCELED;
		overwriteExistingEquates.setVisible(false);
		overwriteExistingEquates.setEnabled(false);
		setTitle("Rename Equate");
		tool.showDialog(this);
		return result;
	}

	/**
	 * Get the Equate Name entered or chosen by the user.
	 */
	public String getEquateName() {
		EquateRowObject equateEntry = getRowObject();
		if (equateEntry != null) {
			return equateEntry.getEntryName();
		}
		String equateFromFilter = filterPanel.getFilterText();
		if (StringUtils.isBlank(equateFromFilter)) {
			equateFromFilter = null;
		}
		return equateFromFilter;
	}

	/**
	 * Get's the user selected entry in the dialog and returns the enum data type for that entry
	 * @return the enum data type for the selected entry, or null if there is no enum.
	 */
	public Enum getEnumDataType() {
		EquateRowObject equateEntry = getRowObject();
		return (equateEntry != null) ? equateEntry.getEnumDataType() : null;
	}

	private EquateRowObject getRowObject() {
		EquateRowObject equateEntry = filterPanel.getSelectedItem();

		// A selection was made in the table
		if (equateEntry != null) {
			return equateEntry;
		}

		// Nothing was typed or selected; return null.
		String equateFromFilter = filterPanel.getFilterText();
		if (StringUtils.isBlank(equateFromFilter)) {
			return null;
		}

		// If text field equals only one match, use that match.
		EquateRowObject match = getMatchFromTable(equateFromFilter);
		if (match != null) {
			return match;
		}
		return null;
	}

	private EquateRowObject getMatchFromTable(String name) {
		//@formatter:off
		Optional<EquateRowObject> getMatch = getCurrentAndPotentialEquateNames().stream()
			.filter(entry -> entry.getEntryName().equals(name))
			.findFirst();
		//@formatter:on

		if (getMatch.isPresent()) {
			EquateRowObject rowObject = getMatch.get();
			return rowObject;
		}
		return null;
	}

	/**
	 * Returns the type of selection the user has chosen.
	 *
	 * @return
	 */
	public SelectionType getSelectionType() {
		if (applyToAll.isSelected()) {
			return SelectionType.ENTIRE_PROGRAM;
		}
		else if (applyToSelection.isSelected()) {
			return SelectionType.SELECTION;
		}
		else {
			return SelectionType.CURRENT_ADDRESS;
		}
	}

	/**
	 * Returns true if the user has chosen to overwrite any existing equate rules.
	 *
	 * @return
	 */
	public boolean getOverwriteExisting() {
		return overwriteExistingEquates.isSelected();
	}

	/**
	 * Set the state of the some buttons on the dialog.  ie: if the user has selected
	 * a range of addresses we should automatically set the "selection" radio button
	 * to the selected state.
	 *
	 * @param context The current context.
	 */
	public void setHasSelection(ListingActionContext context) {
		ProgramSelection selection = context.getSelection();
		boolean hasSelection = selection != null && !selection.isEmpty();
		applyToSelection.setEnabled(hasSelection);
		applyToSelection.setSelected(hasSelection && selection.contains(context.getAddress()));
		overwriteExistingEquates.setEnabled(!applyToCurrent.isSelected());
	}

	/**
	 * Sets the dialogs status display to the given message.
	 */
	void setStatus(String text) {
		this.setStatusText(text);
	}

	/**
	 * Called when user selects OK button
	 */
	@Override
	protected void okCallback() {
		if (isValid(this.getEquateName(), scalar)) {
			result = OK;
			close();
		}
		else {
			filterPanel.requestFocus();
		}
	}

	private boolean isValid(String equateStr, Scalar testScalar) {
		// these are valid in the sense that they represent a clear or remove operation.
		if (StringUtils.isBlank(equateStr)) {
			return true;
		}

		// look up the new equate string
		Equate newEquate = equateTable.getEquate(equateStr);

		if (newEquate != null && getEnumDataType() == null) {
			// make sure any existing equate with that name has the same value.
			if (newEquate.getValue() != testScalar.getValue()) {
				setStatus("Equate " + equateStr + " exists with value 0x" +
					Long.toHexString(newEquate.getValue()) + " (" + newEquate.getValue() + ")");
				return false;
			}
		}
		return true;
	}

	private Enum getEnumWithUUID(UniversalID id) {
		return (Enum) dataTypeManager.findDataTypeForID(id);
	}

	/**
	 * Called when user selects Cancel Button.
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	public void dispose() {
		suggestedEquatesTable.dispose();
		filterPanel.dispose();
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	public class EquateRowObject {
		private String entryName;
		private String path;
		private int refCount;
		private UniversalID dataTypeUUID;
		private Equate equate;
		private Enum enoom;

		EquateRowObject(String name, Enum enoom) {// Equate based off enum
			long value = scalar.getValue();
			if (enoom == null) {
				return;
			}

			this.enoom = enoom;
			this.entryName = enoom.getName(value);
			this.dataTypeUUID = enoom.getUniversalID();
			this.path = getFullPath(enoom);
			String formattedEquateName = EquateManager.formatNameForEquate(dataTypeUUID, value);
			this.equate = equateTable.getEquate(formattedEquateName);
			if (equate != null) {
				this.refCount = equate.getReferenceCount();
			}
		}

		EquateRowObject(Equate equate) { // Old existing equates
			UniversalID id = equate.getEnumUUID();
			this.equate = equate;
			this.entryName = equate.getDisplayName();
			this.refCount = equate.getReferenceCount();

			if (id != null && equate.isValidUUID()) {
				this.dataTypeUUID = id;
				this.enoom = getEnumWithUUID(id);
				this.path = getFullPath(enoom);
			}
		}

		public Equate getEquate() {
			return equate;
		}

		public String getEntryName() {
			return entryName;
		}

		public String getPath() {
			return path;
		}

		private String getFullPath(Enum theEnum) {
			if (theEnum == null) {
				return null;
			}
			String rootCategory = theEnum.getDataTypeManager().getRootCategory().getName();
			String fullCategoryPath = rootCategory + theEnum.getCategoryPath().getPath();
			if (!fullCategoryPath.endsWith("defines")) {
				// Defines data types don't need to repeat themselves inside the path.
				return rootCategory + theEnum.getDataTypePath().getPath();
			}
			return fullCategoryPath;
		}

		public int getRefCount() {
			return refCount;
		}

		public Enum getEnumDataType() {
			return enoom;
		}

		@Override
		public String toString() {
			//@formatter:off
			String dtName = enoom == null ? "<no data type>" : enoom.getName();
			return "{\n" +
				"\tname: " + entryName + ",\n" +
				"\tdata type: " + dtName + ",\n" +
				"\trefs: " + refCount + "\n" +
			"}";
			//@formatter:on
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int hashResult = 1;
			hashResult = prime * hashResult + getOuterType().hashCode();
			hashResult = prime * hashResult + ((entryName == null) ? 0 : entryName.hashCode());
			return hashResult;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (!(obj instanceof EquateRowObject)) {
				return false;
			}

			EquateRowObject other = (EquateRowObject) obj;
			if (!getOuterType().equals(other.getOuterType())) {
				return false;
			}
			if (enoom == null || !enoom.isEquivalent(other.getEnumDataType())) {
				return false;
			}
			return true;
		}

		private SetEquateDialog getOuterType() {
			return SetEquateDialog.this;
		}

	}

	private class EquateFilterListener implements FilterListener {

		@Override
		public void filterChanged(String text) {
			suggestedEquatesTable.getSelectionManager().clearSavedSelection();
		}
	}

	private class EquateEnterListener implements Callback {

		@Override
		public void call() {
			okCallback();
		}

	}

}
