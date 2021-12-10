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
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.table.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

/**
 * A dialog that allows the user to create a new structure based upon providing
 * a new name or by using the name of an existing structure.
 *
 *
 */
public class CreateStructureDialog extends DialogComponentProvider {
	private static final String NEW_STRUCTURE_STATUS_PREFIX = "Creating new structure: ";
	private static final String EXISITING_STRUCTURE_STATUS_PREFIX = "Using existing structure: ";

	private static final String STRUCTURE_COLUMN_NAME = "Structure";
	private static final String PATH_COLUMN_NAME = "Path";

	private JTextField nameTextField;
	private GhidraTable matchingStructuresTable;
	private StructureTableModel structureTableModel;
	private Structure currentStructure;
	private Program currentProgram;
	private PluginTool pluginTool;

	private TitledBorder nameBorder;
	private TitledBorder structureBorder;
	private JRadioButton exactMatchButton;
	private JRadioButton sizeMatchButton;
	private GhidraTableFilterPanel<StructureWrapper> filterPanel;

	/**
	 * Creates a new dialog with the given parent.
	 *
	 * @param tool The current tool that this dialog needs to access services.
	 */
	public CreateStructureDialog(PluginTool tool) {
		super("Create Structure", true, true, true, false);

		pluginTool = tool;
		setHelpLocation(new HelpLocation("DataPlugin", "Create_Structure_Dialog"));

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();

		rootPanel.setPreferredSize(new Dimension(600, 600));
		setDefaultButton(okButton);
	}

	@Override
	public void dispose() {
		currentProgram = null;
		filterPanel.dispose();
		super.dispose();
	}

	private JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

		mainPanel.add(buildNameTextFieldPanel());
		mainPanel.add(Box.createVerticalStrut(10));

		mainPanel.add(buildMatchingStructurePanel());

		setStatusJustification(SwingConstants.LEFT);
		setCreateStructureByName(true);

		return mainPanel;
	}

	private JPanel buildNameTextFieldPanel() {
		JPanel namePanel = new JPanel();
		namePanel.setLayout(new BoxLayout(namePanel, BoxLayout.Y_AXIS));
		nameBorder = BorderFactory.createTitledBorder("Create Structure By Name");
		namePanel.setBorder(nameBorder);

		nameTextField = new JTextField() {
			// make sure our height doesn't stretch
			@Override
			public Dimension getMaximumSize() {
				Dimension d = super.getMaximumSize();
				d.height = getPreferredSize().height;
				return d;
			}
		};
		nameTextField.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent event) {
				setCreateStructureByName(true);
				nameTextField.requestFocus();
			}
		});
		namePanel.add(nameTextField);

		nameTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent event) {
				checkText(event.getDocument());
			}

			@Override
			public void insertUpdate(DocumentEvent event) {
				checkText(event.getDocument());
			}

			@Override
			public void removeUpdate(DocumentEvent event) {
				checkText(event.getDocument());
			}

			private void checkText(Document document) {
				try {
					String text = document.getText(0, document.getLength());
					if ((text == null) || (text.trim().length() == 0)) {
						okButton.setEnabled(false);
						updateStatusText(true, null);
					}
					else {
						okButton.setEnabled(true);
						updateStatusText(true, text);
					}
				}
				catch (BadLocationException ble) {
					// nothing we can do here
				}
			}
		});

		return namePanel;
	}

	private JPanel buildMatchingStructurePanel() {
		JPanel structurePanel = new JPanel();
		structurePanel.setLayout(new BoxLayout(structurePanel, BoxLayout.Y_AXIS));
		structureBorder = BorderFactory.createTitledBorder("Use Existing Structure");
		structurePanel.setBorder(structureBorder);

		GTable table = buildMatchingStructuresTable();
		filterPanel = new GhidraTableFilterPanel<>(table, structureTableModel) {
			// make sure our height doesn't stretch
			@Override
			public Dimension getMaximumSize() {
				Dimension d = super.getMaximumSize();
				d.height = getPreferredSize().height;
				return d;
			}
		};

		JScrollPane scrollPane = new JScrollPane(table);
		structurePanel.add(scrollPane);
		structurePanel.add(Box.createVerticalStrut(10));
		structurePanel.add(filterPanel);
		structurePanel.add(Box.createVerticalStrut(10));
		structurePanel.add(buildMatchingStyelPanel());
		structurePanel.add(Box.createVerticalStrut(10));

		return structurePanel;
	}

	private GTable buildMatchingStructuresTable() {
		structureTableModel = new StructureTableModel();
		matchingStructuresTable = new GhidraTable(structureTableModel);
		matchingStructuresTable.setAutoLookupColumn(0);
		matchingStructuresTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		matchingStructuresTable.setAutoCreateColumnsFromModel(false);
		matchingStructuresTable.setPreferredScrollableViewportSize(new Dimension(200, 100));

		TableCellRenderer cellRenderer = new StructureCellRenderer();
		TableColumnModel columnModel = matchingStructuresTable.getColumnModel();
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			column.setCellRenderer(cellRenderer);
		}
		matchingStructuresTable.getColumnModel().getColumn(0);

		ListSelectionModel lsm = matchingStructuresTable.getSelectionModel();
		lsm.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				ListSelectionModel sourceListSelectionModel = (ListSelectionModel) e.getSource();
				if ((sourceListSelectionModel != null) &&
					!(sourceListSelectionModel.isSelectionEmpty())) {
					// show the user that the structure choice is now
					// coming from the list of current structures
					Structure structure = ((StructureWrapper) matchingStructuresTable.getValueAt(
						matchingStructuresTable.getSelectedRow(), 0)).getStructure();
					updateStatusText(false, structure.getName());
					setCreateStructureByName(false);
				}
				else {
					updateStatusText(true, nameTextField.getText());
					setCreateStructureByName(true);
				}
			}
		});

		return matchingStructuresTable;
	}

	private JPanel buildMatchingStyelPanel() {
		JPanel matchingStylePanel = new JPanel() {
			@Override
			public Dimension getMaximumSize() {
				return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
			}
		};
		matchingStylePanel.setLayout(new BoxLayout(matchingStylePanel, BoxLayout.X_AXIS));
		matchingStylePanel.setBorder(
			new TitledBorder(BorderFactory.createEmptyBorder(), "Matching: "));

		exactMatchButton = new GRadioButton("Exact");
		sizeMatchButton = new GRadioButton("Size");

		exactMatchButton.setToolTipText(
			"Match structures with the same " + "number and type of data elements");
		sizeMatchButton.setToolTipText("Match structures of the same size");

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(exactMatchButton);
		buttonGroup.add(sizeMatchButton);
		sizeMatchButton.setSelected(true);

		ItemListener searchListener =
			event -> searchForMatchingStructures(currentProgram, currentStructure);

		exactMatchButton.addItemListener(searchListener);
		sizeMatchButton.addItemListener(searchListener);

		matchingStylePanel.add(exactMatchButton);
		matchingStylePanel.add(sizeMatchButton);

		return matchingStylePanel;
	}

	// toggles whether the structure being created is new, based upon the
	// name field, or a current structure, based upon a structure in the
	// table.  This method updates the GUI to reflect the current creation
	// state.
	private void setCreateStructureByName(boolean createStructureByName) {
		if (createStructureByName) {
			nameBorder.setTitleColor(Color.BLACK);
			structureBorder.setTitleColor(Color.GRAY);
		}
		else {
			nameBorder.setTitleColor(Color.GRAY);
			structureBorder.setTitleColor(Color.BLACK);
		}

		nameTextField.setEnabled(createStructureByName);

		if (createStructureByName) {
			matchingStructuresTable.clearSelection();
		}

		rootPanel.repaint();
	}

	// populates the table with structures that match the one the passed to
	// this class in terms of data contained
	private void searchForMatchingStructures(final Program program, final Structure structure) {

		SwingUtilities.invokeLater(() -> {
			// Get the structures from the DataTypeManagers of the
			// DataTypeManagerService
			DataTypeManagerService service = pluginTool.getService(DataTypeManagerService.class);
			DataTypeManager[] dataTypeManagers = null;

			if (service != null) {
				dataTypeManagers = service.getDataTypeManagers();
			}
			else {
				dataTypeManagers = new DataTypeManager[] { program.getDataTypeManager() };
			}

			getMatchingStructuresFromDataTypeManagers(structure, dataTypeManagers);
		});
	}

	private void getMatchingStructuresFromDataTypeManagers(Structure structure,
			DataTypeManager[] dataTypeManagers) {

		List<StructureWrapper> dataList = new ArrayList<>();
		for (DataTypeManager dataTypeManager : dataTypeManagers) {
			Iterator<Structure> structureIterator = dataTypeManager.getAllStructures();

			while (structureIterator.hasNext()) {
				// only add structures that match the one that was
				// passed to this dialog
				Structure nextStructure = structureIterator.next();

				if (compareStructures(nextStructure, structure)) {
					dataList.add(new StructureWrapper(nextStructure));
				}
			}
		}

		structureTableModel.setData(dataList);
	}

	// compares structures depending upon the type of matching that is being
	// used
	private boolean compareStructures(Structure structureA, Structure structureB) {
		if (sizeMatchButton.isSelected()) {
			return compareStructuresBySize(structureA, structureB);
		}

		return compareStructuresByData(structureA, structureB);
	}

	// a simple comparision of the size of the given structures
	private boolean compareStructuresBySize(Structure structureA, Structure structureB) {
		return (structureA.getLength() == structureB.getLength());
	}

	// Compares the two structures based upon the data contained.  This method
	// is used instead of isEquivalent() to avoid the comparison of data field
	// names, which is not a concern for this class.
	private boolean compareStructuresByData(Structure structureA, Structure structureB) {

		if (structureA.getLength() != structureB.getLength()) {
			return false;
		}

		DataTypeComponent[] definedComponentsA = structureA.getDefinedComponents();
		DataTypeComponent[] definedComponentsB = structureB.getDefinedComponents();
		if (definedComponentsA.length == definedComponentsB.length) {
			for (int i = 0; i < definedComponentsA.length; i++) {
				if (!compareDataTypeComponents(definedComponentsA[i], definedComponentsB[i])) {
					return false;
				}
			}

			return true;
		}

		return false;
	}

	// called by compareStructures() to compare the data that the structures
	// contain
	private boolean compareDataTypeComponents(DataTypeComponent dtcA, DataTypeComponent dtcB) {

		// be sure to do the easiest comparisons first, those based on
		// equality and then do the possibly recursive calls last
		if ((dtcA.getLength() == dtcB.getLength()) && (dtcA.getOffset() == dtcB.getOffset()) &&
			(dtcA.getOrdinal() == dtcB.getOrdinal()) &&
			compareDataTypes(dtcA.getDataType(), dtcB.getDataType())) {
			return true;
		}

		return false;
	}

	// called by compareDataTypeComponents() in order to compare the data
	// types of the components
	private boolean compareDataTypes(DataType typeA, DataType typeB) {

		// make sure the name and length are the same and then compare
		// the data types recursively
		if (typeA instanceof Structure) {
			if (typeB instanceof Structure) {
				return compareStructuresByData((Structure) typeA, (Structure) typeB);
			}

			return false;
		}
		else if (typeA.getName().equals(typeB.getName()) &&
			typeA.getLength() == typeB.getLength()) {
			return true;
		}

		return false;
	}

	/**
	 * Shows a dialog that allows the user to create a new structure.
	 * <p>
	 * This method expects that <tt>program</tt> and <tt>structure</tt> be
	 * non-null.
	 *
	 * @param  program The current program which will be used to obtain current
	 *         structures in the system.
	 * @param  structure The new structure shell that will be used to find
	 *         matching structures in memory.
	 * @return The new structure that will be added to memory.  This will be
	 *         a new structure with a new name, or an existing structure.
	 * @throws NullPointerException if either of the parameters are null.
	 */
	public Structure showCreateStructureDialog(Program program, Structure structure)
			throws NullPointerException {

		if (program == null) {
			throw new NullPointerException(
				"Cannot show Create Structure dialog without a non-null Program.");
		}

		if (structure == null) {
			throw new NullPointerException(
				"Non-null structure is required when showing the Create Structure dialog.");
		}

		// init the return value, which will be updated if the user presses
		// the OK button
		currentStructure = structure;

		nameTextField.setText(currentStructure.getName());
		updateStatusText(true, currentStructure.getName());

		searchForMatchingStructures(program, structure);

		// modal block
		pluginTool.showDialog(this);

		return currentStructure;
	}

	// overridden to clear the current user selection
	@Override
	protected void cancelCallback() {
		currentStructure = null;
		super.cancelCallback();
	}

	/**
	 * The callback method for when the "OK" button is pressed.
	 */
	@Override
	protected void okCallback() {

		if (nameTextField.isEnabled()) {
			// just use the name set by the user
			String nameText = nameTextField.getText();

			try {
				currentStructure.setName(nameText);
			}
			catch (InvalidNameException ine) {
				setStatusText(ine.getMessage());
				return;
			}
			catch (DuplicateNameException dne) {
				setStatusText(dne.getMessage());
				return;
			}
		}
		else {
			// get the selected object in the table
			currentStructure = ((StructureWrapper) matchingStructuresTable.getValueAt(
				matchingStructuresTable.getSelectedRow(), 0)).getStructure();
		}

		close();
	}

	// a table model that is used to allow for the easy updating of the
	// table with new List data and to disable editing
	/*package*/class StructureTableModel extends AbstractSortedTableModel<StructureWrapper> {
		private List<StructureWrapper> data = Collections.emptyList();

		StructureTableModel() {
		}

		@Override
		public String getName() {
			return "Structure";
		}

		void setData(List<StructureWrapper> data) {
			this.data = data;
			fireTableDataChanged();
		}

		@Override
		public boolean isCellEditable(int row, int column) {
			return false;
		}

		@Override
		public String getColumnName(int column) {
			switch (column) {
				case 0:
					return STRUCTURE_COLUMN_NAME;
				case 1:
					return PATH_COLUMN_NAME;
			}
			return null;
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public List<StructureWrapper> getModelData() {
			return data;
		}

		@Override
		public Object getColumnValueForRow(StructureWrapper t, int columnIndex) {
			switch (columnIndex) {
				case 0:
					return t;
				case 1: {
					Structure structure = t.getStructure();
					CategoryPath path = structure.getCategoryPath();
					String name = structure.getName();
					return path.toString() + '/' + name;
				}
			}
			return null;
		}
	}

	// updates the status text with the provided name
	private void updateStatusText(boolean creatingNew, String name) {
		if (name == null) {
			setStatusText("");
			return;
		}

		String message = null;
		if (creatingNew) {
			message = NEW_STRUCTURE_STATUS_PREFIX;
		}
		else {
			message = EXISITING_STRUCTURE_STATUS_PREFIX;
		}

		setStatusText("<HTML>" + message + "<BR>\"" + HTMLUtilities.escapeHTML(name) + "\"");
	}

	// this class is used instead of a cell renderer so that sorting will
	// work on the table
	/*package*/class StructureWrapper {
		private Structure structure;

		private StructureWrapper(Structure newStructure) {
			structure = newStructure;
		}

		Structure getStructure() {
			return structure;
		}

		@Override
		public String toString() {
			return structure.getName();
		}
	}

	// we need this renderer in order to create nice tool tip text values
	class StructureCellRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JComponent renderer = (JComponent) super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			int column = data.getColumnViewIndex();

			// set the tool tips
			String columnName = table.getColumnName(column);
			if (STRUCTURE_COLUMN_NAME.equals(columnName)) {
				StructureWrapper wrapper = (StructureWrapper) table.getValueAt(row, 0);
				if (wrapper != null) {
					Structure structure = wrapper.getStructure();
					renderer.setToolTipText(ToolTipUtils.getToolTipText(structure));
				}
			}
			else if (PATH_COLUMN_NAME.equals(columnName)) {
				if (value != null) {
					renderer.setToolTipText(value.toString());
				}
			}

			return renderer;
		}
	}

}
