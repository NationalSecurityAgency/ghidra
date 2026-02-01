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

import org.apache.commons.lang3.StringUtils;

import docking.ReusableDialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.table.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.datatype.CategoryPathSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.layout.PairLayout;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

/**
 * A dialog that allows the user to create a new structure based upon providing
 * a new name or by using the name of an existing structure.
 */
public class CreateStructureDialog extends ReusableDialogComponentProvider {
	private static final String NEW_STRUCTURE_STATUS_PREFIX = "Creating new structure: ";
	private static final String EXISITING_STRUCTURE_STATUS_PREFIX = "Using existing structure: ";

	private static final String STRUCTURE_COLUMN_NAME = "Structure";
	private static final String CATEGORY_COLUMN_NAME = "Category";

	private JTextField nameTextField;
	private CategoryPathSelectionEditor categoryPathEditor;
	private GhidraTable matchingStructuresTable;
	private StructureTableModel structureTableModel;
	private Structure currentStructure;
	private Program currentProgram;
	private PluginTool pluginTool;

	private JRadioButton createNewStructButton;
	private JRadioButton useExistingStructButton;
	private JRadioButton exactMatchButton;
	private JRadioButton sizeMatchButton;
	private GhidraTableFilterPanel<StructureWrapper> filterPanel;

	/**
	 * Creates a new dialog with the given parent.
	 *
	 * @param tool The current tool that this dialog needs to access services.
	 * @param program the current program
	 */
	public CreateStructureDialog(PluginTool tool, Program program) {
		super("Create Structure", true, true, true, false);

		this.pluginTool = tool;
		this.currentProgram = program;
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
		mainPanel.add(createChoicePanel());
		setStatusJustification(SwingConstants.LEFT);
		return mainPanel;
	}

	private JPanel createChoicePanel() {
		JPanel radioChoicePanel = new JPanel(new BorderLayout());

		createNewStructButton = new GRadioButton("Create New");
		createNewStructButton.getAccessibleContext().setAccessibleName("Create New");
		useExistingStructButton = new GRadioButton("Use Existing");
		useExistingStructButton.getAccessibleContext().setAccessibleName("Use Existing");

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(createNewStructButton);
		buttonGroup.add(useExistingStructButton);
		createNewStructButton.setSelected(true);
		ItemListener choiceListener = event -> updateEnablement();
		createNewStructButton.addItemListener(choiceListener);
		useExistingStructButton.addItemListener(choiceListener);

		JPanel createNewStructPanel = new JPanel();
		createNewStructPanel.setLayout(new BoxLayout(createNewStructPanel, BoxLayout.Y_AXIS));
		// force the radio button to the left for clarity
		createNewStructPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		// indent everything under the radio button
		createNewStructPanel.setBorder(BorderFactory.createEmptyBorder(5, 30, 15, 5));

		JPanel useExistingStructPanel = new JPanel();
		useExistingStructPanel.setLayout(new BoxLayout(useExistingStructPanel, BoxLayout.Y_AXIS));
		useExistingStructPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
		useExistingStructPanel.setBorder(BorderFactory.createEmptyBorder(0, 30, 10, 5));

		createNewStructPanel.add(buildCreateNewStructPanel());
		useExistingStructPanel.add(buildMatchingStructPanel());

		JPanel top = new JPanel();
		top.setLayout(new BoxLayout(top, BoxLayout.PAGE_AXIS));
		top.add(createNewStructButton);
		top.add(createNewStructPanel);

		JPanel center = new JPanel();
		center.setLayout(new BoxLayout(center, BoxLayout.PAGE_AXIS));
		center.add(useExistingStructButton);
		center.add(useExistingStructPanel);

		// we would like the structure table to get all extra space, so put it in the center
		radioChoicePanel.add(top, BorderLayout.NORTH);
		radioChoicePanel.add(center, BorderLayout.CENTER);

		return radioChoicePanel;
	}

	private JPanel buildCreateNewStructPanel() {
		JPanel newStructPanel = new JPanel();
		newStructPanel.setLayout(new PairLayout());
		newStructPanel.setToolTipText("Enter a name and category (optional)");

		JLabel nameLabel = new JLabel("Name: ");

		nameTextField = new JTextField();
		nameTextField.setName("StructureName");
		nameTextField.getAccessibleContext().setAccessibleName("Name");

		// Allow user to click on the text field to re-activate "create new" panel without forcing
		// a click on the radio button
		nameTextField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				createNewStructButton.setSelected(true);
				updateEnablement();
			}
		});
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
					if (StringUtils.isBlank(text)) {
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

		JLabel categoryLabel = new JLabel("Category: ");
		buildCategoryPathEditor();

		newStructPanel.add(nameLabel);
		newStructPanel.add(nameTextField);
		newStructPanel.add(categoryLabel);
		newStructPanel.add(categoryPathEditor.getEditorComponent());

		return newStructPanel;
	}

	private void buildCategoryPathEditor() {
		categoryPathEditor = new CategoryPathSelectionEditor(pluginTool);
		JComponent editorComponent = categoryPathEditor.getEditorComponent();
		editorComponent.getAccessibleContext().setAccessibleName("Category");

		categoryPathEditor.setCellEditorValue(CategoryPath.ROOT);

		// Allow user to click on the text field to re-activate "create new" panel without forcing
		// a click on the radio button
		categoryPathEditor.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				createNewStructButton.setSelected(true);
				updateEnablement();
			}
		});
	}

	private JPanel buildMatchingStructPanel() {
		JPanel structurePanel = new JPanel();
		structurePanel.setLayout(new BoxLayout(structurePanel, BoxLayout.Y_AXIS));

		GTable table = buildMatchingStructuresTable();
		// allow user to re-activate the "use existing" panel without forcing a radio button click.
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent event) {
				useExistingStructButton.setSelected(true);
				updateEnablement();
			}
		});
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			if (useExistingStructButton.isSelected()) {
				setOkEnabled(table.getSelectedRowCount() > 0);
			}
		});

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
		scrollPane.getAccessibleContext().setAccessibleName("Scroll");

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

		ListSelectionModel lsm = matchingStructuresTable.getSelectionModel();
		lsm.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			ListSelectionModel selectionModel = (ListSelectionModel) e.getSource();
			if (selectionModel != null && !selectionModel.isSelectionEmpty()) {
				// Show the user that the structure choice is now coming from the table
				useExistingStructButton.setSelected(true);
			}

			updateEnablement();
		});

		matchingStructuresTable.getAccessibleContext().setAccessibleName("Matching Structures");
		return matchingStructuresTable;
	}

	private void updateStatus() {

		clearStatusText();

		if (useExistingStructButton.isSelected()) {
			Structure structure = getSelectedStructure();
			if (structure != null) {
				updateStatusText(false, structure.getName());
			}
		}
		else {
			updateStatusText(true, nameTextField.getText());
		}
	}

	private JPanel buildMatchingStyelPanel() {
		JPanel matchingStylePanel = new JPanel() {
			@Override
			public Dimension getMaximumSize() {
				return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
			}
		};
		matchingStylePanel.setLayout(new BoxLayout(matchingStylePanel, BoxLayout.X_AXIS));
		matchingStylePanel
				.setBorder(new TitledBorder(BorderFactory.createEmptyBorder(), "Matching: "));

		exactMatchButton = new GRadioButton("Exact");
		exactMatchButton.getAccessibleContext().setAccessibleName("Exact Match");
		sizeMatchButton = new GRadioButton("Size");
		sizeMatchButton.getAccessibleContext().setAccessibleName("Size Match");

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

	// Toggles whether the structure being created is new, based upon the name field, or existing,
	// based upon a structure in the table. 
	private void updateEnablement() {
		if (createNewStructButton.isSelected()) {
			nameTextField.setEnabled(true);
			categoryPathEditor.setEnabled(true);
			matchingStructuresTable.setEnabled(false);
			exactMatchButton.setEnabled(false);
			sizeMatchButton.setEnabled(false);
			matchingStructuresTable.clearSelection();
		}
		else {
			nameTextField.setEnabled(false);
			categoryPathEditor.setEnabled(false);
			matchingStructuresTable.setEnabled(true);
			exactMatchButton.setEnabled(true);
			sizeMatchButton.setEnabled(true);
		}
		rootPanel.repaint();

		updateStatus();
	}

	// Populates the table with structures that match the one the passed to this class in terms of 
	// data contained
	private void searchForMatchingStructures(final Program program, final Structure structure) {

		// Get the structures from the DataTypeManagers of the DataTypeManagerService
		DataTypeManagerService service = pluginTool.getService(DataTypeManagerService.class);

		DataTypeManager[] dataTypeManagers = null;

		if (service != null) {
			dataTypeManagers = service.getDataTypeManagers();
		}
		else {
			dataTypeManagers = new DataTypeManager[] { program.getDataTypeManager() };
		}

		getMatchingStructuresFromDataTypeManagers(structure, dataTypeManagers);
	}

	private void getMatchingStructuresFromDataTypeManagers(Structure structure,
			DataTypeManager[] dataTypeManagers) {

		List<StructureWrapper> dataList = new ArrayList<>();
		for (DataTypeManager dataTypeManager : dataTypeManagers) {
			Iterator<Structure> structureIterator = dataTypeManager.getAllStructures();

			while (structureIterator.hasNext()) {
				// only add structures that match the one that was passed to this dialog
				Structure nextStructure = structureIterator.next();

				if (compareStructures(nextStructure, structure)) {
					dataList.add(new StructureWrapper(nextStructure));
				}
			}
		}

		structureTableModel.setData(dataList);
	}

	// compares structures depending upon the type of matching that is being used
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

	// Compares the two structures based upon the data contained.  This method is used instead of 
	// isEquivalent() to avoid the comparison of data field names, which is not a concern for this 
	// class.
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

	// called by compareStructures() to compare the data that the structures contain
	private boolean compareDataTypeComponents(DataTypeComponent dtcA, DataTypeComponent dtcB) {

		// be sure to do the easiest comparisons first, those based on equality and then do the 
		// possibly recursive calls last
		if ((dtcA.getLength() == dtcB.getLength()) && (dtcA.getOffset() == dtcB.getOffset()) &&
			(dtcA.getOrdinal() == dtcB.getOrdinal()) &&
			compareDataTypes(dtcA.getDataType(), dtcB.getDataType())) {
			return true;
		}

		return false;
	}

	// called by compareDataTypeComponents() in order to compare the data types of the components
	private boolean compareDataTypes(DataType typeA, DataType typeB) {

		// make sure the name and length are the same and then compare the data types recursively
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

	JTextField getNameField() {
		return nameTextField;
	}

	JTable getTable() {
		return matchingStructuresTable;
	}

	CategoryPathSelectionEditor getCategoryEditor() {
		return categoryPathEditor;
	}

	/**
	 * Shows a dialog that allows the user to create a new structure.
	 * <p>
	 * This method expects that {@code program} and {@code structure} be
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

		// init the return value, which will be updated if the user presses the OK button
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

	@Override
	protected void okCallback() {

		if (useExistingStructButton.isSelected()) {
			// get the selected object in the table
			currentStructure = getSelectedStructure();
			close();
			return;
		}

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

		if (!setCategoryPath()) {
			return;
		}

		if (!validateName()) {
			return;
		}

		close();
	}

	private boolean validateName() {
		// Use the current name and category path to see if there is already an existing name.  This
		// allows us to avoid a conflict.
		ProgramBasedDataTypeManager dtm = currentProgram.getDataTypeManager();
		CategoryPath path = currentStructure.getCategoryPath();
		Category category = dtm.getCategory(path);
		if (category == null) {
			return true;
		}

		String nameText = currentStructure.getName();
		DataType existingDt = category.getDataType(nameText);
		if (existingDt != null) {
			setStatusText("Name already exists: " + nameText, MessageType.ERROR);
			return false;
		}

		return true;
	}

	private Structure getSelectedStructure() {
		int row = matchingStructuresTable.getSelectedRow();
		if (row < 0) {
			return null;
		}

		Object cellValue = matchingStructuresTable.getValueAt(row, 0);
		return ((StructureWrapper) cellValue).getStructure();
	}

	private boolean setCategoryPath() {

		try {
			doSetCategoryPath();
		}
		catch (DuplicateNameException e) {
			setStatusText(e.getMessage(), MessageType.ERROR);
			return false;
		}
		return true;
	}

	private void doSetCategoryPath() throws DuplicateNameException {
		CategoryPath path = categoryPathEditor.getCellEditorValue();
		// First see if a category from the list was chosen and make sure the user didn't modify it.
		// If they did, path needs to be parsed separately.
		String editorValue = categoryPathEditor.getCellEditorValueAsText();
		if (path != null && path.getPath().equals(editorValue)) {
			currentStructure.setCategoryPath(path);
			return;
		}

		// Selecting/entering a category is optional; root is default
		if (!editorValue.isBlank()) {
			CategoryPath parsedPath = parseEnteredCategoryPath(editorValue);
			currentStructure.setCategoryPath(parsedPath);
			return;
		}

		currentStructure.setCategoryPath(CategoryPath.ROOT);
	}

	private CategoryPath parseEnteredCategoryPath(String categoryText) {
		// entering a leading slash is optional, path is still generated accordingly  
		if (categoryText.startsWith(CategoryPath.DELIMITER_STRING)) {
			return new CategoryPath(categoryText);
		}
		return new CategoryPath(CategoryPath.DELIMITER_STRING + categoryText);
	}

	// a table model that is used to allow for the easy updating of the table with new List data 
	// and to disable editing
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
					return CATEGORY_COLUMN_NAME;
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
					return path.toString();
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

		String prefix = EXISITING_STRUCTURE_STATUS_PREFIX;
		if (creatingNew) {
			prefix = NEW_STRUCTURE_STATUS_PREFIX;
		}

		String escapeName = HTMLUtilities.escapeHTML(name);
		String message = "<html>%s'%s'".formatted(prefix, escapeName);
		setStatusText(message);
	}

	// this class is used instead of a cell renderer so that sorting will work on the table
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
	private class StructureCellRenderer extends GTableCellRenderer {
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
			else if (CATEGORY_COLUMN_NAME.equals(columnName)) {
				if (value != null) {
					renderer.setToolTipText(value.toString());
				}
			}

			return renderer;
		}
	}

}
