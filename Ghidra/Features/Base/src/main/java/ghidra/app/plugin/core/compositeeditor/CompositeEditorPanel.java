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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.*;
import javax.swing.text.JTextComponent;

import docking.DockingWindowManager;
import docking.actions.KeyBindingUtils;
import docking.dnd.*;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.textfield.GValidatedTextField;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.app.util.datatype.NavigationDirection;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.UsrException;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel for editing a composite data type. Specific composite data type editors
 * should extend this class.
 * This provides a table with cell edit functionality and drag and drop capability.
 * Below the table is an information area for non-component information about the
 * composite data type. To add your own info panel override the createInfoPanel() method.
 */
public abstract class CompositeEditorPanel extends JPanel
		implements CompositeEditorModelListener, ComponentCellEditorListener, Draggable, Droppable {

	// Normal color for selecting components in the table.
	// TODO: Why do we choose a different selection color?
	//private static final Color SELECTION_COLOR = Color.YELLOW.brighter().brighter();
	//protected static final Insets TEXTFIELD_INSETS = new JTextField().getInsets();

	protected static final Border BEVELED_BORDER = BorderFactory.createLoweredBevelBorder();

	protected static final HelpService helpManager = Help.getHelpService();

	protected CompositeEditorProvider provider;
	protected CompositeEditorModel model;
	protected CompositeTable table;
	private JLabel statusLabel;

	private boolean editorAdjusting = false;

	// ******************************************************
	// The following are for drag and drop of components.
	// ******************************************************
	/** The table cell renderer for drag-n-drop. */
	protected DndTableCellRenderer dndTableCellRenderer;
	protected DndTableCellRenderer dndDtiCellRenderer;
	private DragSource dragSource;
	private DragGestureAdapter dragGestureAdapter;
	private DragSrcAdapter dragSourceAdapter;
	private int dragAction = DnDConstants.ACTION_MOVE;
	private DropTarget dropTarget;
	private DropTgtAdapter dropTargetAdapter;
	private DataFlavor[] acceptableFlavors; // data flavors that are valid.
	protected int lastDndAction = DnDConstants.ACTION_NONE;

	public CompositeEditorPanel(CompositeEditorModel model, CompositeEditorProvider provider) {
		super(new BorderLayout());
		JPanel lowerPanel = new JPanel(new VerticalLayout(5));
		this.provider = provider;
		this.model = model;
		createTable();
		JPanel bitViewerPanel = createBitViewerPanel();
		if (bitViewerPanel != null) {
			lowerPanel.add(bitViewerPanel);
		}
		JPanel infoPanel = createInfoPanel();
		if (infoPanel != null) {
			adjustCompositeInfo();
			lowerPanel.add(infoPanel);
		}
		lowerPanel.add(createStatusPanel());
		add(lowerPanel, BorderLayout.SOUTH);
		model.addCompositeEditorModelListener(this);
		setUpDragDrop();
	}

	protected Composite getOriginalComposite() {
		return model.getOriginalComposite();
	}

	protected abstract void adjustCompositeInfo();

	public JTable getTable() {
		return table;
	}

	protected CompositeEditorModel getModel() {
		return model;
	}

	public void addEditorModelListener(CompositeEditorModelListener listener) {
		model.addCompositeEditorModelListener(listener);
	}

	public void removeEditorModelListener(CompositeEditorModelListener listener) {
		model.removeCompositeEditorModelListener(listener);
	}

	private void setupTableCellRenderer() {
		GTableCellRenderer cellRenderer = new GTableCellRenderer();
		DataTypeCellRenderer dtiCellRenderer =
			new DataTypeCellRenderer(model.getOriginalDataTypeManager());
		table.setDefaultRenderer(String.class, cellRenderer);
		table.setDefaultRenderer(DataTypeInstance.class, dtiCellRenderer);
	}

	private boolean launchBitFieldEditor(int modelColumn, int editingRow) {
		if (model.viewComposite instanceof Structure &&
			!model.viewComposite.isPackingEnabled() &&
			model.getDataTypeColumn() == modelColumn && editingRow < model.getNumComponents()) {
			// check if we are attempting to edit a bitfield
			DataTypeComponent dtComponent = model.getComponent(editingRow);
			if (dtComponent.isBitFieldComponent()) {
				table.getCellEditor().cancelCellEditing();

				BitFieldEditorDialog dlg = new BitFieldEditorDialog(model.viewComposite,
					provider.dtmService, editingRow, model.showHexNumbers, ordinal -> {
						model.notifyCompositeChanged();
					});
				Component c = provider.getComponent();
				DockingWindowManager.showDialog(c, dlg);
				return true;
			}
		}
		return false;
	}

	private void setupTableCellEditor() {

		table.addPropertyChangeListener("tableCellEditor", evt -> {
			TableCellEditor fieldEditor = (TableCellEditor) evt.getNewValue();
			if (fieldEditor == null) {
				// Ending cell edit
				Swing.runLater(() -> model.endEditingField());
			}
			else {
				// Starting cell edit
				Swing.runLater(() -> {
					int editingRow = table.getEditingRow();
					if (editingRow < 0) {
						return;
					}
					int modelColumn = table.convertColumnIndexToModel(table.getEditingColumn());
					if (!launchBitFieldEditor(modelColumn, editingRow)) {
						model.beginEditingField(editingRow, modelColumn);
					}
				});
			}
		});
		ComponentStringCellEditor cellEditor = new ComponentStringCellEditor();
		ComponentOffsetCellEditor offsetCellEditor = new ComponentOffsetCellEditor();
		ComponentDataTypeCellEditor dataTypeCellEditor = new ComponentDataTypeCellEditor();
		ComponentNameCellEditor nameCellEditor = new ComponentNameCellEditor();

		cellEditor.setComponentCellEditorListener(this);
		offsetCellEditor.setComponentCellEditorListener(this);

		nameCellEditor.setComponentCellEditorListener(this);

		table.setDefaultEditor(String.class, cellEditor);
		TableColumnModel tcm = table.getColumnModel();
		int numCols = tcm.getColumnCount();
		for (int i = 0; i < numCols; i++) {
			int column = table.convertColumnIndexToModel(i);
			if (column == model.getNameColumn()) {
				tcm.getColumn(column).setCellEditor(nameCellEditor);
			}
			else if (column == model.getDataTypeColumn()) {
				tcm.getColumn(column).setCellEditor(dataTypeCellEditor);
			}
			else if (column == model.getOffsetColumn()) {
				tcm.getColumn(column).setCellEditor(offsetCellEditor);
			}
			else {
				tcm.getColumn(column).setCellEditor(cellEditor);
			}
		}
	}

	protected void cancelCellEditing() {
		TableCellEditor cellEditor = table.getCellEditor();
		if (cellEditor != null) {
			cellEditor.cancelCellEditing();
		}
	}

	protected void stopCellEditing() {
		TableCellEditor cellEditor = table.getCellEditor();
		if (cellEditor != null) {
			cellEditor.stopCellEditing();
		}
	}

	protected void startCellEditing(int row, int viewColumn) {
		if (row >= 0 && viewColumn >= 0) {
			table.editCellAt(row, viewColumn, new KeyEvent(table, KeyEvent.KEY_PRESSED,
				System.currentTimeMillis(), 0, KeyEvent.VK_F2, KeyEvent.CHAR_UNDEFINED));
		}
	}

	/*********************************************
	 * BEGIN ComponentCellEditorListener methods
	 *********************************************/

	@Override
	public void moveCellEditor(final int direction, final String value) {
		stopCellEditing();

		// Note: We run this later due to focus dependencies.  When we call
		// stopCellEditing() this will trigger a focusLost() event, which itself happens in
		// a Swing.runLater().  If we do not trigger the moving of the cell editor after that focus
		// event, then the focusLost() will trigger our new edit to be cancelled.
		Swing.runLater(() -> doMoveCellEditor(direction, value));
	}

	private void doMoveCellEditor(int direction, String value) {
		if (editorAdjusting) {
			return;
		}

		try {
			editorAdjusting = true;

			if (table.isEditing()) {
				return;
			}

			int currentRow = model.getRow();
			switch (direction) {
				case ComponentCellEditorListener.NEXT:
					editNextField(currentRow);
					break;
				case ComponentCellEditorListener.PREVIOUS:
					editPreviousField(currentRow);
					break;
				case ComponentCellEditorListener.UP:
					editAboveField();
					break;
				case ComponentCellEditorListener.DOWN:
					editBelowField();
					break;
			}
			if (table.isEditing()) {
				table.getEditorComponent().requestFocus();
			}
		}
		finally {
			editorAdjusting = false;
		}
	}

	/*********************************************
	 * END ComponentCellEditorListener methods
	 *********************************************/

	/**
	 * If the field location specified can be edited,
	 * the field is put into edit mode.
	 *
	 * @param row the table row
	 * @param modelColumn the model's column index
	 *
	 * @return true if field has been put into edit mode.
	 */
	private boolean beginEditField(int row, int modelColumn) {
		// Handle the editing for this field.
		int viewColumn = table.convertColumnIndexToView(modelColumn);
		scrollToCell(row, viewColumn);
		startCellEditing(row, viewColumn);
		return table.isEditing();
	}

	/**
	 * Moves the cursor to the next editable field.
	 * @param currentRow The currently selected row
	 * @return true if there was a next editable field.
	 */
	protected boolean locateNextEditField(int currentRow) {
		int row = currentRow;
		int modelColumn = model.getColumn();
		boolean foundEditable = false;

		// Get the current row (index) and column (fieldNum).
		int index = row;
		int fieldNum = table.convertColumnIndexToView(modelColumn);

		int numFields = model.getColumnCount();
		int numComps = model.getRowCount();
		do {
			// Determine the new location for the cursor.
			if (index < numComps) { // on component row
				if (++fieldNum < (numFields)) { // not on last field
					if (model.isCellEditable(index, table.convertColumnIndexToModel(fieldNum))) {
						foundEditable = true;
					}
				}
				else if ((++index < numComps) // on last field for other than last component
					|| (index == numComps)) { // Last field and row but unlocked
					fieldNum = 0; // Set it to first field.
					if (model.isCellEditable(index, table.convertColumnIndexToModel(fieldNum))) {
						foundEditable = true;
					}
				}
				else {
					break;
				}
			}
			else {
				break;
			}
		}
		while (!foundEditable);

		if (foundEditable) {
			row = index;
			modelColumn = table.convertColumnIndexToModel(fieldNum);
			table.setRowSelectionInterval(row, row);
			model.setRow(row);
			model.setColumn(modelColumn);
		}
		return foundEditable;
	}

	/**
	 * Moves the cursor to the previous editable field.
	 * @param currentRow The currently selected row
	 * @return true if there was a previous editable field.
	 */
	protected boolean locatePreviousEditField(int currentRow) {
		int row = currentRow;
		int modelColumn = model.getColumn();
		boolean foundEditable = false;

		// Get the current row (index) and column (fieldNum).
		int index = row;
		int fieldNum = table.convertColumnIndexToView(modelColumn);

		do {
			// Determine the new location for the cursor.
			if (--fieldNum >= 0) {
				if (model.isCellEditable(index, table.convertColumnIndexToModel(fieldNum))) {
					foundEditable = true;
				}
			}
			else if (--index >= 0) {
				fieldNum = model.getColumnCount() - 1; // Set it to last field.
				if (model.isCellEditable(index, table.convertColumnIndexToModel(fieldNum))) {
					foundEditable = true;
				}
			}
			else {
				break;
			}
		}
		while (!foundEditable);

		if (foundEditable) {
			row = index;
			modelColumn = table.convertColumnIndexToModel(fieldNum);
			table.setRowSelectionInterval(row, row);
			model.setRow(row);
			model.setColumn(modelColumn);
		}
		return foundEditable;
	}

	/**
	 * Puts the cell into edit in the row above the current (row, column) location.
	 * @return true if there was a table cell above that could be edited.
	 */
	protected boolean editAboveField() {
		int row = model.getRow();
		int modelColumn = model.getColumn();
		// Get the current row (index) and column (fieldNum).
		int index = row;
		index--;

		if (index >= 0) {
			row = index;
			table.setRowSelectionInterval(row, row);
			if (model.isCellEditable(index, modelColumn)) {
				return beginEditField(model.getRow(), model.getColumn());
			}
		}
		return false;
	}

	/**
	 * Puts the cell into edit in the row below the current (row, column) location.
	 * @return true if there was a table cell below that could be edited.
	 */
	protected boolean editBelowField() {
		int row = model.getRow();
		int modelColumn = model.getColumn();
		// Get the current row (index) and column (fieldNum).
		int index = row;
		index++;

		int numComps = model.getRowCount();
		if (index < numComps) {
			row = index;
			table.setRowSelectionInterval(row, row);
			if (model.isCellEditable(index, modelColumn)) {
				return beginEditField(model.getRow(), model.getColumn());
			}
		}
		return false;
	}

	/**
	 * Puts the next editable cell into edit mode
	 * 
	 * @param currentRow the current row
	 * @return true if there was a table cell that could be edited
	 */
	protected boolean editNextField(int currentRow) {
		if (locateNextEditField(currentRow)) {
			return beginEditField(model.getRow(), model.getColumn());
		}
		return false;
	}

	/**
	 * Puts the previous editable cell into edit mode.
	 * @param currentRow The currently selected row
	 * @return true if there was a table cell that could be edited.
	 */
	protected boolean editPreviousField(int currentRow) {
		if (locatePreviousEditField(currentRow)) {
			return beginEditField(model.getRow(), model.getColumn());
		}
		return false;
	}

	/**
	 * Scrolls the table so that the table cell indicated becomes viewable.
	 * @param rowIndex the row of the table cell
	 * @param columnIndex the column of the table cell
	 */
	private void scrollToCell(int rowIndex, int columnIndex) {
		if (table.getAutoscrolls()) {
			Rectangle cellRect = table.getCellRect(rowIndex, columnIndex, false);
			if (cellRect != null) {
				table.scrollRectToVisible(cellRect);
			}
		}
	}

	public void domainObjectRestored(DataTypeManagerDomainObject domainObject) {
		boolean reload = true;
		String objectType = "domain object";
		if (domainObject instanceof Program) {
			objectType = "program";
		}
		else if (domainObject instanceof DataTypeArchive) {
			objectType = "data type archive";
		}
		DataType dt = model.getOriginalDataTypeManager().getDataType(model.getCompositeID());
		if (dt instanceof Composite) {
			Composite composite = (Composite) dt;
			String origDtPath = composite.getPathName();
			if (!origDtPath.equals(model.getOriginalDataTypePath())) {
				model.fixupOriginalPath(composite);
			}
		}
		Composite originalDt = model.getOriginalComposite();
		if (originalDt == null) {
			provider.show();
			String info =
				"The " + objectType + " \"" + domainObject.getName() + "\" has been restored.\n" +
					"\"" + model.getCompositeName() + "\" may no longer exist outside the editor.";
			Msg.showWarn(this, this, "Program Restored", info);
			return;
		}
		else if (originalDt.isDeleted()) {
			cancelCellEditing(); // Make sure a field isn't being edited.
			provider.dispose(); // Close the editor.
			return;
		}
		else if (model.hasChanges()) {
			provider.show();
			// The user has modified the structure so prompt for whether or
			// not to reload the structure.
			String question =
				"The " + objectType + " \"" + domainObject.getName() + "\" has been restored.\n" +
					"\"" + model.getCompositeName() + "\" may have changed outside the editor.\n" +
					"Discard edits & reload the " + model.getTypeName() + "?";
			String title = "Reload " + model.getTypeName() + " Editor?";
			int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(this, title, question);
			if (response != 1) {
				reload = false;
			}
		}
		if (reload) {
			cancelCellEditing(); // Make sure a field isn't being edited.
			model.load(originalDt, model.isOffline()); // reload the structure
			model.updateAndCheckChangeState();
		}
	}

	public void dispose() {
		if (isVisible()) {
			setVisible(false);
		}
		model.removeCompositeEditorModelListener(this);
		table.dispose();
	}

	private void createTable() {
		table = new CompositeTable(model);
		table.putClientProperty("JTable.autoStartsEdit", Boolean.FALSE);
		table.addMouseListener(new CompositeTableMouseListener());

		CompositeEditorTableAction action = provider.actionMgr.getNamedAction(
			CompositeEditorTableAction.EDIT_ACTION_PREFIX + EditFieldAction.ACTION_NAME);
		Action swingAction = KeyBindingUtils.adaptDockingActionToNonContextAction(action);
		InputMap map = table.getInputMap();
		map.put(action.getKeyBinding(), "StartEditing");
		ActionMap amap = table.getActionMap();
		amap.put("StartEditing", swingAction);

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			model.setSelection(table.getSelectedRows());

		});

		table.getColumnModel().getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			TableColumnModel cm = table.getColumnModel();
			int[] selected = cm.getSelectedColumns();
			if (selected.length == 1) {
				model.setColumn(selected[0]);
			}
			else {
				model.setColumn(-1);
			}
		});

		JPanel tablePanel = new JPanel(new BorderLayout());
		JScrollPane sp = new JScrollPane(table);
		table.setPreferredScrollableViewportSize(new Dimension(model.getWidth(), 250));
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		//table.setSelectionBackground(SELECTION_COLOR);
		//table.setSelectionForeground(Color.black);
		tablePanel.add(sp, BorderLayout.CENTER);
		SearchControlPanel searchPanel = new SearchControlPanel(this);

		if (helpManager != null) {
			helpManager.registerHelp(searchPanel,
				new HelpLocation("DataTypeEditors", "Searching_In_Editor"));
		}
		tablePanel.add(searchPanel, BorderLayout.SOUTH);

		add(tablePanel, BorderLayout.CENTER);

		JTableHeader header = table.getTableHeader();
		header.setUpdateTableInRealTime(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		for (int i = 0; i < model.getColumnCount(); i++) {
			TableColumn tc = table.getColumn(model.getColumnName(i));
			tc.setPreferredWidth(model.getFieldWidth(i));
		}

		setupTableCellRenderer();
		setupTableCellEditor();
		selectionChanged();

		Color gridColor = table.getGridColor();
		Color tableBackground = table.getBackground();
		if (tableBackground.equals(gridColor)) {
			// This can happen on the Mac and is usually white.  This is a simple solution for
			// that scenario.  If this fails on other platforms, then do something more advanced
			// at that point.
			table.setGridColor(Color.GRAY);
		}
	}

	/**
	 * Override this method to add your own bit-viewer panel below the
	 * component table.
	 * <P>Creates a panel that appears below the component table. This panel
	 * contains a bit-level view of a selected component.
	 * By default, there is no panel below the component table.
	 * @return the panel or null if there isn't one.
	 */
	protected JPanel createBitViewerPanel() {
		return null;
	}

	/**
	 * Override this method to add your own view/edit panel below the
	 * component table.
	 * <P>Creates a panel that appears below the component table. This panel
	 * contains viewable and editable information that isn't component information.
	 * By default, there is no panel below the component table.
	 * @return the panel or null if there isn't one.
	 */
	protected JPanel createInfoPanel() {
		return null;
	}

	private JPanel createStatusPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		statusLabel = new GDLabel(" ");
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
		statusLabel.setForeground(Color.blue);
		statusLabel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateStatusToolTip();
			}
		});
		panel.add(statusLabel, BorderLayout.CENTER);
		statusLabel.setName("Editor Status");
		return panel;
	}

	/**
	 * Sets the currently displayed status message.
	 *
	 * @param status non-html message string to be displayed.
	 */
	public void setStatus(String status) {
		if (statusLabel != null) {
			statusLabel.setText(status);
			updateStatusToolTip();
		}
		else {
			provider.setStatusMessage(status);
		}
	}

	/**
	 * If the status text doesn't fit in the dialog, set a tool tip
	 * for the status label so the user can see what it says.
	 * If the status message fits then there is no tool tip.
	 */
	private void updateStatusToolTip() {
		String text = statusLabel.getText();
		// Get the width of the message.
		FontMetrics fm = statusLabel.getFontMetrics(statusLabel.getFont());
		int messageWidth = 0;
		if ((fm != null) && (text != null)) {
			messageWidth = fm.stringWidth(text);
		}
		if (messageWidth > statusLabel.getWidth()) {
			statusLabel.setToolTipText(text);
		}
		else {
			statusLabel.setToolTipText("Editor messages appear here.");
		}
	}

	protected JPanel createNamedTextPanel(JTextField textField, String name) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		JLabel label = new GLabel(name + ":", SwingConstants.RIGHT);
		label.setPreferredSize(new Dimension(label.getPreferredSize()));
		panel.add(label);
		panel.add(Box.createHorizontalStrut(2));
		panel.add(textField);
		if (helpManager != null) {
			helpManager.registerHelp(textField,
				new HelpLocation(provider.getHelpTopic(), provider.getHelpName() + "_" + name));
		}
		return panel;
	}

	protected JPanel createHorizontalPanel(JComponent[] comps) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
		for (int i = 0; i < comps.length; i++) {
			if (i > 0) {
				panel.add(Box.createHorizontalStrut(10));
			}
			panel.add(comps[i]);
		}
		return panel;
	}

	protected JPanel createVerticalPanel(JComponent[] comps) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		for (int i = 0; i < comps.length; i++) {
			if (i > 0) {
				panel.add(Box.createVerticalStrut(5));
			}
			panel.add(comps[i]);
		}
		return panel;
	}

	/****************************************************************************
	 *
	 * DragNDrop support
	 *
	 ****************************************************************************/

	/** set up drag and drop and drop for the component edit area. */
	private void setUpDragDrop() {

		// Set up the drop site table selection color for DnD.
		TableCellRenderer defRenderer = table.getDefaultRenderer(String.class);
		dndTableCellRenderer = new DndTableCellRenderer(defRenderer, table);
		dndTableCellRenderer.setBorderColor(
			ColorUtils.deriveBackground(table.getSelectionBackground(), ColorUtils.HUE_PINE));
		table.setDefaultRenderer(String.class, dndTableCellRenderer);

		TableCellRenderer dtiRenderer = table.getDefaultRenderer(DataTypeInstance.class);
		dndDtiCellRenderer = new DndTableCellRenderer(dtiRenderer, table);
		dndDtiCellRenderer.setBorderColor(
			ColorUtils.deriveBackground(table.getSelectionBackground(), ColorUtils.HUE_PINE));
		table.setDefaultRenderer(DataTypeInstance.class, dndDtiCellRenderer);

		// Data Types are the only thing that can be dragged/dropped in the editor.
		acceptableFlavors = new DataFlavor[] { DataTypeTransferable.localDataTypeFlavor,
			DataTypeTransferable.localBuiltinDataTypeFlavor };

		// set up the fieldPanel as a drop target that accepts Data Types.
		dropTargetAdapter =
			new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);
		dropTarget =
			new DropTarget(table, DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		dropTarget.setActive(true);

		// set up the component area as a drag site that provides Data Types.
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new DragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(table, dragAction, dragGestureAdapter);
	}

	/**
	 * Return true if the object at the location in the DragGesture
	 * event is draggable.
	 *
	 * @param e event passed to a DragGestureListener via its
	 * dragGestureRecognized() method when a particular DragGestureRecognizer
	 * detects a platform dependent Drag and Drop action initiating
	 * gesture has occurred on the Component it is tracking.
	 * @see docking.dnd.DragGestureAdapter
	 */
	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		return false;
//            boolean dragOk = false;
//            // Need to check that the location is on a component.
//            Point point = e.getDragOrigin();
//          int index = table.rowAtPoint(point);
//            // If we are on a component then drag is allowed.
//            if ((index >= 0) && (index < model.getNumComponents())) {
//                dragOk = true;
//            }
//            return dragOk;
	}

	/**
	 * Called by the DragGestureAdapter to start the drag.
	 */
	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	/**
	 * Do the move operation; called when the drag and drop operation
	 * completes.
	 * @see docking.dnd.DragSrcAdapter#dragDropEnd
	 */
	@Override
	public void move() {
		// no-op
	}

	/**
	 * Method called when the drag operation exits the drop target
	 * without dropping.
	 */
	@Override
	public void dragCanceled(DragSourceDropEvent event) {
		// no-op
	}

	/**
	 * Get the drag actions supported by this drag source:
	 * <ul>
	 * <li>DnDConstants.ACTION_MOVE
	 * <li>DnDConstants.ACTION_COPY
	 * <li>DnDConstants.ACTION_COPY_OR_MOVE
	 * </ul>
	 *
	 * @return the drag actions
	 */
	@Override
	public int getDragAction() {
		return dragAction;
	}

	/**
	 * Get the object to transfer.
	 *
	 * @param p location of object to transfer
	 * @return object to transfer
	 */
	@Override
	public Transferable getTransferable(Point p) {
		int index = table.rowAtPoint(p);
		int numRows = model.getRowCount();
		if (index >= numRows) {
			index = numRows;
		}
		DataType dt = DefaultDataType.dataType;
		// If we are on a component then get the data type.
		if ((index >= 0)) {
			dt = model.getComponent(index).getDataType();
		}
		return new DataTypeTransferable(dt);
	}

	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		return true;
	}

	/**
	 * Add the object to the droppable component. The DragSrcAdapter calls this method from its 
	 * drop() method.
	 *
	 * @param obj Transferable object that is to be dropped.
	 * @param e  has current state of drop operation
	 * @param f represents the opaque concept of a data format as
	 * would appear on a clipboard, during drag and drop.
	 */
	@Override
	public void add(Object obj, DropTargetDropEvent e, DataFlavor f) {
		if (!(obj instanceof DataType)) {
			model.setStatus("Only data types can be dropped here.", true);
			return;
		}

		model.clearStatus();
		DataType draggedDataType = (DataType) obj;
		Point p = e.getLocation();
		if (e.getDropAction() == DnDConstants.ACTION_COPY) {
			insertAtPoint(p, draggedDataType);
		}
		// ADD : INSERT OR REPLACE
		else {
			addAtPoint(p, draggedDataType);
		}
	}

	/**
	 * Add the object to the droppable component. The DragSrcAdapter calls this method from its 
	 * drop() method.
	 *
	 * @param p the point of insert
	 * @param dt the data type to insert
	 */
	public void insertAtPoint(Point p, DataType dt) {
		endFieldEditing(); // Make sure a field isn't being edited.

		int currentIndex = table.rowAtPoint(p);
		try {
			model.insert(currentIndex, dt);
		}
		catch (UsrException e) {
			model.setStatus(e.getMessage(), true);
		}
	}

	/**
	 * Add the object to the droppable component. The DragSrcAdapter calls this method from its 
	 * drop() method.
	 * 
	 * @param p the point of insert
	 * @param dt the data type to insert
	 */
	public void addAtPoint(Point p, DataType dt) {
		endFieldEditing(); // Make sure a field isn't being edited.

		int currentIndex = table.rowAtPoint(p);
		try {
			model.add(currentIndex, dt);
		}
		catch (UsrException e) {
			model.setStatus(e.getMessage(), true);
		}
	}

	/**
	 * Called from the DropTgtAdapter when the drag operation
	 * is going over a drop site; indicate when the drop is ok
	 * by providing appropriate feedback.
	 * @param ok true means ok to drop
	 */
	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		synchronized (table) {
			int dropAction = e.getDropAction();
			boolean actionChanged = false;
			if (dropAction != lastDndAction) {
				actionChanged = true;
				lastDndAction = dropAction;
			}
			if (table.isEditing()) {
				table.editingCanceled(null);
			}
			dndTableCellRenderer.selectRange(true);
			dndDtiCellRenderer.selectRange(true);
			Point p = e.getLocation();
			int row = table.rowAtPoint(p);
			boolean setRow = dndTableCellRenderer.setRowForFeedback(row);
			boolean setDtiRow = dndDtiCellRenderer.setRowForFeedback(row);
			if (actionChanged || setRow || setDtiRow) {
				table.repaint();
			}
		}
	}

	/**
	 * Called from the DropTgtAdapter to revert any feedback
	 * changes back to normal.
	 */
	@Override
	public void undoDragUnderFeedback() {
		synchronized (table) {
			this.dndTableCellRenderer.setRowForFeedback(-1);
			this.dndDtiCellRenderer.setRowForFeedback(-1);
			table.repaint();
		}
	}

	/**
	 * CompositeEditorModelListener method called to handle lock/unlock or
	 * structure modification state change.
	 * This could also get called by a structure load or unload.
	 *
	 * @param type the type of state change: COMPOSITE_MODIFIED, COMPOSITE_UNMODIFIED,
	 * COMPOSITE_LOADED, NO_COMPOSITE_LOADED.
	 */
	@Override
	public void compositeEditStateChanged(int type) {
		switch (type) {
			case COMPOSITE_LOADED:
				cancelCellEditing(); // Make sure a field isn't being edited.
				break;
			case NO_COMPOSITE_LOADED:
				cancelCellEditing(); // Make sure a field isn't being edited.
				break;
			case COMPOSITE_MODIFIED:
			case COMPOSITE_UNMODIFIED:
				// No change in the panel.
				break;
			case EDIT_STARTED:
				if (table.isEditing()) {
					return;
				}
				beginEditField(model.getRow(), model.getColumn());
				break;
			case EDIT_ENDED:
				break;
			default:
				model.setStatus("Unrecognized edit state: " + type, true);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.datamanager.editor.CompositeEditorModelListener#endFieldEditing()
	 */
	@Override
	public void endFieldEditing() {
		stopCellEditing();
		if (table.isEditing()) {
			cancelCellEditing(); // Just in case stop failed due to bad input.
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeModelStatusListener#statusChanged(java.lang.String, boolean)
	 */
	@Override
	public void statusChanged(String message, boolean beep) {
		if ((message == null) || (message.length() == 0)) {
			message = " ";
		}
		setStatus(message);
		if (beep) {
			getToolkit().beep();
		}
	}

	void search(String searchText, boolean forward) {
		searchText = searchText.toLowerCase();
		Integer row = forward ? findForward(searchText) : findBackward(searchText);

		if (row != null) {
			table.getSelectionModel().setSelectionInterval(row, row);
			Rectangle cellRect = table.getCellRect(row, 0, true);
			table.scrollRectToVisible(cellRect);
		}

	}

	private Integer findForward(String searchText) {
		int colCount = model.getColumnCount();
		int currentRow = Math.max(0, model.getRow());

		// search  remaining lines
		int rowCount = model.getRowCount();
		for (int row = currentRow + 1; row < rowCount; row++) {
			for (int col = 0; col < colCount; col++) {
				if (matchesSearch(searchText, row, col)) {
					return row;
				}
			}
		}
		// wrap search search rows from beginning
		for (int row = 0; row < currentRow; row++) {
			for (int col = 0; col < colCount; col++) {
				if (matchesSearch(searchText, row, col)) {
					getToolkit().beep(); // notify search wrapped
					return row;
				}
			}
		}
		getToolkit().beep(); // notify search wrapped
		return null;
	}

	private Integer findBackward(String searchText) {
		int colCount = model.getColumnCount();
		int currentRow = Math.max(0, model.getRow());

		// search previous lines
		for (int row = currentRow - 1; row >= 0; row--) {
			for (int col = colCount - 1; col >= 0; col--) {
				if (matchesSearch(searchText, row, col)) {
					return row;
				}
			}
		}
		//wrap search - search from last row to current row
		for (int row = model.getRowCount() - 1; row >= currentRow; row--) {
			for (int col = colCount - 1; col >= 0; col--) {
				if (matchesSearch(searchText, row, col)) {
					getToolkit().beep(); // notify search wrapped
					return row;
				}
			}
		}
		getToolkit().beep(); // notify search wrapped
		return null;
	}

	private boolean matchesSearch(String searchText, int row, int col) {
		Object valueAt = model.getValueAt(row, col);
		if (valueAt == null) {
			return false;
		}
		String value = getString(valueAt);

		return value.toLowerCase().contains(searchText);
	}

	private String getString(Object object) {
		if (object instanceof DataTypeInstance) {
			return ((DataTypeInstance) object).getDataType().getName();
		}
		return object.toString();
	}

	@Override
	public void selectionChanged() {
		int[] tRows = table.getSelectedRows();
		int[] mRows = model.getSelectedRows();
		if (Arrays.equals(tRows, mRows)) {
			return;
		}
		FieldSelection fs = model.getSelection();
		ListSelectionModel lsm = table.getSelectionModel();
		ListSelectionModel clsm = table.getColumnModel().getSelectionModel();

		lsm.clearSelection();
		int num = fs.getNumRanges();
		for (int i = 0; i < num; i++) {
			FieldRange range = fs.getFieldRange(i);
			BigInteger startIndex = range.getStart().getIndex();
			BigInteger endIndex = range.getEnd().getIndex();
			lsm.addSelectionInterval(startIndex.intValue(), endIndex.intValue() - 1);
		}
		int column = model.getColumn();
		clsm.setAnchorSelectionIndex(column);
		clsm.setLeadSelectionIndex(column);
	}

	private class ComponentStringCellEditor extends ComponentCellEditor {
		public ComponentStringCellEditor(JTextField textField) {
			super(textField);

			getComponent().addFocusListener(new FocusAdapter() {
				@Override
				public void focusLost(FocusEvent e) {
					endFieldEditing();
				}
			});
		}

		public ComponentStringCellEditor() {
			this(new JTextField());
		}

		@Override
		public Component getTableCellEditorComponent(JTable table1, Object value,
				boolean isSelected, int row, int column) {
			model.clearStatus();
			return super.getTableCellEditorComponent(table1, value, isSelected, row, column);
		}
	}

	private class ComponentOffsetCellEditor extends ComponentStringCellEditor {
		JTextField offsetField;

		public ComponentOffsetCellEditor() {
			super(new GValidatedTextField.LongField(8));
			offsetField = (JTextField) editorComponent;
		}

		/**
		 * Calls <code>fireEditingStopped</code> and returns true.
		 * @return true
		 */
		@Override
		public boolean stopCellEditing() {
			try {
				model.validateComponentOffset(table.getEditingRow(), offsetField.getText());
				fireEditingStopped();
				return true;
			}
			catch (UsrException ue) {
				model.setStatus(ue.getMessage(), true);
			}
			return false;
		}
	}

	private class ComponentNameCellEditor extends ComponentStringCellEditor {
		private static final long serialVersionUID = 1L;

		public ComponentNameCellEditor() {
			super(new JTextField());
		}

		@Override
		public boolean stopCellEditing() {
			try {
				model.validateComponentName(table.getEditingRow(),
					((JTextComponent) getComponent()).getText());
				fireEditingStopped();
				return true;
			}
			catch (UsrException ue) {
				model.setStatus(ue.getMessage(), true);
			}
			return false;
		}
	}

	private class ComponentDataTypeCellEditor extends AbstractCellEditor
			implements TableCellEditor {

		private DataTypeSelectionEditor editor;
		private DataType dt;
		private int maxLength;
		private boolean bitfieldAllowed;

		private JPanel editorPanel;

		@Override
		public Component getTableCellEditorComponent(JTable table1, Object value,
				boolean isSelected, int row, int column) {
			model.clearStatus();
			maxLength = model.getMaxAddLength(row);
			bitfieldAllowed = model.isBitFieldAllowed();
			init();

			DataTypeInstance dti = (DataTypeInstance) value;
			if (dti != null) {
				dt = dti.getDataType();
			}
			else {
				dt = null;
			}

			editor.setCellEditorValue(dt);

			return editorPanel;
		}

		private void init() {

			Plugin plugin = provider.getPlugin();
			final PluginTool tool = plugin.getTool();
			editor = new DataTypeSelectionEditor(tool,
				bitfieldAllowed ? AllowedDataTypes.SIZABLE_DYNAMIC_AND_BITFIELD
						: AllowedDataTypes.SIZABLE_DYNAMIC);
			editor.setTabCommitsEdit(true);
			DataTypeManager originalDataTypeManager = model.getOriginalDataTypeManager();
			editor.setPreferredDataTypeManager(originalDataTypeManager);
			editor.setConsumeEnterKeyPress(false); // we want the table to handle Enter key presses

			final DropDownSelectionTextField<DataType> textField = editor.getDropDownTextField();
			textField.setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));
			editor.addCellEditorListener(new CellEditorListener() {
				@Override
				public void editingCanceled(ChangeEvent e) {
					cancelCellEditing();
				}

				@Override
				public void editingStopped(ChangeEvent e) {
					stopCellEditing();
				}
			});

			// force a small button for the table's cell editor
			JButton dataTypeChooserButton = new JButton("...") {
				@Override
				public Dimension getPreferredSize() {
					Dimension preferredSize = super.getPreferredSize();
					preferredSize.width = 15;
					return preferredSize;
				}
			};

			dataTypeChooserButton.addActionListener(e -> Swing.runLater(() -> stopEdit(tool)));

			textField.addFocusListener(new FocusAdapter() {
				@Override
				public void focusGained(FocusEvent e) {
					textField.selectAll();
					textField.removeFocusListener(this);
				}
			});

			editorPanel = new JPanel() {
				@Override
				public void requestFocus() {
					textField.requestFocus();
				}
			};
			editorPanel.setLayout(new BorderLayout());
			editorPanel.add(textField, BorderLayout.CENTER);
			editorPanel.add(dataTypeChooserButton, BorderLayout.EAST);
		}

		private void stopEdit(PluginTool tool) {
			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			DataType dataType = service.getDataType((String) null);
			if (dataType != null) {
				editor.setCellEditorValue(dataType);
				editor.stopCellEditing();
			}
			else {
				editor.cancelCellEditing();
			}
		}

		@Override
		public Object getCellEditorValue() {
			return dt;
		}

		@Override
		public boolean stopCellEditing() {

			ListSelectionModel columnSelectionModel = table.getColumnModel().getSelectionModel();
			columnSelectionModel.setValueIsAdjusting(true);

			int editingColumn = table.getEditingColumn();

			model.setStatus("");

			if (!isEmptyEditorCell() && !validateUserChoice()) {
				return false;
			}

			int editingRow = model.getRow();

			DataType dataType = (DataType) editor.getCellEditorValue();
			if (dataType != null) {
				if (dataType.equals(dt)) {
					fireEditingCanceled(); // user picked the same datatype
				}
				else {
					dt = model.resolve(dataType);
					fireEditingStopped();
				}
			}
			else {
				fireEditingCanceled();
			}

			columnSelectionModel.setAnchorSelectionIndex(editingColumn);
			columnSelectionModel.setLeadSelectionIndex(editingColumn);
			columnSelectionModel.setValueIsAdjusting(false);

			NavigationDirection navigationDirection = editor.getNavigationDirection();
			if (navigationDirection == NavigationDirection.BACKWARD) {
				editPreviousField(editingRow);
			}
			else if (navigationDirection == NavigationDirection.FORWARD) {
				editNextField(editingRow);
			}

			return true;
		}

		private boolean isEmptyEditorCell() {
			String cellEditorValueAsText = editor.getCellEditorValueAsText();
			String cellText = cellEditorValueAsText.trim();
			return cellText.isEmpty();
		}

		private boolean validateUserChoice() {
			try {
				if (!editor.validateUserSelection()) {
					// users can only select existing data types
					model.setStatus("Unrecognized data type of \"" +
						editor.getCellEditorValueAsText() + "\" entered.");
					return false;
				}

				DataType dataType = (DataType) editor.getCellEditorValue();
				int dtLen = dataType.getLength();
				if (maxLength >= 0 && dtLen > maxLength) {
					model.setStatus(dataType.getDisplayName() + " doesn't fit within " + maxLength +
						" bytes, need " + dtLen + " bytes");
					return false;
				}
			}
			catch (InvalidDataTypeException idte) {
				model.setStatus(idte.getMessage());
				return false;
			}

			return true;
		}

		// only double-click edits
		@Override
		public boolean isCellEditable(EventObject anEvent) {
			if (anEvent instanceof MouseEvent) {
				return ((MouseEvent) anEvent).getClickCount() >= 2;
			}
			return true;
		}
	}

	private class CompositeTableMouseListener extends MouseAdapter {
		@Override
		public void mouseReleased(MouseEvent e) {
			checkMouseEvent(e);
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			checkMouseEvent(e);
		}

		@Override
		public void mousePressed(MouseEvent e) {
			checkMouseEvent(e);
		}

		private void checkMouseEvent(MouseEvent e) {
			boolean isPopup = e.isPopupTrigger();
			Point point = e.getPoint();
			int row = table.rowAtPoint(point);
			int column = table.columnAtPoint(point);
			int modelColumn = table.convertColumnIndexToModel(column);
			int clickCount = e.getClickCount();
			if (!table.isEditing() && (e.getID() == MouseEvent.MOUSE_PRESSED)) {
				model.clearStatus(); // Only want to clear status when starting new actions (pressed).
			}
			if (isPopup) {
				if (!table.isRowSelected(row)) {
					table.setRowSelectionInterval(row, row);
				}
				return;
			}
			if ((clickCount < 2) || (e.getButton() != MouseEvent.BUTTON1)) {
				return;
			}
			String status = null;
			if (model.isCellEditable(row, modelColumn)) {
				return;
			}

			status = model.getColumnName(modelColumn) + " field is not editable";
			if ((row >= 0) && (row < model.getNumComponents()) &&
				((modelColumn == model.getNameColumn()) ||
					(modelColumn == model.getCommentColumn()))) {
				if (!model.isCellEditable(row, modelColumn)) {
					DataType dt = model.getComponent(row).getDataType();
					if (dt == DataType.DEFAULT) {
						if (modelColumn == model.getNameColumn()) {
							status = model.getColumnName(modelColumn) +
								" field is not editable for Undefined byte.";
						}
						else if (modelColumn == model.getCommentColumn()) {
							status = model.getColumnName(modelColumn) +
								" field is not editable for Undefined byte.";
						}
					}
				}
			}

			model.setStatus(status);

			e.consume();
		}
	}

	class CompositeTable extends GTable {

		public CompositeTable(TableModel dm) {
			super(dm);
		}

		@Override
		// overridden because the editor component was not being given focus
		public Component prepareEditor(TableCellEditor editor, int row, int column) {
			final Component component = super.prepareEditor(editor, row, column);
			Swing.runLater(() -> component.requestFocus());
			return component;
		}
	}

}
