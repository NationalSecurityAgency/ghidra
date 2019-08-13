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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.Color;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;

import docking.DockingWindowManager;
import docking.widgets.EmptyBorderButton;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.*;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * Table that displays all selected instructions. The table is interactive,
 * allowing toggling of mnemonics and operands between masked and unmasked
 * states.
 */
public class InstructionTable extends AbstractInstructionTable {

	private static final String HEADER_COL_MNEMONIC = "Mnemonic";
	private static final String HEADER_COL_OPERAND = "Operand";

	// Defines the width/height for all icons on the toolbar
	private static final int ICON_SIZE = 16;

	private static final String GO_HOME_ICON_OVERLAY = "images/go-home.png";
	private static final String ADDRESS_ICON_OVERLAY = "images/DOSA_A.png";
	private static final String SCALAR_ICON_OVERLAY = "images/DOSA_S.png";
	private static final String OPERAND_ICON_OVERLAY = "images/DOSA_O.png";
	private static final String UNDEFINED_ICON_OVERLAY = "images/DOSA_D.png";
	private static final String CLEAR_ICON_OVERLAY = "images/edit-clear.png";
	private static final String RELOAD_ICON_OVERLAY = "images/reload.png";
	private static final String MANUAL_ENTRY_ICON_OVERLAY = "images/editbytes.gif";

	// Need to keep track of the column in case the user clicks on the column header and we 
	// need to display the context menu.
	private int selectedColumn = -1;

	// Widget that is displayed if the user selects the manual entry button on the toolbar.
	private InsertBytesWidget insertBytesWidget = null;

	InstructionSearchPlugin plugin = null;

	/**
	 * Constructor
	 * 
	 * @param columns the number of columns in the table
	 * @param plugin the parent plugin
	 * @param dialog the parent dialog
	 * @throws InvalidInputException if the given plugin is not valid
	 */
	public InstructionTable(int columns, InstructionSearchPlugin plugin,
			InstructionSearchDialog dialog) throws InvalidInputException {
		super(columns, dialog);

		// If the plugin is bogus, we're in trouble - throw something up the chain.
		if (plugin == null) {
			throw new InvalidInputException("plugin object cannot be null!");
		}
		this.plugin = plugin;

		insertBytesWidget = new InsertBytesWidget(plugin.getCurrentProgram(), dialog);

		setTableAttributes();
		createContextMenu();
		createMouseEvents();

		// The data model will want to know when items in this table change...so have it register.
		// This will trigger the model to be updated as the user is toggling mask settings.
		dialog.getSearchData().registerForGuiUpdates(this);
	}

	@Override
	protected boolean supportsPopupActions() {
		return false;
	}

	public InsertBytesWidget getInsertBytesWidget() {
		return insertBytesWidget;
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	/**
	 * Creates the array of strings that will be our column headers. The first
	 * column is always the mnemonic; all others will be operands and will use a
	 * simple numeric indicator (ie: operand 1, operand 2, etc...).
	 */
	@Override
	protected Object[] createColumnHeaders() {

		if (numColumns <= 0) {
			return null;
		}

		Object[] columnNamesLocal = new Object[numColumns];

		columnNamesLocal[0] = HEADER_COL_MNEMONIC;
		for (int i = 1; i < numColumns; i++) {
			columnNamesLocal[i] = HEADER_COL_OPERAND + " " + i;
		}

		return columnNamesLocal;
	}

	/**
	 * Creates the toolbar that will be visible above the instruction table.
	 */
	@Override
	protected JToolBar createToolbar() {

		JToolBar toolbar1 = new JToolBar();
		toolbar1.add(Box.createHorizontalGlue());

		createMaskClearAllBtn(toolbar1);
		toolbar1.addSeparator();
		createMaskDataBtn(toolbar1);
		createMaskOperandsBtn(toolbar1);
		createMaskScalarsBtn(toolbar1);
		createMaskAddressesBtn(toolbar1);
		toolbar1.addSeparator();
		createReloadBtn(toolbar1);
		toolbar1.addSeparator();
		createManualEditBtn(toolbar1);
		toolbar1.addSeparator();
		createGoToAddressBtn(toolbar1);

		toolbar1.setFloatable(false);

		return toolbar1;
	}

	/**
	 * Creates and populates {@link InstructionTableDataObject} instances, one
	 * for every mnemonic/operand in the instruction set. These will define the
	 * contents of the table.
	 */
	@Override
	protected InstructionTableDataObject[][] createDataObjects() {
		if (dialog.getSearchData().getInstructions() == null) {
			return null;
		}

		InstructionTableDataObject[][] dataObjects =
			new InstructionTableDataObject[dialog.getSearchData().getInstructions().size()][numColumns];

		// Loop over all instructions, adding pertinent info to each data object. This could be a long-running
		// operation so put in a task that can be cancelled.
		Task bTask = new Task("Creating Table Data", true, true, true) {

			@Override
			public void run(TaskMonitor monitor) {
				int numInstructions = dialog.getSearchData().getInstructions().size();
				monitor.setMaximum(numInstructions);
				for (int i = 0; i < numInstructions; i++) {
					if (monitor.isCancelled()) {
						return;
					}
					monitor.incrementProgress(1);
					processInstruction(dataObjects, i);
				}
			}
		};

		new TaskLauncher(bTask, this);

		return dataObjects;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	private void createContextMenu() {

		// Create a pop-up context menu on the column header and customize.  
		getTableColumnPopupMenu(1).addSeparator();
		getTableColumnPopupMenu(1).add(
			createColumnMaskUnmaskAllMenuItem(true, "Mask entire column"));
		getTableColumnPopupMenu(1).add(
			createColumnMaskUnmaskAllMenuItem(false, "Unmask entire column"));

		// Now we MUST remove the "Add/Remove Columns" item; allowing users to do this causes
		// problems.
		MenuElement[] elements = getTableColumnPopupMenu(1).getSubElements();
		for (MenuElement element : elements) {
			if (element instanceof JMenuItem) {
				JMenuItem item = (JMenuItem) element;
				if (item.getText().contains("Add/Remove Columns")) {
					item.setEnabled(false);
				}
			}
		}
	}

	/**
	 * Sets some basic attributes of the table. Specifically, we need to specify
	 * the row selection scheme and allow popups to used.
	 */
	private void setTableAttributes() {
		this.setColumnHeaderPopupEnabled(true);

		// There is no reason for users to select entire rows, so disable it.  We only
		// want them to be able to select individual cells.
		this.setRowSelectionAllowed(false);
	}

	/**
	 * Adds mouse event listeners for clicking on the table header and internal
	 * cells.
	 */
	private void createMouseEvents() {
		// A mouse listener is needed to keep track of mouse clicks on a column.  This is
		// the only way for us to know which column to apply an event to when using the 
		// context pop-up.
		this.getTableHeader().addMouseListener(new MouseAdapter() {

			@Override
			public void mousePressed(MouseEvent arg0) {
				selectedColumn = InstructionTable.this.columnAtPoint(arg0.getPoint());
			}
		});

		// Set up a mouse release listener as the trigger for toggling mask state
		// on table cells.  
		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent evt) {
				if (SwingUtilities.isLeftMouseButton(evt)) {

					// To get the proper cell that the mouse was released on we have to 
					// use rowAtPoint(). Using getRowSelection() would seem to be a better option, 
					// but will not be accurate in the case of a drag-and-release, since it 
					// will produce an array of options along the entire drag path, and we won't 
					// know whether to grab the first item in the array or the last (depends on 
					// which direction the user drags - up or down).
					int rowSelection = InstructionTable.this.rowAtPoint(evt.getPoint());
					int columnSelection = InstructionTable.this.columnAtPoint(evt.getPoint());

					// If the row or col are -1, then the user has released the mouse outside of
					// the table; don't process this.
					if (rowSelection == -1 || columnSelection == -1) {
						return;
					}

					InstructionTableDataObject dataObject =
						getCellData(rowSelection, columnSelection);
					if (dataObject != null) {
						dataObject.toggleMaskState();

						// Clear out any messages.
						if (dialog.getMessagePanel() != null) {
							dialog.getMessagePanel().clear();
						}
					}
				}
			}
		});
	}

	private void createGoToAddressBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(GO_HOME_ICON_OVERLAY);
		Action action = new NavAction("navigation", icon,
			"Navigate to the address defined by this instruction set");
		createToolbarButton(buttonToolbar, icon, action, "nav button");
	}

	private void createMaskClearAllBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(CLEAR_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action = new ClearMasksAction("undefined", scaledIcon, "Unmask all");
		createToolbarButton(buttonToolbar, icon, action, "unmask all button");
	}

	private void createReloadBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(RELOAD_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action =
			new ReloadAction("undefined", scaledIcon, "Load selected instructions from listing");
		createToolbarButton(buttonToolbar, icon, action, "reload");
	}

	private void createManualEditBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(MANUAL_ENTRY_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action = new ManualEntryAction("undefined", scaledIcon, "Enter bytes manually");
		createToolbarButton(buttonToolbar, icon, action, "manual entry");
	}

	private void createMaskDataBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(UNDEFINED_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action =
			new MaskUndefinedAction("undefined", scaledIcon, "Mask all non-instructions (data)");
		createToolbarButton(buttonToolbar, icon, action, "mask undefined items button");
	}

	private void createMaskAddressesBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(ADDRESS_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action = new MaskAddressesAction("addresses", scaledIcon, "Mask all addresses");
		createToolbarButton(buttonToolbar, icon, action, "mask addresses button");
	}

	private void createMaskScalarsBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(SCALAR_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action = new MaskScalarsAction("scalars", scaledIcon, "Mask all scalars");
		createToolbarButton(buttonToolbar, icon, action, "mask scalars button");
	}

	private void createMaskOperandsBtn(JToolBar buttonToolbar) {
		Icon icon = ResourceManager.loadImage(OPERAND_ICON_OVERLAY);
		Icon scaledIcon = ResourceManager.getScaledIcon(icon, ICON_SIZE, ICON_SIZE);
		Action action = new MaskOperandsAction("operands", scaledIcon, "Mask all operands");
		createToolbarButton(buttonToolbar, icon, action, "mask operands button");
	}

	/**
	 * Generic method for creating a toolbar button with the given attributes.
	 * The button is automatically added to the given toolbar instance.
	 * 
	 */
	private void createToolbarButton(JToolBar toolbar1, Icon icon, Action action, String name) {
		EmptyBorderButton button = new EmptyBorderButton();
		button.setAction(action);
		button.setName(name);
		button.setHideActionText(true);
		toolbar1.add(button);
	}

	private void processInstruction(InstructionTableDataObject[][] dataObjects,
			int instructionIndex) {
		for (int i = 0; i < numColumns; i++) {
			// The mnemonic column is always first.  Otherwise it's an operand.
			if (i == 0) {
				processMnemonic(instructionIndex, i, dataObjects);
			}
			else {
				processOperand(instructionIndex, i, dataObjects);
			}
		}
	}

	private JMenuItem createColumnMaskUnmaskAllMenuItem(boolean mask, String menuLabel) {

		HelpLocation helpLocation = new HelpLocation("Tables", "GhidraTableHeaders");

		final JMenuItem item = new JMenuItem(menuLabel);
		item.addActionListener(e -> {
			int rows = InstructionTable.this.getRowCount();
			for (int row = 0; row < rows; row++) {
				maskField(row, selectedColumn, mask);
			}
		});
		DockingWindowManager.getHelpService().registerHelp(item, helpLocation);
		return item;

	}

	private class ClearMasksAction extends AbstractAction {

		public ClearMasksAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			clearAllMasks();
		}
	}

	private class ReloadAction extends AbstractAction {

		public ReloadAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			try {
				dialog.loadInstructions(plugin);
			}
			catch (InvalidInputException e1) {
				Msg.error(this, "Error loading instructions: " + e);
			}
		}
	}

	private class ManualEntryAction extends AbstractAction {

		public ManualEntryAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			insertBytesWidget = getInsertBytesWidget();
			plugin.getTool().showDialog(insertBytesWidget, plugin.getSearchDialog().getComponent());
		}
	}

	private class MaskUndefinedAction extends AbstractAction {

		public MaskUndefinedAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			maskNonInstructionsItems(false);
		}
	}

	private class MaskScalarsAction extends AbstractAction {

		public MaskScalarsAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			maskOperandsByType(OperandType.SCALAR, true);
		}
	}

	private class MaskAddressesAction extends AbstractAction {

		public MaskAddressesAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			maskOperandsByType(OperandType.ADDRESS, true);
		}
	}

	private class MaskOperandsAction extends AbstractAction {

		public MaskOperandsAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			maskAllOperands(true);
		}
	}

	/**
	 * Defines an action for navigating to the address locations defined by the
	 * instructions in the table. This is to help users who lose their place in
	 * the listing and need to get back to where the original selection was.
	 */
	private class NavAction extends AbstractAction {

		public NavAction(String text, Icon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			GoToService gs = plugin.getTool().getService(GoToService.class);

			// Only go somewhere if something is actually in the table.  If it's empty this makes
			// no sense.  Note that the plugin.getInstructions() call can never be null, so no 
			// need to check that here.
			if (dialog.getSearchData().getInstructions().size() <= 0) {
				return;
			}

			// We have something in the table, so navigate to the first instruction.  If the
			// first instruction address is null, this means the instruction was likely loaded
			// manually (hence no actual location in the listing).  In this case, just search
			// for the first instance of this instruction and navigate there.  If search returns
			// no results, display a message to the user.
			Address firstAddr = dialog.getSearchData().getInstructions().get(0).getAddr();

			if (firstAddr != null) {
				gs.goTo(firstAddr);
			}
			else {
				if (dialog.getMessagePanel() != null) {
					dialog.getMessagePanel().setMessageText(
						"Instruction was loaded manually, no address in the listing to navigate to.",
						Color.BLUE);
				}
			}
		}
	}

	/**
	 * Creates a new {@link InstructionTableDataObject} for the given mnemonic.
	 * The display text for the data object will be the mnemonic name.
	 *
	 * @param row the row of the instruction
	 * @param col the column of the mnemonic
	 * @param dataObjects the full list of data objects
	 * @return the updated data objects
	 */
	private InstructionTableDataObject[][] processMnemonic(int row, int col,
			InstructionTableDataObject[][] dataObjects) {
		dataObjects[row][col] = new InstructionTableDataObject(
			dialog.getSearchData().getInstructions().get(row).getTextRep(),
			dialog.getSearchData().getInstructions().get(row).isInstruction(),
			OperandState.NOT_MASKED);

		return dataObjects;
	}

	/**
	 * Creates a new {@link InstructionTableDataObject} for the given operand.
	 * 
	 * @param mnemonic the mnemonic ID
	 * @param col the column in the table
	 * @param dataObjects the set of data objects to modify
	 */
	private InstructionTableDataObject[][] processOperand(int row, int col,
			InstructionTableDataObject[][] dataObjects) {

		// Just make sure the col is > 0...this is processing operands so a value of 0 would be 
		// a mnemonic, and a negative number is just meaningless.
		if (col <= 0) {
			return null;
		}

		OperandMetadata operandMetadata = null;

		// First get the operand information (if any exist) for this instruction.
		// Note, the getOperands() call will never return null so we're safe here.
		List<OperandMetadata> operands =
			dialog.getSearchData().getInstructions().get(row).getOperands();
		if (operands.size() > col - 1) {
			operandMetadata =
				dialog.getSearchData().getInstructions().get(row).getOperands().get(col - 1);
		}

		// If here then we have a valid operand, so store it.
		if (operandMetadata != null) {
			InstructionTableDataObject obj =
				new InstructionTableDataObject(operandMetadata.getTextRep(),
					dialog.getSearchData().getInstructions().get(row).isInstruction(),
					OperandState.NOT_MASKED);
			obj.setOperandCase(operandMetadata);
			dataObjects[row][col] = obj;
		}

		// If here then the instruction has no operands, which isn't an error.  We just need
		// to create an empty data object for the table to display.  Setting the state to 
		// NA will cause it to not be able to be toggled on/off by the user.
		else {
			dataObjects[row][col] = new InstructionTableDataObject("",
				dialog.getSearchData().getInstructions().get(row).isInstruction(), OperandState.NA);
		}

		return dataObjects;
	}

	/**
	 * Finds all items in the table that are NOT instructions, and masks them.
	 * 
	 * @param mask the instruction mask
	 */
	private void maskNonInstructionsItems(boolean mask) {

		Task bTask = new Task("Masking Non-Instructions", true, true, true) {

			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMaximum(getRowCount() * getColumnCount());
				for (int i = 0; i < getRowCount(); i++) {
					InstructionTableDataObject mnemonicObj = getCellData(i, 0);
					if (!mnemonicObj.isInstruction()) {
						for (int j = 0; j < getColumnCount(); j++) {
							if (monitor.isCancelled()) {
								return;
							}
							monitor.incrementProgress(1);
							maskField(i, j, !mask);
						}
					}
				}
			}
		};

		new TaskLauncher(bTask, this);

		InstructionTableModel model = (InstructionTableModel) getModel();
		model.fireTableDataChanged();
	}

	/**
	 * Unmasks all instructions
	 */
	private void clearAllMasks() {

		Task bTask = new Task("Clearing All Masks", true, true, true) {

			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMaximum(getRowCount() * getColumnCount());
				for (int i = 0; i < getRowCount(); i++) {
					for (int j = 0; j < getColumnCount(); j++) {
						if (monitor.isCancelled()) {
							return;
						}
						monitor.incrementProgress(1);
						maskField(i, j, false);
					}
				}
			}
		};

		new TaskLauncher(bTask, this);

		InstructionTableModel model = (InstructionTableModel) getModel();
		model.fireTableDataChanged();
	}

	/**
	 * Sets all {@link InstructionTableDataObject} instances in the table that
	 * are operands to a masked or unmasked state.
	 * 
	 * @param mask true for mask, false for unmask
	 */
	private void maskAllOperands(boolean mask) {

		Task bTask = new Task("Masking All Operands", true, true, true) {

			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMaximum(getRowCount() * getColumnCount());
				for (int i = 0; i < getRowCount(); i++) {
					for (int j = 0; j < getColumnCount(); j++) {
						if (monitor.isCancelled()) {
							return;
						}
						monitor.incrementProgress(1);
						maskOperand(mask, i, j);
					}
				}
			}
		};

		new TaskLauncher(bTask, this);

		InstructionTableModel model = (InstructionTableModel) getModel();
		model.fireTableDataChanged();
	}

	/**
	 * Masks a single operand.
	 * 
	 * @param mask true for mask, false for unmask
	 * @param i the row index of the instruction
	 * @param j the column index of the operand
	 */
	private void maskOperand(boolean mask, int i, int j) {
		InstructionTableDataObject obj = getCellData(i, j);

		// Check the object viability and type. Only proceed if this is an operand.
		if (obj != null && obj.getOperandCase() != null) {
			if (mask) {
				obj.setState(OperandState.MASKED, false);
			}
			else {
				obj.setState(OperandState.NOT_MASKED, false);
			}
		}
	}

	/**
	 * Masks a single field.
	 * 
	 * @param mask true for mask, false for unmask
	 * @param row the row index of the instruction
	 * @param col the column index of the operand
	 */
	private void maskField(int row, int col, boolean mask) {

		// First get the data object from the cell (row, col) passed-in.  If it's invalid,
		// just return.
		InstructionTableDataObject obj = getCellData(row, col);
		if (obj == null || obj.getData() == null) {
			return;
		}

		// Do a check on the operand state - if it's 'NA', then there's no operand there at all
		// and we should leave it alone so it can continue to be in a non-toggleable state. 
		// Otherwise, set its state according to what was passed in.
		if (obj.getState() != OperandState.NA) {
			if (mask) {
				obj.setState(OperandState.MASKED, false);
			}
			else {
				obj.setState(OperandState.NOT_MASKED, false);
			}
		}
	}

	/**
	 * Sets all operands with the given type to a masked or unmasked state.
	 * 
	 * note: This is done in a background task since it may be long-running.
	 * 
	 * @param opType the type of the operand
	 * @param mask true for mask, false for unmask
	 */
	private void maskOperandsByType(int opType, boolean mask) {

		Task bTask = new Task("Masking Operands", true, true, true) {

			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMaximum(getRowCount() * getColumnCount());
				for (int i = 0; i < getRowCount(); i++) {
					for (int j = 0; j < getColumnCount(); j++) {
						if (monitor.isCancelled()) {
							return;
						}
						monitor.incrementProgress(1);
						InstructionTableDataObject obj = getCellData(i, j);
						maskOperandByType(opType, mask, obj);
					}
				}
			}
		};

		new TaskLauncher(bTask, this);

		InstructionTableModel model = (InstructionTableModel) getModel();
		model.fireTableDataChanged();
	}

	/**
	 * Sets the given {@link InstructionTableDataObject} to a masked or unmasked
	 * state, if it matches the given type.
	 * 
	 * @param opType the operand type the operand must match
	 * @param mask true for mask, false for unmask
	 * @param obj the object to mask
	 */
	private void maskOperandByType(int opType, boolean mask, InstructionTableDataObject obj) {

		if (obj != null && obj.getOperandCase() != null) {

			switch (opType) {
				case OperandType.SCALAR:
					if (OperandType.isScalar(obj.getOperandCase().getOpType())) {
						if (mask) {
							obj.setState(OperandState.MASKED, false);
						}
						else {
							obj.setState(OperandState.NOT_MASKED, false);
						}
					}
					break;
				case OperandType.ADDRESS:
					if (OperandType.isAddress(obj.getOperandCase().getOpType())) {
						if (mask) {
							obj.setState(OperandState.MASKED, false);
						}
						else {
							obj.setState(OperandState.NOT_MASKED, false);
						}
					}
			}
		}
	}
}
