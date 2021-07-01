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

import java.awt.Component;
import java.awt.Dimension;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;

import docking.ActionContext;
import docking.EmptyBorderToggleButton;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.dnd.GClipboard;
import docking.widgets.EmptyBorderButton;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.*;
import ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * Displays the preview string for all instructions in the
 * {@link InstructionTable}. This table is updated whenever a change is made to
 * the mask settings in the instruction table.
 */
public class PreviewTable extends AbstractInstructionTable {

	// Defines the formats we can display the search strings in.
	public enum ViewType {
		BINARY, HEX
	}

	// Copies all selected instructions to the clipboard, with spaces stripped.
	private DockingAction copyNoSpacesAction;

	// Copies the selected instructions to the clipboard.
	private DockingAction copyInstructionAction;

	// Copies the selected instructions, with comments, to the clipboard.
	private DockingAction copyInstructionWithCommentsAction;

	// For internal use only; this id identifies the action group and is not displayed anywhere.
	private String actionMenuGroup = "aaaTableGroup";

	public static final String HEADER_COL_PREVIEW = "Search String Preview";

	private ViewType currentView = ViewType.HEX;

	/**
	 * List of preview strings, organized by their index in the table. This is
	 * set when the selected instructions are first loaded and should not
	 * change.
	 */
	private final Map<Integer, String> previewStringMap = new LinkedHashMap<>();

	/**
	 * Constructor
	 * 
	 * @param numColumns the number of columns in the table
	 * @param plugin the parent plugin
	 * @param dialog the search dialog
	 */
	public PreviewTable(int numColumns, InstructionSearchPlugin plugin,
			InstructionSearchDialog dialog) {
		super(numColumns, dialog);

		// Turn off the column-level context menu so users can't show/hide columns.
		setColumnHeaderPopupEnabled(false);

		// And now create our custom menu options.
		createContextMenuActions();
	}

	/**
	 * Must override this in order for horizontal scrolling to work. Scrolling
	 * isn't automatically given when embedding a jtable in a scrollpanel; the
	 * preferred width of the table must be explicitly set to the width of the
	 * contents of the widest cell.
	 * 
	 * Note: We could override getPreferredSize() instead but we don't want to
	 * change the default behavior for setting the preferred height, only the
	 * width. So it's better to do it here.
	 */
	@Override
	public boolean getScrollableTracksViewportWidth() {

		// Loop over all cells, getting the width of the largest cell.
		int width = 0;
		for (int row = 0; row < getRowCount(); row++) {
			TableCellRenderer rendererr = getCellRenderer(row, 0);
			Component comp = prepareRenderer(rendererr, row, 0);
			width = Math.max(comp.getPreferredSize().width, width);
		}

		// Now set the new preferred size using that max width, and the
		// existing preferred height.
		this.setPreferredSize(new Dimension(width, getPreferredSize().height));

		// Return true if the viewport has changed such that the table columns need to 
		// be resized.
		return getPreferredSize().width < getParent().getWidth();
	}

	/**
	 * Adds a string to the preview table.
	 *
	 * @param previewText the string to add
	 * @param index the row in the preview table to update
	 */
	public void addPreviewString(String previewText, Integer index) {
		previewStringMap.put(index, previewText);
		refreshView();
	}

	/**
	 * Replaces the contents of the preview table at the given row with the
	 * given string.
	 * 
	 * @param row the row to replace
	 * @param val the new text
	 */
	public void setPreviewText(int row, String val) {
		for (int i = 0; i < getColumnCount(); i++) {
			if (getColumnName(i).equals(HEADER_COL_PREVIEW)) {
				InstructionTableDataObject instrDO = getCellData(row, i);
				if (instrDO == null) {
					continue;
				}
				instrDO.setData(val);
			}
		}
	}

	/**
	 * Constructs the preview strings to display in the table, based on the
	 * current mask settings.
	 * <p>
	 * This is a potentially long-running task so it's implemented in a
	 * background task. Also, note that we need to specify the dialog parent so
	 * we can't use the convenience TaskLauncher.launch... methods.
	 */
	public void buildPreviewStrings() {

		Task task = new Task("Building Preview", true, true, true) {

			@Override
			public void run(TaskMonitor monitor) {
				int numInstructions = searchData.getInstructions().size();

				monitor.setMaximum(numInstructions);

				// Get the search strings for all instructions.
				String valueStr = searchData.getValueString();
				String maskStr = searchData.getMaskString();

				// Keep a count of where we are in terms of bytes as we're processing each
				// instruction.
				int posptr = 0;

				// Loop over all instructions, extracting information for each, and 
				// converting the binary instruction to a string we can display.
				for (int i = 0; i < numInstructions; i++) {

					if (monitor.isCancelled()) {
						return;
					}

					monitor.incrementProgress(1);

					// Keep track of the instruction size as we're processing; we use this to 
					// increment our byte position.
					int instrSize = 0;

					InstructionMetadata metadata = searchData.getInstructions().get(i);
					if (metadata != null) {

						// See if we only have a mnemonic and NO operands.  If so, then just add
						// the mnemonic to the preview panel and increment our counter.
						if (metadata.getOperands() == null || metadata.getOperands().size() == 0) {
							MaskContainer maskContainer = metadata.getMaskContainer();
							if (maskContainer != null && maskContainer.getValue() != null) {
								instrSize = maskContainer.getValue().length;
							}
						}
						else if (metadata.getOperands() != null) {

							OperandMetadata operand = metadata.getOperands().get(0);

							// We should never have a null operand here, but if we do, we need to
							// break out of this and continue to the next item, without incrementing
							// our pointer (because we didn't process anything).
							if (operand == null) {
								continue;
							}

							instrSize = operand.getMaskContainer().getValue().length;
						}
					}

					// Finally build the preview string for this instruction, and increment our
					// byte position.
					buildPreviewString(instrSize, valueStr, maskStr, posptr, i);
					posptr += instrSize * 8;
				}
			}
		};

		new TaskLauncher(task, PreviewTable.this);
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/
	/**
	 * 
	 */
	@Override
	protected Object[] createColumnHeaders() {

		Object[] colsNames = new Object[numColumns];
		colsNames[numColumns - 1] = HEADER_COL_PREVIEW;

		return colsNames;
	}

	/**
	 * 
	 */
	@Override
	protected JToolBar createToolbar() {
		JToolBar toolbar1 = new JToolBar();
		toolbar1.add(Box.createHorizontalGlue());

		EmptyBorderToggleButton binaryBtn = createBinaryViewBtn(toolbar1);
		EmptyBorderToggleButton hexBtn = createHexViewBtn(toolbar1);
		createSetViewButtonGroup(binaryBtn, hexBtn);

		toolbar1.addSeparator();
		createCopyBtn(toolbar1);
		toolbar1.setFloatable(false);

		return toolbar1;
	}

	/**
	 * Creates {@link InstructionTableDataObject} objects to back the preview
	 * table.
	 */
	@Override
	protected InstructionTableDataObject[][] createDataObjects() {

		// Make sure we have valid objects to work with.
		if (searchData.getInstructions() == null) {
			return null;
		}

		// Create the array to return...
		InstructionTableDataObject[][] dataObjects =
			new InstructionTableDataObject[searchData.getInstructions().size()][numColumns];

		// ..and populate it with DataObject instances.
		for (int mnemonic = 0; mnemonic < searchData.getInstructions().size(); mnemonic++) {
			for (int col = 0; col < numColumns; col++) {
				dataObjects[mnemonic][col] = new InstructionTableDataObject("",
					searchData.getInstructions().get(mnemonic).isInstruction(),
					OperandState.PREVIEW);
			}
		}

		return dataObjects;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	private void buildPreviewString(int instrSize, String valueStr, String maskStr, int posptr,
			int row) {

		// Extract the number of bytes from the full string created above, both for the value 
		// and the mask;
		String instrValTmp = valueStr.substring(posptr, posptr + (instrSize * 8));
		String instrMaskTmp = maskStr.substring(posptr, posptr + (instrSize * 8));

		// Add the strings to the table, making sure to format the string such that
		// masked bits are displayed correctly.
		String prevStr = "";
		try {
			prevStr = InstructionSearchUtils.formatSearchString(instrValTmp, instrMaskTmp);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error formatting string for preview: " + instrValTmp);
			// Note, don't return here - continue to add the string (empty at this point) to the
			// preview at the given row.
		}

		addPreviewString(prevStr, row);
	}

	private void createSetViewButtonGroup(EmptyBorderToggleButton binaryBtn,
			EmptyBorderToggleButton hexBtn) {
		ButtonGroup viewTypeGroup = new ButtonGroup();
		viewTypeGroup.add(binaryBtn);
		viewTypeGroup.add(hexBtn);
	}

	private void createCopyBtn(JToolBar toolbar1) {
		Icon copyIcon = ResourceManager.loadImage("images/page_white_copy.png");
		Action copyAction = new CopyAction("copy", (ImageIcon) copyIcon,
			"Copy the full search string to clipboard");
		EmptyBorderButton copyBtn = new EmptyBorderButton();
		copyBtn.setAction(copyAction);
		copyBtn.setName("Copy Preview Button");
		copyBtn.setHideActionText(true);
		toolbar1.add(copyBtn);
	}

	private EmptyBorderToggleButton createHexViewBtn(JToolBar toolbar1) {
		Icon hexIcon = ResourceManager.loadImage("images/hexData.png");
		Action hexAction = new HexAction("hex", (ImageIcon) hexIcon, "hex view");
		EmptyBorderToggleButton hexBtn = new EmptyBorderToggleButton();
		hexBtn.setAction(hexAction);
		hexBtn.setName("Hex View Button");
		hexBtn.setHideActionText(true);
		hexBtn.setSelected(true);
		toolbar1.add(hexBtn);
		return hexBtn;
	}

	private EmptyBorderToggleButton createBinaryViewBtn(JToolBar toolbar1) {
		Icon binaryIcon = ResourceManager.loadImage("images/binaryData.gif");
		Action binaryAction = new BinaryAction("binary", (ImageIcon) binaryIcon, "binary view");
		EmptyBorderToggleButton binaryBtn = new EmptyBorderToggleButton();
		binaryBtn.setAction(binaryAction);
		binaryBtn.setName("binary view button");
		binaryBtn.setHideActionText(true);
		toolbar1.add(binaryBtn);
		return binaryBtn;
	}

	/**
	 * Gathers the search strings for each instruction and returns them as a
	 * single string.
	 * 
	 * @return the complete search string
	 */
	private String buildSearchString() {
		StringBuilder sb = new StringBuilder();

		int previewColumnIndex = getPreviewColumnIndex();

		// Loop over all rows, extracting the text in each, and appending
		// it to our return string.
		for (int j = 0; j < this.getModel().getRowCount(); j++) {
			addRowToSearchString(sb, previewColumnIndex, j);
		}

		return sb.toString();
	}

	private void addRowToSearchString(StringBuilder sb, int previewColumnIndex, int j) {
		InstructionTableDataObject obj =
			(InstructionTableDataObject) this.getModel().getValueAt(j, previewColumnIndex);
		String preview = obj.getData();
		if (preview != null) {
			sb.append(preview);
		}
	}

	private int getPreviewColumnIndex() {
		int previewColumnIndex = 0;
		for (int i = 0; i < this.getModel().getColumnCount(); i++) {
			if (this.getColumnName(i).equals(HEADER_COL_PREVIEW)) {
				previewColumnIndex = i;
				break;
			}
		}
		return previewColumnIndex;
	}

	/**
	 * Updates the table to display preview data as either hex or binary
	 * (depends on the setting of 'currentView').
	 */
	private void refreshView() {

		// Grab an iterator so we can process each preview string.
		Iterator<Map.Entry<Integer, String>> it = previewStringMap.entrySet().iterator();

		while (it.hasNext()) {
			Map.Entry<Integer, String> pair = it.next();
			Integer index = pair.getKey();
			String instr = pair.getValue();

			// Create a new string to hold the string we'll set in the table.
			String previewString = "";

			switch (currentView) {
				case BINARY:
					// If it's binary, just grab the value of the preview string
					// in the map; they're stored there as binary so nothing to 
					// do but format it with the correct mask settings.
					previewString =
						InstructionSearchUtils.addSpaceOnByteBoundary(instr, InputMode.BINARY);
					break;
				case HEX:
					// For hex, we have to convert the binary string to hex, so use
					// our utility...
					previewString = InstructionSearchUtils.toHex(instr, true).toString();
					break;
			}

			setPreviewText(index, previewString);
		}

		repaint();
	}

	private void createContextMenuActions() {
		String owner = getClass().getSimpleName();

		InstructionSearchPlugin plugin = getPlugin();
		PluginTool tool = plugin.getTool();
		tool.setMenuGroup(new String[] { "Copy Special" }, actionMenuGroup, "1");

		createCopyNoSpacesAction(owner);
		copyNoSpacesAction.setPopupMenuData(
			new MenuData(new String[] { "Copy Special", "Selected instructions (no spaces)" },
				ResourceManager.loadImage("images/page_white_copy.png"), actionMenuGroup,
				MenuData.NO_MNEMONIC, Integer.toString(1)));

		createCopyInstructionAction(owner);
		copyInstructionAction.setPopupMenuData(
			new MenuData(new String[] { "Copy Special", "Selected Instructions" },
				ResourceManager.loadImage("images/page_white_copy.png"), actionMenuGroup,
				MenuData.NO_MNEMONIC, Integer.toString(1)));

		createCopyInstructionWithCommentsAction(owner);
		copyInstructionWithCommentsAction.setPopupMenuData(
			new MenuData(new String[] { "Copy Special", "Selected Instructions (with comments)" },
				ResourceManager.loadImage("images/page_white_copy.png"), actionMenuGroup,
				MenuData.NO_MNEMONIC, Integer.toString(1)));

		dialog.addAction(copyNoSpacesAction);
		dialog.addAction(copyInstructionAction);
		dialog.addAction(copyInstructionWithCommentsAction);
	}

	/**
	 * Creates a string from the selected items, with comments indicating the
	 * mnemonic/operand types.
	 */
	private void createCopyInstructionWithCommentsAction(String owner) {
		copyInstructionWithCommentsAction =
			new DockingAction("Selected Instructions (with comments)", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					int[] selectedRows = PreviewTable.this.getSelectedRows();
					String val = "";
					for (int selectedRow : selectedRows) {

						val += getColumnValue(selectedRow, HEADER_COL_PREVIEW);

						String comment = searchData.getInstructions().get(selectedRow).getTextRep();

						if (comment != null) {
							StringBuilder builder = new StringBuilder();
							builder.append(val).append("\t").append("// ").append(comment).append(
								"\n");
							val = builder.toString();
						}
					}

					StringSelection sel = new StringSelection(val);
					Clipboard clip = GClipboard.getSystemClipboard();
					clip.setContents(sel, null);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return context.getSourceComponent() == PreviewTable.this;
				}
			};

		copyInstructionWithCommentsAction.setHelpLocation(dialog.getHelpLocatdion());
	}

	/**
	 * Creates a string based on the contents of the preview column in all rows,
	 * as shown in the table.
	 */
	private void createCopyInstructionAction(String owner) {
		copyInstructionAction = new DockingAction("Selected Instructions", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				int[] selectedRows = PreviewTable.this.getSelectedRows();
				String val = "";
				for (int selectedRow : selectedRows) {
					val += getColumnValue(selectedRow, HEADER_COL_PREVIEW) + "\n";
				}

				StringSelection sel = new StringSelection(val);
				Clipboard clip = GClipboard.getSystemClipboard();
				clip.setContents(sel, null);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context.getSourceComponent() == PreviewTable.this;
			}
		};

		copyInstructionAction.setHelpLocation(dialog.getHelpLocatdion());
	}

	/**
	 * Creates a string based on the contents of the preview col in selected
	 * rows, as shown in the table, with no spaces.
	 */
	private void createCopyNoSpacesAction(String owner) {
		copyNoSpacesAction = new DockingAction("Selected instructions (no spaces)", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				int[] selectedRows = PreviewTable.this.getSelectedRows();
				String val = "";
				for (int selectedRow : selectedRows) {
					val += getColumnValue(selectedRow, HEADER_COL_PREVIEW).replaceAll(" ", "");
				}

				StringSelection sel = new StringSelection(val);
				Clipboard clip = GClipboard.getSystemClipboard();
				clip.setContents(sel, null);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context.getSourceComponent() == PreviewTable.this;
			}
		};

		copyNoSpacesAction.setHelpLocation(dialog.getHelpLocatdion());
	}

	private class BinaryAction extends AbstractAction {

		public BinaryAction(String text, ImageIcon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			currentView = ViewType.BINARY;
			refreshView();
		}
	}

	private class HexAction extends AbstractAction {

		public HexAction(String text, ImageIcon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			currentView = ViewType.HEX;
			refreshView();
		}
	}

	private class CopyAction extends AbstractAction {

		public CopyAction(String text, ImageIcon icon, String desc) {
			super(text, icon);
			putValue(SHORT_DESCRIPTION, desc);

		}

		@Override
		public void actionPerformed(ActionEvent e) {
			StringSelection sel = new StringSelection(PreviewTable.this.buildSearchString());
			Clipboard clip = GClipboard.getSystemClipboard();
			clip.setContents(sel, null);
		}
	}
}
