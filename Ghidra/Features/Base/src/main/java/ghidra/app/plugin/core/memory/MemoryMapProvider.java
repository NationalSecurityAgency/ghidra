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
package ghidra.app.plugin.core.memory;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.table.*;
import docking.widgets.textfield.GValidatedTextField.MaxLengthField;
import generic.theme.GIcon;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.UsrException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.actions.MakeProgramSelectionAction;

/**
 * Provider for the memory map Component.
 */
class MemoryMapProvider extends ComponentProviderAdapter {
	private final static int MAX_SIZE = 256;

	private JPanel mainPanel;
	private MemoryMapModel tableModel;
	private GhidraTable table;
	private GTableFilterPanel<MemoryBlock> filterPanel;

	private DockingAction addAction;
	private DockingAction moveAction;
	private DockingAction splitAction;
	private DockingAction expandUpAction;
	private DockingAction expandDownAction;
	private DockingAction mergeAction;
	private DockingAction deleteAction;
	private DockingAction setBaseAction;

	private MemoryMapPlugin plugin = null;

	private Program program;
	private MemoryMapManager memManager;

	MemoryMapProvider(MemoryMapPlugin plugin) {
		super(plugin.getTool(), "Memory Map", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setHelpLocation(new HelpLocation(plugin.getName(), getName()));
		memManager = plugin.getMemoryMapManager();
		setIcon(new GIcon("icon.plugin.memorymap.provider"));
		addToToolbar();
		mainPanel = buildMainPanel();
		addToTool();
		addLocalActions();
	}

	@Override
	public void componentShown() {
		updateMap();
		contextChanged();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program, table);
	}

	void setStatusText(String msg) {
		tool.setStatusInfo(msg);
	}

	void dispose() {
		removeFromTool();
		filterPanel.dispose();
		plugin = null;
		program = null;
		tool = null;
	}

	void setProgram(Program program) {
		this.program = program;
		updateProgram(program);
		arrangeTable();
	}

	MemoryMapManager getMemoryMapManager() {
		return memManager;
	}

	private JPanel buildMainPanel() {
		JPanel memPanel = new JPanel(new BorderLayout());
		tableModel = new MemoryMapModel(this, null);
		table = new MemoryMapTable(tableModel);
		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);

		table.installNavigation(tool);
		table.setAutoCreateColumnsFromModel(false);

		GTableCellRenderer monoRenderer = new GTableCellRenderer();
		monoRenderer.setFont(monoRenderer.getFixedWidthFont());

		TableColumn column = table.getColumn(MemoryMapModel.START_COL);
		column.setCellRenderer(monoRenderer);
		column = table.getColumn(MemoryMapModel.END_COL);
		column.setCellRenderer(monoRenderer);
		column = table.getColumn(MemoryMapModel.LENGTH_COL);
		column.setCellRenderer(monoRenderer);

		column = table.getColumn(MemoryMapModel.READ_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = table.getColumn(MemoryMapModel.WRITE_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = table.getColumn(MemoryMapModel.EXECUTE_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = table.getColumn(MemoryMapModel.VOLATILE_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = table.getColumn(MemoryMapModel.INIT_COL);
		column.setCellRenderer(new GBooleanCellRenderer());

		table.setDefaultEditor(String.class,
			new GTableTextCellEditor(new MaxLengthField(MAX_SIZE)));

		table.setPreferredScrollableViewportSize(new Dimension(700, 105));

		table.addMouseListener(new MouseHandler());

		table.addKeyListener(new KeyHandler());

		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		ListSelectionModel lsm = table.getSelectionModel();

		lsm.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			ListSelectionModel model = (ListSelectionModel) e.getSource();
			enableOptions(model);
			contextChanged();
		});

		memPanel.add(new JScrollPane(table), BorderLayout.CENTER);
		memPanel.add(filterPanel, BorderLayout.SOUTH);

		return memPanel;
	}

	private boolean canRenameOverlaySpace(ActionContext context) {
		if (context.getContextObject() != getTable()) {
			return false;
		}
		MemoryBlock block = getSelectedBlock();
		return block != null && block.isOverlay();
	}

	private void addLocalActions() {

		// Add popup menu action for renaming overlay space on selected overlay block
		new ActionBuilder("Rename Overlay Space", plugin.getName())
				.helpLocation(new HelpLocation("MemoryMapPlugin", "OverlaySpaceRename"))
				.popupMenuPath("Rename Overlay Space")
				.enabledWhen(c -> canRenameOverlaySpace(c))
				.onAction(c -> renameOverlaySpace(c))
				.buildAndInstallLocal(this);

		Icon addImage = new GIcon("icon.plugin.memorymap.add");
		addAction = new MemoryMapAction("Add Block", addImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					showAddBlockDialog();
				}
			}
		};
		addAction.setEnabled(false);

		addAction.setDescription("Add a new block to memory");
		tool.addLocalAction(this, addAction);

		Icon moveImage = new GIcon("icon.plugin.memorymap.move");
		moveAction = new MemoryMapAction("Move Block", moveImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					moveBlock();
				}
			}
		};
		moveAction.setEnabled(false);
		moveAction.setDescription("Move a block to another address");
		tool.addLocalAction(this, moveAction);

		Icon splitImage = new GIcon("icon.plugin.memorymap.split");

		splitAction = new MemoryMapAction("Split Block", splitImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					splitBlock();
				}
			}
		};
		splitAction.setEnabled(false);

		splitAction.setDescription("Split a block");
		tool.addLocalAction(this, splitAction);

		Icon expandUpImage = new GIcon("icon.plugin.memorymap.expand.up");

		expandUpAction = new MemoryMapAction("Expand Block Up", expandUpImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					expandBlock(ExpandBlockDialog.EXPAND_UP);
				}
			}
		};
		expandUpAction.setEnabled(false);
		expandUpAction.setDescription("Expand block by setting new start address");
		tool.addLocalAction(this, expandUpAction);

		Icon expandDownImage = new GIcon("icon.plugin.memorymap.expand.down");

		expandDownAction = new MemoryMapAction("Expand Block Down", expandDownImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					expandBlock(ExpandBlockDialog.EXPAND_DOWN);
				}
			}
		};
		expandDownAction.setEnabled(false);
		expandDownAction.setDescription("Expand block by setting new end address");
		tool.addLocalAction(this, expandDownAction);

		Icon mergeImage = new GIcon("icon.plugin.memorymap.merge");
		mergeAction = new MemoryMapAction("Merge Blocks", mergeImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					mergeBlocks();
				}
			}
		};
		mergeAction.setEnabled(false);
		mergeAction.setDescription("Merge blocks into a single block");
		tool.addLocalAction(this, mergeAction);

		Icon deleteImage = new GIcon("icon.plugin.memorymap.delete");
		deleteAction = new MemoryMapAction("Delete Block", deleteImage) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					deleteBlocks();
				}
			}
		};
		deleteAction.setEnabled(false);
		deleteAction.setDescription("Delete a block");
		tool.addLocalAction(this, deleteAction);

		Icon setBaseIcon = new GIcon("icon.plugin.memorymap.image.base");
		setBaseAction = new MemoryMapAction("Set Image Base", setBaseIcon) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (checkExclusiveAccess()) {
					setBase();
				}
			}
		};
		setBaseAction.setEnabled(false);

		setBaseAction.setDescription("Set Image Base");
		tool.addLocalAction(this, setBaseAction);

		MakeProgramSelectionAction action = new MakeProgramSelectionAction(plugin, table);
		action.getToolBarData().setToolBarGroup("B"); // the other actions are in group 'A'
		tool.addLocalAction(this, action);
	}

	private boolean checkExclusiveAccess() {
		if (program.hasExclusiveAccess()) {
			return true;
		}
		String msg = "Close the file and undo your checkout,\n" +
			"then do a checkout with the exclusive lock.";

		DomainFile df = program.getDomainFile();
		if (df.modifiedSinceCheckout() || df.isChanged()) {
			msg = "Check in this file, then do a checkout with the\n" + "exclusive lock.";
		}

		Msg.showInfo(getClass(), MemoryMapProvider.this.getComponent(),
			"Exclusive Checkout Required", "An exclusive checkout is required in order to\n" +
				"manipulate memory blocks or change the image base.\n" + msg);
		return false;
	}

	private void setBase() {
		ImageBaseDialog dialog = new ImageBaseDialog(tool, program, program.getImageBase());
		tool.showDialog(dialog, this);
		dialog.dispose();
	}

	private void enableOptions(ListSelectionModel lsm) {
		// find out how many items are selected.
		int numSelected = 0;
		if (lsm == null || lsm.isSelectionEmpty()) {
			numSelected = 0;
		}
		else if (lsm.getMinSelectionIndex() == lsm.getMaxSelectionIndex()) {
			numSelected = 1;
		}
		else {
			numSelected = 2;
		}
		addAction.setEnabled(true);
		moveAction.setEnabled(numSelected == 1);
		enableSplitAction(numSelected);
		enableExpandActions(numSelected);
		mergeAction.setEnabled(numSelected > 1);
		deleteAction.setEnabled(numSelected >= 1);
	}

	private void enableSplitAction(int numSelected) {
		if (numSelected != 1) {
			splitAction.setEnabled(false);
		}
		else {
			MemoryBlock block = getSelectedBlock();
			splitAction.setEnabled(block.getType() == MemoryBlockType.DEFAULT);
		}
	}

	private void enableExpandActions(int numSelected) {
		if (numSelected != 1) {
			expandUpAction.setEnabled(false);
			expandDownAction.setEnabled(false);
		}
		else {
			MemoryBlock block = getSelectedBlock();
			if (block.getType() != MemoryBlockType.DEFAULT) {
				expandDownAction.setEnabled(false);
				expandUpAction.setEnabled(false);
				return;
			}

			if (block.getStart().getOffset() == 0) {
				expandUpAction.setEnabled(false);
			}
			else {
				expandUpAction.setEnabled(true);
			}
			Address endAddr = block.getEnd();
			if (endAddr.equals(endAddr.getAddressSpace().getMaxAddress())) {
				expandDownAction.setEnabled(false);
			}
			else {
				expandDownAction.setEnabled(true);
			}
		}
	}

	JTable getTable() {
		return table;
	}

	/**
	 * Update the memory map table. Something has changed.
	 */
	void updateMap() {
		if (isVisible()) {
			tableModel.update();
			arrangeTable();
			updateTitle();
		}
	}

	void updateData() {
		if (isVisible()) {
			updateTitle();
			table.repaint();
		}
	}

	private void updateTitle() {
		if (program != null) {
			setSubTitle("Image Base: " + program.getImageBase().toString());
		}
	}

	/**
	 * Update the memory map with the new program's memory
	 */
	private void updateProgram(Program updatedProgram) {
		enableOptions(null);
		if (updatedProgram == null) {
			addAction.setEnabled(false);
			setBaseAction.setEnabled(false);
		}
		else {
			setBaseAction.setEnabled(true);
		}

		tableModel.setProgram(updatedProgram);
		updateTitle();
	}

	/**
	 * Set up the table so it looks well arranged.
	 */
	private void arrangeTable() {
		// memTable.setRowHeight(20);
		TableColumn column;

		column = table.getColumn(MemoryMapModel.READ_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}

		column = table.getColumn(MemoryMapModel.WRITE_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}

		column = table.getColumn(MemoryMapModel.EXECUTE_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}

		column = table.getColumn(MemoryMapModel.VOLATILE_COL);
		if (column != null) {
			column.setMaxWidth(65);
			column.setMinWidth(65);
			column.setResizable(false);
		}

		column = table.getColumn(MemoryMapModel.BLOCK_TYPE_COL);
		if (column != null) {
			column.setMinWidth(25);
//			column.setResizable(true);
		}

		column = table.getColumn(MemoryMapModel.INIT_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}
	}

	/**
	 * Class to Handle Mouse events on Memory Map Table component
	 */
	private class MouseHandler extends MouseAdapter {
		@Override
		public void mouseReleased(MouseEvent e) {
			setStatusText("");
		}

		@Override
		public void mousePressed(MouseEvent e) {
			setStatusText("");
			if (!e.isPopupTrigger()) {
				if ((e.getModifiersEx() &
					(InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)) == 0) {
					navigateToAddress();
				}
			}
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			setStatusText("");
		}
	}

	private class KeyHandler extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent e) {
			if (e.getKeyCode() == KeyEvent.VK_ENTER) {
				navigateToAddress();
				e.consume();
			}
		}
	}

	private void navigateToAddress() {
		int viewRow = table.getSelectedRow();
		int viewColumn = table.getSelectedColumn();
		int modelColumn = table.convertColumnIndexToModel(viewColumn);
		MemoryBlock block = tableModel.getBlockAt(viewRow);
		if (block != null && (modelColumn == 1 || modelColumn == 2)) {
			Address addr = (modelColumn == 1 ? block.getStart() : block.getEnd());
			plugin.blockSelected(block, addr);
			table.setRowSelectionInterval(viewRow, viewRow);
		}
	}

	private MemoryBlock getSelectedBlock() {
		int row = table.getSelectedRow();
		if (row < 0) {
			return null;
		}
		return tableModel.getBlockAt(row);
	}

	private void renameOverlaySpace(ActionContext c) {
		if (!checkExclusiveAccess()) {
			return;
		}
		if (!program.canLock()) {
			setStatusText("Program is busy, try again later");
			return;
		}
		MemoryBlock block = getSelectedBlock();
		if (block == null || !block.isOverlay()) {
			return;
		}
		OverlayAddressSpace overlaySpace = (OverlayAddressSpace) block.getStart().getAddressSpace();
		String oldName = overlaySpace.getName();

		String newName = OptionDialog.showInputSingleLineDialog(getComponent(),
			"Rename Overlay Space", "New Name:", oldName);
		if (newName == null || oldName.equals(newName)) {
			return;
		}

		try {
			program.withTransaction("Rename Overlay Space: " + oldName, () -> {
				program.renameOverlaySpace(oldName, newName);
			});
		}
		catch (UsrException e) {
			Msg.showError(this, getComponent(), "Rename Overlay Error", e.getMessage());
		}
	}

	/**
	 * Delete the selected blocks.
	 */
	private void deleteBlocks() {
		if (!program.canLock()) {
			setStatusText("Program is busy, try again later");
			return;
		}
		ArrayList<MemoryBlock> delBlocks = new ArrayList<>();
		int delRows[] = table.getSelectedRows();
		for (int element : delRows) {
			MemoryBlock block = tableModel.getBlockAt(element);
			delBlocks.add(block);
		}
		table.clearSelection();
		deleteBlock(delBlocks);
	}

	/**
	 * Callback for deleting a block of memory
	 */
	private void deleteBlock(ArrayList<MemoryBlock> blocks) {
		memManager.deleteBlocks(blocks);
	}

	/**
	 * Pop up a dialog to expand the block either up or down; "up" means make a
	 * block have a lesser starting address; "down" means to make the block have
	 * a greater ending address.
	 *
	 * @param dialogType either ExpandBlockDialog.EXPAND_UP or
	 *            ExpandBlockDialog.EXPAND_DOWN.
	 */
	private void expandBlock(int dialogType) {
		MemoryBlock block = getSelectedBlock();
		if (block == null) {
			return;
		}

		// Check for expansion of FileBytes use
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		int sourceIndex = dialogType == ExpandBlockDialog.EXPAND_UP ? 0 : (sourceInfos.size() - 1);
		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(sourceIndex);
		if (sourceInfo.getFileBytes().isPresent()) {
			int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(getComponent(),
				"Expanding File Bytes Block",
				"Block use of File Bytes will be expanded with a 0-filled region.  Continue?",
				"Continue...");
			if (choice != OptionDialog.OPTION_ONE) {
				return;
			}
		}

		showExpandBlockDialog(dialogType, block);
	}

	private void moveBlock() {
		if (!program.canLock()) {
			setStatusText("Program is busy, try again later");
			return;
		}
		MemoryBlock block = getSelectedBlock();
		if (block == null) {
			return;
		}

		if (block.isOverlay() && block.getStart().isNonLoadedMemoryAddress()) {
			// impose convention-based restriction
			Msg.showInfo(getClass(), getComponent(), "Moving OTHER Overlay Block Not Allowed",
				"OTHER overlay blocks cannot be moved.");
		}
		else {
			showMoveBlockDialog(block);
		}
	}

	/**
	 * Pop up a dialog to split the selected block.
	 */
	private void splitBlock() {
		MemoryBlock block = getSelectedBlock();
		if (block == null) {
			return;
		}
		if (block.isOverlay() && block.getStart().isNonLoadedMemoryAddress()) {
			// impose convention-based restriction
			Msg.showInfo(getClass(), getComponent(), "Split OTHER Overlay Block Not Allowed",
				"OTHER overlay blocks can not be split.");
		}
		else {
			SplitBlockDialog d = new SplitBlockDialog(plugin, block, program.getAddressFactory());
			tool.showDialog(d, this);
		}
	}

	/**
	 * Show the dialog to expand a memory block.
	 *
	 * @param dialogType expand up or down
	 * @param block block to expand
	 */
	private void showExpandBlockDialog(int dialogType, MemoryBlock block) {
		ExpandBlockModel model;
		if (dialogType == ExpandBlockDialog.EXPAND_UP) {
			model = new ExpandBlockUpModel(tool, program);
		}
		else {
			model = new ExpandBlockDownModel(tool, program);
		}

		ExpandBlockDialog dialog =
			new ExpandBlockDialog(tool, model, block, program.getAddressFactory(), dialogType);
		model.initialize(block);
		dialog.dispose();
	}

	private void showMoveBlockDialog(MemoryBlock block) {

		MoveBlockModel model = new MoveBlockModel(program);
		new MoveBlockDialog(model, tool);
		model.initialize(block);
	}

	/**
	 * Merge the selected blocks.
	 */
	private void mergeBlocks() {
		ArrayList<MemoryBlock> blocks = new ArrayList<>();
		int rows[] = table.getSelectedRows();
		for (int element : rows) {
			MemoryBlock block = tableModel.getBlockAt(element);
			blocks.add(block);
		}
		table.clearSelection();
		memManager.mergeBlocks(blocks);
	}

	void setCursor(Cursor cursor) {
		tool.getToolFrame().setCursor(cursor);
	}

	/**
	 * Callback for adding a block of memory
	 */
	void showAddBlockDialog() {
		AddBlockModel model = new AddBlockModel(tool, program);

		AddBlockDialog d = new AddBlockDialog(model);
		d.showDialog(tool);
	}

	@Override
	public PluginTool getTool() {
		return plugin.getTool();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MemoryMapTable extends GhidraTable {
		MemoryMapTable(TableModel model) {
			super(model);
			setAutoEditEnabled(true);
			setActionsEnabled(true);
			setVisibleRowCount(10);
		}

		@Override
		protected <T> SelectionManager createSelectionManager() {
			return null;
		}
	}

	private abstract class MemoryMapAction extends DockingAction {
		MemoryMapAction(String name, Icon icon) {
			super(name, plugin.getName());
			this.setToolBarData(new ToolBarData(icon, "A"));
		}
	}
}
