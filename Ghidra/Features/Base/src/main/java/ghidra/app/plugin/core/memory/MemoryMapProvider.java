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

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.label.GLabel;
import docking.widgets.table.*;
import docking.widgets.textfield.GValidatedTextField.MaxLengthField;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

/**
 * Provider for the memory map Component.
 *
 */
class MemoryMapProvider extends ComponentProviderAdapter {
	private final static int MAX_SIZE = 256;

	private JPanel mainPanel;
	private GTable memTable;
	private JScrollPane memPane;
	private MemoryMapModel mapModel;

	private DockingAction addAction;
	private DockingAction moveAction;
	private DockingAction splitAction;
	private DockingAction expandUpAction;
	private DockingAction expandDownAction;
	private DockingAction mergeAction;
	private DockingAction deleteAction;
	private DockingAction setBaseAction;

	private MemoryMapPlugin plugin = null;

	private final static String ADD_IMAGE = "images/Plus.png";
	private final static String MOVE_IMAGE = "images/move.png";
	private final static String SPLIT_IMAGE = "images/verticalSplit.png";
	private final static String EXPAND_UP_IMAGE = "images/collapse.gif";
	private final static String EXPAND_DOWN_IMAGE = "images/expand.gif";
	private final static String MERGE_IMAGE = "images/Merge.png";
	private final static String DELETE_IMAGE = "images/edit-delete.png";
	private final static String IMAGE_BASE = "images/house.png";
	final static String MEMORY_IMAGE = "images/memory16.gif";

	private Program program;
	private MemoryMapManager memManager;

	MemoryMapProvider(MemoryMapPlugin plugin) {
		super(plugin.getTool(), "Memory Map", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setHelpLocation(new HelpLocation(plugin.getName(), getName()));
		memManager = plugin.getMemoryMapManager();
		setIcon(ResourceManager.loadImage(MEMORY_IMAGE));
		addToToolbar();
		mainPanel = buildMainPanel();
		addToTool();
		addLocalActions();
	}

	@Override
	public void componentShown() {
		updateMap();
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
		return new ProgramActionContext(this, program);
	}

	void setStatusText(String msg) {
		tool.setStatusInfo(msg);
	}

	void dispose() {
		removeFromTool();
		memTable.dispose();
		plugin = null;
		program = null;
		tool = null;
	}

	void setProgram(Program program) {
		this.program = program;
		updateMap(program);
		arrangeTable();
	}

	MemoryMapManager getMemoryMapManager() {
		return memManager;
	}

	/**
	 * Creates the Main Panel for the Memory Map Dialog
	 */
	private JPanel buildMainPanel() {
		JPanel memPanel = new JPanel(new BorderLayout());
		mapModel = new MemoryMapModel(this, null);
		memTable = new MemoryMapTable(mapModel);

		memTable.setAutoCreateColumnsFromModel(false);

		TableColumn column;
		column = memTable.getColumn(MemoryMapModel.READ_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = memTable.getColumn(MemoryMapModel.WRITE_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = memTable.getColumn(MemoryMapModel.EXECUTE_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = memTable.getColumn(MemoryMapModel.VOLATILE_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = memTable.getColumn(MemoryMapModel.OVERLAY_COL);
		column.setCellRenderer(new GBooleanCellRenderer());
		column = memTable.getColumn(MemoryMapModel.INIT_COL);
		column.setCellRenderer(new GBooleanCellRenderer());

		memTable.setDefaultEditor(String.class,
			new GTableTextCellEditor(new MaxLengthField(MAX_SIZE)));

		memPane = new JScrollPane(memTable);
		memTable.setPreferredScrollableViewportSize(new Dimension(570, 105));

		memTable.addMouseListener(new MouseHandler());

		memTable.addKeyListener(new KeyHandler());

		memTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		ListSelectionModel lsm = memTable.getSelectionModel();

		lsm.addListSelectionListener(e -> {
			// Ignore extra messages.
			if (e.getValueIsAdjusting()) {
				return;
			}

			ListSelectionModel model = (ListSelectionModel) e.getSource();
			enableOptions(model);
		});

		memPanel.add(new GLabel("Memory Blocks", SwingConstants.CENTER), BorderLayout.NORTH);
		memPanel.add(memPane, BorderLayout.CENTER);

		return memPanel;
	}

	private void addLocalActions() {
		ImageIcon addImage = ResourceManager.loadImage(ADD_IMAGE);

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

		ImageIcon moveImage = ResourceManager.loadImage(MOVE_IMAGE);
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

		ImageIcon splitImage = ResourceManager.loadImage(SPLIT_IMAGE);

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

		ImageIcon expandUpImage = ResourceManager.loadImage(EXPAND_UP_IMAGE);

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

		ImageIcon expandDownImage = ResourceManager.loadImage(EXPAND_DOWN_IMAGE);

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

		ImageIcon mergeImage = ResourceManager.loadImage(MERGE_IMAGE);
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

		ImageIcon deleteImage = ResourceManager.loadImage(DELETE_IMAGE);
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

		ImageIcon setBaseIcon = ResourceManager.loadImage(IMAGE_BASE);
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

	/**
	 * Enable/disable the expand up/down actions according to the selected
	 * block.
	 * 
	 * @param numSelected number of blocks selected
	 */
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
		return memTable;
	}

	/**
	 * Update the memory map table. Something has changed.
	 */
	void updateMap() {
		if (isVisible()) {
			mapModel.update();
			arrangeTable();
			updateTitle();
		}
	}

	void updateData() {
		if (isVisible()) {
			updateTitle();
			memTable.repaint();
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
	private void updateMap(Program updateProgram) {
		enableOptions(null);
		if (updateProgram == null) {
			addAction.setEnabled(false);
			setBaseAction.setEnabled(false);
		}
		else {
			setBaseAction.setEnabled(true);
		}

		mapModel = new MemoryMapModel(this, updateProgram);
		memTable.setModel(mapModel);
		updateTitle();
	}

	/**
	 * Set up the table so it looks well arranged.
	 */
	private void arrangeTable() {
		// memTable.setRowHeight(20);
		TableColumn column;

		column = memTable.getColumn(MemoryMapModel.READ_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}

		column = memTable.getColumn(MemoryMapModel.WRITE_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}

		column = memTable.getColumn(MemoryMapModel.EXECUTE_COL);
		if (column != null) {
			column.setMaxWidth(25);
			column.setMinWidth(25);
			column.setResizable(false);
		}

		column = memTable.getColumn(MemoryMapModel.VOLATILE_COL);
		if (column != null) {
			column.setMaxWidth(57);
			column.setMinWidth(57);
			column.setResizable(false);
		}

		column = memTable.getColumn(MemoryMapModel.OVERLAY_COL);
		if (column != null) {
			column.setMaxWidth(55);
			column.setMinWidth(55);
			column.setResizable(false);
		}

		column = memTable.getColumn(MemoryMapModel.BLOCK_TYPE_COL);
		if (column != null) {
			column.setMinWidth(60);
//			column.setResizable(true);
		}

		column = memTable.getColumn(MemoryMapModel.INIT_COL);
		if (column != null) {
			column.setMaxWidth(68);
			column.setMinWidth(68);
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
					selectAddress();
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
				selectAddress();
				e.consume();
			}
		}
	}

	private void selectAddress() {
		int row = memTable.getSelectedRow();
		int viewColumn = memTable.getSelectedColumn();
		int col = memTable.convertColumnIndexToModel(viewColumn);
		MemoryBlock block = mapModel.getBlockAt(row);
		if (block != null && (col == 1 || col == 2)) {
			Address addr = (col == 1 ? block.getStart() : block.getEnd());
			plugin.blockSelected(block, addr);
			memTable.setRowSelectionInterval(row, row);
		}
	}

	private MemoryBlock getSelectedBlock() {
		int row = memTable.getSelectedRow();
		if (row < 0) {
			return null;
		}
		return mapModel.getBlockAt(row);
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
		int delRows[] = memTable.getSelectedRows();
		for (int element : delRows) {
			MemoryBlock block = mapModel.getBlockAt(element);
			delBlocks.add(block);
		}
		memTable.clearSelection();
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
		if (block.isOverlay()) {
			Msg.showInfo(getClass(), getComponent(), "Expand Overlay Block Not Allowed",
				"Overlay blocks cannot be expanded.");
		}
		else {
			showExpandBlockDialog(dialogType, block);
		}
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

		if (block.isOverlay()) {
			Msg.showInfo(getClass(), getComponent(), "Move Overlay Block Not Allowed",
				"Overlay blocks cannot be moved.");
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
		if (block.isOverlay()) {
			Msg.showInfo(getClass(), getComponent(), "Split Overlay Block Not Allowed",
				"Overlay blocks cannot be split.");
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
		new ExpandBlockDialog(tool, model, block, program.getAddressFactory(), dialogType);
		model.initialize(block);
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
		int rows[] = memTable.getSelectedRows();
		for (int element : rows) {
			MemoryBlock block = mapModel.getBlockAt(element);
			blocks.add(block);
		}
		memTable.clearSelection();
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

// ==================================================================================================
// Inner Classes
// ==================================================================================================

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
		MemoryMapAction(String name, ImageIcon icon) {
			super(name, plugin.getName());
			this.setToolBarData(new ToolBarData(icon, null));
		}

		public boolean checkExclusiveAccess() {
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
	}
}
