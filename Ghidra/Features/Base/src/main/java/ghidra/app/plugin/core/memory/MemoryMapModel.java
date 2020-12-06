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

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.TableCellEditor;

import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.table.AbstractSortedTableModel;

/**
 * Table Model for a Table where each entry represents a MemoryBlock
 * from a Program's Memory.
 */

import ghidra.framework.model.DomainFile;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;

class MemoryMapModel extends AbstractSortedTableModel<MemoryBlock> {

	final static byte NAME = 0;
	final static byte START = 1;
	final static byte END = 2;
	final static byte LENGTH = 3;
	final static byte READ = 4;
	final static byte WRITE = 5;
	final static byte EXECUTE = 6;
	final static byte VOLATILE = 7;
	final static byte OVERLAY = 8;
	final static byte BLOCK_TYPE = 9;
	final static byte INIT = 10;
	final static byte BYTE_SOURCE = 11;
	final static byte SOURCE = 12;
	final static byte COMMENT = 13;

	final static String NAME_COL = "Name";
	final static String START_COL = "Start";
	final static String END_COL = "End";
	final static String LENGTH_COL = "Length";
	final static String READ_COL = "R";
	final static String WRITE_COL = "W";
	final static String EXECUTE_COL = "X";
	final static String VOLATILE_COL = "Volatile";
	final static String OVERLAY_COL = "Overlay";
	final static String BLOCK_TYPE_COL = "Type";
	final static String INIT_COL = "Initialized";
	final static String BYTE_SOURCE_COL = "Byte Source";
	final static String SOURCE_COL = "Source";
	final static String COMMENT_COL = "Comment";

	private Program program;

	private ArrayList<MemoryBlock> memList;
	private MemoryMapProvider provider;

	private final static String COLUMN_NAMES[] =
		{ NAME_COL, START_COL, END_COL, LENGTH_COL, READ_COL, WRITE_COL, EXECUTE_COL, VOLATILE_COL,
			OVERLAY_COL, BLOCK_TYPE_COL, INIT_COL, BYTE_SOURCE_COL, SOURCE_COL, COMMENT_COL };

	MemoryMapModel(MemoryMapProvider provider, Program program) {
		super(START);
		this.program = program;
		this.provider = provider;

		populateMap();
	}

	private void populateMap() {
		memList = new ArrayList<>();

		if (program == null) {
			return;
		}

		// Get all the memory blocks
		Memory mem = program.getMemory();
		MemoryBlock[] blocks = mem.getBlocks();
		for (MemoryBlock block : blocks) {
			memList.add(block);
		}
		fireTableDataChanged();
	}

	void update() {
		JTable table = provider.getTable();
		TableCellEditor cellEditor = table.getCellEditor();
		if (cellEditor != null) {
			cellEditor.cancelCellEditing();
		}
		populateMap();
	}

	@Override
	public boolean isSortable(int columnIndex) {
		if (columnIndex == READ || columnIndex == WRITE || columnIndex == EXECUTE ||
			columnIndex == VOLATILE || columnIndex == OVERLAY || columnIndex == INIT) {
			return false;
		}
		return true;
	}

	@Override
	public String getName() {
		return "Memory Map";
	}

	@Override
	public int getColumnCount() {
		return COLUMN_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {

		if (column < 0 || column >= COLUMN_NAMES.length) {
			return "UNKNOWN";
		}

		return COLUMN_NAMES[column];
	}

	/**
	 * Convenience method for locating columns by name.
	 * Implementation is naive so this should be overridden if
	 * this method is to be called often. This method is not
	 * in the TableModel interface and is not used by the JTable.
	 */
	@Override
	public int findColumn(String columnName) {
		for (int i = 0; i < COLUMN_NAMES.length; i++) {
			if (COLUMN_NAMES[i].equals(columnName)) {
				return i;
			}
		}
		return 0;
	}

	/**
	 *  Returns Object.class by default
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == READ || columnIndex == WRITE || columnIndex == EXECUTE ||
			columnIndex == VOLATILE || columnIndex == OVERLAY || columnIndex == INIT) {
			return Boolean.class;
		}
		return String.class;
	}

	/**
	 *  Return whether this column is editable.
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {

		switch (columnIndex) {
			case NAME:
			case READ:
			case WRITE:
			case EXECUTE:
			case VOLATILE:
			case COMMENT:
				return true;
			case INIT:
				MemoryBlock block = memList.get(rowIndex);
				MemoryBlockType blockType = block.getType();
				if (blockType != MemoryBlockType.BIT_MAPPED &&
					blockType != MemoryBlockType.BYTE_MAPPED) {
					return true;
				}
			default:
				return false;
		}
	}

	/**
	 * Returns the number of records managed by the data source object. A
	 * <B>JTable</B> uses this method to determine how many rows it
	 * should create and display.  This method should be quick, as it
	 * is call by <B>JTable</B> quite frequently.
	 *
	 * @return the number or rows in the model
	 * @see #getColumnCount
	 */
	@Override
	public int getRowCount() {
		return memList.size();
	}

	private String getAddressString(Address address) {
		AddressSpace space = address.getAddressSpace();
		if (space.isOverlaySpace()) {
			OverlayAddressSpace ovSpace = (OverlayAddressSpace) space;
			AddressSpace baseSpace = ovSpace.getOverlayedSpace();
			address = baseSpace.getAddress(address.getOffset());
		}
		return address.toString();
	}

	public MemoryBlock getBlockAt(int rowIndex) {
		if (memList == null) {
			return null;
		}
		if (rowIndex < 0 || rowIndex >= memList.size()) {
			return null;
		}
		MemoryBlock block = memList.get(rowIndex);
		try {
			// make sure block is still valid
			block.getStart();
		}
		catch (ConcurrentModificationException e) {
			update();
		}
		return memList.get(rowIndex);
	}

	/**
	 *  This empty implementation is provided so users don't have to implement
	 *  this method if their data model is not editable.
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		provider.setCursor(MemoryMapPlugin.WAIT_CURSOR);
		try {

			MemoryBlock block = getBlockAt(rowIndex);
			if (block == null) {
				// this can happen when the tool is closing while an edit is open
				return;
			}

			switch (columnIndex) {
				case NAME:
					String name = ((String) aValue).trim();
					if (!verifyRenameAllowed(block, name)) {
						return;
					}
					if (name.length() == 0) {
						Msg.showError(this, provider.getComponent(), "Enter Block Label",
							"Please enter a label name.");
						break;
					}
					if (name.equals(block.getName())) {
						break;
					}
					if (!Memory.isValidMemoryBlockName(name)) {
						Msg.showError(this, provider.getComponent(), "Invalid Name",
							"Invalid Memory Block Name: " + name);
						break;
					}
					if (!name.equals(block.getName())) {
						int id = program.startTransaction("Rename Memory Block");
						try {
							block.setName(name);
							program.endTransaction(id, true);
						}
						catch (LockException e) {
							program.endTransaction(id, false);
							this.provider.setStatusText(e.getMessage());
							return;
						}
						catch (RuntimeException e1) {
							program.endTransaction(id, false);
							throw e1;
						}
					}
					break;
				case READ: {
					int id = program.startTransaction("Set Read State");
					try {
						boolean value = ((Boolean) aValue).booleanValue();
						block.setRead(value);
						provider.setStatusText("");
						program.endTransaction(id, true);
					}
					catch (RuntimeException e) {
						program.endTransaction(id, false);
						throw e;
					}
					break;
				}
				case WRITE: {
					int id = program.startTransaction("Set Write State");
					try {
						boolean value = ((Boolean) aValue).booleanValue();
						block.setWrite(value);
						provider.setStatusText("");
						program.endTransaction(id, true);
					}
					catch (RuntimeException e) {
						program.endTransaction(id, false);
						throw e;
					}
					break;
				}
				case EXECUTE: {
					int id = program.startTransaction("Set Execute State");
					try {
						boolean value = ((Boolean) aValue).booleanValue();
						block.setExecute(value);
						provider.setStatusText("");
						program.endTransaction(id, true);
					}
					catch (RuntimeException e) {
						program.endTransaction(id, false);
						throw e;
					}
					break;
				}
				case VOLATILE: {
					int id = program.startTransaction("Set Volatile State");
					try {
						boolean value = ((Boolean) aValue).booleanValue();
						block.setVolatile(value);
						provider.setStatusText("");
						program.endTransaction(id, true);
					}
					catch (RuntimeException e) {
						program.endTransaction(id, false);
						throw e;
					}
					break;
				}
				case INIT:
					MemoryBlockType blockType = block.getType();
					if (blockType == MemoryBlockType.BIT_MAPPED ||
						blockType == MemoryBlockType.BYTE_MAPPED) {

						showMessage("Cannot change intialized memory state of a mapped Block");
						return;
					}
					provider.setStatusText("");
					boolean booleanValue = ((Boolean) aValue).booleanValue();
					if (booleanValue) {
						initializeBlock(block);
					}
					else {
						revertBlockToUnitialized(block);
					}
					return;

				case SOURCE:
					break;
				case COMMENT:
					String cmt = block.getComment();
					if (cmt == null || !cmt.equals(aValue)) {
						String value = (String) aValue;
						if (value.length() == 0) {
							value = null;
						}
						int id = program.startTransaction("Set Comment State");
						try {
							block.setComment(value);
							program.endTransaction(id, true);
						}
						catch (RuntimeException e) {
							program.endTransaction(id, false);
							throw e;
						}
					}
					break;
				default:
					break;
			}
			fireTableRowsUpdated(rowIndex, rowIndex);
		}
		finally {
			provider.setCursor(MemoryMapPlugin.NORM_CURSOR);
		}
	}

	private void revertBlockToUnitialized(MemoryBlock block) {
		int result = OptionDialog.showYesNoDialog(provider.getComponent(),
			"Confirm Setting Block To Unitialized",
			"Are you sure you want to remove the bytes from this block? \n\n" +
				"This will result in removing all functions, instructions, data,\n" +
				"and outgoing references from the block!");

		if (result == OptionDialog.NO_OPTION) {
			return;
		}
		UninitializedBlockCmd cmd = new UninitializedBlockCmd(program, block);
		provider.getTool().executeBackgroundCommand(cmd, program);
	}

	private boolean verifyRenameAllowed(MemoryBlock block, String newName) {
		if (!block.isOverlay() || block.getName().equals(newName)) {
			return true;
		}
		if (!program.hasExclusiveAccess()) {
			String msg = "Close the file and undo your checkout,\n" +
				"then do a checkout with the exclusive lock.";

			DomainFile df = program.getDomainFile();
			if (df.modifiedSinceCheckout() || df.isChanged()) {
				msg = "Check in this file, then do a checkout with the\n" + "exclusive lock.";
			}
			Msg.showInfo(getClass(), provider.getComponent(), "Exclusive Checkout Required",
				"An exclusive checkout is required in order to\n" +
					"rename an overlay memory block.\n" + msg);
			return false;
		}
		return true;
	}

	/**
	 * Create a new initialized block based on the given uninitialized block.
	 */
	private void initializeBlock(MemoryBlock block) {

		NumberInputDialog dialog = new NumberInputDialog("Initialize Memory Block",
			"Enter fill byte value for block: ", 0, 0, 255, true);

		if (!dialog.show()) {
			return;	// cancelled
		}

		byte value = (byte) dialog.getValue();

		int id = program.startTransaction("Initialize Memory Block");
		try {
			Memory mem = program.getMemory();
			int index = memList.indexOf(block);
			MemoryBlock newBlock = mem.convertToInitialized(block, value);
			memList.set(index, newBlock);
			program.endTransaction(id, true);
		}
		catch (Throwable t) {
			program.endTransaction(id, false);
			String msg = t.getMessage();
			msg = msg == null ? t.toString() : msg;
			Msg.showError(this, provider.getComponent(), "Block Initialization Failed", msg, t);
		}
	}

	private void showMessage(final String msg) {
		// mouse listeners wipe out the message so show it later...
		SwingUtilities.invokeLater(() -> provider.setStatusText(msg));
	}

	@Override
	public Object getColumnValueForRow(MemoryBlock block, int columnIndex) {
		try {
			switch (columnIndex) {
				case NAME:
					return block.getName();
				case START:
					return getAddressString(block.getStart());
				case END:
					return getAddressString(block.getEnd());
				case LENGTH:
					long len = block.getEnd().subtract(block.getStart()) + 1;
					return "0x" + Long.toHexString(len);
				case READ:
					return block.isRead() ? Boolean.TRUE : Boolean.FALSE;
				case WRITE:
					return block.isWrite() ? Boolean.TRUE : Boolean.FALSE;
				case EXECUTE:
					return block.isExecute() ? Boolean.TRUE : Boolean.FALSE;
				case VOLATILE:
					return block.isVolatile() ? Boolean.TRUE : Boolean.FALSE;
				case OVERLAY:
					return block.isOverlay() ? Boolean.TRUE : Boolean.FALSE;
				case INIT:
					MemoryBlockType blockType = block.getType();
					if (blockType == MemoryBlockType.BIT_MAPPED) {
						return null;
					}
					return (block.isInitialized() ? Boolean.TRUE : Boolean.FALSE);
				case BYTE_SOURCE:
					return getByteSourceDescription(block.getSourceInfos());
				case SOURCE:
					if ((block.getType() == MemoryBlockType.BIT_MAPPED) ||
						(block.getType() == MemoryBlockType.BYTE_MAPPED)) {
						MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
						return info.getMappedRange().get().getMinAddress().toString();
					}
					return block.getSourceName();
				case COMMENT:
					return block.getComment();
				case BLOCK_TYPE:
					return block.getType().toString();
				default:
					return "UNKNOWN";
			}
		}
		catch (ConcurrentModificationException e) {
			update();
		}
		return null;
	}

	private String getByteSourceDescription(List<MemoryBlockSourceInfo> sourceInfos) {
		List<MemoryBlockSourceInfo> limited = sourceInfos.size() < 5 ? sourceInfos : sourceInfos.subList(0, 4);
		
		//@formatter:off
		String description = limited
							.stream()
							.map(info -> info.getDescription())
							.collect(Collectors.joining(", "));
		//@formatter:on
		if (limited != sourceInfos) {
			description += "...";
		}
		return description;
	}

	@Override
	public List<MemoryBlock> getModelData() {
		return memList;
	}

	@Override
	protected Comparator<MemoryBlock> createSortComparator(int columnIndex) {
		return new MemoryMapComparator(columnIndex);
	}

	private class MemoryMapComparator implements Comparator<MemoryBlock> {
		private final int sortColumn;

		public MemoryMapComparator(int sortColumn) {
			this.sortColumn = sortColumn;
		}

		@Override
		public int compare(MemoryBlock b1, MemoryBlock b2) {

			switch (sortColumn) {
				case NAME:
					return b1.getName().compareToIgnoreCase(b2.getName());
				case START:
					return b1.getStart().compareTo(b2.getStart());
				case END:
					return b1.getEnd().compareTo(b2.getEnd());
				case LENGTH:
					return (int) (b1.getSize() - b2.getSize());
				case READ:
					int b1r = (b1.isRead() ? 1 : -1);
					int b2r = (b2.isRead() ? 1 : -1);
					return (b1r - b2r);
				case WRITE:
					int b1w = (b1.isWrite() ? 1 : -1);
					int b2w = (b2.isWrite() ? 1 : -1);
					return (b1w - b2w);
				case EXECUTE:
					int b1x = (b1.isExecute() ? 1 : -1);
					int b2x = (b2.isExecute() ? 1 : -1);
					return (b1x - b2x);
				case VOLATILE:
					int b1v = (b1.isVolatile() ? 1 : -1);
					int b2v = (b2.isVolatile() ? 1 : -1);
					return (b1v - b2v);
				case OVERLAY:
					int b1o = (b1.isOverlay() ? 1 : -1);
					int b2o = (b2.isOverlay() ? 1 : -1);
					return (b1o - b2o);
				case INIT:
					int b1init = (b1.isInitialized() ? 1 : -1);
					int b2init = (b2.isInitialized() ? 1 : -1);
					return (b1init - b2init);
				case SOURCE:
					String b1src = b1.getSourceName();
					String b2src = b2.getSourceName();
					if (b1src == null) {
						b1src = "";
					}
					if (b2src == null) {
						b2src = "";
					}
					return b1src.compareToIgnoreCase(b2src);

				case COMMENT:
					String comment1 = b1.getComment();
					String comment2 = b2.getComment();
					if (comment1 == null) {
						comment1 = "";
					}
					if (comment2 == null) {
						comment2 = "";
					}
					return comment1.compareToIgnoreCase(comment2);

				case BLOCK_TYPE:
					String bt1 = b1.getType().toString();
					String bt2 = b2.getType().toString();
					return bt1.compareToIgnoreCase(bt2);
				default:
					return 0;
			}
		}
	}
}
