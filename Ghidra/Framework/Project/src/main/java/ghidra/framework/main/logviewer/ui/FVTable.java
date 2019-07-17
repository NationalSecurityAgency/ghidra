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
package ghidra.framework.main.logviewer.ui;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.*;
import java.io.IOException;
import java.util.List;
import java.util.stream.IntStream;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

import docking.widgets.table.GTable;
import ghidra.framework.main.logviewer.event.*;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.model.*;
import ghidra.util.Msg;

/**
 * The table that backs the {@link FileViewer} window. It is responsible for displaying
 * {@link Chunk} instances.
 *
 */
public class FVTable extends GTable
		implements MouseMotionListener, MouseListener {

	private ChunkReader reader;

	private ViewportUtility viewportUtility;

	private ChunkModel model;

	// Need to keep track of whether the shift key is down or not, for managing selection across
	// chunks.
	private boolean shiftDown = false;
	private boolean mouseDragging = false;

	private FVEventListener eventListener;

	private TableColumn dateCol;
	private TableColumn timeCol;
	private TableColumn levelCol;
	private TableColumn messageCol;

	/**
	 * Ctor.
	 * 
	 * @param reader
	 * @param viewportUtility
	 * @param model
	 * @param eventListener
	 */
	public FVTable(ChunkReader reader, ViewportUtility viewportUtility, ChunkModel model,
			FVEventListener eventListener) {

		this.reader = reader;
		this.viewportUtility = viewportUtility;
		this.model = model;
		this.eventListener = eventListener;

		setModel(new FVTableModel());
		setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

		// Date and time columns are a bit short by default - need to increase them.
		dateCol = getColumnModel().getColumn(FVTableModel.DATE_COL);
		dateCol.setPreferredWidth(100);
		timeCol = getColumnModel().getColumn(FVTableModel.TIME_COL);
		timeCol.setPreferredWidth(75);
		levelCol = getColumnModel().getColumn(FVTableModel.LEVEL_COL);
		levelCol.setPreferredWidth(60);

		// Turn off all gridlines - this is a problem on windows.
		setShowGrid(false);
		setIntercellSpacing(new Dimension(0, 0));

		// Set the cell renderer that will set the background color of the row based
		// on the log level.
		getColumnModel().getColumn(FVTableModel.LEVEL_COL).setCellRenderer(
			new LogLevelTableCellRenderer());

		// The selection listener is kicked off whenever the table selection has been changed. We
		// need to know this so we can store the selection in the viewport utility.
		getSelectionModel().addListSelectionListener(this);

		createKeyBindings(reader, model, eventListener);

		// Set this to enable the columns to set to the proper widths; we don't want swing 
		// resizing them or we won't be able to get horizontal scrolling to work.
		setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		getTableHeader().setResizingAllowed(false);

		addMouseMotionListener(this);
		addMouseListener(this);

		// Turn autoscrolling off - otherwise if the user clicks in the 'Message' column,
		// the horizontal scrollbar will automatically move to only show that column, which
		// is very disconcerting (and rude!).
		setAutoscrolls(false);
	}

	/**
	 * Adjusts the column widths to be at least as wide as the widest cell.  This is required
	 * for horizontal scrolling to work properly.
	 */
	@Override
	public Component prepareRenderer(final TableCellRenderer renderer, final int row,
			final int column) {

		final Component prepareRenderer = super.prepareRenderer(renderer, row, column);
		final TableColumn tableColumn = getColumnModel().getColumn(column);

		tableColumn.setPreferredWidth(
			Math.max(prepareRenderer.getPreferredSize().width, tableColumn.getPreferredWidth()));

		return prepareRenderer;
	}

	/**
	 * Sets the status of the shift key.
	 * 
	 * @param isDown
	 */
	public void setShiftDown(boolean isDown) {
		shiftDown = isDown;
	}

	public void setMouseDragging(boolean isMouseDragging) {
		mouseDragging = isMouseDragging;
	}

	/**
	 * Adds the given row to the table.
	 * 
	 * @param row
	 */
	public void addRow(String row) {
		((FVTableModel) getModel()).addRow(row, true);
	}

	/**
	 * Adds the list of rows to the table.
	 * 
	 * @param rows
	 */
	public void addRows(List<String> rows) {
		((FVTableModel) getModel()).addRowsToBottom(rows);
	}

	/**
	 * Set any previously selected table rows to a selected state. This should be called any 
	 * time a chunk is read into the table. 
	 * 
	 * Note: This is critically important when the user has selected a row, then scrolled such that 
	 * the selected row is in a chunk that has been swapped out and is no longer in the table. When
	 * that chunk is scrolled back into view, this will restore the selection.
	 * 
	 * Note2: If there is a range of selected values and the table is somewhere in the middle of
	 * that range, just select the entire table.
	 */
	public void restoreSelection() {

		// Get the byte position (start/end) of the first and last row in the visible table.
		if (model.getNumChunks() <= 0) {
			return;
		}
		Chunk firstRowChunk = model.get(0);
		Chunk lastRowChunk = model.get(model.getNumChunks() - 1);
		if (firstRowChunk == null || lastRowChunk == null) {
			return;
		}
		long firstRowStart = firstRowChunk.start;
		long lastRowEnd = lastRowChunk.end;

		// CASE 1: Selection encompasses all of the table. 
		if (model.selectedByteStart <= firstRowStart && model.selectedByteEnd >= lastRowEnd) {
			setRowSelectionInterval(0, getRowCount() - 1);
		}

		// CASE 2: Selection start is in the table, but the end is beyond it.
		else if ((model.selectedByteStart >= firstRowStart &&
			model.selectedByteStart <= lastRowEnd) && (model.selectedByteEnd > lastRowEnd)) {
			int rowStart = model.getRowForBytePos(model.selectedByteStart);
			int rowEnd = getRowCount() - 1;
			if (checkBounds(rowStart, rowEnd)) {
				setRowSelectionInterval(rowStart, rowEnd);
			}
		}

		// CASE 3: Selection start is in the table, and so is the end.
		else if ((model.selectedByteStart >= firstRowStart &&
			model.selectedByteStart <= lastRowEnd) &&
			(model.selectedByteEnd >= firstRowStart && model.selectedByteEnd <= lastRowEnd)) {
			int rowStart = model.getRowForBytePos(model.selectedByteStart);
			int rowEnd = model.getRowForBytePos(model.selectedByteEnd);
			if (checkBounds(rowStart, rowEnd)) {
				setRowSelectionInterval(rowStart, rowEnd);
			}
		}

		// CASE 4: Selection start is not in the table, but the end is.
		else if ((model.selectedByteStart < firstRowStart) &&
			(model.selectedByteEnd >= firstRowStart && model.selectedByteEnd <= lastRowEnd)) {
			int rowEnd = model.getRowForBytePos(model.selectedByteEnd);
			if (checkBounds(0, rowEnd)) {
				setRowSelectionInterval(0, rowEnd);
			}
		}
	}

	/**
	 * Removes all rows from the table model.
	 */
	public void clear() {
		((FVTableModel) getModel()).clear();
	}

	/**
	 * Increments the selection by the given number of rows, but doesn't affect any previously
	 * selected rows. This is typically called when selecting while dragging.
	 * 
	 * @param rows
	 */
	public void incrementAndAddSelection(int rows) {
		int[] rowsSelected = getSelectedRows();

		// If the last row selected is still within the table, just update our selection model.
		if (rowsSelected[rowsSelected.length - 1] + rows < getRowCount()) {
			if (rowsSelected.length > 0) {
				Pair filePos = model.getFilePositionForRow(
					rowsSelected[rowsSelected.length - 1] + rows);
				if (filePos == null) {
					return;
				}
				model.selectedByteEnd = filePos.getEnd();

				if (!viewportUtility.isInViewport(rowsSelected[rowsSelected.length - 1] + rows)) {
					viewportUtility.scrollViewportTo(rowsSelected[rowsSelected.length - 1] + rows);
				}
			}
		}

		// If it's beyond the bounds of the table, we have to load a new chunk.
		else {
			try {

				List<String> lines = reader.readNextChunk();

				if (lines.size() == 0) {
					return;
				}

				((FVTableModel) getModel()).addRowsToBottom(lines);

				Pair filePos = model.getFilePositionForRow(
					rowsSelected[rowsSelected.length - 1] + rows);
				if (filePos == null) {
					return;
				}
				model.selectedByteEnd = filePos.getEnd();

				SwingUtilities.invokeLater(() -> {
					if (model.getSize() > model.MAX_VISIBLE_CHUNKS) {
						Chunk chunk = model.remove(0);
						if (chunk == null) {
							return;
						}
						((FVTableModel) getModel()).removeRowsFromTop(chunk.linesInChunk);
	
						// Now slide the viewport back up to account for what we just read in.
						viewportUtility.moveViewportUp(chunk.linesInChunk, false);
					}
				});

			}
			catch (IOException e) {
				Msg.error(this, "Error reading next chunk of data", e);
			}
		}
	}

	/**
	 * Moves the table selection down by the number of rows specified, ensuring that selection
	 * does not go beyond the bounds of the file.
	 * 
	 * @param rows
	 */
	public void incrementSelection(int rows) {
		int rowSelected = getSelectedRow();

		if (rowSelected < 0 && model.selectedByteStart >= 0) {
			try {
				model.clear();
				clear();
				List<String> lines = reader.readNextChunkFrom(model.selectedByteStart);
				((FVTableModel) getModel()).addRowsToTop(lines);
			}
			catch (IOException e) {
				Msg.error(this, "Error reading next chunk of data starting from byte " +
					model.selectedByteStart, e);
			}
		}

		else if (rowSelected + rows < getRowCount()) {
			Pair byteRange = model.getFilePositionForRow(rowSelected + rows);
			if (byteRange == null) {
				return;
			}
			model.selectedByteStart = byteRange.getStart();
			model.selectedByteEnd = byteRange.getEnd();

			if (!viewportUtility.isInViewport(rowSelected + rows)) {
				viewportUtility.scrollViewportTo(rowSelected + rows);
			}
		}
		else {
			try {

				List<String> lines = reader.readNextChunk();

				if (lines.size() == 0) {
					return;
				}

				((FVTableModel) getModel()).addRowsToBottom(lines);

				Pair byteRange = model.getFilePositionForRow(rowSelected + rows);
				if (byteRange == null) {
					return;
				}
				model.selectedByteStart = byteRange.getStart();
				model.selectedByteEnd = byteRange.getEnd();

				SwingUtilities.invokeLater(() -> {
					if (model.getSize() > model.MAX_VISIBLE_CHUNKS) {
						Chunk chunk = model.remove(0);
						if (chunk == null) {
							return;
						}
						((FVTableModel) getModel()).removeRowsFromTop(chunk.linesInChunk);
	
						// Now slide the viewport back up to account for what we just read in.
						viewportUtility.moveViewportUp(chunk.linesInChunk, false);
					}
				});

			}
			catch (IOException e) {
				Msg.error(this, "Error reading next chunk of data", e);
			}
		}
	}

	/**
	 * Decrements the selection by the number of rows given, and adds the new rows to the 
	 * selection.
	 * 
	 * @param rows
	 */
	public void decrementAndAddSelection(int rows) {
		int[] rowsSelected = getSelectedRows();

		// If the last row selected is still within the table, just update our selection model.
		if (rowsSelected[0] - rows >= 0) {
			if (rowsSelected.length > 0) {
				Pair filePos = model.getFilePositionForRow(rowsSelected[0] - rows);
				if (filePos == null) {
					return;
				}
				model.selectedByteStart = filePos.getStart();

				// Now update the viewport...
				if (!viewportUtility.isInViewport(rowsSelected[0] - rows)) {
					viewportUtility.scrollViewportTo(rowsSelected[0] - rows);
				}
			}
		}

		// If it's beyond the bounds of the table, we have to load a new chunk.
		else {
			try {

				List<String> lines = reader.readPreviousChunk();
				if (lines.size() == 0) {
					return;
				}

				((FVTableModel) getModel()).addRowsToTop(lines);

				Pair filePos = model.getFilePositionForRow(lines.size() - rows);
				if (filePos == null) {
					return;
				}
				model.selectedByteStart = filePos.getStart();

				SwingUtilities.invokeLater(() -> {

					// Now slide the viewport back up to account for what we just read in.
					viewportUtility.moveViewportDown(lines.size(), false);
	
					if (model.getSize() > model.MAX_VISIBLE_CHUNKS) {
						Chunk chunk = model.remove(model.getSize() - 1);
						if (chunk == null) {
							return;
						}
						((FVTableModel) this.getModel()).removeRowsFromBottom(chunk.linesInChunk);
					}
				});

			}
			catch (IOException e) {
				Msg.error(this, "Error reading next chunk of data", e);
			}
		}
	}

	/**
	 * Moves the table selection up by the number of rows specified, ensuring that selection
	 * does not go beyond the beginning of the file.
	 * 
	 * @param rows
	 */
	public void decrementSelection(int rows) {

		int rowSelected = getSelectedRow();

		if (rowSelected < 0 && model.selectedByteStart >= 0) {
			try {
				model.clear();
				clear();
				List<String> lines = reader.readNextChunkFrom(model.selectedByteStart);
				((FVTableModel) getModel()).addRowsToTop(lines);
			}
			catch (IOException e) {
				Msg.error(this, "Error reading next chunk of data starting from byte " +
					model.selectedByteStart, e);
			}
		}

		// If we're moving to a row that is already in the table, just decrement.
		else if (rowSelected - rows >= 0) {
			Pair byteRange = model.getFilePositionForRow(rowSelected - rows);
			if (byteRange == null) {
				return;
			}
			model.selectedByteStart = byteRange.getStart();
			model.selectedByteEnd = byteRange.getEnd();

			// Now update the viewport...
			if (!viewportUtility.isInViewport(rowSelected - rows)) {
				viewportUtility.scrollViewportTo(rowSelected - rows);
			}
		}
		else {
			// If here, then we either need to load a previous chunk, or we're at the beginning
			// of the file and should just stop.
			try {
				List<String> lines = reader.readPreviousChunk();
				if (lines.size() == 0) {
					return;
				}

				((FVTableModel) getModel()).addRowsToTop(lines);

				Pair byteRange = model.getFilePositionForRow((rowSelected + lines.size()) - rows);
				model.selectedByteStart = byteRange.getStart();
				model.selectedByteEnd = byteRange.getEnd();

				// Need to wait until the table has finished updating before we try and move the
				// viewport down.
				SwingUtilities.invokeLater(() -> {

					// Now slide the viewport back up to account for what we just read in.
					viewportUtility.moveViewportDown(lines.size(), false);
					
					// And remove chunks if necessary.
					if (model.getSize() > model.MAX_VISIBLE_CHUNKS) {
						Chunk chunk = model.remove(model.getSize() - 1);
						if (chunk == null) {
							return;
						}
						((FVTableModel) getModel()).removeRowsFromBottom(chunk.linesInChunk);
					}
				});

				
			}
			catch (IOException e) {
				Msg.error(this, "Error reading previous chunk of data", e);
			}
		}
	}

	/**
	 * Invoked when a new row has been selected in the table. Update our chunk model to 
	 * reflect as much.
	 * 
	 * @param e
	 */
	@Override
	public void valueChanged(ListSelectionEvent e) {
		super.valueChanged(e);

		// This check ensures that we only update the selected row when it happens as a result
		// of user input (table selection happens behind the scenes for other reasons that would
		// be problematic).
		//
		// IF the shift key is down, then we're selecting a range. It may be the case that the start
		// of the range is no longer in the table (ie: click one row, then scroll 7 chunks down, 
		// hold shift, and click again). To make sure we handle this case, ONLY reset the 
		// selected end position if the shift key is down.
		//
		// However, if the user is selecting a row ABOVE the currently-selected one(s), then
		// leave the the that row as the 'end' selection and reset the start.
		//
		// Also, if the mouse is dragging, don't reset the start position as the user is selecting
		// a range via the mouse.
		if (e.getValueIsAdjusting() && getSelectedRow() >= 0) {
			int[] selectedRows = getSelectedRows();

			if (!shiftDown && !mouseDragging) {
				Pair filePos = model.getFilePositionForRow(selectedRows[0]);
				if (filePos == null) {
					return;
				}
				model.selectedByteStart = filePos.getStart();
				model.selectedByteEnd = filePos.getEnd();
			}

			else {
				Pair filePosFirstRow = model.getFilePositionForRow(selectedRows[0]);
				Pair filePosLastRow  = model.getFilePositionForRow(selectedRows[selectedRows.length - 1]);
				
				if (filePosFirstRow == null || filePosLastRow == null) {
					return;
				}
				long newFilePosStart = filePosFirstRow.getStart();
				long newFilePosEnd = filePosLastRow.getEnd();

				if (newFilePosStart <= model.selectedByteStart) {
					model.selectedByteStart = newFilePosStart;
				}
				if (newFilePosEnd >= model.selectedByteEnd) {
					model.selectedByteEnd = newFilePosEnd;
				}
				restoreSelection();
			}
		}
	}

	/****************************************************************************************
	 * PRIVATE METHODS
	 ***************************************************************************************/

	/**
	 * Create key bindings for the table. We have to capture the following:
	 *   - arrow down
	 *   - arrow up
	 *   - page down
	 *   - page up
	 *   - home
	 *   - end
	 *   - Ctrl-C (Command-C for mac) for copy
	 *   - Ctrl-A (Command-A for mac) for select all
	 *   - Shift pressed 
	 *   - Shift released
	 * 
	 * @param reader
	 * @param model
	 * @param eventListener
	 */
	private void createKeyBindings(ChunkReader reader, ChunkModel model,
			FVEventListener eventListener) {

		// Use input maps to handle keystrokes. Don't use the old KeyListener interface for these;
		// we want to provide our own behavior and not be confused with any default keystroke
		// handlers.
		InputMap im_table = getInputMap();
		ActionMap am_table = getActionMap();
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), "DownArrow");
		am_table.put("DownArrow", new ArrowDownAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_UP, 0), "UpArrow");
		am_table.put("UpArrow", new ArrowUpAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, 0), "PageDown");
		am_table.put("PageDown", new PageDownAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0), "PageUp");
		am_table.put("PageUp", new PageUpAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_HOME, 0), "Home");
		am_table.put("Home", new HomeAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_END, 0), "End");
		am_table.put("End", new EndAction(eventListener));

		// Handle arrow up and arrow down when the shift key is pressed, meaning we need to 
		// move the viewport AND maintain selection.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, InputEvent.SHIFT_DOWN_MASK),
			"DownArrowSelection");
		am_table.put("DownArrowSelection", new ArrowDownSelectionAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_UP, InputEvent.SHIFT_DOWN_MASK),
			"UpArrowSelection");
		am_table.put("UpArrowSelection", new ArrowUpSelectionAction(eventListener));

		// Handle Page up and Page down when the shift key is pressed, meaning we need to 
		// move the viewport AND maintain selection.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, InputEvent.SHIFT_DOWN_MASK),
			"PageDownSelection");
		am_table.put("PageDownSelection", new PageDownSelectionAction(eventListener));
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, InputEvent.SHIFT_DOWN_MASK),
			"PageUpSelection");
		am_table.put("PageUpSelection", new PageUpSelectionAction(eventListener));

		// Set up a key binding for copying selected rows to the clipboard.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), "copyText");
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.META_DOWN_MASK), "copyText");
		am_table.put("copyText", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				FVEvent copyEvt = new FVEvent(EventType.COPY_SELECTION, null);
				eventListener.send(copyEvt);
			}

		});

		// Recognize when the shift key has been pressed and released, so we know how to handle 
		// selection.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_SHIFT, InputEvent.SHIFT_DOWN_MASK, false),
			"ShiftPressed");
		am_table.put("ShiftPressed", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				shiftDown = true;
			}
		});
		im_table.put(KeyStroke.getKeyStroke("released SHIFT"), "ShiftReleased");
		am_table.put("ShiftReleased", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				shiftDown = false;
			}
		});

		// Now create a binding for the CTRL-A, select all action.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK, false),
			"SelectAll");
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.META_DOWN_MASK, false),
			"SelectAll");
		am_table.put("SelectAll", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					model.selectedByteStart = 0;
					model.selectedByteEnd = reader.getFileSize() - 1;

					FVEvent copyEvt = new FVEvent(EventType.COPY_SELECTION, null);
					eventListener.send(copyEvt);

					restoreSelection();
				}
				catch (IOException e1) {
					Msg.error(this, "error reading file size: " + e);
				}
			}
		});
	}

	/**
	 * Returns true if the rows provided are both in the table.
	 * 
	 * @param rowStart
	 * @param rowEnd
	 * @return
	 */
	private boolean checkBounds(int rowStart, int rowEnd) {
		return ((rowStart >= 0 && rowStart < getRowCount()) &&
			(rowEnd >= 0 && rowEnd < getRowCount()));
	}

	@Override
	public void mouseDragged(MouseEvent e) {

		this.mouseDragging = true;

		int[] selectedRows = getSelectedRows();

		// First get the bounds of the table so we can tell if the mouse is below or above it. This
		// will tell us if we're dragging up or down.
		int tableTop = (int) this.getParent().getLocationOnScreen().getY();
		int tableBottom = (int) (tableTop + this.getSize().getHeight());

		// See if the last row is selected; if so, and we're dragging up, we need to load a new 
		// chunk. 
		if (e.getLocationOnScreen().getY() < tableTop) {
			if (IntStream.of(selectedRows).anyMatch(x -> x == 0)) {
				FVEvent decrementEvt = new FVEvent(EventType.DECREMENT_AND_ADD_SELECTION, 1);
				eventListener.send(decrementEvt);
				return;
			}
		}

		// See if the first row is selected; if so, and we're dragging down, we need to load a new
		// chunk;
		else if (e.getLocationOnScreen().getY() > tableBottom) {
			if (IntStream.of(selectedRows).anyMatch(x -> x == (getRowCount() - 1))) {
				FVEvent incrementEvt = new FVEvent(EventType.INCREMENT_AND_ADD_SELECTION, 1);
				eventListener.send(incrementEvt);
				return;
			}
		}
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		// Do nothing
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// do nothing

	}

	@Override
	public void mousePressed(MouseEvent e) {
		// do nothing

	}

	@Override
	public void mouseReleased(MouseEvent e) {
		this.mouseDragging = false;
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// do nothing

	}

	@Override
	public void mouseExited(MouseEvent e) {
		// do nothing

	}
}
