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

import java.awt.Point;
import java.io.IOException;
import java.util.*;

import javax.swing.JViewport;
import javax.swing.SwingUtilities;

import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;
import ghidra.framework.main.logviewer.model.*;
import ghidra.util.Msg;

/**
 * Utility class for managing the viewport in the {@link FVTable}. This viewport must be 
 * adjusted manually whenever {@link Chunk} objects are added to or removed from to the view, 
 * or whenever the {@link FVSlider} is moved.
 *
 */
public class ViewportUtility implements Observer {

	// Stores the top-line position of the viewport in case it needs to be restored (eg: after
	// a reload).  Note that this value is a not a line number; it's the pixel y-value of the 
	// viewport within the parent container.
	private int savePosition;

	private JViewport viewport;
	private FVTable table;

	private ChunkReader reader;
	private ChunkModel model;

	private FVEventListener eventListener;

	/**
	 * 
	 */
	public ViewportUtility(FVEventListener eventListener) {
		this.eventListener = eventListener;
		eventListener.addObserver(this);
	}

	/**
	 * 
	 * @param viewport
	 */
	public void setViewport(JViewport viewport) {
		this.viewport = viewport;
	}

	/**
	 * 
	 * @param table
	 */
	public void setTable(FVTable table) {
		this.table = table;
	}

	/**
	 * 
	 * @param reader
	 */
	public void setReader(ChunkReader reader) {
		this.reader = reader;
	}

	/**
	 * 
	 * @param model
	 */
	public void setModel(ChunkModel model) {
		this.model = model;
	}
	
	/**
	 * Returns the height (in pixels) of the viewport.
	 * 
	 * @return
	 */
	public int getHeight() {
		return viewport.getHeight();
	}

	/**
	 * Returns the table row associated with the top of the viewport.
	 * 
	 * @return
	 */
	public int getViewportPositionAsRow() {
		return viewport.getViewPosition().y / table.getRowHeight();
	}

	/**
	 * Returns true if the given row is in the viewport.
	 * 
	 * @param row
	 * 
	 * @return
	 */
	public boolean isInViewport(int row) {
		int viewportRowStart = viewport.getViewPosition().y / table.getRowHeight();
		int viewportRowEnd = viewportRowStart + viewport.getHeight() / table.getRowHeight();

		return (row >= viewportRowStart && row <= viewportRowEnd);
	}

	/**
	 * Snaps the viewport to the bottom of the table.
	 */
	public void moveViewportToBottom() {
		Point bottomPoint =
			new Point(0, (table.getRowCount() * table.getRowHeight()) - viewport.getHeight());
		viewport.setViewPosition(bottomPoint);

		FVEvent updateViewportEvt = new FVEvent(EventType.VIEWPORT_UPDATE, null);
		eventListener.send(updateViewportEvt);
	}

	/**
	 * Snaps the viewport to the top of the table.
	 */
	public void moveViewportToTop() {
		Point topPoint = new Point(0, 0);
		viewport.setViewPosition(topPoint);

		FVEvent updateViewportEvt = new FVEvent(EventType.VIEWPORT_UPDATE, null);
		eventListener.send(updateViewportEvt);
	}

	/**
	 * Returns the number of rows that are visible in the viewport. 
	 * 
	 * @return
	 */
	public int getNumRowsInViewport() {
		return viewport.getHeight() / table.getRowHeight();
	}

	/**
	 * Moves the viewport (top) to the given row in the current view.
	 *
	 * @param row
	 */
	public void scrollViewportTo(int row) {

		int offset = getViewportOffset(row);
		if (offset < 0) {
			moveViewportUp(-offset, false);
		}
		else if (offset > 0) {
			moveViewportDown(offset, false);
		}
	}

	/**
	 * Moves the viewport up the number of rows specified. If moving up puts he view above 
	 * the bounds of the first-visible chunk, load a previous chunk.
	 * 
	 * @param rows
	 * @param selection
	 */
	public void moveViewportUp(int rows, boolean selection) {

		// Do some object checking up front and exit if these aren't set.
		if (!isStateValid()) {
			return;
		}

		// Calculate the position of the viewport if we were to move it up the number of 
		// rows given.
		Point newViewportPos =
			new Point(0, (int) viewport.getViewPosition().getY() - (table.getRowHeight() * rows));

		// Save off the new viewport pos; this will be our new location unless we need to 
		// adjust it by adding/removing new chunks.
		savePosition = newViewportPos.y;

		// If our proposed new viewport position is less than zero, then we need to add a new
		// previous chunk (unless we're already at the beginning of the file).
		if (newViewportPos.y < 0) {

			try {

				// Read in a previous chunk and make sure we get some valid lines. If we don't get
				// any valid lines, then we must be moving to the top of the file so just move
				// the viewport to the top.
				List<String> readLines = reader.readPreviousChunk();
				if (readLines.size() > 0) {

					// We have valid rows, so add them to the table (at the top, because we're 
					// reading a previous chunk).
					((FVTableModel) table.getModel()).addRowsToTop(readLines);

					// If adding that chunk just put us over the chunk limit we want to show, we 
					// have to remove one from the bottom, and adjust our viewport accordingly.
					//
					// Otherwise, just move our viewport down the corresponding number of rows
					// we just added.
					if (model.getSize() > model.MAX_VISIBLE_CHUNKS) {
						Chunk chunk = model.remove(model.getSize() - 1);
						newViewportPos = new Point(0,
							newViewportPos.y + (table.getRowHeight() * chunk.linesInChunk));
						savePosition = newViewportPos.y;
						((FVTableModel) table.getModel()).removeRowsFromBottom(chunk.linesInChunk);
					}
					else {
						savePosition += table.getRowHeight() * readLines.size();
					}
				}
				else {
					moveViewportToTop();
					if (selection) {
						updateSelectionToViewportTop();
					}
					return;
				}
			}
			catch (IOException e) {
				Msg.error(this,
					"Error creating loading new chunk for viewport decrement", e);
			}
		}

		// At this point we should have a valid new viewport position, so set it.
		setPosition(new Point(0, savePosition));
		
		// And if necessary, set new selection to encompass the top row that's in the viewport.
		if (selection) {
			updateSelectionToViewportTop();
		}
	}

	/**
	 * Moves the viewport down the number of rows specified. If moving down puts he view below 
	 * the bounds of the first-visible chunk, load the next chunk.
	 * 
	 * @param rows
	 * @param selection
	 */
	public void moveViewportDown(int rows, boolean selection) {

		// Do some object checking up front and exit if these aren't set.
		if (!isStateValid()) {
			return;
		}

		// Calculate the position of the viewport if we were to move it down the number of 
		// rows given.
		Point newViewportPos =
			new Point(0, (int) viewport.getViewPosition().getY() + (table.getRowHeight() * rows));
		int viewportBottom = newViewportPos.y + viewport.getHeight();

		// Save off the new viewport pos; this will be our new location unless we need to 
		// adjust it by adding/removing new chunks.
		savePosition = newViewportPos.y;

		// If our proposed new viewport position pushes it beyond the bounds of the table, we have
		// to load a new chunk.
		if (viewportBottom >= table.getHeight()) {

			try {

				// Read in the next chunk and make sure we get some valid lines. If we don't get
				// any valid lines, then we must be at the end of the file so just move the 
				// viewport to the bottom.
				List<String> readLines = reader.readNextChunk();
				if (readLines.size() > 0) {

					// We have valid rows, so add them to the table (at the bottom, because we're 
					// reading the next chunk).
					((FVTableModel) table.getModel()).addRowsToBottom(readLines);

					// If adding that chunk just put us over the chunk limit we want to show, we 
					// have to remove one from the top, and adjust our viewport accordingly.
					if (model.getSize() > model.MAX_VISIBLE_CHUNKS) {
						Chunk chunk = model.remove(0);
						newViewportPos = new Point(0,
							newViewportPos.y - (table.getRowHeight() * chunk.linesInChunk));
						savePosition = newViewportPos.y;

						((FVTableModel) table.getModel()).removeRowsFromTop(chunk.linesInChunk);
					}
				}
				else {
					moveViewportToBottom();
					if (selection) {
						updateSelectionToViewportBottom();
					}
					return;
				}
			}
			catch (IOException e) {
				Msg.error(this,
					"Error creating loading new chunk for viewport increment", e);
			}
		}

		// At this point we should have a valid new viewport position, so set it.
		setPosition(new Point(0, savePosition));
		
		// And if necessary, set new selection to encompass the bottom row that's in the viewport.
		if (selection) {
			updateSelectionToViewportBottom();
		}
	}

	/*********************************************************************************
	 * PRIVATE METHODS
	 *********************************************************************************/

	/**
	 * Sets the first row in the viewport to be the start of the current selection range.  The 
	 * end of the selection range remains untouched.
	 */
	private void updateSelectionToViewportTop() {
		
		Pair filePos = model.getFilePositionForRow(getViewportPositionAsRow());
		if (filePos == null) {
			return;
		}
		
		long filePosForTopRow = filePos.getStart();
		model.selectedByteStart = filePosForTopRow;
		table.restoreSelection();
	}

	
	/**
	 * Sets the last row in the viewport to be the end of the current selection range.  The 
	 * start of the selection range remains untouched.
	 */
	private void updateSelectionToViewportBottom() {
		int bottomRow = getViewportPositionAsRow() + getNumRowsInViewport();
		
		Pair filePos = model.getFilePositionForRow(bottomRow);
		if (filePos == null) {
			return;
		}
		long filePosForBottomRow = filePos.getEnd();
		model.selectedByteEnd = filePosForBottomRow;
		table.restoreSelection();
	}
	
	/**
	 * Sets the viewport to the given position, and fires off an event to notify any
	 * subscribers.
	 * 
	 * @param position
	 */
	private void setPosition(Point position) {

		// Do some object checking up front and exit if these aren't set.
		if (!isStateValid()) {
			return;
		}

		if (position.y < 0) {
			position = new Point(0, 0);
		}
		viewport.setViewPosition(position);

		FVEvent updateViewportEvt = new FVEvent(EventType.VIEWPORT_UPDATE, null);
		eventListener.send(updateViewportEvt);
	}

	/**
	 * Returns how many rows the given row is above or below the current viewport. 
	 * 
	 * @param row
	 * 
	 * @return negative value if above the top of the viewport, positive value if below the bottom
	 *         of the viewport, 0 if the line is already in the viewport.
	 */
	private int getViewportOffset(int row) {

		// Do some object checking up front and exit if these aren't set.
		if (!isStateValid()) {
			return 0;
		}

		// First figure out which rows in the table our viewport is bounding.
		int viewportRowStart = viewport.getViewPosition().y / table.getRowHeight();
		int viewportRowEnd = viewportRowStart + viewport.getHeight() / table.getRowHeight();

		// Now calculate if the given row is in, above, or below the viewport.
		if (row < viewportRowStart) {
			return row - viewportRowStart;
		}
		else if (row > viewportRowEnd) {
			return row - viewportRowEnd;
		}

		return 0;
	}

	/**
	 * @param o
	 * @param arg
	 */
	@Override
	public void update(Observable o, Object arg) {
		if (o instanceof FVEventListener && arg instanceof FVEvent) {

			if (SwingUtilities.isEventDispatchThread()) {
				handleFVEvent((FVEvent) arg);
			}
			else {
				SwingUtilities.invokeLater(() -> {
					handleFVEvent((FVEvent) arg);
				});
			}
		}
	}

	/**
	 * Processes events received via the {@link FVEvent} mechanism. 
	 * 
	 * @param event the event type received
	 */
	private void handleFVEvent(FVEvent event) {

		switch (event.eventType) {

			case VIEWPORT_UP:
				moveViewportUp((int) event.arg, false);
				break;
			case VIEWPORT_DOWN:
				moveViewportDown((int) event.arg, false);
				break;
			case VIEWPORT_PAGE_UP:
				moveViewportUp(getNumRowsInViewport(), (boolean)event.arg);
				break;
			case VIEWPORT_PAGE_DOWN:
				moveViewportDown(getNumRowsInViewport(), (boolean)event.arg);
				break;
			default:
		}
	}

	/**
	 * Returns true if all necessary state objects have been set.
	 * 
	 * @return
	 */
	private boolean isStateValid() {
		return (model != null && reader != null && viewport != null);
	}
}
