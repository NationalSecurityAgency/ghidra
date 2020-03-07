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

import java.awt.BorderLayout;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

import javax.swing.*;

import docking.dnd.GClipboard;
import ghidra.framework.main.logviewer.event.*;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.model.*;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

/**
 * UI for viewing the contents of very large files efficiently. Pieces of a file are read in using
 * the {@link ChunkReader}, which are then displayed line-by-line in {@link FVTable}.  As
 * users scroll up/down, new sections of the file are swapped in as appropriate.
 *
 * Notes:
 * 1. The viewer consists of a simple JTable and a custom JSlider. The table displays lines of
 *    text described by {@link Chunk} objects. The number of chunks visible at any given time
 *    is restricted by the {@link ChunkModel#MAX_VISIBLE_CHUNKS} property.
 *
 * 2. Because only part of the file is loaded into the viewable table at any given time, the
 *    built-in scrollbar associated with the scrollpane cannot be used. We want the scroll bar
 *    maximum size to reflect the total size of the file, not just what's in view at the time. So
 *    we use our own slider implementation ({@link FVSlider}) and manage the
 *    size/position ourselves. If you're asking why a JSlider is used instead of a JScrollPane,
 *    it's because the former is more easily configuration for what we need.
 *
 * 3. Communication between modules (the table, the slider, the viewport utility, etc...) is done
 *    almost exclusively via events, using the custom {@link FVEvent} framework.
 *
 */
public class FileViewer extends JPanel implements Observer {

	private FVTable table;
	private JScrollPane scrollPane;
	private FVSlider slider;
	private FVToolBar toolbar;

	private ChunkReader reader;

	private ViewportUtility viewportUtility;

	private ChunkModel model;

	private FVEventListener eventListener;

	/**
	 * Constructor. Sets up the UI elements and subscribes to events.
	 *
	 * @param reader
	 * @param model
	 * @param eventListener
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public FileViewer(ChunkReader reader, ChunkModel model, FVEventListener eventListener)
			throws FileNotFoundException, IOException {

		this.reader = reader;
		this.model = model;
		this.eventListener = eventListener;

		// Use a border layout so the table will take up all available space.
		setLayout(new BorderLayout());

		viewportUtility = new ViewportUtility(eventListener);

		// Create the table, add the scroll panel and initialize the ViewportUtility.
		table = new FVTable(reader, viewportUtility, model, eventListener);
		scrollPane = new JScrollPane(table);
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		viewportUtility.setTable(table);
		viewportUtility.setReader(reader);
		viewportUtility.setModel(model);
		viewportUtility.setViewport(scrollPane.getViewport());

		// Make sure the table responds to mouse wheel scrolling.
		scrollPane.addMouseWheelListener(new MouseWheelAction(eventListener));

		// Set up the slider and the toolbar, and lay out the components.
		slider = new FVSlider(scrollPane, table, viewportUtility, model, reader, eventListener);
		toolbar = new FVToolBar(eventListener);

		slider.setMaximum(reader.getFileSize());

		add(toolbar, BorderLayout.PAGE_START);
		add(scrollPane, BorderLayout.CENTER);
		add(slider, BorderLayout.EAST);

		// Subscribe to get FV events.
		eventListener.addObserver(this);
	}

	/**
	 * Part of the Java {@link Observer} pattern. This class is a subscriber to all
	 * {@link FVEventListener} events, so when those are fired, they will be received here.
	 *
	 * Note: this method invokes the {@link #handleFVEvent(FVEvent)} method on the Swing
	 * thread to ensure that we will make all UI updates on the EDT.
	 *
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
				SwingUtilities.invokeLater(() -> handleFVEvent((FVEvent) arg));
			}
		}
	}

	/***************************************************************************************
	 * PRIVATE METHODS
	 ***************************************************************************************/

	/**
	 * Processes events received via the {@link FVEvent} mechanism.
	 *
	 * @param event the event type received
	 */
	private void handleFVEvent(FVEvent event) {

		switch (event.eventType) {

			case COPY_SELECTION:

				try {
					// 1. Read in the bytes containing the selected range.
					List<byte[]> byteArrays =
						reader.readBytes(model.selectedByteStart, model.selectedByteEnd);

					// 2. Create strings from the byte arrays.
					StringBuilder strBuilder = new StringBuilder();
					for (byte[] byteArray : byteArrays) {
						String str = new String(byteArray);
						strBuilder.append(str);
					}
					StringSelection stringSelection = new StringSelection(strBuilder.toString());

					// 3. Copy it to the clipboard.
					Clipboard clipboard = GClipboard.getSystemClipboard();
					clipboard.setContents(stringSelection, null);
				}
				catch (IOException e) {
					Msg.error(this, "error reading bytes from file", e);
				}

				break;
			case DECREMENT_SELECTION:
				if (table.getSelectedRow() >= 0) {
					table.decrementSelection((int) event.arg);
					slider.syncWithViewport();
					table.restoreSelection();
				}
				break;

			case DECREMENT_AND_ADD_SELECTION:
				if (table.getSelectedRow() >= 0) {
					table.decrementAndAddSelection((int) event.arg);
					slider.syncWithViewport();
					table.restoreSelection();
				}
				break;

			case FILE_CHANGED:
				reloadFile();
				break;

			case INCREMENT_SELECTION:
				if (table.getSelectedRow() >= 0) {
					table.incrementSelection((int) event.arg);
					slider.syncWithViewport();
					table.restoreSelection();
				}
				break;

			case INCREMENT_AND_ADD_SELECTION:
				if (table.getSelectedRow() >= 0) {
					table.incrementAndAddSelection((int) event.arg);
					slider.syncWithViewport();
					table.restoreSelection();
				}
				break;

			case OPEN_FILE_LOCATION:
				try {
					FileUtilities.openNative(reader.getFile().getParentFile());
				}
				catch (IOException e) {
					Msg.error(this, e);
				}
				break;

			case RELOAD_FILE:
				reloadFile();
				break;

			case SCROLL_HOME:
				viewTopOfFile();
				setScrollLock(true);
				break;

			case SCROLL_END:
				boolean updateSlider = event.arg == null ? true : (boolean) event.arg;
				viewEndOfFile(updateSlider);
				viewportUtility.moveViewportToBottom();
				break;

			case SLIDER_CHANGED:

				try {
					long newFilePos = (long) event.arg;
					newFilePos =
						newFilePos > reader.getFileSize() ? reader.getFileSize() - 1 : newFilePos;
					updateViewToFilePos(newFilePos);
					table.restoreSelection();
				}
				catch (IOException e) {
					Msg.error(this, "error retrieving file size from reader", e);
				}

				break;

			case SCROLL_LOCK_OFF:
				setScrollLock(false);
				break;

			case SCROLL_LOCK_ON:
				setScrollLock(true);
				break;

			case VIEWPORT_UPDATE:
				slider.syncWithViewport();
				table.restoreSelection();
				break;

			default:
		}
	}

	/**
	 * Sets the scroll lock state.
	 *
	 * @param lock if true, scrolling will be locked
	 */
	private void setScrollLock(boolean lock) {
		toolbar.getScrollLockBtn().setSelected(lock);
	}

	/**
	 * Loads the last chunk and moves the viewport accordingly.
	 */
	private void viewEndOfFile(boolean updateSlider) {
		table.clear();
		model.clear();
		try {
			((FVTableModel) (table.getModel())).addRowsToBottom(reader.readLastChunk());
			viewportUtility.moveViewportToBottom();
			table.restoreSelection();

			if (updateSlider) {
				slider.setValue(slider.getMaximum());
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error reading last chunk of data", e);
		}
	}

	/**
	 * Loads the first chunk and moves the viewport accordingly.
	 */
	private void viewTopOfFile() {
		table.clear();
		model.clear();
		try {
			((FVTableModel) (table.getModel())).addRowsToBottom(reader.readNextChunk());
			viewportUtility.moveViewportToTop();
			table.restoreSelection();
		}
		catch (IOException e) {
			Msg.error(this, "Error reading first chunk of data", e);
		}
	}

	/**
	 * Updates the view to show the correct portion of the file specified by the given
	 * file position.
	 *
	 * @param filePos
	 * @param model
	 */
	private void updateViewToFilePos(long filePos) {
		model.clear();
		table.clear();
		try {
			List<String> lines = reader.readNextChunkFrom(filePos);

			// If the number of lines read is < 1, then we're at the end of the file. If we
			// try to read a chunk from here we'll get nothing in return and will have nothing
			// to display. So back up from the end until we get a full line that we can show.
			int i = 0;
			while (lines.size() < 1) {
				lines = reader.readNextChunkFrom(filePos - i);
				i += 1;
			}
			((FVTableModel) table.getModel()).addRowsToTop(lines);
			viewportUtility.moveViewportToTop();
		}
		catch (IOException e) {
			Msg.error(this, "Error reading next chunk of data", e);
		}
	}

	/**
	 * Reloads the file. When this happens we maintain the position of the slider, unless the
	 * scroll lock capability is turned OFF; in that case we will display new text that is
	 * appended to the file (if the user is also at the bottom of the file).
	 */
	private void reloadFile() {

		// Save the current slider position so we can restore after the reload.
		int savedSliderPos = slider.getValue();

		try {
			reader.reload();
			slider.setMaximum(reader.getFileSize());
		}
		catch (IOException e) {
			Msg.error(this, "error reading file size", e);
		}

		// If scroll locking is not on, then we want to tail the file, so just move to the
		// bottom.
		if (!toolbar.getScrollLockBtn().isSelected()) {
			FVEvent endEvt = new FVEvent(EventType.SCROLL_END, true);
			eventListener.send(endEvt);
			return;
		}

		// Otherwise, just adjust the view to the file position.
		long filePos = slider.getFilePosition(savedSliderPos);
		updateViewToFilePos(filePos);
	}
}
