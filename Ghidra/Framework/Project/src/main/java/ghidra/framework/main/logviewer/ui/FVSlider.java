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

import java.awt.event.*;
import java.io.IOException;
import java.util.Iterator;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.framework.main.logviewer.event.*;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.model.*;
import ghidra.util.Msg;

/**
 * <pre> Custom slider that acts as the scroll bar for the FVTable. This slider listens for
 * changes to the viewport and updates its position accordingly.
 * 
 * Q. Why not just use the standard {@link javax.swing.JScrollBar JScrollBar} that comes with the {@link JScrollPane}?
 * 
 * A. It's because we are viewing only a portion of the total file at any given time.
 *    If we used the standard scroll mechanism, it would size itself and its viewport
 *    according to that subset of the total file, while we want it to reflect the file
 *    in its entirety.
 * 
 * Q. Why extend a {@link JSlider} for this custom scroll bar instead of a {@link JScrollBar}?
 * 
 * A. The {@link JSlider} is much easier to customize, specifically when trying to adjust
 *    the size of the slider thumb. Functionally they are both acceptable for our
 *    purposes, but the ease of using the slider wins out.
 * </pre>
 */
public class FVSlider extends JSlider
		implements ChangeListener, MouseMotionListener, MouseListener {

	// Need to keep track of mouse status when updating slider position and firing off update
	// notifications. If we receive a notification that the slider position has changed we need
	// to know if the change is because the user is actively moving it, or whether it moved
	// programmatically in response to a viewport change.
	private boolean mouseDown = false;

	private ViewportUtility viewportUtility;

	private ChunkModel model;

	private ChunkReader reader;

	private FVEventListener eventListener;

	private long previousSliderValue;

	/**
	 * Constructor. Builds the UI elements and establishes event listeners.
	 *
	 * @param scrollPane
	 * @param table
	 * @param viewportUtility
	 * @param model
	 * @param reader
	 * @param eventListener
	 */
	public FVSlider(JScrollPane scrollPane, FVTable table, ViewportUtility viewportUtility,
			ChunkModel model, ChunkReader reader, FVEventListener eventListener) {

		this.viewportUtility = viewportUtility;
		this.model = model;
		this.reader = reader;
		this.eventListener = eventListener;

		// Create a UI object for this slider that will be responsible for updating the thumb
		// size dynamically. 
		setUI(new FVSliderUI(this, scrollPane, table, reader, model));

		// Orient the slider; the default is horizontal.
		setOrientation(SwingConstants.VERTICAL);
		setInverted(true);

		// Listen for changes to the slider value, as well as mouse events.  When the slider 
		// changes we have to update the viewport to stay in sync.
		addChangeListener(this);
		addMouseMotionListener(this);
		addMouseListener(this);

		createKeyBindings(table, model, reader, eventListener);
	}

	
	/**
	 * Sets the value of the slider based on the given file position.
	 * 
	 * @param filePos
	 */
	public void setValue(long filePos) {
		int sliderPos = getSliderPosition(filePos);
		super.setValue(sliderPos);
	}

	/**
	 * Sets the maximum slider position given the size of the file. If the file position is
	 * greater than the maximum size of an integer, we just set it to that maximum size.
	 * 
	 * @param fileSize
	 */
	public void setMaximum(long fileSize) {
		int sliderMax = (int) (fileSize >= Integer.MAX_VALUE ? Integer.MAX_VALUE : fileSize);
		setMaximum(sliderMax);
	}

	/**
	 * Updates the slider so it is in sync with the current position of the viewport. 
	 * 
	 * Note that this is only done if the mouse is NOT down; if it is, it means the user is 
	 * moving the thumb and we should do nothing.
	 */
	public void syncWithViewport() {

		if (!mouseDown) {

			// 1. Figure out which row in the table the viewport is currently set to (the top 
			// left corner of it).
			int row = viewportUtility.getViewportPositionAsRow();

			// 2. Now we need to figure out what bytes in the file that row corresponds to. To do
			// that, we have to figure out which chunk this row belongs to, then use the 
			// Chunk.byteMap object to get the exact start byte of the row.
			//
			// Once we have that byte value, just set the slider to be the same.
			//
			int chunkRowStart = 0;
			Iterator<Chunk> iter = model.iterator();

			while (iter.hasNext()) {
				Chunk chunk = iter.next();

				// Figure out the starting row of the next chunk. If the row we want is less than
				// that, then we know we've found the chunk that contains our row.
				chunkRowStart += chunk.linesInChunk;
				if (row < chunkRowStart) {

					// To find our exact row WITHIN the chunk, we have to do some simple math (!), 
					// then get the starting byte for that row from the byteMap.
					int rowWithinChunk = (row - (chunkRowStart - chunk.linesInChunk));
					Pair byteRange = chunk.rowToFilePositionMap.get(rowWithinChunk);
					if (byteRange != null) {
						setValue(byteRange.getStart());
					}
					break;
				}
			}
		}
	}

	/**
	 * Invoked when the slider value has changed. When this happens we need to update the 
	 * viewport to match, but ONLY if this event is triggered as a result of the user 
	 * manually moving the slider (and not as a result of the slider being moved programmatically
	 * in response to a viewport change).
	 */
	@Override
	public void stateChanged(ChangeEvent e) {

		if (mouseDown) {

			try {
				long filePosition = getFilePosition(getValue() - 1);
				int sliderRow = model.getRowForBytePos(filePosition);
				int lastLineRow = model.getRowForBytePos(reader.getFileSize() - 1);
				int numRowsVisible = viewportUtility.getNumRowsInViewport();

				// This is a special check for when the user has scrolled to the end of the
				// file. In this case, we don't want to continue moving the viewport once the
				// last row has become visible at the bottom. To ensure that this happens, we check
				// to see that: 
				// 		1) The last line in the file is in the table
				//		2) The last line is in the visible portion of the viewport
				//
				// If both conditions are met, we just automatically load the bottom
				// of the file and view that in the viewport.
				if (lastLineRow != -1) {
					if (lastLineRow - sliderRow < numRowsVisible) {
						FVEvent scrollEndEvt = new FVEvent(EventType.SCROLL_END, false);
						eventListener.send(scrollEndEvt);
						return;
					}
				}
			}
			catch (IOException e1) {
				Msg.error(this, e1);
			}

			long filePosition = getFilePosition(getValue() - 1);

			FVEvent tailOffEvt = new FVEvent(EventType.SCROLL_LOCK_ON, null);
			eventListener.send(tailOffEvt);
				
			FVEvent sliderChangedEvt = new FVEvent(EventType.SLIDER_CHANGED, filePosition);
			eventListener.send(sliderChangedEvt);

			previousSliderValue = getValue();
		}
	}

	/***************************************************************************************
	 * MOUSE EVENTS
	 * 
	 * We need to set the mouseDown attribute so we only initiate a viewport
	 * update if the slider is moving in response to user action on the slider.
	 ***************************************************************************************/

	@Override
	public void mouseDragged(MouseEvent e) {
		mouseDown = true;
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		// do nothing
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// do nothing
	}

	@Override
	public void mousePressed(MouseEvent e) {
		mouseDown = true;
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		mouseDown = false;
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// do nothing
	}

	@Override
	public void mouseExited(MouseEvent e) {
		// do nothing
	}
	
	/**
	 * Returns the file position (long) for the given slider position (int). This is calculated by
	 * computing the position of the slider as a percentage of its maximum, and applying the same
	 * to the file position (relative to the total file size). 
	 * 
	 * @param sliderPos
	 * @return
	 */
	public long getFilePosition(int sliderPos) {
		try {
			float fileRatio = (float) sliderPos / getMaximum();
			return (long) (reader.getFileSize() * fileRatio);
		}
		catch (IOException e) {
			Msg.error(this, "Error getting file size", e);
		}

		return 0;
	}

	/*********************************************************************************
	 * PRIVATE METHODS
	 *********************************************************************************/

	/**
	 * Returns the slider position for the given file pointer position. This is calculated by
	 * computing the position of the file pointer as a percentage of the total file size, and 
	 * applying the same to the slider (relative to its maximum value).
	 * 
	 * @param filePos
	 * @return
	 */
	private int getSliderPosition(long filePos) {
		try {
			float fileRatio = (float) filePos / reader.getFileSize();
			return (int) (getMaximum() * fileRatio);
		}
		catch (IOException e) {
			Msg.error(this, "Error getting file size", e);
		}

		return 0;
	}

	/**
	 * Create key bindings for the slider. These are also captured by the {@link FVTable}, but if
	 * focus is on this slider we still want these keys to work.  
	 * 
	 * We have to capture the following:
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
	 * @param table
	 * @param model
	 * @param reader
	 * @param eventListener
	 */
	private void createKeyBindings(FVTable table, ChunkModel model, ChunkReader reader,
			FVEventListener eventListener) {
		
		// These key bindings are identical to the ones set in the FVTable class. These are 
		// necessary for cases where the user hits a key that should manipulate the table, but 
		// keyboard focus is on the slider.
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
		
		// Recognize when the shift key has been pressed and released, so we know how to handle 
		// selection.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_SHIFT, InputEvent.SHIFT_DOWN_MASK, false), "ShiftPressed");
		am_table.put("ShiftPressed", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				table.setShiftDown(true);	
			}	
		});
		im_table.put(KeyStroke.getKeyStroke("released SHIFT"), "ShiftReleased");
		am_table.put("ShiftReleased", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				table.setShiftDown(false);	
			}	
		});
		
		// Now create a binding for the CTRL-A, select all action.
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK, false), "SelectAll");
		im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.META_DOWN_MASK, false), "SelectAll");
		am_table.put("SelectAll", new AbstractAction() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					model.selectedByteStart = 0;
					model.selectedByteEnd = reader.getFileSize()-1;
					
					FVEvent copyEvt = new FVEvent(EventType.COPY_SELECTION, null);
					eventListener.send(copyEvt);
				}
				catch (IOException e1) {
					Msg.error(this, "error reading file size", e1);
				}
			}
		});
	}
	
}
