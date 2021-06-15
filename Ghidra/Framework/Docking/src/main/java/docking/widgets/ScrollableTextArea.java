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
package docking.widgets;

import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.datatransfer.Clipboard;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.text.Document;

import docking.DockingUtils;
import docking.dnd.GClipboard;
import docking.dnd.StringTransferable;
import generic.util.WindowUtilities;

/**
 * A JScrollPane wrapper for a text area that can be told to scroll to bottom
 */
public class ScrollableTextArea extends JScrollPane {
	private PrivateTextArea textArea;

	/**
	 * Constructs a scrollable JTextArea, where a default model is set,
	 * the initial string is null, and rows/columns are set to 0.
	 */
	public ScrollableTextArea() {
		textArea = new PrivateTextArea();
		initialize();
	}

	/**
	 * Constructs a scrollable JextArea with the specified text displayed.
	 * A default model is created and rows/columns are set to 0.
	 * @param text the initial text.
	 */
	public ScrollableTextArea(String text) {
		textArea = new PrivateTextArea(text);
		initialize();
	}

	/**
	 * Constructs a new empty TextArea with the specified number
	 * of rows and columns. A default model is created, and the
	 * initial string is null.
	 * @param rows the number of visible rows.
	 * @param columns the number of visible columns.
	 */
	public ScrollableTextArea(int rows, int columns) {
		textArea = new PrivateTextArea(rows, columns);
		initialize();
	}

	/**
	 * Constructs a scrollable JTextArea with the specified text and 
	 * number of rows and columns. A default model is created.
	 * @param text initial text.
	 * @param rows the number of visible rows.
	 * @param columns the number of visible columns.
	 */
	public ScrollableTextArea(String text, int rows, int columns) {
		textArea = new PrivateTextArea(text, rows, columns);
		initialize();
	}

	/**
	 * Constructs a scrollable JTextArea with the given document model,
	 * and defaults for all of the other arguments (null, 0, 0).
	 * @param doc - the model to use
	 */
	public ScrollableTextArea(Document doc) {
		textArea = new PrivateTextArea(doc);
		initialize();
	}

	/**
	 * Constructs a scrollable JTextArea with the specified number of
	 * rows and columns, and the given model. All of the
	 * constructors feed through this constructor.
	 * @param doc - the model to use
	 * @param text initial text.
	 * @param rows the number of visible rows.
	 * @param columns the number of visible columns.
	 */
	public ScrollableTextArea(Document doc, String text, int rows, int columns) {
		textArea = new PrivateTextArea(doc, text, rows, columns);
		initialize();
	}

	/**
	 * Appends the text to the text area maintained in this scroll pane
	 * @param text the text to append.
	 */
	public void append(String text) {
		textArea.append(text);
	}

	/**
	 * Returns the number of lines current set in the text area
	 * @return the count
	 */
	public int getLineCount() {
		return textArea.getLineCount();
	}

	/**
	 * Returns the tab size set in the text area
	 * @return the size
	 */
	public int getTabSize() {
		return textArea.getTabSize();
	}

	/**
	 * Returns the total area height of the text area (row height * line count)
	 * @return the height
	 */
	public int getTextAreaHeight() {
		return (textArea.getAreaHeight());
	}

	/**
	 * Returns the visible height of the text area
	 * @return the height
	 */
	public int getTextVisibleHeight() {
		return textArea.getVisibleHeight();
	}

	/**
	 * Inserts the string at the specified position
	 * @param text the text to insert.
	 * @param position the character postition at which to insert the text.
	 */
	public void insert(String text, int position) {
		textArea.insert(text, position);
	}

	/**
	 * replaces the range of text specified
	 * @param text the new text that will replace the old text.
	 * @param start the starting character postition of the text to replace.
	 * @param end the ending character position of the text to replace.
	 */
	public void replaceRange(String text, int start, int end) {
		textArea.replaceRange(text, start, end);
	}

	public void setCaretPosition(int position) {
		textArea.setCaretPosition(position);
	}

	@Override
	public java.awt.Dimension getPreferredSize() {
		return getViewport().getPreferredSize();
	}

	/**
	 * forces the scroll pane to scroll to bottom of text area
	 */
	public void scrollToBottom() {
		setCaretPosition(textArea.getDocument().getLength());
	}

	/**
	 * Scroll the pane to the top of the text area.
	 */
	public void scrollToTop() {
		setCaretPosition(0);
	}

	/**
	 * Sets the number of characters to expand tabs to. This will be
	 * multiplied by the maximum advance for variable width fonts.
	 * A PropertyChange event ("tabSize") is fired when tab size changes.
	 * @param tabSize the new tab size.
	 */
	public void setTabSize(int tabSize) {
		textArea.setTabSize(tabSize);
	}

	/**
	 * set the text in the text area
	 * @param text the text to set.
	 */
	public void setText(String text) {
		textArea.setText(text);
		textArea.invalidate();
	}

	/**
	 * Returns the text contained within the text area
	 * @return the text
	 */
	public String getText() {
		return textArea.getText();
	}

	/**
	 * Sets the ability to edit the text area content
	 * @param editable true to edit, false to not allow edit.
	 */
	public void setEditable(boolean editable) {
		textArea.setEditable(editable);
	}

	/**
	 * used by all constructors to finish initialization of the object
	 */
	private void initialize() {
		textArea.setLineWrap(false);
		this.setAutoscrolls(true);
		this.setViewportView(textArea);

		final JPopupMenu popup = new JPopupMenu();
		JMenuItem menuCopy = new JMenuItem("Copy");
		menuCopy.setActionCommand((String) TransferHandler.getCopyAction().getValue(Action.NAME));
		menuCopy.addActionListener(new CopyActionListener());
		menuCopy.setAccelerator(
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		popup.add(menuCopy);

		textArea.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				maybeShowPopup(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				maybeShowPopup(e);
			}

			private void maybeShowPopup(MouseEvent e) {
				if (e.isPopupTrigger()) {
					popup.show(e.getComponent(), e.getX(), e.getY());
				}
			}
		});
	}

	private class CopyActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			Clipboard systemClipboard = GClipboard.getSystemClipboard();
			String text = textArea.getText();
			StringTransferable transferable = new StringTransferable(text);
			systemClipboard.setContents(transferable, null);
		}
	}

	/**
	 * JTextArea's getRowHeight() is protected, so we need to derive
	 * a class to use it :(
	 */
	private class PrivateTextArea extends JTextArea {

		/**
		 * Constructs a new TextArea, where a default model is set,
		 * the initial string is null, and rows/columns are set to 0.
		 */
		private PrivateTextArea() {
			super();
		}

		/**
		 * Constructs a new TextArea with the specified text displayed.
		 * A default model is created and rows/columns are set to 0.
		 */
		private PrivateTextArea(String text) {
			super(text);
		}

		/**
		 * Constructs a new empty TextArea with the specified number
		 * of rows and columns. A default model is created, and the
		 * initial string is null.
		 */
		private PrivateTextArea(int rows, int columns) {
			super(rows, columns);
		}

		/**
		 * Constructs a new TextArea with the specified text and 
		 * number of rows and columns. A default model is created.
		 */
		private PrivateTextArea(String text, int rows, int columns) {
			super(text, rows, columns);
		}

		/**
		 * Constructs a new JTextArea with the given document model,
		 * and defaults for all of the other arguments (null, 0, 0).
		 * @param doc - the model to use
		 */
		private PrivateTextArea(Document doc) {
			super(doc);
		}

		/**
		 * Constructs a new JTextArea with the specified number of
		 * rows and columns, and the given model. All of the
		 * constructors feed through this constructor.
		 */
		private PrivateTextArea(Document doc, String text, int rows, int columns) {
			super(doc, text, rows, columns);
		}

		private int getAreaHeight() {
			return (super.getRowHeight() * super.getLineCount());
		}

		@SuppressWarnings("unused")
		private int getSingleRowHeight() {
			return super.getRowHeight();
		}

		private int getVisibleHeight() {
			return (super.getRowHeight() * super.getRows());
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			//
			// Overridden to allow the text of the text area to be as big as it wants to be to
			// prevent horizontal scrolling.  This helps with content like error messages, which
			// often are sized too small to see all the text.
			//
			Dimension size = getPreferredSize();
			size.width += getScrollBarWidth();

			Rectangle screenBounds = WindowUtilities.getScreenBounds(this);
			if (screenBounds == null) {
				// not yet 'realized' on screen; don't know which screen we will be on
				return size;
			}

			size.width = Math.min(size.width, screenBounds.width);
			size.height = Math.min(size.height, screenBounds.height);
			return size;
		}

		private int getScrollBarWidth() {
			JScrollBar bar = getVerticalScrollBar();
			if (bar == null) {
				return 0;
			}

			return bar.getPreferredSize().width * 2; // double the size (fudge factor)
		}

	} //end class PrivateTextArea
}
