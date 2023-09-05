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
package ghidra.app.services;

import java.nio.ByteBuffer;

import ghidra.app.plugin.core.terminal.TerminalListener;

/**
 * A handle to a terminal window in the UI.
 */
public interface Terminal extends AutoCloseable {
	/**
	 * Add a listener for terminal events
	 * 
	 * @param listener the listener
	 */
	void addTerminalListener(TerminalListener listener);

	/**
	 * Remove a listener for terminal events
	 * 
	 * @param listener the listener
	 */
	void removeTerminalListener(TerminalListener listener);

	/**
	 * Process the given buffer as if it were output by the terminal's application.
	 * 
	 * <p>
	 * <b>Warning:</b> While implementations may synchronize to ensure the additional buffer is not
	 * processed at the same time as actual application input, there may not be any effort to ensure
	 * that the buffer is not injected in the middle of an escape sequence. Even if the injection is
	 * outside an escape sequence, this may still lead to unexpected behavior, since the injected
	 * output may be affected by or otherwise interfere with the application's control of the
	 * terminal's state. Generally, this should only be used for testing, or other cases when the
	 * caller knows it has exclusive control of the terminal.
	 * 
	 * @param bb the buffer of bytes to inject
	 */
	void injectDisplayOutput(ByteBuffer bb);

	/**
	 * @see #injectDisplayOutput(ByteBuffer)
	 */
	default void injectDisplayOutput(byte[] arr) {
		injectDisplayOutput(ByteBuffer.wrap(arr));
	}

	/**
	 * Set the terminal size to the given dimensions, and do <em>not</em> resize it to the window.
	 * 
	 * @param cols the number of columns
	 * @param rows the number of rows
	 */
	void setFixedSize(short cols, short rows);

	/**
	 * @see #setFixedSize(short, short)
	 */
	default void setFixedSize(int cols, int rows) {
		setFixedSize((short) cols, (short) rows);
	}

	/**
	 * Fit the terminal's dimensions to the containing window.
	 */
	void setDynamicSize();

	/**
	 * Set the maximum size of the scroll-back buffer in lines
	 * 
	 * <p>
	 * This only affects the primary buffer. The alternate buffer has no scroll-back.
	 */
	void setMaxScrollBackRows(int rows);

	/**
	 * Get the maximum number of characters in each row
	 * 
	 * @return the column count
	 */
	int getColumns();

	/**
	 * Get the maximum number of rows in the display (not counting scroll-back)
	 * 
	 * @return the row count
	 */
	int getRows();

	/**
	 * Get the number of lines in the scroll-back buffer
	 * 
	 * @return the size of the buffer in lines
	 */
	int getScrollBackRows();

	/**
	 * Get all the text in the terminal, including the scroll-back buffer
	 * 
	 * @return the full text
	 */
	String getFullText();

	/**
	 * Get the text in the terminal, excluding the scroll-back buffer
	 * 
	 * @return the display text
	 */
	String getDisplayText();

	/**
	 * Get the given line's text
	 * 
	 * <p>
	 * The line at the top of the display has index 0. Lines in the scroll-back buffer have negative
	 * indices.
	 * 
	 * @param line the index, 0 up
	 * @return the text in the line
	 */
	String getLineText(int line);

	/**
	 * Get the text in the given range
	 * 
	 * <p>
	 * The line at the top of the display has index 0. Lines in the scroll-back buffer have negative
	 * indices.
	 * 
	 * @param startCol the first column to include in the starting line
	 * @param startLine the first line to include
	 * @param endCol the first column to <em>exclude</em> in the ending line
	 * @param endLine the last line to include
	 * @return the text in the given range
	 */
	String getRangeText(int startCol, int startLine, int endCol, int endLine);

	/**
	 * Get the cursor's current line
	 * 
	 * <p>
	 * Lines are indexed 0 up where the top line of the display is 0. The cursor can never be in the
	 * scroll-back buffer.
	 * 
	 * @return the line, 0 up, top to bottom
	 */
	int getCursorRow();

	/**
	 * Get the cursor's current column
	 * 
	 * @return the column, 0 up, left to right
	 */
	int getCursorColumn();

	@Override
	void close();
}
