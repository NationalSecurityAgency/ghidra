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
package ghidra.app.plugin.core.terminal.vt;

import java.util.ArrayDeque;
import java.util.ArrayList;

import ghidra.app.plugin.core.terminal.vt.VtHandler.Erasure;

/**
 * A buffer for a terminal display and scroll-back
 * 
 * <p>
 * This object implements all of the buffer, line, and character manipulations available in the
 * terminal. It's likely more will need to be added in the future. While the ANSI VT parser
 * determines what commands to execute, this buffer provides the actual implementation of those
 * commands.
 */
public class VtBuffer {
	public static final int DEFAULT_ROWS = 25;
	public static final int DEFAULT_COLS = 80;

	protected static final int TAB_WIDTH = 8;

	protected int rows;
	protected int cols;
	protected int curX;
	protected int curY;
	protected int savedX;
	protected int savedY;
	protected int bottomY; // for scrolling UI after an update
	protected int scrollStart;
	protected int scrollEnd; // exclusive

	protected int maxScrollBack = 10_000;

	protected VtAttributes curAttrs = VtAttributes.DEFAULTS;

	protected ArrayDeque<VtLine> scrollBack = new ArrayDeque<>();
	protected ArrayList<VtLine> lines = new ArrayList<>();

	/**
	 * Create a new buffer of the default size (25 lines, 80 columns)
	 */
	public VtBuffer() {
		this(DEFAULT_ROWS, DEFAULT_COLS);
	}

	/**
	 * Create a new buffer of the given size
	 * 
	 * @param rows the number of rows
	 * @param cols the number of columns
	 */
	public VtBuffer(int rows, int cols) {
		this.rows = Math.max(1, rows);
		this.cols = Math.max(1, cols);
		this.scrollStart = 0;
		this.scrollEnd = rows;

		while (lines.size() < rows) {
			lines.add(new VtLine(cols));
		}
	}

	/**
	 * Clear the buffer and all state, as if it has just been created
	 */
	public void reset() {
		lines.clear();
		while (lines.size() < rows) {
			lines.add(new VtLine(cols));
		}
		curX = 0;
		curY = 0;
		scrollBack.clear();
	}

	/**
	 * Get the number of rows in the display
	 * 
	 * <p>
	 * This is not just the number of rows currently being used. This is the "rows" dimension of the
	 * display, i.e., the maximum number of rows it can display before scrolling.
	 * 
	 * @return the number of rows
	 */
	public int getRows() {
		return rows;
	}

	/**
	 * Get the number of columns in the display
	 * 
	 * <p>
	 * This is not just the number of columns currently being used. This is the "columns" dimension
	 * of the display, i.e., the maximum number of characters in a rows before wrapping.
	 * 
	 * @return the number of columns
	 */
	public int getCols() {
		return cols;
	}

	/**
	 * Put the given character at the cursor, and move the cursor forward
	 * 
	 * <p>
	 * The cursor's current attributes are applied to the character.
	 * 
	 * @param c the character to put into the buffer
	 * @see #setAttributes(VtAttributes)
	 * @see #getAttributes()
	 */
	public void putChar(char c) {
		if (c == 0) {
			return;
		}
		checkVerticalScroll();
		// At this point, we have no choice but to wrap
		lines.get(curY).putChar(curX, c, curAttrs);
	}

	/**
	 * More the cursor forward to the next tab stop
	 */
	public void tab() {
		int n = TAB_WIDTH + (-curX % TAB_WIDTH);
		moveCursorRight(n, false, false);
	}

	/**
	 * Move the cursor backward to the previous tab stop
	 */
	public void tabBack() {
		if (curX == 0) {
			return;
		}
		int n = (curX - 1) % TAB_WIDTH + 1;
		moveCursorLeft(n, false);
	}

	/**
	 * Move the cursor back to the beginning of the line
	 * 
	 * <p>
	 * This does <em>not</em> move the cursor down.
	 */
	public void carriageReturn() {
		if (curX == 0) {
			return;
		}
		int prevY = curY - 1;
		if (prevY >= 0 && prevY < lines.size()) {
			lines.get(prevY).wrappedToNext = false;
		}
		curX = 0;
	}

	/**
	 * Scroll the viewport down a line
	 * 
	 * <p>
	 * The lines are shifted upward. The line at the top of the viewport is removed, and a blank
	 * line is inserted at the bottom of the viewport. If the viewport includes the display's top
	 * line and intoScrollBack is specified, the line is shifted into the scroll-back buffer.
	 */
	public void scrollViewportDown(boolean intoScrollBack) {
		if (scrollStart == scrollEnd) {
			return;
		}
		VtLine temp;
		if (intoScrollBack && scrollStart == 0 && maxScrollBack > 0) {
			temp = scrollBack.size() >= maxScrollBack ? scrollBack.remove() : null;
			scrollBack.add(lines.remove(0));
		}
		else {
			temp = lines.remove(scrollStart);
		}

		if (temp == null) {
			temp = new VtLine(cols);
		}
		else {
			temp.reset(cols);
		}
		lines.add(scrollEnd - 1, temp); // Account for removed line
	}

	/**
	 * Scroll the viewport up a line
	 * 
	 * <p>
	 * The lines are shifted downward. The line at the bottom of the viewport is removed, and a
	 * blank line is inserted at the top of the viewport.
	 */
	public void scrollViewportUp() {
		VtLine temp = lines.remove(scrollEnd - 1);
		temp.reset(cols);
		lines.add(scrollStart, temp);
	}

	/**
	 * If the cursor is beyond the bottom of the display, scroll the viewport down and move the
	 * cursor up until the cursor is at the bottom of the display. If applicable, lines at the top
	 * of the display is shifted into the scroll-back buffer.
	 */
	public void checkVerticalScroll() {
		while (curY >= scrollEnd) {
			scrollViewportDown(true);
			curY = Math.max(0, curY - 1);
		}
	}

	/**
	 * Move the cursor up n rows
	 * 
	 * <p>
	 * The cursor cannot move above the top of the display. The value of n must be positive,
	 * otherwise behavior is undefined. To move the cursor down, use {@link #moveCursorDown(int)}.
	 * 
	 * @param n the number of rows to move the cursor up
	 */
	public void moveCursorUp(int n) {
		curY = Math.max(0, curY - n);
	}

	/**
	 * Move the cursor down n rows
	 * 
	 * <p>
	 * If the cursor would move below the bottom of the display, the viewport will be scrolled so
	 * that the cursor remains in the display. The value of n must be positive, otherwise behavior
	 * is undefined. To move the cursor up, use {@link #moveCursorUp(int)}.
	 * 
	 * <p>
	 * ConPty has a habit of moving the cursor past the end of the current line before sending CRLF.
	 * (Though, I imagine there are other applications that might do this.) The {@code dedupWrap}
	 * parameter is made to accommodate this. If it is set, n is a single line, and the previous
	 * line was wrapped, then this does nothing more than remove the wrapped flag from the previous
	 * line.
	 * 
	 * @param n the number of lines to move down
	 * @param dedupWrap whether to detect and ignore a line feed after wrapping
	 */
	public void moveCursorDown(int n, boolean dedupWrap) {
		int prevY = curY - 1;
		if (dedupWrap && n == 1 && prevY >= 0 && prevY < lines.size() &&
			lines.get(prevY).wrappedToNext) {
			lines.get(prevY).wrappedToNext = false;
		}
		else {
			curY += n;
			bottomY = Math.max(bottomY, curY);
			checkVerticalScroll();
		}
	}

	/**
	 * Move the cursor left (backward) n columns
	 * 
	 * <p>
	 * The cursor is clamped into the display. If wrap is specified, the cursor would exceed the
	 * left side of the display, and the previous line was wrapped onto the current line, then the
	 * cursor will instead be moved to the end of the previous line. (It doesn't matter how far the
	 * cursor would exceed the left; it moves up at most one line.) The value of n must be positive,
	 * otherwise behavior is undefined. To move the cursor right, use {@link #moveCursorRight(int)}.
	 * 
	 * @param n the number of columns
	 * @param wrap whether to wrap the cursor to the previous line if would exceed the left of the
	 *            display
	 */
	public void moveCursorLeft(int n, boolean wrap) {
		int prevY = curY - 1;
		if (wrap && curX - n < 0 && prevY >= 0 && prevY < lines.size() &&
			lines.get(prevY).wrappedToNext) {
			curX = cols - 1;
			curY--;
			lines.get(curY).wrappedToNext = false;
		}
		curX = Math.max(0, Math.min(curX - n, cols - 1));
	}

	/**
	 * Move the cursor right (forward) n columns
	 * 
	 * <p>
	 * The cursor is clamped into the display. If wrap is specified and the cursor would exceed the
	 * right side of the display, the cursor will instead be wrapped to the start of the next line,
	 * possibly scrolling the viewport down. (It doesn't matter how far the cursor exceeds the
	 * right; the cursor moves down exactly one line.) The value of n must be positive, otherwise
	 * behavior is undefined. To move the cursor left, use {@link #moveCursorLeft(int)}.
	 * 
	 * @param n the number of columns
	 * @param wrap whether to wrap the cursor to the next line if it would exceed the right of the
	 *            display
	 */
	public void moveCursorRight(int n, boolean wrap, boolean isCursorShowing) {
		if (wrap && curX + n >= cols) {
			checkVerticalScroll();
			curX = 0;
			lines.get(curY).wrappedToNext = true;
			curY++;
			bottomY = Math.max(bottomY, curY);
			if (isCursorShowing) {
				checkVerticalScroll();
			}
		}
		else {
			curX = Math.max(0, Math.min(curX + n, cols - 1));
		}
	}

	/**
	 * Save the current cursor position
	 * 
	 * <p>
	 * There is only one slot for the saved cursor. It is not a stack or anything fancy. To restore
	 * the cursor, use {@link #restoreCursorPos()}. The advantage to using this vice
	 * {@link #getCurX()} and {@link #getCurY()} to save it externally, is that the buffer will
	 * adjust the saved position if the buffer is resized via {@link #resize(int, int)}.
	 */
	public void saveCursorPos() {
		savedX = curX;
		savedY = curY;
	}

	/**
	 * Restore a saved cursor position
	 * 
	 * <p>
	 * If there was no previous call to {@link #saveCursorPos()}, the cursor is placed at the
	 * top-left of the display.
	 */
	public void restoreCursorPos() {
		curX = savedX;
		curY = savedY;
		bottomY = Math.max(bottomY, curY);
	}

	/**
	 * Move the cursor to the given row and column
	 *
	 * <p>
	 * The position is clamped to the dimensions of the display. No scrolling will take place if
	 * {@code col} exceeds the number of rows.
	 * 
	 * @param row the desired row, 0 up, top to bottom
	 * @param col the desired column, 0 up, left to right
	 */
	public void moveCursor(int row, int col) {
		curX = Math.max(0, Math.min(cols - 1, col));
		curY = Math.max(0, Math.min(rows - 1, row));
		bottomY = Math.max(bottomY, curY);
	}

	/**
	 * Get the cursor's current attributes
	 * 
	 * <p>
	 * Characters put into the buffer via {@link #putChar(char)} are assigned the cursor's current
	 * attributes at the time they are inserted.
	 * 
	 * @see #setAttributes(VtAttributes)
	 * @return the current attributes
	 */
	public VtAttributes getAttributes() {
		return curAttrs;
	}

	/**
	 * Set the cursor's current attributes
	 * 
	 * <p>
	 * These are usually the attributes given by the ANSI SGR control sequences. They may not affect
	 * the display of the cursor itself, but rather of the characters placed at the cursor via
	 * {@link #putChar(char)}. NOTE: Not all attributes are necessarily supported by the renderer.
	 * 
	 * @param attributes the desired attributes
	 */
	public void setAttributes(VtAttributes attributes) {
		this.curAttrs = attributes == null ? VtAttributes.DEFAULTS : attributes;
	}

	/**
	 * Erase (clear) some portion of the display buffer
	 * 
	 * <p>
	 * If the current line is erased from start to the cursor, the cursor's attributes are applied
	 * to the cleared columns.
	 * 
	 * @param erasure specifies what, relative to the cursor, to erase.
	 */
	public void erase(Erasure erasure) {
		switch (erasure) {
			case TO_DISPLAY_END:
				if (curY >= lines.size()) {
					return;
				}
				for (int y = curY; y < rows; y++) {
					VtLine line = lines.get(y);
					if (y == curY) {
						line.clearToEnd(curX);
					}
					else {
						line.clear();
					}
				}
				return;
			case TO_DISPLAY_START:
				for (int y = 0; y <= curY; y++) {
					VtLine line = lines.get(y);
					if (y == curY) {
						line.clearToStart(curX, curAttrs);
					}
					else {
						line.clear();
					}
				}
				return;
			case FULL_DISPLAY:
				for (VtLine line : lines) {
					line.clear();
				}
				return;
			case FULL_DISPLAY_AND_SCROLLBACK:
				for (VtLine line : lines) {
					line.clear();
				}
				scrollBack.clear();
				return;
			case TO_LINE_END:
				if (curY >= lines.size()) {
					return;
				}
				lines.get(curY).clearToEnd(curX);
				return;
			case TO_LINE_START:
				if (curY >= lines.size()) {
					return;
				}
				lines.get(curY).clearToStart(curX, curAttrs);
				return;
			case FULL_LINE:
				if (curY >= lines.size()) {
					return;
				}
				lines.get(curY).clear();
				return;
		}
	}

	/**
	 * Insert n blank lines at the cursor
	 * 
	 * <p>
	 * Lines at the bottom of the viewport are removed and all the lines between the cursor and the
	 * bottom of the viewport are shifted down, to make room for n blank lines. None of the lines
	 * above the cursor are affected, including those in the scroll-back buffer.
	 * 
	 * @param n the number of lines to insert
	 */
	public void insertLines(int n) {
		for (int i = 0; i < n; i++) {
			VtLine temp = lines.remove(scrollEnd - 1);
			temp.reset(cols);
			lines.add(curY, temp);
		}
	}

	/**
	 * Delete n lines at the cursor
	 * 
	 * <p>
	 * Lines at (and immediately below) the cursor are removed and all lines between the cursor and
	 * the bottom of the viewport are shifted up to make room for n blank lines inserted at (and
	 * above) the bottom of the viewport. None of the lines above the cursor are affected.
	 * 
	 * @param n the number of lines to delete
	 */
	public void deleteLines(int n) {
		for (int i = 0; i < n; i++) {
			VtLine temp = lines.remove(curY);
			temp.reset(cols);
			lines.add(scrollEnd - 1, temp); // account for removed index
		}
	}

	/**
	 * Insert n blank characters at the cursor
	 * 
	 * <p>
	 * Any characters right the cursor on the same line are shifted right to make room and n blanks
	 * are inserted at (and to the right) of the cursor. No wrapping occurs. Characters that would
	 * be moved or inserted right of the display buffer are effectively deleted. The cursor is
	 * <em>not</em> moved after this operation.
	 * 
	 * @param n the number of blanks to insert.
	 */
	public void insertChars(int n) {
		if (curY >= lines.size()) {
			return;
		}
		lines.get(curY).insert(curX, n);
	}

	/**
	 * Delete n characters at the cursor
	 * 
	 * <p>
	 * Characters at (and {@code n-1} to the right) of the cursor are deleted. The remaining
	 * characters to the right are shifted left {@code n} columns.
	 * 
	 * @param n the number of characters to delete
	 */
	public void deleteChars(int n) {
		if (curY >= lines.size()) {
			return;
		}
		lines.get(curY).delete(curX, curX + n);
	}

	/**
	 * Erase n characters at the cursor
	 * 
	 * <p>
	 * Characters at (and {@code n-1} to the right) of the cursor are erased, i.e., replaced with
	 * blanks. No shifting takes place.
	 * 
	 * @param n the number of characters to erase
	 */
	public void eraseChars(int n) {
		if (curY >= lines.size()) {
			return;
		}
		lines.get(curY).erase(curX, curX + n, curAttrs);
	}

	/**
	 * Specify the scrolling viewport of the buffer
	 * 
	 * <p>
	 * By default, the viewport is the entire display, and scrolling the viewport downward may cause
	 * lines to enter the scroll-back buffer. The buffer manages these boundaries so that they can
	 * be updated on calls to {@link #resize(int, int)}. Both parameters are optional, though
	 * {@code end} should likely only be given if {@code start} is also given. The parameters are
	 * silently adjusted to ensure that both are within the bounds of the display and so that the
	 * end is at or below the start. Once set, the cursor should remain within the viewport, or
	 * otherwise cause the viewport to scroll. Operations that would cause the display to scroll,
	 * instead cause just the viewport to scroll. Additionally, cursor movement operations are
	 * clamped to the viewport.
	 * 
	 * @param start the first line in the viewport, 0 up, top to bottom, inclusive. If omitted, this
	 *            is the top line of the display.
	 * @param end the last line in the viewport, 0 up, top to bottom, inclusive. If omitted, this is
	 *            the bottom line of the display.
	 */
	public void setScrollViewport(Integer start, Integer end) {
		if (start != null) {
			scrollStart = Math.max(0, start);
		}
		else {
			scrollStart = 0;
		}
		if (end != null) {
			// scrollEnd is exclusive
			scrollEnd = Math.max(scrollStart + 1, Math.min(rows, end + 1));
		}
		else {
			scrollEnd = rows;
		}
	}

	/**
	 * Resize the buffer to the given number of rows and columns
	 * 
	 * <p>
	 * The viewport is reset to include the full display. Each line, including those in the
	 * scroll-back buffer are resized to match the requested number of columns. If the row count is
	 * decreasing, lines at the top of the display are be shifted into the scroll-back buffer. If
	 * the row count is increasing, lines at the bottom of the scroll-back buffer are shifted into
	 * the display buffer. The scroll-back buffer may be culled if the resulting number of lines
	 * exceeds that scroll-back maximum. The cursor position is adjusted so that, if possible, it
	 * remains on the same line. (The cursor cannot enter the scroll-back region.) Finally, the
	 * cursor is clamped into the display region. The saved cursor, if applicable, is similarly
	 * treated.
	 * 
	 * @param cols the number of columns
	 * @param rows the number of rows
	 * @return true if the buffer was actually resized
	 */
	public boolean resize(int cols, int rows) {
		cols = Math.max(1, cols);
		rows = Math.max(1, rows);

		if (this.rows == rows && this.cols == cols) {
			return false;
		}

		for (VtLine line : scrollBack) {
			line.resize(cols);
		}
		for (VtLine line : lines) {
			line.resize(cols);
		}
		this.rows = rows;
		this.cols = cols;
		this.scrollStart = 0;
		this.scrollEnd = rows;

		while (lines.size() < rows) {
			lines.add(0, scrollBack.isEmpty() ? new VtLine(cols) : scrollBack.pollLast());
			curY++;
			savedY++;
		}
		while (lines.size() > rows) {
			scrollBack.addLast(lines.remove(0));
			curY--;
			savedY--;
		}
		while (scrollBack.size() > maxScrollBack) {
			scrollBack.pollFirst();
		}

		curX = Math.min(curX, cols - 1);
		savedX = Math.min(savedX, cols - 1);

		curY = Math.max(0, Math.min(curY, rows - 1));
		savedY = Math.max(0, Math.min(savedY, rows - 1));

		return true;
	}

	/**
	 * Adjust the maximum number of lines in the scroll-back buffer
	 * 
	 * <p>
	 * If the scroll-back buffer exceeds the given maximum, it is immediately culled.
	 * 
	 * @param maxScrollBack the maximum number of scroll-back lines
	 */
	public void setMaxScrollBack(int maxScrollBack) {
		this.maxScrollBack = maxScrollBack;
		while (scrollBack.size() > maxScrollBack) {
			scrollBack.pollFirst();
		}
	}

	/**
	 * A callback for iterating over the lines of the buffer
	 */
	public interface LineConsumer {
		/**
		 * Process a line of terminal text
		 * 
		 * @param i the index of the line, optionally including scroll-back, 0 up, top to bottom
		 * @param y the vertical position of the line. For a scroll-back line, this is -1.
		 *            Otherwise, this counts 0 up, top to bottom.
		 * @param t the line
		 * @see VtBuffer#forEachLine(boolean, LineConsumer)
		 */
		void accept(int i, int y, VtLine t);
	}

	/**
	 * Perform an action on each line of terminal text, optionally including the scroll-back buffer.
	 * 
	 * @param includeScrollBack true to include the scroll-back buffer
	 * @param action the action
	 */
	public void forEachLine(boolean includeScrollBack, LineConsumer action) {
		int i = 0;
		if (includeScrollBack) {
			for (VtLine line : scrollBack) {
				action.accept(i, -1, line);
				i++;
			}
		}
		int y = 0;
		for (VtLine line : lines) {
			action.accept(i, y, line);
			i++;
			y++;
		}
	}

	/**
	 * Get the total number of lines, including scroll-back lines, in the buffer
	 * 
	 * <p>
	 * This is equal to {@link #getScrollBackSize()}{@code +}{@link #getRows()}.
	 * 
	 * @return the number of lines
	 */
	public int size() {
		return scrollBack.size() + rows;
	}

	/**
	 * Get the number of lines in the scroll-back buffer
	 * 
	 * @return the number of lines
	 */
	public int getScrollBackSize() {
		return scrollBack.size();
	}

	/**
	 * Get the cursor's column, 0 up, left to right
	 * 
	 * @return the column
	 */
	public int getCurX() {
		return curX;
	}

	/**
	 * Get the cursor's row, 0 up, top to bottom
	 * 
	 * @return the row
	 */
	public int getCurY() {
		return curY;
	}

	/**
	 * This is essentially the loop body for {@link #getText(int, int, int, int, CharSequence)}. It
	 * is factored into a separate method, because we need to loop over the scroll-back buffer as
	 * well as the display buffer, and we want the same body.
	 */
	protected boolean gatherLineText(StringBuilder sb, int startRow, int startCol, int endRow,
			int endCol, int i, VtLine line, CharSequence lineSep) {
		if (i < startRow) {
			return false;
		}
		if (i == startRow && startRow == endRow) {
			line.gatherText(sb, startCol, endCol);
			return true;
		}
		if (i == startRow) {
			line.gatherText(sb, startCol, cols);
			sb.append(lineSep);
			return false;
		}
		if (i == endRow) {
			line.gatherText(sb, 0, endCol);
			return true;
		}
		if (i > endRow) {
			return true;
		}
		line.gatherText(sb, 0, cols);
		sb.append(lineSep);
		return false;
	}

	/**
	 * Get the text between two locations in the buffer
	 * 
	 * <p>
	 * The buffer attempts to avoid extraneous space at the end of each line. This isn't always
	 * perfect and depends on how lines are cleared. If they are cleared using
	 * {@link #erase(Erasure)}, then the buffer will cull the trailing spaces resulting from the
	 * clear. If they are cleared using {@link #putChar(char)} passing a space {@code ' '}, then the
	 * inserted spaces will be included. In practice, this depends on the application controlling
	 * the terminal.
	 * 
	 * <p>
	 * Like the other methods, locations are specified 0 up, top to bottom, and left to right.
	 * Unlike the other methods, the ending character is excluded from the result.
	 * 
	 * @param startRow the row for the starting location, inclusive
	 * @param startCol the column for the starting location, inclusive
	 * @param endRow the row for the ending location, inclusive
	 * @param endCol the column for the ending location, <em>exclusive</em>
	 * @param lineSep the line separator
	 * @return the text
	 */
	public String getText(int startRow, int startCol, int endRow, int endCol,
			CharSequence lineSep) {
		StringBuilder buf = new StringBuilder();
		int sbSize = scrollBack.size();
		if (startRow < sbSize) {
			int i = 0;
			for (VtLine line : scrollBack) {
				if (gatherLineText(buf, startRow, startCol, endRow, endCol, i, line, lineSep)) {
					break;
				}
				i++;
			}
		}
		for (int i = Math.max(sbSize, startRow); i <= endRow; i++) {
			VtLine line = lines.get(i - sbSize);
			gatherLineText(buf, startRow, startCol, endRow, endCol, i, line, lineSep);
		}
		return buf.toString();
	}

	public int resetBottomY() {
		int ret = bottomY;
		bottomY = curY;
		return ret;
	}
}
