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

/**
 * A line of text in the {@link VtBuffer}
 */
public class VtLine {
	protected int cols;
	protected int len;
	protected char[] chars;
	protected boolean wrappedToNext;
	private VtAttributes[] cellAttrs;

	/**
	 * Create a line with the given maximum number of characters
	 * 
	 * @param cols the maximum number of characters
	 */
	public VtLine(int cols) {
		reset(cols);
	}

	/**
	 * Get the character in the given column
	 * 
	 * @param x the column, 0 up
	 * @return the character
	 */
	public char getChar(int x) {
		return chars[x];
	}

	/**
	 * Get the full character buffer
	 * 
	 * <p>
	 * This is a reference to the buffer, which is very useful when rendering. Modifying this buffer
	 * externally is not recommended.
	 * 
	 * @return the buffer
	 */
	public char[] getCharBuffer() {
		return chars;
	}

	/**
	 * Get the attributes for the character in the given column
	 * 
	 * @param x the column, 0 up
	 * @return the attributes
	 */
	public VtAttributes getCellAttrs(int x) {
		VtAttributes attrs = cellAttrs[x];
		if (attrs == null) {
			return VtAttributes.DEFAULTS;
		}
		return attrs;
	}

	/**
	 * Place the given character with attributes into the given column
	 * 
	 * @param x the column, 0 up
	 * @param c the character
	 * @param attrs the attributes
	 */
	public void putChar(int x, char c, VtAttributes attrs) {
		int oldLen = len;
		len = Math.max(len, x + 1);
		wrappedToNext = false; // Maybe remove
		for (int i = oldLen; i < x; i++) {
			chars[i] = ' ';
			cellAttrs[i] = VtAttributes.DEFAULTS;
		}
		chars[x] = c;
		if (attrs != null) {
			cellAttrs[x] = attrs;
		}
	}

	/**
	 * Resize the line to the given maximum character count
	 * 
	 * @param cols the maximum number of characters
	 */
	public void resize(int cols) {
		this.cols = cols;
		// NB. Don't forget the characters in the buffer. User may resize back again.
		// TODO: Could/should we re-wrap? Would need to record wraps vs returns, though.
		if (cols <= chars.length) {
			return;
		}
		char[] newChars = new char[cols];
		VtAttributes[] newCellAttrs = new VtAttributes[cols];
		System.arraycopy(chars, 0, newChars, 0, Math.min(cols, chars.length));
		System.arraycopy(cellAttrs, 0, newCellAttrs, 0, Math.min(cols, cellAttrs.length));
		this.chars = newChars;
		this.cellAttrs = newCellAttrs;
	}

	/**
	 * Reset the line
	 * 
	 * @param cols
	 */
	public void reset(int cols) {
		this.cols = cols;
		this.len = 0;
		this.wrappedToNext = false;
		if (this.cols != cols || this.chars == null) {
			this.chars = new char[cols];
			this.cellAttrs = new VtAttributes[cols];
		}
	}

	/**
	 * Get the length of the line, excluding trailing cleared characters
	 * 
	 * @return the length
	 */
	public int length() {
		return Math.min(len, cols);
	}

	/**
	 * Get the number of columns in the line
	 * 
	 * @return the column count
	 */
	public int cols() {
		return cols;
	}

	/**
	 * Clear the full line
	 */
	public void clear() {
		len = 0;
		wrappedToNext = false;
	}

	/**
	 * Clear characters at and after the given column
	 * 
	 * @param x the column, 0 up
	 */
	public void clearToEnd(int x) {
		len = Math.min(len, x);
		wrappedToNext = false;
	}

	/**
	 * Clear characters before and at the given column
	 * 
	 * @param x the column, 0 up
	 * @param attrs attributes to apply to the cleared (space) characters
	 */
	public void clearToStart(int x, VtAttributes attrs) {
		if (len <= x) {
			len = 0;
			wrappedToNext = false;
			return;
		}
		for (int i = 0; i <= x; i++) {
			chars[i] = ' ';
			cellAttrs[i] = attrs;
		}
	}

	/**
	 * Delete characters in the given range, shifting remaining characters to the left
	 * 
	 * @param start the first column, 0 up
	 * @param end the last column, exclusive, 0 up
	 */
	public void delete(int start, int end) {
		if (len <= end) {
			len = Math.min(len, start);
			wrappedToNext = false;
			return;
		}
		int shift = end - start;
		len -= shift;
		for (int x = start; x < end; x++) {
			chars[x] = chars[x + shift];
			cellAttrs[x] = cellAttrs[x + shift];
		}
	}

	/**
	 * Replace characters in the given range with spaces
	 * 
	 * <p>
	 * If the last column is erased, this instead clears from the start to the end. The difference
	 * is subtle, but deals in how the line reports its text contents. The trailing spaces will not
	 * be included if this call results in the last column being erased.
	 * 
	 * @param start the first column, 0 up
	 * @param end the last column, exclusive, 0 up
	 * @param attrs the attributes to assign the space characters
	 */
	public void erase(int start, int end, VtAttributes attrs) {
		if (len <= end) {
			len = Math.min(len, start);
			wrappedToNext = false;
			return;
		}
		for (int x = start; x < end; x++) {
			chars[x] = ' ';
			cellAttrs[x] = attrs;
		}
	}

	/**
	 * Insert n (space) characters at and after the given column
	 * 
	 * @param start the column, 0 up
	 * @param n the number of characters to insert
	 */
	public void insert(int start, int n) {
		// Via experimentation, there is no wrapping.
		// Neither of the shifted, nor the inserted characters.
		// Additionally, the cursor does not move.

		// TODO: What about colors/attributes?
		int end = Math.min(cols, start + n);
		for (int x = cols - 1; x >= end; x--) {
			chars[x] = chars[x - n];
			cellAttrs[x] = cellAttrs[x - n];
		}
		for (int x = start; x < end; x++) {
			chars[x] = ' ';
		}
		len = Math.min(cols, len + n);
		wrappedToNext = false;
	}

	/**
	 * A callback for a run of contiguous characters having the same attributes
	 */
	public interface RunConsumer {
		/**
		 * Execute an action on a run
		 * 
		 * @param attrs the attributes shared by all in the run
		 * @param start the first column of the run, 0 up
		 * @param end the last column of the run, exclusive, 0 up
		 */
		void accept(VtAttributes attrs, int start, int end);
	}

	/**
	 * Execute an action on each run of contiguous characters having the same attributes, from left
	 * to right.
	 * 
	 * @param action the callback action
	 */
	public void forEachRun(RunConsumer action) {
		int length = length();
		if (length == 0) {
			action.accept(VtAttributes.DEFAULTS, 0, 0);
		}
		int first = 0;
		VtAttributes attrs = getCellAttrs(0);
		for (int x = 1; x < length; x++) {
			if (!attrs.equals(getCellAttrs(x))) {
				action.accept(attrs, first, x);
				first = x;
				attrs = getCellAttrs(x);
			}
		}
		action.accept(attrs, first, length);
	}

	/**
	 * Append a portion of this line's text to the given string builder
	 * 
	 * @param sb the destination builder
	 * @param start the first column, 0 up
	 * @param end the last column, exclusive, 0 up
	 */
	public void gatherText(StringBuilder sb, int start, int end) {
		start = Math.max(0, Math.min(start, len));
		end = Math.max(0, Math.min(end, len));
		sb.append(chars, start, end - start);
	}

	/**
	 * Check if the given character is considered part of a word
	 * 
	 * <p>
	 * This is used both when selecting words, and when requiring search to find whole words.
	 * 
	 * @param ch the character
	 * @return true if the character is part of a word
	 */
	public static boolean isWordChar(char ch) {
		return Character.isLetterOrDigit(ch) || ch == '_' || ch == '-' || ch == '@';
	}

	/**
	 * Find the boundaries for the word at the given column
	 * 
	 * @param x the column, 0 up
	 * @param forward true to find the end, false to find the beginning
	 * @return the first column, 0 up, or the last column, exclusive, 0 up
	 */
	public int findWord(int x, boolean forward) {
		int step = forward ? 1 : -1;
		for (int i = x; i < len && i >= 0; i += step) {
			char ch = chars[i];
			if (isWordChar(ch)) {
				continue;
			}
			if (forward) {
				return i;
			}
			return i + 1;
		}
		if (forward) {
			return len;
		}
		return 0;
	}
}
