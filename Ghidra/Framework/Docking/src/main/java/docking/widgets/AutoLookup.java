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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.function.Predicate;

import org.apache.commons.lang3.StringUtils;

/**
 * A class that holds the logic and state for finding matching rows in a widget when a user types
 * in the widget.   This class was designed for row-based widgets, such as tables and lists.
 */
public abstract class AutoLookup {

	public static final long KEY_TYPING_TIMEOUT = 800;
	private static final int MAX_SEARCH_ROWS = 50000;

	private long keyTimeout = KEY_TYPING_TIMEOUT;
	private Predicate<Long> keyTimeoutPredicate = elapsedTime -> elapsedTime > keyTimeout;

	private AutoLookupItem lastLookup;

	private int lookupColumn = 0;

	/**
	 * Returns the currently selected row
	 * @return the row
	 */
	public abstract int getCurrentRow();

	/**
	 * Returns the total number of rows
	 * @return the row count
	 */
	public abstract int getRowCount();

	/**
	 * Returns a string representation of the item at the given row and column.  The text 
	 * should match what the user sees.
	 * 
	 * @param row the row
	 * @param col the column
	 * @return the text
	 */
	public abstract String getValueString(int row, int col);

	/**
	 * Returns true if the given column is sorted.  This class will use a binary search if the
	 * given column is sorted.  Otherwise, a brute-force search will be used.
	 * 
	 * @param column the column 
	 * @return true if sorted
	 */
	public abstract boolean isSorted(int column);

	/**
	 * A method that subclasses can override to affect whether this class uses a binary search
	 * for a particular column
	 * @param column the column
	 * @return true if the binary search algorithm will work on the given column
	 */
	protected boolean canBinarySearchColumn(int column) {
		return isSorted(column);
	}

	/**
	 * Returns true if the currently sorted column is sorted ascending.  This is used in 
	 * conjunction with {@link #isSorted(int)}.  If that method returns false, then this method
	 * will not be called. 
	 * 
	 * @return true if sorted ascending
	 */
	public abstract boolean isSortedAscending();

	/**
	 * This method will be called when a match for the call to {@link #keyTyped(KeyEvent)} is 
	 * found
	 * 
	 * @param row the matching row
	 */
	public abstract void matchFound(int row);

	/**
	 * Sets the delay between keystrokes after which each keystroke is considered a new lookup
	 * @param timeout the timeout
	 */
	public void setTimeout(long timeout) {
		keyTimeout = timeout;
		lastLookup = null;
	}

	/**
	 * Sets the column that is searched when a lookup is performed
	 * @param column the column
	 */
	public void setColumn(int column) {
		this.lookupColumn = column;
		lastLookup = null;
	}

	/**
	 * Sets the logic for deciding whether the elapsed time between keystrokes is enough to
	 * trigger a new auto lookup or to continue with the previous match.
	 * 
	 * <p>This method is intended for tests that need precise control over the timeout mechanism.
	 * 
	 * 
	 * @param p the predicate that takes the amount of elapsed time
	 * @see #setTimeout(long)
	 */
	public void setTimeoutPredicate(Predicate<Long> p) {
		this.keyTimeoutPredicate = p;
	}

	/**
	 * Clients call this method when the user types keys
	 * 
	 * @param e the key event
	 */
	public void keyTyped(KeyEvent e) {
		if (getRowCount() == 0) {
			return;
		}

		AutoLookupItem lookup = lastLookup;
		if (lookup == null) {
			lookup = new AutoLookupItem();
		}

		lookup.keyTyped(e);
		if (lookup.shouldSkip()) {
			return;
		}

		int row = lookupText(lookup.getText());
		lookup.setFoundMatch(row >= 0);

		if (row >= 0) {
			matchFound(row);
		}

		lastLookup = lookup;
	}

	private int lookupText(String text) {
		if (text == null) {
			return -1;
		}

		int row = getCurrentRow();
		if (row >= 0 && row < getRowCount() - 1) {
			if (text.length() == 1) {
				// fresh search; ignore the current row, could be from a previous match
				++row;
			}

			int col = lookupColumn;
			if (textMatches(text, row, col)) {
				return row;
			}
		}

		if (canBinarySearchColumn(lookupColumn)) {
			return autoLookupBinary(text);
		}
		return autoLookupLinear(text);
	}

	private boolean textMatches(String text, int row, int col) {
		String value = getValueString(row, col);
		return StringUtils.startsWithIgnoreCase(value, text);
	}

	private boolean isIgnorableKeyEvent(KeyEvent event) {

		// ignore modified keys, except for SHIFT
		if (!isUnmodifiedOrShift(event.getModifiersEx())) {
			return true;
		}

		if (event.isActionKey() || event.getKeyChar() == KeyEvent.CHAR_UNDEFINED ||
			Character.isISOControl(event.getKeyChar())) {
			return true;
		}

		return false;
	}

	private boolean isUnmodifiedOrShift(int modifiers) {
		if (modifiers == 0) {
			return true;
		}

		int shift = InputEvent.SHIFT_DOWN_MASK;
		return (modifiers | shift) != shift;
	}

	private int autoLookupLinear(String text) {
		int max = MAX_SEARCH_ROWS;
		int rows = getRowCount();
		int start = getCurrentRow();
		int counter = 0;
		int col = lookupColumn;

		// first search from the current row until the last row
		for (int i = start + 1; i < rows && counter < max; i++, counter++) {
			if (textMatches(text, i, col)) {
				return i;
			}
		}

		// then wrap the search to be from the beginning to the current row
		for (int i = 0; i < start && counter < max; i++, counter++) {
			if (textMatches(text, i, col)) {
				return i;
			}
		}
		return -1;
	}

	private int autoLookupBinary(String text) {

		int index = binarySearch(text);
		int col = lookupColumn;
		if (textMatches(text, index, col)) {
			return index;
		}
		if (index - 1 >= 0) {
			if (textMatches(text, index - 1, col)) {
				return index - 1;
			}
		}
		if (index + 1 < getRowCount()) {
			if (textMatches(text, index + 1, col)) {
				return index + 1;
			}
		}

		return -1;
	}

	private int binarySearch(String text) {

		int sortedOrder = 1;

		// if sorted descending, then reverse the search direction and change the lookup text to 
		// so that a match will come after the range we seek, which is before the desired text
		// when sorted in reverse
		if (!isSortedAscending()) {
			sortedOrder = -1;
			int lastPos = text.length() - 1;
			char lastChar = text.charAt(lastPos);
			++lastChar;
			text = text.substring(0, lastPos) + lastChar;
		}

		int min = 0;
		int rows = getRowCount();
		int max = rows - 1;
		int col = lookupColumn;
		while (min < max) {

			// divide by 2; preserve the sign to prevent possible overflow issue
			int mid = (min + max) >>> 1;
			String value = getValueString(mid, col);
			int compare = text.compareToIgnoreCase(value);
			compare *= sortedOrder;

			if (compare < 0) {
				max = mid - 1;
			}
			else if (compare > 0) {
				min = mid + 1;
			}
			else { // exact match
				return mid;
			}
		}

		return min;
	}

	private class AutoLookupItem {
		private long lastTime;
		private String text;
		private boolean foundPreviousMatch;
		private boolean skip;

		void keyTyped(KeyEvent e) {
			skip = false;

			if (isIgnorableKeyEvent(e)) {
				skip = true;
				return;
			}

			String eventChar = Character.toString(e.getKeyChar());
			long when = e.getWhen();
			long elapsed = when - lastTime;
			boolean didTimeout = keyTimeoutPredicate.test(elapsed);
			if (didTimeout) {
				text = eventChar;
			}
			else {
				text += eventChar;

				if (!foundPreviousMatch) {
					// The given character is being added to the previous search.  If that search
					// was fruitless, then so too will be this one, since we use a 
					// 'starts with' match.
					skip = true;
					when = lastTime;  // don't save time if no match found; trigger a timeout
				}
			}

			lastTime = when;
		}

		void setFoundMatch(boolean foundMatch) {
			foundPreviousMatch = foundMatch;
		}

		String getText() {
			return text;
		}

		boolean shouldSkip() {
			return skip;
		}
	}
}
