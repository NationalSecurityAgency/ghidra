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
package util;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.FixedSizeStack;

/**
 * An object meant to track items with the ability to go back and forth within the list of
 * items.
 * 
 * <p>By default, duplicate entries are not allowed.  This allows for a simplified history of
 * unique items.  If the client prefers to have an accurate history, then call
 * {@link #setAllowDuplicates(boolean)} in order to keep all history entries.
 * 
 * <p>By default, null values are not allowed.  If the client allows null/empty values, then
 * they should call {@link #setAllowNulls(boolean)} with a value of true.  This allows the
 * backward navigation to work correctly when the client's active item is cleared.  When that 
 * item is cleared, then client is expected to call {@link #add(Object)} with value of 
 * null.  (This is safe to do, regardless of whether null are allowed).  When nulls are allowed
 * and a null value is received, then current item is placed onto the history stack as the 
 * previous item.  This way, when the user presses the back button, the last visible item 
 * will be activated.  
 * 
 * <p>Note: when nulls are allowed, only a single null value will be stored.  Further, 
 * if new, non-null items are added, then the null value is dropped.  
 * 
 *
 * @param <T> the type of items in the list
 */
public class HistoryList<T> {

	private final FixedSizeStack<T> historyStack;
	private final BiConsumer<T, T> itemSelectedCallback;
	private int historyIndex;
	private boolean isBroadcasting;

	private boolean allowDuplicates;
	private boolean allowsNulls;

	/**
	 * The sized passed here limits the size of the list, with the oldest items being dropped
	 * as the list grows.  The given callback will be called when {@link #goBack()} or 
	 * {@link #goForward()} are called.
	 * 
	 * @param size the max number of items to keep in the list
	 * @param itemSelectedCallback the function to call when the client selects an item by 
	 *        going back or forward
	 */
	public HistoryList(int size, Consumer<T> itemSelectedCallback) {
		this(size, asBiConsumer(itemSelectedCallback));
	}

	/**
	 * The sized passed here limits the size of the list, with the oldest items being dropped
	 * as the list grows.  The given callback will be called when {@link #goBack()} or 
	 * {@link #goForward()} are called.
	 * 
	 * @param size the max number of items to keep in the list
	 * @param itemSelectedCallback the function to call when the client selects an item by 
	 *        going back or forward.  This callback will be passed the newly selected item as 
	 *        the first argument and the previously selected item as the second argument.
	 */
	public HistoryList(int size, BiConsumer<T, T> itemSelectedCallback) {
		Objects.requireNonNull(itemSelectedCallback, "Item selected callback cannot be null");

		if (size < 1) {
			throw new IllegalArgumentException("Size cannot be less than 1");
		}

		this.itemSelectedCallback = itemSelectedCallback;
		this.historyStack = new FixedSizeStack<>(size);
	}

	private static <T> BiConsumer<T, T> asBiConsumer(Consumer<T> consumer) {
		return (t, ignored) -> consumer.accept(t);
	}

//==================================================================================================
// Interface Methods
//==================================================================================================	

	/**
	 * True signals that this list will allow duplicate entries.  False signals to not only not
	 * allow duplicates, but to also move the position of an item if it is re-added to the 
	 * list.
	 *   
	 * <p>For correct behavior when not allowing duplicates, ensure you have defined an 
	 * <code>equals</code> method to work as you expect.  If two different items are considered
	 * equal, then this class will only remove the duplicate if the equals method returns true.
	 * 
	 * <p>The default is false
	 * 
	 * @param allowDuplicates true to allow duplicates
	 */
	public void setAllowDuplicates(boolean allowDuplicates) {
		this.allowDuplicates = allowDuplicates;
	}

	/**
	 * True signals that the client allows null items to be used.  When this is true, a null
	 * value will be stored in this list <b>only as the last item</b>.  See the javadoc for 
	 * more info.
	 * 
	 * @param allowNulls true to allow nulls; the default is false
	 */
	public void setAllowNulls(boolean allowNulls) {
		this.allowsNulls = allowNulls;
	}

	/**
	 * Adds an item to this history list.  <code>null</code> values are ignored.
	 * 
	 * <p>Calls to this method during selection notification will have no effect.  If you need
	 * to update the history during a notification, then you must do so at a later time, perhaps
	 * by using  {@link SystemUtilities#runSwingLater(Runnable)}.
	 * 
	 * @param t the item to add.
	 */
	public void add(T t) {

		if (isBroadcasting) {
			return;
		}

		if (ignoreItem(t)) {
			return;
		}

		dropNull();

		// once we add a new item, any old history that was after this item needs to be
		// removed, as that is old alternate timeline that no longer makes sense
		trimHistoryToCurrentIndex();

		handleDuplicate(t);

		historyStack.push(t);

		// '- 1' because we want to be at the new item
		historyIndex = historyStack.size() - 1;
	}

	/**
	 * Returns true if this history list's current item pointer is not at the end of the list.
	 * 
	 * @return true if this history list's current item pointer is not at the end of the list.
	 */
	public boolean hasNext() {
		boolean hasNext = historyIndex < historyStack.size() - 1;
		return hasNext;
	}

	/**
	 * Returns true if this history list's current item pointer is not at the beginning of the list.
	 * 
	 * @return true if this history list's current item pointer is not at the beginning of the list.
	 */
	public boolean hasPrevious() {
		boolean hasPrevious = historyIndex > 0;
		return hasPrevious;
	}

	/**
	 * Moves this history list's current item pointer back one and then calls the user-provided
	 * callback to signal the newly selected item.
	 * 
	 * <p>No action is taken if the current pointer is already at the beginning of the list.
	 */
	public void goBack() {
		if (historyIndex == 0) {
			return;
		}

		T leaving = getCurrentHistoryItem();
		T t = historyStack.get(--historyIndex);
		dropNull();
		broadcast(t, leaving);
	}

	/**
	 * Performs a {@link #goBack()} until the given item becomes the current item.  This is 
	 * useful if you wish to go backward to a specific item in the list.
	 * 
	 * @param t the item
	 */
	public void goBackTo(T t) {
		while (!getCurrentHistoryItem().equals(t) && hasPrevious()) {
			goBack();
		}
	}

	/**
	 * Moves this history list's current item pointer forward one and then calls the user-provided
	 * callback to signal the newly selected item.
	 * 
	 * <p>No action is taken if the current pointer is already at the end of the list.
	 */
	public void goForward() {
		if (historyIndex >= historyStack.size() - 1) {
			return;
		}

		T leaving = getCurrentHistoryItem();
		T t = historyStack.get(++historyIndex);
		broadcast(t, leaving);
	}

	/**
	 * Performs a {@link #goForward()} until the given item becomes the current item.  This is 
	 * useful if you wish to go forward to a specific item in the list.
	 * 
	 * @param t the item
	 */
	public void goForwardTo(T t) {
		while (!getCurrentHistoryItem().equals(t) && hasNext()) {
			goForward();
		}
	}

	/**
	 * Returns the item currently pointed to within the list of items.  When an item is 
	 * added, this will be that item.  Otherwise, it will be the last item navigated.
	 * 
	 * @return the item currently pointed to within the list of items.
	 */
	public T getCurrentHistoryItem() {
		if (historyStack.isEmpty()) {
			return null;
		}
		return historyStack.get(historyIndex);
	}

	/**
	 * Get all items in the history that come before the current history item.  They are 
	 * returned in navigation order, as traversed if {@link #goBack()} is called.
	 * 
	 * @return the items
	 */
	public List<T> getPreviousHistoryItems() {

		List<T> list = new ArrayList<>();
		for (int i = historyIndex - 1; i >= 0; i--) {
			list.add(historyStack.get(i));
		}
		return list;
	}

	/**
	 * Get all items in the history that come after the current history item.  They are 
	 * returned in navigation order, as traversed if {@link #goForward()} is called.
	 * 
	 * @return the items
	 */
	public List<T> getNextHistoryItems() {

		List<T> list = new ArrayList<>();
		int nextIndex = historyIndex + 1;
		for (int i = nextIndex; i < historyStack.size(); i++) {
			list.add(historyStack.get(i));
		}
		return list;
	}

	/**
	 * Clears all history entries and resets the current item pointer.
	 */
	public void clear() {
		historyStack.clear();
		historyIndex = 0;
	}

	/**
	 * Returns the number of items in this history list
	 * 
	 * @return the number of items in this history list
	 */
	public int size() {
		return historyStack.size();
	}

//==================================================================================================
// Non-interface Methods
//==================================================================================================	

	private boolean ignoreItem(T t) {
		if (ignoreNull(t)) {
			return true;
		}

		if (t == null) {
			return false; // not ignoring null
		}

		if (t.equals(getCurrentHistoryItem())) {
			return true;
		}
		return false;
	}

	private boolean ignoreNull(T t) {
		if (t != null) {
			return false;
		}

		if (!allowsNulls) {
			return true;
		}

		if (!isAtEnd()) {
			// null values can only go at the end (see javadoc)
			return true;
		}

		if (historyStack.peek() == null) {
			// no repeated nulls
			return true;
		}

		return false;
	}

	private void dropNull() {
		if (historyStack.peek() == null) {
			historyStack.pop();
		}
	}

	private boolean isAtEnd() {
		return historyIndex == historyStack.size() - 1;
	}

	/* package for testing */ FixedSizeStack<T> getHistoryStack() {
		return historyStack;
	}

	private void handleDuplicate(T t) {
		if (allowDuplicates) {
			return;
		}

		int itemIndex = historyStack.search(t);
		if (itemIndex == -1) {
			return;
		}
		historyStack.remove(itemIndex);
	}

	private void broadcast(T t, T leaving) {
		try {
			isBroadcasting = true;
			itemSelectedCallback.accept(t, leaving);
		}
		finally {
			isBroadcasting = false;
		}
	}

	private void trimHistoryToCurrentIndex() {
		int upcomingIndex = historyIndex + 1; // this is the index value for the pending update
		while (historyStack.size() > upcomingIndex) {
			historyStack.pop();
		}
	}

	@Override
	public String toString() {

		String key = "    items: ";
		String newlinePad = StringUtils.repeat(' ', key.length());

		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < historyStack.size(); i++) {
			T t = historyStack.get(i);
			if (t == null) {
				continue; // the last item is permitted to be null
			}

			if (i == historyIndex) {
				buffy.append('[').append(t.toString()).append(']');
			}
			else {
				buffy.append(t.toString());
			}

			if (i != historyStack.size() - 1) {
				buffy.append(',').append('\n').append(newlinePad);
			}
		}

		//@formatter:off
		return "{\n" +
			key + buffy.toString() + "\n" + 
		"}";
		//@formatter:on				
	}
}
