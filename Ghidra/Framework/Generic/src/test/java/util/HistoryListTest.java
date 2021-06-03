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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import org.junit.Test;

import ghidra.util.datastruct.FixedSizeStack;

public class HistoryListTest {

	private static final String A = "A";
	private static final String B = "B";
	private static final String C = "C";
	private static final String D = "D";
	private static final String E = "E";

	private LinkedList<String> selectedItems = new LinkedList<>();
	private Consumer<String> callback = s -> {
		selectedItems.add(s);
	};
	private HistoryList<String> historyList = new HistoryList<>(10, callback);

	@Test
	public void testBasicNavigation() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		addHistory(D);

		assertHistory(A, B, C, D);

		goBack();
		assertNotified(C);
		goBack();
		assertNotified(B);
		goBack();
		assertNotified(A);
		assertHistory(A, B, C, D);

		assertCannotGoBack();

		goForward();
		assertNotified(B);
		goForward();
		assertNotified(C);
		goForward();
		assertNotified(D);

		assertCannotGoForward();

		// All original history remains throughout navigation
		assertHistory(A, B, C, D);
	}

	@Test
	public void testAddingNewItem_AtBeginningOfStack() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		addHistory(D);

		goBack();
		assertNotified(C);
		goBack();
		assertNotified(B);
		goBack();
		assertNotified(A);

		assertCannotGoBack();
		assertCanGoForward();

		addHistory(E);

		assertCanGoBack();
		assertCannotGoForward();

		// Once E is addHistoryed, the previous forward history (B,C,D) is truncated
		assertHistory(A, E);
	}

	@Test
	public void testAddingNewItem_AtMiddleOfStack() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		addHistory(D);

		goBack();
		assertNotified(C);

		assertCanGoBack();
		assertCanGoForward();

		addHistory(E);

		assertCanGoBack();
		assertCannotGoForward();

		// Once E is addHistoryed, the previous forward history (D) is truncated
		assertHistory(A, B, C, E);
	}

	@Test
	public void testAddingDuringCallbackDoesNothing() {

		historyList = new HistoryList<>(10, s -> {
			// default behavior for the test
			selectedItems.add(s);

			// this should have no effect; the history list should ignore it
			addHistory(E);
		});

		addHistory(A);
		addHistory(B);
		addHistory(C);
		addHistory(D);

		assertHistory(A, B, C, D);

		goBack();
		assertNotified(C);
		goBack();
		assertNotified(B);
		goBack();
		assertNotified(A);
		assertHistory(A, B, C, D);

		assertCannotGoBack();
	}

	@Test
	public void testNavigationMixedWithHistoryAddition() {
		// 
		// Test that we can navigate and then add items to history, correctly updating the list.
		//

		addHistory(A);
		addHistory(B);
		assertHistory(A, B);

		goBack();
		assertHistory(A, B);

		addHistory(C);
		assertHistory(A, C); // B was lost due to the new, alternate future

		addHistory(A);

		// Since we don't allow duplicates, A gets moved
		assertHistory(C, A);
	}

	@Test
	public void testNull_NullNotAllowed() {

		// Note: null is not allowed by default

		addHistory(A);
		addHistory(null);
		assertHistory(A);

		addHistory(null);
		assertHistory(A);
	}

	@Test
	public void testNull_NullAllowed() {

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(null);
		assertHistory(A, null);

		addHistory(null);
		assertHistory(A, null); // null not repeated
	}

	@Test
	public void testNull_WhenEmpty() {

		historyList.setAllowNulls(true);
		addHistory(null);
		assertHistory();
	}

	@Test
	public void testNull_GoBack() {

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(null);
		assertHistory(A, null);

		addHistory(B);
		assertHistory(A, B); // null removed

		addHistory(null);
		assertHistory(A, B, null);
	}

	@Test
	public void testNull_GoBack_GoForward() {

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(B);
		addHistory(null);
		assertHistory(A, B, null);

		goBack();
		assertNotified(B);
		assertHistory(A, B); // null removed

		assertCannotGoForward();

		addHistory(null);
		assertHistory(A, B, null);
		assertCannotGoForward();
		assertCanGoBack(); // can now go back to B after adding null
	}

	@Test
	public void testNull_GetCurrentHistoryItem() {

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(B);
		addHistory(null);
		assertHistory(A, B, null);
		assertNotified(null);
	}

	@Test
	public void testNull_GetPreviousHistoryItems() {

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(B);
		addHistory(null);
		assertPreviousItems(B, A);
	}

	@Test
	public void testNull_GetNextHistoryItems() {

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(B);
		addHistory(null);
		assertNextItems();

		goBack();
		goBack();
		assertNotified(A);
		assertNextItems(B); // no null
	}

	@Test
	public void testRepeatedAdds_DoesntAddSameItemTwice() {

		addHistory(A);
		addHistory(B);
		assertHistory(A, B);

		addHistory(B);
		assertHistory(A, B);
	}

	@Test
	public void testRepeatedAdds_DontAllowDuplicates_IndexGetsChanged() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		assertHistory(A, B, C);

		addHistory(A);

		// Since we don't allow duplicates, A gets moved
		assertHistory(B, C, A);
	}

	@Test
	public void testRepeatedAdds_AllowDuplicates_ItemGetsAdded() {

		historyList.setAllowDuplicates(true);

		addHistory(A);
		addHistory(B);
		addHistory(C);
		assertHistory(A, B, C);

		addHistory(A);

		// Since we don't allow duplicates, A gets moved
		assertHistory(A, B, C, A);
	}

	@Test
	public void testRepeatedAdds_WhenInMiddleOfHistory_NoChanges() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		assertHistory(A, B, C);

		goBack();
		assertHistory(A, B, C);
		assertNotified(B);

		addHistory(B);
		assertHistory(A, B, C); // no change
		assertNotified(B);   // no change
	}

	@Test
	public void test_AddHistory_AddNull_AddHistory_DoesntAddSameItemTwice_NullNotAllowed() {
		// 
		// Simulate a navigate, an update with no item (by using null), and then re-select
		// the last selected item again--it should not be double-added.
		//

		addHistory(A);
		addHistory(B);
		assertHistory(A, B);

		addHistory(B);
		assertHistory(A, B);

		addHistory(null);
		assertHistory(A, B);

		addHistory(B);
		assertHistory(A, B);
	}

	@Test
	public void test_AddHistory_AddNull_AddHistory_DoesntAddSameItemTwice_NullAllowed() {
		// 
		// Simulate a navigate, an update with no item (by using null), and then re-select
		// the last selected item again--it should not be double-added.
		//

		historyList.setAllowNulls(true);
		addHistory(A);
		addHistory(B);
		assertHistory(A, B);

		addHistory(B);
		assertHistory(A, B);

		addHistory(null);
		assertHistory(A, B, null);

		addHistory(B);
		assertHistory(A, B);
	}

	@Test
	public void testGetPreviousAndNextHistoryItems() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		addHistory(D);

		assertCannotGoForward();
		assertCurrentItem(D);
		assertPreviousItems(C, B, A);
		assertNextItems();

		goBack();
		assertCurrentItem(C);
		assertPreviousItems(B, A);
		assertNextItems(D);

		goBack();
		assertCurrentItem(B);
		assertPreviousItems(A);
		assertNextItems(C, D);

		goBack();
		assertCurrentItem(A);
		assertPreviousItems();
		assertNextItems(B, C, D);

		goForward();
		assertCurrentItem(B);
		assertPreviousItems(A);
		assertNextItems(C, D);

		goForward();
		assertCurrentItem(C);
		assertPreviousItems(B, A);
		assertNextItems(D);

		goForward();
		assertCannotGoForward();
		assertCurrentItem(D);
		assertPreviousItems(C, B, A);
		assertNextItems();
	}

	@Test
	public void testBackToItem() {

		addHistory(A);
		addHistory(B);
		addHistory(C);

		historyList.goBackTo(A);
		assertCurrentItem(A);
	}

	@Test
	public void testForwardToItem() {

		addHistory(A);
		addHistory(B);
		addHistory(C);
		goBack();
		goBack();
		goBack();
		assertCurrentItem(A);

		historyList.goForwardTo(C);
		assertCurrentItem(C);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertCurrentItem(String item) {
		assertThat("History list is not pointing to the expected item", item,
			is(historyList.getCurrentHistoryItem()));
	}

	private void assertNotified(String item) {
		assertEquals("History list did not broadcast expected item", item,
			selectedItems.peekLast());
	}

	private void assertCanGoBack() {
		assertTrue("History list should not have been all the way to the " +
			"front of the list - list: " + debugList(), historyList.hasPrevious());
	}

	private void assertCanGoForward() {
		assertTrue("History list should not have been all the way to the " +
			"end of the list - list: " + debugList(), historyList.hasNext());
	}

	private void assertCannotGoForward() {
		assertFalse("History list should have been all the way to the end of the list - list: " +
			debugList(), historyList.hasNext());
	}

	private void assertCannotGoBack() {
		assertFalse("History list should have been all the way to the front of the list - list: " +
			debugList(), historyList.hasPrevious());
	}

	private String debugList() {
		return historyList.toString();
	}

	private void goForward() {
		historyList.goForward();
	}

	private void goBack() {
		historyList.goBack();
	}

	private void addHistory(String item) {
		historyList.add(item);
	}

	private void assertHistory(String... names) {

		FixedSizeStack<String> stack = historyList.getHistoryStack();
		assertEquals(names.length, stack.size());
		for (int i = 0; i < stack.size(); i++) {
			assertEquals("Unexpected item in history", names[i], stack.get(i));
		}
	}

	private void assertPreviousItems(String... names) {
		List<String> items = historyList.getPreviousHistoryItems();
		assertEquals(names.length, items.size());
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], items.get(i));
		}
	}

	private void assertNextItems(String... names) {
		List<String> items = historyList.getNextHistoryItems();
		assertEquals(names.length, items.size());
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], items.get(i));
		}
	}
}
