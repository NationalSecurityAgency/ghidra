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

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.util.Swing;

public class FindDialogTest {

	@Test
	public void testSetSelectedValueDoesNotTriggerMatch() {
		FindDialogSearcher searcher = new DummySearcher();
		FindDialog findDialog = new FindDialog("Title", searcher);
		findDialog.setHistory(List.of("search1"));

		String searchText = "search"; // a prefix of an existing history entry
		Swing.runNow(() -> findDialog.setSearchText(searchText));
		assertEquals(searchText, Swing.runNow(() -> findDialog.getSearchText()));
	}

	private class DummySearcher implements FindDialogSearcher {

		@Override
		public CursorPosition getCursorPosition() {
			return new CursorPosition(0);
		}

		@Override
		public void setCursorPosition(CursorPosition position) {
			// stub
		}

		@Override
		public CursorPosition getStart() {
			return new CursorPosition(0);
		}

		@Override
		public CursorPosition getEnd() {
			return new CursorPosition(1);
		}

		@Override
		public void highlightSearchResults(SearchLocation location) {
			// stub
		}

		@Override
		public SearchLocation search(String text, CursorPosition cursorPosition,
				boolean searchForward, boolean useRegex) {
			return null;
		}

	}
}
