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
package docking.widgets.search;

import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.text.Highlighter.Highlight;
import javax.swing.text.StyledDocument;

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.CursorPosition;
import docking.widgets.SearchLocation;
import ghidra.util.worker.Worker;

public class TextComponentSearcherTest extends AbstractDockingTest {

	private JTextPane textPane = new JTextPane();
	private TextComponentSearcher searcher = new TextComponentSearcher(textPane);

	private int lineCount = 0;
	private List<Line> expectedMatches = new ArrayList<>();

	@Before
	public void setUp() {

		JScrollPane scrollPane = new JScrollPane(textPane);

		JFrame frame = new JFrame("Find Dialog Test");
		frame.setSize(400, 400);
		frame.getContentPane().add(scrollPane);
		frame.setVisible(true);
		waitForSwing();
	}

	@Test
	public void testFindNextPrevious_ChangeDocument() throws Exception {

		// After changing the document, the results are stale and highlights should not work. But, 
		// the results should remain.

		createDocumenText();

		String searchText = "text";
		TextComponentSearchResults results = searchNext(searchText);
		assertFalse(isEmpty(results));
		assertValid(results, searchText);
		assertTrue(hasHighlights(results));

		add("More text in the document after the search");
		waitFor(results);
		assertInvalid(results, searchText);
		assertFalse(isEmpty(results));
		assertFalse(hasHighlights(results));

		// call search again and get new, valid results
		TextComponentSearchResults newResults = searchNext(searchText);
		assertNotEquals(results, newResults);
		assertFalse(isEmpty(newResults));
		assertValid(newResults, searchText);
		assertTrue(hasHighlights(newResults));
	}

	@Test
	public void testSearchAll_ChangeDocument() throws Exception {

		// After changing the document, the results are stale and highlights should not work. But, 
		// the results should remain.
		createDocumenText();

		String searchText = "text";
		TextComponentSearchResults results = searchAll(searchText);
		assertFalse(isEmpty(results));
		assertValid(results, searchText);
		assertTrue(hasHighlights(results));

		add("More text in the document after the search");
		waitFor(results);
		assertInvalid(results, searchText);
		assertFalse(isEmpty(results));
		assertFalse(hasHighlights(results));

		// call search again and get new, valid results
		TextComponentSearchResults newResults = searchAll(searchText);
		assertNotEquals(results, newResults);
		assertFalse(isEmpty(newResults));
		assertValid(newResults, searchText);
		assertTrue(hasHighlights(newResults));
	}

	@Test
	public void testSearchAll_ContextTruncation_EvenLimit() throws Exception {
		//
		// Test that the context generated for the search results gets correctly truncated.  We test
		// various boundary conditions
		//
		int max = 20;
		doTest(max);
	}

	@Test
	public void testSearchAll_ContextTruncation_OddLimit() throws Exception {
		int max = 21;
		doTest(max);
	}

	@Test
	public void testSearchAll_ManySearches_Activation() throws Exception {
		//
		// Test that we can activate and deactivate many search results rapidly and get the correct
		// behavior.  There is a worker queue managing activation requests.  We hope to ensure the
		// jobs are processed correctly.
		//
		createDocumenText();

		// text
		Map<String, SearchResults> allResults = new HashMap<>();
		SearchResults results = searchAll("text");
		allResults.put("text", results);

		// some
		results = searchAll("some");
		allResults.put("some", results);

		// leading
		results = searchAll("leading");
		allResults.put("leading", results);

		// trailing
		results = searchAll("trailing");
		allResults.put("trailing", results);

		Set<Entry<String, SearchResults>> entries = allResults.entrySet();
		for (Entry<String, SearchResults> entry : entries) {
			String searchText = entry.getKey();
			TextComponentSearchResults searchResults =
				(TextComponentSearchResults) entry.getValue();
			searchResults.activate();
			waitFor(searchResults);
			assertTrue("Search results did not activate '%s'".formatted(searchText),
				searchResults.isActive());
		}

		// Each call could possible cancel any activate request that has not finished.  The last 
		// request should be active.
		allResults.get("leading").activate();
		allResults.get("trailing").activate();
		allResults.get("leading").activate();
		allResults.get("text").activate();
		allResults.get("some").activate();

		String searchText = "some";
		TextComponentSearchResults lastResults =
			(TextComponentSearchResults) allResults.get(searchText);
		waitFor(lastResults);
		assertTrue("Search results did not activate '%s'".formatted(searchText),
			lastResults.isActive());
	}

	@Test
	public void testSearchAll_ManySearches_Disposal() throws Exception {
		//
		// Test that we can activate and deactivate many search results rapidly and get the correct
		// behavior.  There is a worker queue managing activation requests.  We hope to ensure the
		// jobs are processed correctly.
		//
		createDocumenText();

		TextComponentSearchResults results = searchAll("text");
		assertTrue(results.isActive());

		results.deactivate();
		assertInactive(results);

		results.activate();
		assertActive(results);

		runSwing(() -> results.dispose());
		assertInactive(results);

		// make sure active() does not work once disposed
		results.activate();
		assertDisposed(results);
	}

	private TextComponentSearchResults searchNext(String text) {
		CursorPosition cursor = new CursorPosition(0);
		SearchResults results = searcher.search(text, cursor, true, false);
		waitFor(results);
		return (TextComponentSearchResults) results;
	}

	private TextComponentSearchResults searchAll(String text) {
		TextComponentSearchResults results = searcher.searchAll(text, false);
		waitFor(results);
		return results;
	}

	private void waitFor(SearchResults results) {
		Worker worker = results.getWorker();
		waitFor(() -> !worker.isBusy());
	}

	private void doTest(int max) throws Exception {
		runSwing(() -> searcher.setMaxContextChars(max));

		String searchText = "gold";
		createDocumenText(searchText, max);

		SearchResults results = searchAll(searchText);
		assertMatches(results, max);
	}

	private void createDocumenText() throws Exception {
		createDocumenText("stuff", 20);
	}

	private void createDocumenText(String searchText, int max) throws Exception {
		add("No match on this line", false);

		add("%s", searchText);

		// non-truncated
		add("We found %s here", searchText);

		// truncated middle match
		add("This text will be (%s) truncated, since it is more than max", searchText);

		// truncated beginning match
		add("%s, this text will be truncated, since it is more than max", searchText);

		// truncated end match
		add("This text will be truncated, since it is more than max, %s", searchText);

		// truncated at beginning boundary
		int half = (max - searchText.length()) / 2; // 'half' of the available space; max includes search text
		add(padLeft(half, "%s with some trailing text that is quite long", searchText));
		add(padLeft(half - 1, "%s with some trailing text that is quite long", searchText));
		add(padLeft(half + 1, "%s with some trailing text that is quite long", searchText));

		// truncated at end boundary
		add(padRight(half, "this is some leading text that is quite long, %s", searchText));
		add(padRight(half - 1, "this is some leading text that is quite long, %s", searchText));
		add(padRight(half + 1, "this is some leading text that is quite long, %s", searchText));

		// truncated at beginning at ellipses
		add(padLeft(half, "%s with some trailing text that is quite long", searchText));
	}

	private void assertMatches(SearchResults results, int max) {

		List<SearchLocation> locations = results.getLocations();
		Map<Integer, SearchLocation> locationsByLine = locations.stream()
				.collect(Collectors.toMap(loc -> loc.getLineNumber(), Function.identity()));

		// Debug
//		Set<Entry<Integer, SearchLocation>> entries1 = locationsByLine.entrySet();
//		for (Entry<Integer, SearchLocation> entry : entries1) {
//			SearchLocation loc = entry.getValue();
//			Msg.debug(this, loc.getContext());
//		}

		for (Line line : expectedMatches) {
			int n = line.lineNumber();
			SearchLocation result = locationsByLine.remove(n);
			assertNotNull("No match at line: " + n, result);

			SearchLocationContext context = result.getContext();
			String text = context.getPlainText();
			int length = text.length();
			int maxWithEllipses = max + 6; // ... text ...
			assertTrue("Length is to long.  Expected max %s, but found %s"
					.formatted(maxWithEllipses, length),
				length <= maxWithEllipses);
		}

		if (!locationsByLine.isEmpty()) {

			StringBuilder sb = new StringBuilder();
			sb.append("Found more search results than expected:").append('\n');

			Set<Entry<Integer, SearchLocation>> entries = locationsByLine.entrySet();
			for (Entry<Integer, SearchLocation> entry : entries) {
				SearchLocation loc = entry.getValue();
				sb.append(loc.toString()).append('\n');
			}

			fail(sb.toString());
		}
	}

	private void assertValid(TextComponentSearchResults results, String searchText) {
		boolean invalid = runSwing(() -> results.isInvalid(searchText));
		assertFalse(invalid);
	}

	private void assertInvalid(TextComponentSearchResults results, String searchText) {
		boolean invalid = runSwing(() -> results.isInvalid(searchText));
		assertTrue(invalid);
	}

	private boolean isEmpty(TextComponentSearchResults results) {
		return runSwing(() -> results.isEmpty());
	}

	private boolean hasHighlights(TextComponentSearchResults results) {
		Highlight[] highlights = runSwing(() -> results.getHighlights());
		return highlights.length > 0;
	}

	private void assertActive(TextComponentSearchResults results) {
		waitFor(results);
		assertTrue(results.isActive());
		Highlight[] highlights = runSwing(() -> results.getHighlights());
		List<SearchLocation> locations = results.getLocations();
		assertEquals(locations.size(), highlights.length);
	}

	private void assertInactive(TextComponentSearchResults results) {
		waitFor(results);
		assertFalse(results.isActive());
		Highlight[] highlights = runSwing(() -> results.getHighlights());
		assertEquals(0, highlights.length);
	}

	private void assertDisposed(TextComponentSearchResults results) {
		waitFor(results);
		assertFalse(results.isActive());
		Highlight[] highlights = runSwing(() -> results.getHighlights());
		assertEquals(0, highlights.length);
		List<SearchLocation> locations = results.getLocations();
		assertEquals(0, locations.size());
	}

	private String padLeft(int n, String s, String searchText) {
		s = s.formatted(searchText);
		String pad = StringUtils.repeat('@', n);
		return pad + s;
	}

	private String padRight(int n, String s, String searchText) {
		s = s.formatted(searchText);
		String pad = StringUtils.repeat('@', n);
		return s + pad;
	}

	private void add(String s) throws Exception {
		add(s, true);
	}

	private void add(String raw, String searchText) throws Exception {
		String s = raw;
		boolean hasMatch = searchText != null;
		if (hasMatch) {
			s = raw.formatted(searchText);
		}
		add(s, true);
	}

	private void add(String s, boolean hasMatch) throws Exception {

		runSwingWithException(() -> {
			StyledDocument sd = textPane.getStyledDocument();
			sd.insertString(sd.getLength(), s + '\n', null);
		});

		lineCount++;

		if (!hasMatch) {
			return;
		}

		Line line = new Line(s, lineCount);
		expectedMatches.add(line);
	}

	private record Line(String text, int lineNumber) {}
}
