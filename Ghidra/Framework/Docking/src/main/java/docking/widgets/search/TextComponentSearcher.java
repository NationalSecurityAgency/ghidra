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

import java.awt.TextComponent;
import java.util.TreeMap;
import java.util.regex.*;

import javax.swing.JEditorPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import docking.widgets.CursorPosition;
import docking.widgets.SearchLocation;
import ghidra.util.Msg;
import ghidra.util.UserSearchUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import ghidra.util.worker.Worker;

/**
 * A class to find text matches in the given {@link TextComponent}.  This class will search for all
 * matches and cache the results for future requests when the user presses Next or Previous.  All
 * matches will be highlighted in the text component.  The match containing the cursor will be a 
 * different highlight color than the others.  When the find dialog is closed, all highlights are
 * removed.
 * <p>
 * If {@link #searchAll(String, boolean)} is called, then the search results will not be cached, as 
 * they are when {@link #search(String, CursorPosition, boolean, boolean)} is used.  The expectation
 * is that clients will cache the search results themselves.
 */
public class TextComponentSearcher implements FindDialogSearcher {

	static final int MAX_CONTEXT_CHARS = 100;
	private int maxContextChars = MAX_CONTEXT_CHARS;

	protected JEditorPane editorPane;

	private Worker worker = Worker.createGuiWorker();
	private TextComponentSearchResults searchResults;

	public TextComponentSearcher(JEditorPane editorPane) {
		this.editorPane = editorPane;
	}

	public void setEditorPane(JEditorPane editorPane) {
		if (this.editorPane != editorPane) {
			if (searchResults != null) {
				searchResults.dispose();
				searchResults = null;
			}
		}
		this.editorPane = editorPane;
	}

	public JEditorPane getEditorPane() {
		return editorPane;
	}

	void setMaxContextChars(int max) {
		this.maxContextChars = max;
	}

	public boolean isBusy() {
		return worker.isBusy();
	}

	@Override
	public void dispose() {

		if (searchResults != null) {
			searchResults.dispose();
			searchResults = null;
		}
	}

	public boolean hasSearchResults() {
		return searchResults != null && !searchResults.isEmpty();
	}

	public boolean isStale() {
		return searchResults != null && searchResults.isStale();
	}

	@Override
	public CursorPosition getCursorPosition() {
		int pos = editorPane.getCaretPosition();
		return new CursorPosition(pos);
	}

	@Override
	public CursorPosition getStart() {
		return new CursorPosition(0);
	}

	@Override
	public CursorPosition getEnd() {
		int length = editorPane.getDocument().getLength();
		return new CursorPosition(length - 1);
	}

	@Override
	public TextComponentSearchResults searchAll(String text, boolean useRegex) {
		return doSearch(text, useRegex);
	}

	@Override
	public SearchResults search(String text, CursorPosition cursorPosition,
			boolean searchForward, boolean useRegex) {

		updateSearchResults(text, useRegex);

		int pos = cursorPosition.getPosition();
		int searchStart = getSearchStart(pos, searchForward);
		if (searchStart == -1) {
			return null; // signal no more matches in the current direction
		}

		TextComponentSearchLocation location =
			searchResults.getNextLocation(searchStart, searchForward);
		if (location == null) {
			return null;
		}

		searchResults.setActiveLocation(location);
		return searchResults;
	}

	private void updateSearchResults(String text, boolean useRegex) {
		if (searchResults != null) {
			if (!searchResults.isInvalid(text)) {

				// the current results are still valid; ensure the highlights are still active
				searchResults.activate();
				return;
			}

			searchResults.dispose();
			searchResults = null;
		}

		searchResults = doSearch(text, useRegex);
	}

	private TextComponentSearchResults doSearch(String text, boolean useRegex) {
		SearchTask searchTask = new SearchTask(text, useRegex);
		TaskLauncher.launch(searchTask);

		TextComponentSearchResults newSearchResults = searchTask.doCreateSearchResults();
		newSearchResults.activate();
		return newSearchResults;
	}

	private int getSearchStart(int startPosition, boolean isForward) {

		SearchLocation location = searchResults.getActiveLocation();
		if (location == null) {
			return startPosition;
		}

		int lastMatchStart = location.getStartIndexInclusive();
		if (startPosition != lastMatchStart) {
			return startPosition;
		}

		// Always prefer the caret position, unless it aligns with the previous match.  By
		// moving it forward one we will continue our search, as opposed to always matching
		// the same hit.
		if (isForward) {
			int next = startPosition + 1;
			int end = editorPane.getText().length();
			if (next == end) {
				return -1; // signal no more hits in this direction
			}
			return next;
		}

		// backwards
		if (startPosition == 0) {
			return -1; // signal no more hits in this direction 
		}
		return startPosition - 1;
	}

	protected TextComponentSearchResults createSearchResults(
			Worker theWorker, JEditorPane editor, String searchText,
			TreeMap<Integer, TextComponentSearchLocation> matchesByPosition) {
		return new TextComponentSearchResults(theWorker, editor, searchText, matchesByPosition);
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class SearchTask extends Task {

		private String searchText;
		private TreeMap<Integer, TextComponentSearchLocation> matchesByPosition = new TreeMap<>();
		private boolean useRegex;

		SearchTask(String searchText, boolean useRegex) {
			super("Text Find Task", true, false, true, true);
			this.searchText = searchText;
			this.useRegex = useRegex;
		}

		TextComponentSearchResults doCreateSearchResults() {
			return createSearchResults(worker, editorPane, searchText, matchesByPosition);
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			Document document;
			String fullText;
			try {
				document = editorPane.getDocument();
				fullText = document.getText(0, document.getLength());
			}
			catch (BadLocationException e) {
				Msg.error(this, "Unable to get text for user find operation", e);
				return;
			}

			TreeMap<Integer, Line> lineRangeMap = mapLines(fullText);

			Pattern pattern = createSearchPattern(searchText, useRegex);
			Matcher matcher = pattern.matcher(fullText);
			while (matcher.find()) {
				monitor.checkCancelled();
				int start = matcher.start();
				int end = matcher.end();
				Line line = lineRangeMap.floorEntry(start).getValue();

				String matchText = fullText.substring(start, end);
				SearchLocationContext context = createContext(line, start, end);
				TextComponentSearchLocation location =
					new TextComponentSearchLocation(matchText, start, end - 1, line.lineNumber(),
						context);
				matchesByPosition.put(start, location);
			}

		}

		private TreeMap<Integer, Line> mapLines(String fullText) {
			TreeMap<Integer, Line> linesRangeMap = new TreeMap<>();
			int lineNumber = 0;
			int pos = 0;
			String[] lines = fullText.split("\\n");
			for (String line : lines) {
				lineNumber++;
				linesRangeMap.put(pos, new Line(line, lineNumber, pos));
				pos += line.length() + 1; // +1 for newline
			}
			return linesRangeMap;
		}

		private SearchLocationContext createContext(Line line, int start, int end) {
			SearchLocationContextBuilder builder = new SearchLocationContextBuilder();
			String text = line.text();
			int offset = line.offset(); // document offset
			int rstart = start - offset; // line-relative start
			int rend = end - offset; // line-relative end
			int lineStart = 0;
			int lineEnd = text.length();

			int length = text.length();
			int max = maxContextChars;
			if (length > max) {
				// HTML content can have very long lines, since it doesn't use newline characters to
				// break text.  We just want to show some context, so we don't need all characters.
				// When the text is too long, just grab some surrounding text for the context.
				int matchLength = end - start;
				int remaining = max - matchLength;
				int half = remaining / 2;
				int firstHalf = rstart; // from 0 to match start
				int available = Math.min(half, firstHalf);
				int newStart = rstart - available;

				available = max - (available + matchLength);
				int newEnd = Math.min(length, rend + available);

				lineStart = newStart;
				lineEnd = newEnd;
			}

			if (lineStart != 0) {
				builder.append("...");
			}

			builder.append(text.substring(lineStart, rstart));
			builder.appendMatch(text.substring(rstart, rend));
			if (rend < text.length()) {
				builder.append(text.substring(rend, lineEnd));
			}

			if (lineEnd < text.length()) {
				builder.append("...");
			}

			return builder.build();
		}

		private Pattern createSearchPattern(String searchString, boolean isRegex) {

			int options = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;
			if (isRegex) {
				try {
					return Pattern.compile(searchString, options);
				}
				catch (PatternSyntaxException e) {
					Msg.showError(this, editorPane, "Regular Expression Syntax Error",
						e.getMessage());
					return null;
				}
			}

			return UserSearchUtils.createPattern(searchString, false, options);
		}

		record Line(String text, int lineNumber, int offset) {

		}
	}

}
