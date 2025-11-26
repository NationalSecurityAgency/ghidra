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
package ghidra.app.plugin.core.decompile.actions;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.*;

import docking.widgets.CursorPosition;
import docking.widgets.SearchLocation;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import docking.widgets.search.*;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.util.Msg;
import ghidra.util.UserSearchUtils;
import ghidra.util.worker.Worker;

/**
 * A {@link FindDialogSearcher} for searching the text of the decompiler window.
 */
public class DecompilerSearcher implements FindDialogSearcher {

	private Worker worker = Worker.createGuiWorker();
	private DecompilerPanel decompilerPanel;
	private DecompilerSearchResults searchResults;

	/**
	 * Constructor
	 * @param decompilerPanel decompiler panel
	 */
	public DecompilerSearcher(DecompilerPanel decompilerPanel) {
		this.decompilerPanel = decompilerPanel;
	}

	@Override
	public CursorPosition getCursorPosition() {
		FieldLocation fieldLocation = decompilerPanel.getCursorPosition();
		return new DecompilerCursorPosition(fieldLocation);
	}

	@Override
	public CursorPosition getStart() {

		int lineNumber = 0;
		int fieldNumber = 0; // always 0, as the field is the entire line and it is the only field
		int column = 0; // or length for the end
		FieldLocation fieldLocation = new FieldLocation(lineNumber, fieldNumber, 0, column);
		return new DecompilerCursorPosition(fieldLocation);
	}

	@Override
	public CursorPosition getEnd() {

		List<Field> lines = decompilerPanel.getFields();
		int lineNumber = lines.size() - 1;
		ClangTextField textLine = (ClangTextField) lines.get(lineNumber);

		int fieldNumber = 0; // always 0, as the field is the entire line and it is the only field
		int rowCount = textLine.getNumRows();
		int row = rowCount - 1; // 0-based
		int column = textLine.getNumCols(row);
		FieldLocation fieldLocation = new FieldLocation(lineNumber, fieldNumber, row, column);
		return new DecompilerCursorPosition(fieldLocation);
	}

	@Override
	public void dispose() {
		decompilerPanel.setSearchResults(null);

		if (searchResults != null) {
			searchResults.dispose();
		}
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

	private DecompilerSearchResults doSearch(String searchText, boolean isRegex) {

		Pattern pattern = createPattern(searchText, isRegex);
		Function<String, SearchMatch> forwardMatcher = createForwardMatchFunction(pattern);
		FieldLocation start = new FieldLocation();

		List<SearchLocation> results = new ArrayList<>();
		DecompilerSearchLocation searchLocation = findNext(forwardMatcher, searchText, start);
		while (searchLocation != null) {
			results.add(searchLocation);

			FieldLocation last = searchLocation.getFieldLocation();
			int line = last.getIndex().intValue();
			int field = 0; // there is only 1 field
			int row = 0; // there is only 1 row 
			int col = last.getCol() + 1; // move over one char to handle sub-matches
			start = new FieldLocation(line, field, row, col);
			searchLocation = findNext(forwardMatcher, searchText, start);
		}

		DecompilerSearchResults newResults =
			new DecompilerSearchResults(worker, decompilerPanel, searchText, results);
		newResults.activate();
		return newResults;
	}

//=================================================================================================
// Search Methods
//=================================================================================================	

	@Override
	public SearchResults search(String text, CursorPosition position, boolean searchForward,
			boolean useRegex) {

		updateSearchResults(text, useRegex);

		DecompilerCursorPosition cursorPosition = (DecompilerCursorPosition) position;
		FieldLocation startLocation = getNextSearchStartLocation(cursorPosition, searchForward);
		DecompilerSearchLocation location =
			searchResults.getNextLocation(startLocation, searchForward);
		if (location == null) {
			return null;
		}

		searchResults.setActiveLocation(location);
		return searchResults;
	}

	private FieldLocation getNextSearchStartLocation(
			DecompilerCursorPosition decompilerCursorPosition, boolean searchForward) {

		FieldLocation cursor = decompilerCursorPosition.getFieldLocation();
		DecompilerSearchLocation containingLocation =
			searchResults.getContainingLocation(cursor, searchForward);

		if (containingLocation == null) {
			return cursor; // nothing to do; not on a search hit
		}

		// the given cursor position is inside of an existing match
		if (searchForward) {
			cursor.col += 1;
		}
		else {
			cursor.col = containingLocation.getStartIndexInclusive() - 1;
		}

		return cursor;
	}

	@Override
	public SearchResults searchAll(String searchString, boolean isRegex) {
		return doSearch(searchString, isRegex);
	}

	private Pattern createPattern(String searchString, boolean isRegex) {

		int options = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;
		if (isRegex) {
			try {
				return Pattern.compile(searchString, options);
			}
			catch (PatternSyntaxException e) {
				Msg.showError(this, decompilerPanel, "Regular Expression Syntax Error",
					e.getMessage());
				return null;
			}
		}

		return UserSearchUtils.createPattern(searchString, false, options);
	}

	private Function<String, SearchMatch> createForwardMatchFunction(Pattern pattern) {

		return textLine -> {

			Matcher matcher = pattern.matcher(textLine);
			if (matcher.find()) {
				int start = matcher.start();
				int end = matcher.end();
				return new SearchMatch(start, end, textLine);
			}

			return SearchMatch.NO_MATCH;
		};

	}

	private DecompilerSearchLocation findNext(Function<String, SearchMatch> matcher,
			String searchString, FieldLocation currentLocation) {

		List<Field> fields = decompilerPanel.getFields();
		int line = currentLocation.getIndex().intValue();
		for (int i = line; i < fields.size(); i++) {
			ClangTextField field = (ClangTextField) fields.get(i);
			String partialLine = substring(field, (i == line) ? currentLocation : null, true);
			SearchMatch match = matcher.apply(partialLine);
			if (match == SearchMatch.NO_MATCH) {
				continue;
			}

			String fullLine = field.getText();
			if (i == line) { // cursor is on this line
				//
				// The match start for all lines without the cursor will be relative to the start
				// of the line, which is 0.  However, when searching on the row with the cursor,
				// the match start is relative to the cursor position.  Update the start to
				// compensate for the difference between the start of the line and the cursor.
				//				
				int cursorOffset = fullLine.length() - partialLine.length();
				match.start += cursorOffset;
				match.end += cursorOffset;
			}

			FieldLineLocation lineInfo = getFieldIndexFromOffset(match.start, field);
			FieldLocation fieldLocation =
				new FieldLocation(i, lineInfo.fieldNumber(), 0, lineInfo.column());
			int lineNumber = lineInfo.lineNumber();
			SearchLocationContext context = createContext(fullLine, match);
			return new DecompilerSearchLocation(fieldLocation, match.start, match.end - 1,
				searchString, true, field.getText(), lineNumber, context);
		}
		return null;
	}

	private SearchLocationContext createContext(String line, SearchMatch match) {
		SearchLocationContextBuilder builder = new SearchLocationContextBuilder();
		int start = match.start;
		int end = match.end;
		builder.append(line.substring(0, start));
		builder.appendMatch(line.substring(start, end));
		if (end < line.length()) {
			builder.append(line.substring(end));
		}

		return builder.build();
	}

	private String substring(ClangTextField textField, FieldLocation location,
			boolean forwardSearch) {

		if (location == null) { // the cursor location is not on this line; use all of the text
			return textField.getText();
		}

		if (textField.getText().isEmpty()) { // the cursor is on blank line
			return "";
		}

		String partialText = textField.getText();
		if (forwardSearch) {

			int nextCol = location.getCol();

			// protects against the location column being out of range (this can happen if we're
			// searching forward and the cursor is past the last token)
			if (nextCol >= partialText.length()) {
				return "";
			}

			// skip a character to start the next search; this prevents matching the previous match
			return partialText.substring(nextCol);
		}

		// backwards search
		return partialText.substring(0, location.getCol());
	}

	private FieldLineLocation getFieldIndexFromOffset(int screenOffset, ClangTextField textField) {

		RowColLocation rowColLocation = textField.textOffsetToScreenLocation(screenOffset);
		int lineNumber = textField.getLineNumber();

		// we use 0 here because currently there is only one field, which is the entire line
		return new FieldLineLocation(0, lineNumber, rowColLocation.col());
	}

	private static class SearchMatch {
		private static SearchMatch NO_MATCH = new SearchMatch(-1, -1, null);
		private int start;
		private int end;
		private String textLine;

		SearchMatch(int start, int end, String textLine) {
			this.start = start;
			this.end = end;
			this.textLine = textLine;
		}

		@Override
		public String toString() {
			if (this == NO_MATCH) {
				return "NO MATCH";
			}
			return "[start=" + start + ",end=" + end + "]: " + textLine;
		}
	}

	private record FieldLineLocation(int fieldNumber, int lineNumber, int column) {}
}
