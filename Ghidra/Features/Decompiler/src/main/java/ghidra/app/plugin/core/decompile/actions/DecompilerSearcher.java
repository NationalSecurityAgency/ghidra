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

import java.util.*;
import java.util.function.Function;
import java.util.regex.*;

import docking.widgets.*;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.util.Msg;
import ghidra.util.UserSearchUtils;

/**
 * A {@link FindDialogSearcher} for searching the text of the decompiler window.
 */
public class DecompilerSearcher implements FindDialogSearcher {

	private DecompilerPanel decompilerPanel;

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
	public void setCursorPosition(CursorPosition position) {
		decompilerPanel.setCursorPosition(((DecompilerCursorPosition) position).getFieldLocation());
	}

	@Override
	public void highlightSearchResults(SearchLocation location) {
		decompilerPanel.setSearchResults(location);
	}

	@Override
	public SearchLocation search(String text, CursorPosition position, boolean searchForward,
			boolean useRegex) {
		DecompilerCursorPosition decompilerCursorPosition = (DecompilerCursorPosition) position;
		FieldLocation startLocation =
			getNextSearchStartLocation(decompilerCursorPosition, searchForward);
		return doFind(text, startLocation, searchForward, useRegex);
	}

	private FieldLocation getNextSearchStartLocation(
			DecompilerCursorPosition decompilerCursorPosition, boolean searchForward) {

		FieldLocation startLocation = decompilerCursorPosition.getFieldLocation();
		DecompilerSearchLocation currentSearchLocation = decompilerPanel.getSearchResults();
		if (currentSearchLocation == null) {
			return startLocation; // nothing to do; no prior search hit
		}

		//
		// Special Case Handling:  Start the search at the cursor location by default.
		// However, if the cursor location is at the beginning of previous search hit, then
		// move the cursor forward by one character to ensure the previous search hit is not
		// found.
		//
		// Note: for a forward or backward search the cursor is placed at the beginning of the
		// match.
		//
		if (Objects.equals(startLocation, currentSearchLocation.getFieldLocation())) {

			if (searchForward) {
				// Given:
				// -search text: 'fox'
				// -search domain: 'What the |fox say'
				// -a previous search hit just before 'fox'
				//
				// Move the cursor just past the 'f' so the next forward search will not
				// find the current 'fox' hit.  Thus the new search domain for this line
				// will be: "ox say"
				//
				startLocation.col += 1;
			}
			else {
				// Given:
				// -search text: 'fox'
				// -search domain: 'What the |fox say'
				// -a previous search hit just before 'fox'
				//
				// Move the cursor just past the 'o' so the next backward search will not
				// find the current 'fox' hit.  Thus the new search domain for this line
				// will be: "What the fo"
				//
				int length = currentSearchLocation.getMatchLength();
				startLocation.col += length - 1;
			}
		}

		return startLocation;
	}

//=================================================================================================
// Search Methods
//=================================================================================================	

	@Override
	public List<SearchLocation> searchAll(String searchString, boolean isRegex) {

		Pattern pattern = createPattern(searchString, isRegex);
		Function<String, SearchMatch> function = createForwardMatchFunction(pattern);
		FieldLocation start = new FieldLocation();

		List<SearchLocation> results = new ArrayList<>();
		DecompilerSearchLocation searchLocation = findNext(function, searchString, start);
		while (searchLocation != null) {
			results.add(searchLocation);

			FieldLocation last = searchLocation.getFieldLocation();

			int line = last.getIndex().intValue();
			int field = 0; // there is only 1 field
			int row = 0; // there is only 1 row 
			int col = last.getCol() + 1; // move over one char to handle sub-matches
			start = new FieldLocation(line, field, row, col);
			searchLocation = findNext(function, searchString, start);
		}

		return results;
	}

	private DecompilerSearchLocation doFind(String searchString, FieldLocation currentLocation,
			boolean forwardSearch, boolean isRegex) {

		Pattern pattern = createPattern(searchString, isRegex);

		if (forwardSearch) {
			Function<String, SearchMatch> function = createForwardMatchFunction(pattern);
			return findNext(function, searchString, currentLocation);
		}

		Function<String, SearchMatch> reverse = createReverseMatchFunction(pattern);
		return findPrevious(reverse, searchString, currentLocation);
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

	private Function<String, SearchMatch> createReverseMatchFunction(Pattern pattern) {

		return textLine -> {

			Matcher matcher = pattern.matcher(textLine);
			if (!matcher.find()) {
				return SearchMatch.NO_MATCH;
			}

			int start = matcher.start();
			int end = matcher.end();

			// Since the matcher can only match from the start to end of line, we need to find all 
			// matches and then take the last match

			// Setting the region to one character past the previous match allows repeated matches
			// within a match.  The default behavior of the matcher is to start the match after 
			// the previous match found by find().  
			matcher.region(start + 1, textLine.length());
			while (matcher.find()) {
				start = matcher.start();
				end = matcher.end();
				matcher.region(start + 1, textLine.length());
			}

			return new SearchMatch(start, end, textLine);
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
			if (i == line) { // cursor is on this line
				//
				// The match start for all lines without the cursor will be relative to the start
				// of the line, which is 0.  However, when searching on the row with the cursor,
				// the match start is relative to the cursor position.  Update the start to
				// compensate for the difference between the start of the line and the cursor.
				//
				String fullLine = field.getText();
				int cursorOffset = fullLine.length() - partialLine.length();
				match.start += cursorOffset;
				match.end += cursorOffset;
			}

			FieldLineLocation lineInfo = getFieldIndexFromOffset(match.start, field);
			FieldLocation fieldLocation =
				new FieldLocation(i, lineInfo.fieldNumber(), 0, lineInfo.column());

			return new DecompilerSearchLocation(fieldLocation, match.start, match.end - 1,
				searchString, true, field.getText());
		}
		return null;
	}

	private DecompilerSearchLocation findPrevious(Function<String, SearchMatch> matcher,
			String searchString, FieldLocation currentLocation) {

		List<Field> fields = decompilerPanel.getFields();
		int line = currentLocation.getIndex().intValue();
		for (int i = line; i >= 0; i--) {
			ClangTextField field = (ClangTextField) fields.get(i);
			String textLine = substring(field, (i == line) ? currentLocation : null, false);

			SearchMatch match = matcher.apply(textLine);
			if (match != SearchMatch.NO_MATCH) {
				FieldLineLocation lineInfo = getFieldIndexFromOffset(match.start, field);
				FieldLocation fieldLocation =
					new FieldLocation(i, lineInfo.fieldNumber(), 0, lineInfo.column());

				return new DecompilerSearchLocation(fieldLocation, match.start, match.end - 1,
					searchString, false, field.getText());
			}
		}
		return null;
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

		// we use 0 here because currently there is only one field, which is the entire line
		return new FieldLineLocation(0, rowColLocation.col());
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

	private record FieldLineLocation(int fieldNumber, int column) {
	}
}
