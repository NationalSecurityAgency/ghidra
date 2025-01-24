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

import java.awt.*;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.regex.*;

import javax.swing.JEditorPane;
import javax.swing.event.*;
import javax.swing.text.*;

import generic.theme.GColor;
import ghidra.util.Msg;
import ghidra.util.UserSearchUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * A class to find text matches in the given {@link TextComponent}.  This class will search for all
 * matches and cache the results for future requests when the user presses Next or Previous.  All
 * matches will be highlighted in the text component.  The match containing the cursor will be a 
 * different highlight color than the others.  When the find dialog is closed, all highlights are
 * removed.
 */
public class TextComponentSearcher implements FindDialogSearcher {

	private Color highlightColor = new GColor("color.bg.find.highlight");
	private Color activeHighlightColor = new GColor("color.bg.find.highlight.active");

	private JEditorPane editorPane;
	private DocumentListener documentListener = new DocumentChangeListener();

	private CaretListener caretListener = new CaretChangeListener();
	private SwingUpdateManager caretUpdater = new SwingUpdateManager(() -> updateActiveHighlight());
	private volatile boolean isUpdatingCaretInternally;

	private SearchResults searchResults;

	public TextComponentSearcher(JEditorPane editorPane) {
		this.editorPane = editorPane;

		if (editorPane == null) {
			return; // some clients initialize without an editor pane
		}

		Document document = editorPane.getDocument();
		document.addDocumentListener(documentListener);

		editorPane.addCaretListener(caretListener);
	}

	public void setEditorPane(JEditorPane editorPane) {
		if (this.editorPane != editorPane) {
			Document document = editorPane.getDocument();
			document.removeDocumentListener(documentListener);
			markResultsStale();
		}
		this.editorPane = editorPane;
	}

	public JEditorPane getEditorPane() {
		return editorPane;
	}

	@Override
	public void dispose() {
		caretUpdater.dispose();

		if (editorPane != null) {
			Document document = editorPane.getDocument();
			document.removeDocumentListener(documentListener);

			clearHighlights();
		}
	}

	@Override
	public void clearHighlights() {
		if (searchResults != null) {
			searchResults.removeHighlights();
			searchResults = null;
		}
	}

	public boolean hasSearchResults() {
		return searchResults != null && !searchResults.isEmpty();
	}

	public boolean isStale() {
		return searchResults != null && searchResults.isStale();
	}

	private void markResultsStale() {
		if (searchResults != null) {
			searchResults.setStale();
		}
	}

	private void updateActiveHighlight() {
		if (searchResults == null) {
			return;
		}

		int pos = editorPane.getCaretPosition();
		searchResults.updateActiveMatch(pos);
	}

	private void setCaretPositionInternally(int pos) {
		isUpdatingCaretInternally = true;
		try {
			editorPane.setCaretPosition(pos);
		}
		finally {
			isUpdatingCaretInternally = false;
		}
	}

	@Override
	public CursorPosition getCursorPosition() {
		int pos = editorPane.getCaretPosition();
		return new CursorPosition(pos);
	}

	@Override
	public void setCursorPosition(CursorPosition position) {
		int pos = position.getPosition();
		editorPane.setCaretPosition(pos);
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
	public void highlightSearchResults(SearchLocation location) {

		if (location == null) {
			clearHighlights();
			return;
		}

		TextComponentSearchLocation textLocation = (TextComponentSearchLocation) location;
		FindMatch match = textLocation.getMatch();
		searchResults.setActiveMatch(match);
	}

	@Override
	public SearchLocation search(String text, CursorPosition cursorPosition,
			boolean searchForward, boolean useRegex) {

		updateSearchResults(text, useRegex);

		int pos = cursorPosition.getPosition();
		int searchStart = getSearchStart(pos, searchForward);

		FindMatch match = searchResults.getNextMatch(searchStart, searchForward);
		if (match == null) {
			return null;
		}

		return new TextComponentSearchLocation(match.getStart(), match.getEnd(), text,
			searchForward, match);
	}

	private void updateSearchResults(String text, boolean useRegex) {
		if (searchResults != null) {
			if (!searchResults.isInvalid(text)) {
				return; // the current results are still valid
			}

			searchResults.removeHighlights();
		}

		SearchTask searchTask = new SearchTask(text, useRegex);
		TaskLauncher.launch(searchTask);
		searchResults = searchTask.getSearchResults();
		searchResults.applyHighlights();
	}

	private int getSearchStart(int startPosition, boolean isForward) {

		FindMatch activeMatch = searchResults.getActiveMatch();
		if (activeMatch == null) {
			return startPosition;
		}

		int lastMatchStart = activeMatch.getStart();
		if (startPosition != lastMatchStart) {
			return startPosition;
		}

		// Always prefer the caret position, unless it aligns with the previous match.  By
		// moving it forward one we will continue our search, as opposed to always matching
		// the same hit.
		if (isForward) {
			return startPosition + 1;
		}

		// backwards
		if (startPosition == 0) {
			return editorPane.getText().length();
		}
		return startPosition - 1;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class SearchResults {

		private TreeMap<Integer, FindMatch> matchesByPosition;
		private FindMatch activeMatch;
		private boolean isStale;
		private String searchText;

		SearchResults(String searchText, TreeMap<Integer, FindMatch> matchesByPosition) {
			this.searchText = searchText;
			this.matchesByPosition = matchesByPosition;
		}

		boolean isStale() {
			return isStale;
		}

		void updateActiveMatch(int pos) {
			if (activeMatch != null) {
				activeMatch.setActive(false);
				activeMatch = null;
			}

			if (isStale) {
				// not way to easily change highlights for the caret position while we are stale, 
				// since the matches no longer match the document positions
				return;
			}

			for (FindMatch match : matchesByPosition.values()) {
				boolean isActive = false;
				if (match.contains(pos)) {
					activeMatch = match;
					isActive = true;
				}
				match.setActive(isActive);
			}
		}

		FindMatch getActiveMatch() {
			return activeMatch;
		}

		FindMatch getNextMatch(int searchStart, boolean searchForward) {

			Entry<Integer, FindMatch> entry;
			if (searchForward) {
				entry = matchesByPosition.ceilingEntry(searchStart);
			}
			else {
				entry = matchesByPosition.floorEntry(searchStart);
			}

			if (entry == null) {
				return null; // no more matches in the current direction
			}

			return entry.getValue();
		}

		boolean isEmpty() {
			return matchesByPosition.isEmpty();
		}

		void setStale() {
			isStale = true;
		}

		boolean isInvalid(String otherSearchText) {
			if (isStale) {
				return true;
			}
			return !searchText.equals(otherSearchText);
		}

		void setActiveMatch(FindMatch match) {
			if (activeMatch != null) {
				activeMatch.setActive(false);
			}

			activeMatch = match;
			activeMatch.activate();
		}

		void applyHighlights() {
			Collection<FindMatch> matches = matchesByPosition.values();
			for (FindMatch match : matches) {
				match.applyHighlight();
			}
		}

		void removeHighlights() {

			activeMatch = null;

			JEditorPane editor = editorPane;
			Highlighter highlighter = editor.getHighlighter();
			if (highlighter != null) {
				highlighter.removeAllHighlights();
			}

			matchesByPosition.clear();
		}
	}

	private class TextComponentSearchLocation extends SearchLocation {

		private FindMatch match;

		public TextComponentSearchLocation(int start, int end,
				String searchText, boolean forwardDirection, FindMatch match) {
			super(start, end, searchText, forwardDirection);
			this.match = match;
		}

		FindMatch getMatch() {
			return match;
		}
	}

	private class SearchTask extends Task {

		private String searchText;
		private TreeMap<Integer, FindMatch> searchHits = new TreeMap<>();
		private boolean useRegex;

		SearchTask(String searchText, boolean useRegex) {
			super("Help Search Task", true, false, true, true);
			this.searchText = searchText;
			this.useRegex = useRegex;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			String screenText;
			try {
				Document document = editorPane.getDocument();
				screenText = document.getText(0, document.getLength());
			}
			catch (BadLocationException e) {
				Msg.error(this, "Unable to get text for user find operation", e);
				return;
			}

			Pattern pattern = createSearchPattern(searchText, useRegex);
			Matcher matcher = pattern.matcher(screenText);
			while (matcher.find()) {
				monitor.checkCancelled();
				int start = matcher.start();
				int end = matcher.end();
				FindMatch match = new FindMatch(searchText, start, end);
				searchHits.put(start, match);
			}

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

		SearchResults getSearchResults() {
			return new SearchResults(searchText, searchHits);
		}
	}

	private class FindMatch {

		private String text;
		private int start;
		private int end;
		private boolean isActive;

		// this tag is a way to remove an installed highlight
		private Object lastHighlightTag;

		FindMatch(String text, int start, int end) {
			this.start = start;
			this.end = end;
			this.text = text;
		}

		boolean contains(int pos) {
			// exclusive of end so the cursor behind the match does is not in the highlight
			return start <= pos && pos < end;
		}

		/** Calls setActive() and moves the caret position */
		void activate() {
			setActive(true);
			setCaretPositionInternally(start);
			scrollToVisible();
		}

		/** 
		 * Makes this match active and updates the highlight color
		 * @param b true for active
		 */
		void setActive(boolean b) {
			isActive = b;
			applyHighlight();
		}

		int getStart() {
			return start;
		}

		int getEnd() {
			return end;
		}

		void scrollToVisible() {

			try {
				Rectangle startR = editorPane.modelToView2D(start).getBounds();
				Rectangle endR = editorPane.modelToView2D(end).getBounds();
				endR.width += 20; // a little extra space so the view is not right at the text end
				Rectangle union = startR.union(endR);
				editorPane.scrollRectToVisible(union);
			}
			catch (BadLocationException e) {
				Msg.debug(this, "Exception scrolling to text", e);
			}
		}

		@Override
		public String toString() {
			return "[" + start + ',' + end + "] " + text;
		}

		void applyHighlight() {
			Highlighter highlighter = editorPane.getHighlighter();
			if (highlighter == null) {
				highlighter = new DefaultHighlighter();
				editorPane.setHighlighter(highlighter);
			}

			Highlighter.HighlightPainter painter =
				new DefaultHighlighter.DefaultHighlightPainter(
					isActive ? activeHighlightColor : highlightColor);

			try {

				if (lastHighlightTag != null) {
					highlighter.removeHighlight(lastHighlightTag);
				}

				lastHighlightTag = highlighter.addHighlight(start, end, painter);
			}
			catch (BadLocationException e) {
				Msg.debug(this, "Exception adding highlight", e);
			}
		}
	}

	private class DocumentChangeListener implements DocumentListener {

		@Override
		public void insertUpdate(DocumentEvent e) {
			// this allows the previous search results to stay visible until a new find is requested			
			markResultsStale();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			markResultsStale();
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			// ignore attribute changes since they don't affect the text content
		}
	}

	private class CaretChangeListener implements CaretListener {

		private int lastPos = -1;

		@Override
		public void caretUpdate(CaretEvent e) {
			int pos = e.getDot();
			if (isUpdatingCaretInternally) {
				lastPos = pos;
				return;
			}

			if (pos == lastPos) {
				return;
			}
			lastPos = pos;
			caretUpdater.update();
		}

	}
}
