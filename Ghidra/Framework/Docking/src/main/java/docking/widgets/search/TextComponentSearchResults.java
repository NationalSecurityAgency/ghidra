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

import java.awt.*;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.JEditorPane;
import javax.swing.event.*;
import javax.swing.text.*;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;
import javax.swing.text.Highlighter.Highlight;
import javax.swing.text.Highlighter.HighlightPainter;

import docking.widgets.SearchLocation;
import generic.theme.GColor;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.worker.Worker;
import util.CollectionUtils;

public class TextComponentSearchResults extends SearchResults {

	private Color highlightColor = new GColor("color.bg.find.highlight");
	private Color activeHighlightColor = new GColor("color.bg.find.highlight.active");

	protected JEditorPane editorPane;
	private SearchResultsHighlighterWrapper highlighter;
	private DocumentListener documentListener = new DocumentChangeListener();
	private CaretListener caretListener = new CaretChangeListener();
	private SwingUpdateManager caretUpdater =
		new SwingUpdateManager(() -> setActiveHighlightBasedOnCaret());
	private boolean isUpdatingCaretInternally;

	private String name;
	private List<TextComponentSearchLocation> searchLocations;
	private TreeMap<Integer, TextComponentSearchLocation> matchesByPosition;
	private String searchText;
	private TextComponentSearchLocation activeLocation;

	/** 
	 * Stale means the document has changed and our location offsets may no longer match.  Once 
	 * stale, always stale.
	 */
	private boolean isStale;

	protected TextComponentSearchResults(Worker worker, JEditorPane editorPane, String searchText,
			TreeMap<Integer, TextComponentSearchLocation> matchesByPosition) {
		super(worker);
		this.editorPane = editorPane;
		this.searchText = searchText;
		this.matchesByPosition = matchesByPosition;

		URL url = editorPane.getPage();
		this.name = getFilename(url);

		Collection<TextComponentSearchLocation> matches = matchesByPosition.values();
		this.searchLocations = new ArrayList<>(matches);

		Document document = editorPane.getDocument();
		document.addDocumentListener(documentListener);

		editorPane.addCaretListener(caretListener);

		// All results will be highlighted. Since we don't move the caret to a specific match, make 
		// sure that the highlight color gets updated based on the current caret position.
		caretUpdater.updateLater();

		highlighter = createHighlighter();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void deactivate() {
		if (isActive()) {
			FindJob job = new SwingJob(this::unapplyHighlights);
			runJob(job);
		}
	}

	/**
	 * Triggers the potentially asynchronous activation of this set of search results. When that is
	 * finished, we then restore our highlights.  This is needed in the case that the implementor
	 * is using a document that does not match our search results.  Some subclasses use 
	 * asynchronous loading of their document.
	 */
	@Override
	public void activate() {
		FindJob job = startActivation();
		runJob(job);
	}

	@Override
	public void setActiveLocation(SearchLocation location) {
		if (isStale) {
			return;
		}

		if (activeLocation == location) {
			return;
		}

		if (location == null) {
			// no need to activate these results when clearing the active location
			Swing.runNow(() -> doSetActiveLocation(null));
			return;
		}

		FindJob job = startActivation().thenRunSwing(() -> doSetActiveLocation(location));
		runActivationJob((ActivationJob) job);
	}

	/**
	 * Create a job to perform activation for this class.  The activation job may be a 'done' job
	 * if not activation is required.
	 * @return the job
	 */
	protected ActivationJob startActivation() {
		if (isActive()) {
			return createFinishedActivationJob();
		}

		if (isStale) {
			unapplyHighlights();
			return createFinishedActivationJob();
		}

		return (ActivationJob) createActivationJob().thenRunSwing(() -> applyHighlights());
	}

	/**
	 * Starts the job that will activate this class.  Subclasses can override this method to change
	 * the job that gets run.
	 * @return the job
	 */
	protected ActivationJob createActivationJob() {
		return new ActivationJob();
	}

	protected ActivationJob createFinishedActivationJob() {
		return new ActivationJob();
	}

	private void doSetActiveLocation(SearchLocation newLocation) {
		TextComponentSearchLocation oldLocation = activeLocation;
		activeLocation = (TextComponentSearchLocation) newLocation;
		if (oldLocation == newLocation) {
			scrollToLocation(activeLocation); // this handles null
			return;
		}

		changeActiveLocation(oldLocation, activeLocation);
	}

	TextComponentSearchLocation getNextLocation(int searchStart, boolean searchForward) {

		Entry<Integer, TextComponentSearchLocation> entry;
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

	@Override
	public boolean isEmpty() {
		return searchLocations.isEmpty();
	}

	@Override
	public List<SearchLocation> getLocations() {
		return CollectionUtils.asList(searchLocations, SearchLocation.class);
	}

	boolean isStale() {
		return isStale;
	}

	void setStale() {
		isStale = true;
		unapplyHighlights();
	}

	protected boolean isInvalid(String otherSearchText) {
		if (isStale) {
			return true;
		}
		return !searchText.equals(otherSearchText);
	}

	@Override
	public SearchLocation getActiveLocation() {
		return activeLocation;
	}

	private void updateActiveLocationForCaretChange(int caret) {
		TextComponentSearchLocation location = getLocation(caret);
		setActiveLocation(location);
	}

	private TextComponentSearchLocation getLocation(int caret) {
		Optional<TextComponentSearchLocation> optional =
			searchLocations.stream().filter(l -> l.contains(caret)).findFirst();
		return optional.orElseGet(() -> null);
	}

	private void changeActiveLocation(TextComponentSearchLocation oldLocation,
			TextComponentSearchLocation newLocation) {

		clearActiveHighlight(oldLocation);

		if (isStale) {
			// no way to easily change highlights for the caret position while we are stale, 
			// since the locations no longer match the document positions
			return;
		}

		if (newLocation == null) {
			return;
		}

		newLocation.setActive(true);
		doHighlightLocation(newLocation);
		scrollToLocation(newLocation);
	}

	private void clearActiveHighlight(TextComponentSearchLocation location) {

		if (location == null) {
			return;
		}

		location.setActive(false);
		doHighlightLocation(location);  // turn off the active highlight
	}

	private void scrollToLocation(TextComponentSearchLocation location) {
		if (location == null) {
			return;
		}

		int caret = editorPane.getCaretPosition();
		if (!location.contains(caret)) {
			setCaretPositionInternally(location);
		}
		scrollToVisible(location);
	}

	private void setCaretPositionInternally(TextComponentSearchLocation location) {

		if (isStale) {
			// once the document contents have changed, we have know way of knowing if the matches
			// are still valid
			return;
		}

		Document doc = editorPane.getDocument();
		int len = doc.getLength();
		if (len == 0) {
			// This can happen if the document is getting loaded asynchronously.  We work around
			// this elsewhere, making this a very low occurrence event.  If it happens, just
			// ignore the caret update.
			return;
		}

		isUpdatingCaretInternally = true;
		try {
			int pos = location.getStartIndexInclusive();
			editorPane.setCaretPosition(pos);

		}
		finally {
			isUpdatingCaretInternally = false;
		}
	}

	private void scrollToVisible(TextComponentSearchLocation location) {

		try {
			int start = location.getStartIndexInclusive();
			int end = location.getEndIndexInclusive();
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

	private void setActiveHighlightBasedOnCaret() {
		if (!isActive()) {
			return;
		}

		int pos = editorPane.getCaretPosition();
		updateActiveLocationForCaretChange(pos);
	}

	/**
	 * Creates our search highlighter, wrapping any existing highlighter in order to not lose 
	 * client highlights.
	 * @return the new highlighter
	 */
	private SearchResultsHighlighterWrapper createHighlighter() {

		Highlighter activeHighlighter = editorPane.getHighlighter();
		if (activeHighlighter == null) {
			return new SearchResultsHighlighterWrapper(null);
		}

		if (activeHighlighter instanceof SearchResultsHighlighterWrapper wrapper) {
			// don't wrap another search highlighter, as we will check for them later			
			return new SearchResultsHighlighterWrapper(wrapper.delegate);
		}

		// some other client non-search highlighter
		return new SearchResultsHighlighterWrapper(activeHighlighter);
	}

	private SearchResultsHighlighterWrapper getInstalledSearchResultsHighlighter() {

		Highlighter activeHighlighter = editorPane.getHighlighter();
		if (activeHighlighter == null) {
			return null;
		}

		if (activeHighlighter instanceof SearchResultsHighlighterWrapper wrapper) {
			return wrapper;
		}

		// some other client non-search highlighter
		return null;
	}

	/*
	 	We used to use a boolean to track the active state.  However, due to how clients activate
	 	and deactivate, the boolean could get out-of-sync with the highlighter.  Thus, use the 
	 	active highlighter as the method for checking if we are active.
	 */
	boolean isActive() {
		SearchResultsHighlighterWrapper activeSearchHighlighter =
			getInstalledSearchResultsHighlighter();

		return activeSearchHighlighter == highlighter;
	}

	Highlight[] getHighlights() {
		return highlighter.getHighlights();
	}

	private void maybeInstallHighlighter() {

		SearchResultsHighlighterWrapper activeHighlighter =
			getInstalledSearchResultsHighlighter();

		if (activeHighlighter == highlighter) {
			// we are already installed
			return;
		}

		if (activeHighlighter != null) {
			// another search highlighter is installed
			activeHighlighter.removeAllHighlights();
		}

		editorPane.setHighlighter(highlighter);
	}

	private void applyHighlights() {

		unapplyHighlights();

		// Any other search highlights will be cleared when we install our highlighter
		maybeInstallHighlighter();

		Collection<TextComponentSearchLocation> locations = matchesByPosition.values();

		for (TextComponentSearchLocation location : locations) {
			doHighlightLocation(location);
		}

		setActiveHighlightBasedOnCaret();
	}

	/**
	 * Clears highlights, but does not remove known matches.  This allows highlights to later be
	 * restored.  
	 */
	private void unapplyHighlights() {

		// reset and repaint the active highlight 
		setActiveLocation(null);

		Highlighter activeHighlighter = editorPane.getHighlighter();
		if (activeHighlighter == highlighter) {
			// only remove our highlights
			highlighter.removeAllHighlights();
			highlighter.uninstall();
		}
	}

	private void doHighlightLocation(TextComponentSearchLocation location) {

		Highlighter activeHighlighter = editorPane.getHighlighter();
		if (activeHighlighter != highlighter) {
			// Not our highlighter; don't change highlights.  Shouldn't happen.
			return;
		}

		Object tag = location.getHighlightTag();
		if (tag != null) {
			// always remove any previous highlight before adding a new one
			highlighter.removeHighlight(tag);
		}

		if (isStale) {
			return; // do not highlight when stale
		}

		Color c = location.isActive() ? activeHighlightColor : highlightColor;
		HighlightPainter painter = new DefaultHighlightPainter(c);
		int start = location.getStartIndexInclusive();
		int end = location.getEndIndexInclusive() + 1; // +1 to make inclusive be exclusive
		try {
			tag = highlighter.addHighlight(start, end, painter);
			location.setHighlightTag(tag);
		}
		catch (BadLocationException e) {
			Msg.debug(this, "Exception adding highlight", e);
		}
	}

	@Override
	public void dispose() {
		caretUpdater.dispose();

		if (editorPane != null) {
			Document document = editorPane.getDocument();
			document.removeDocumentListener(documentListener);
		}

		matchesByPosition.clear();
		searchLocations.clear();

		highlighter.uninstall();
		isStale = true;
	}

	@Override
	public String toString() {
		return "%s: %s (%s)".formatted(getClass().getSimpleName(), searchText,
			System.identityHashCode(this));
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	private class DocumentChangeListener implements DocumentListener {

		@Override
		public void insertUpdate(DocumentEvent e) {
			// this allows the previous search results to stay visible until a new find is requested			
			setStale();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			setStale();
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

	/**
	 * A class that allows us to replace any already installed highlighter.  This also allows us to
	 * add and remove highlighters, depending upon the active search.
	 * <p>
	 * Note: any non-search highlighters installed after this wrapper is created may be overwritten
	 * as the usr interacts with the search.
	 */
	private class SearchResultsHighlighterWrapper extends DefaultHighlighter {

		private Highlighter delegate;
		private boolean nonSearchDelegate;

		SearchResultsHighlighterWrapper(Highlighter delegate) {
			if (delegate == null) {
				delegate = new DefaultHighlighter();
				nonSearchDelegate = false;
			}
			else {
				nonSearchDelegate = true;
			}
			this.delegate = delegate;
		}

		void uninstall() {
			Highlighter activeHighlighter = editorPane.getHighlighter();
			if (activeHighlighter != this) {
				return;
			}

			if (nonSearchDelegate) {
				editorPane.setHighlighter(delegate);
			}
			else {
				editorPane.setHighlighter(null);
			}
		}

		@Override
		public void install(JTextComponent c) {
			delegate.install(c);
		}

		@Override
		public void deinstall(JTextComponent c) {
			delegate.deinstall(c);
		}

		@Override
		public void paint(Graphics g) {
			delegate.paint(g);
		}

		@Override
		public void paintLayeredHighlights(Graphics g, int p0, int p1, Shape viewBounds,
				JTextComponent editor, View view) {
			if (delegate instanceof LayeredHighlighter lh) {
				lh.paintLayeredHighlights(g, p0, p1, viewBounds, editor, view);
			}
		}

		@Override
		public Object addHighlight(int p0, int p1, HighlightPainter p) throws BadLocationException {
			return delegate.addHighlight(p0, p1, p);
		}

		@Override
		public void removeHighlight(Object tag) {
			delegate.removeHighlight(tag);
		}

		@Override
		public void removeAllHighlights() {
			delegate.removeAllHighlights();
		}

		@Override
		public void changeHighlight(Object tag, int p0, int p1) throws BadLocationException {
			delegate.changeHighlight(tag, p0, p1);
		}

		@Override
		public Highlight[] getHighlights() {
			return delegate.getHighlights();
		}

	}
}
