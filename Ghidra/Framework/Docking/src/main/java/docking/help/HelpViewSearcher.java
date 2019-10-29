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
package docking.help;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.regex.*;

import javax.help.*;
import javax.help.DefaultHelpModel.DefaultHighlight;
import javax.help.search.SearchEngine;
import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.actions.KeyBindingUtils;
import docking.widgets.*;
import generic.util.WindowUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.*;

/**
 * Enables the Find Dialog for searching through the current page of a help document.
 */
class HelpViewSearcher {

	private static final String DIALOG_TITLE_PREFIX = "Whole Word Search in ";
	private static final String FIND_ACTION_NAME = "find.action";

	private static KeyStroke FIND_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_F, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

	private Comparator<SearchHit> searchResultComparator =
		(o1, o2) -> o1.getBegin() - o2.getBegin();

	private Comparator<? super SearchHit> searchResultReverseComparator =
		(o1, o2) -> o2.getBegin() - o1.getBegin();

	private JHelp jHelp;
	private SearchEngine searchEngine;
	private HelpModel helpModel;

	private JEditorPane htmlEditorPane;

	private FindDialog findDialog;

	private boolean startSearchFromBeginning;
	private boolean settingHighlights;

	HelpViewSearcher(JHelp jHelp, HelpModel helpModel) {
		this.jHelp = jHelp;
		this.helpModel = helpModel;

		findDialog = new FindDialog(DIALOG_TITLE_PREFIX, new Searcher()) {
			@Override
			public void close() {
				super.close();
				clearHighlights();
			}
		};

//		URL startURL = helpModel.getCurrentURL();
//		if (isValidHelpURL(startURL)) {
//			currentPageURL = startURL;
//		}

		grabSearchEngine();

		JHelpContentViewer contentViewer = jHelp.getContentViewer();
		contentViewer.addTextHelpModelListener(e -> {
			if (settingHighlights) {
				return; // ignore our changes
			}
			clearSearchState();
		});

		contentViewer.addHelpModelListener(e -> {
			URL url = e.getURL();
			if (!isValidHelpURL(url)) {
				// invalid file--don't enable searching for it
				return;
			}

//				currentPageURL = url;

			String file = url.getFile();
			int separatorIndex = file.lastIndexOf(File.separator);
			file = file.substring(separatorIndex + 1);
			findDialog.setTitle(DIALOG_TITLE_PREFIX + file);

			clearSearchState();  // new page
		});

		// note: see HTMLEditorKit$LinkController.mouseMoved() for inspiration
		htmlEditorPane = getHTMLEditorPane(contentViewer);

		htmlEditorPane.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				htmlEditorPane.getCaret().setVisible(true);
				startSearchFromBeginning = false;
			}
		});

		installPopup();
		installKeybindings();

// if we ever need any highlight manipulation (currently done by BasicHelpContentViewUI)
//		Highlighter highlighter = htmlEditorPane.getHighlighter();
//		highlighter.addHighlight(0, 0, null)
	}

	private boolean isValidHelpURL(URL url) {
		if (url == null) {
			return false;
		}
		String file = url.getFile();
		return new File(file).exists();
	}

	private void grabSearchEngine() {
		Enumeration<?> navigators = jHelp.getHelpNavigators();
		while (navigators.hasMoreElements()) {
			Object element = navigators.nextElement();
			if (element instanceof JHelpSearchNavigator) {
				searchEngine = ((JHelpSearchNavigator) element).getSearchEngine();
			}
		}

		if (searchEngine == null) {
			throw new AssertException("Unable to locate help search engine");
		}
	}

	private void installPopup() {
		htmlEditorPane.addMouseListener(new MouseAdapter() {

			@Override
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showPopupMenu(e);
					return;
				}
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showPopupMenu(e);
					return;
				}
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showPopupMenu(e);
					return;
				}
			}
		});
	}

	private void installKeybindings() {
		KeyBindingUtils.registerAction(htmlEditorPane, FIND_KEYSTROKE, new FindDialogAction(),
			JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
	}

	private void showPopupMenu(MouseEvent e) {
		JMenuItem menuItem = new JMenuItem("Find on Page...");
		menuItem.setAction(new FindDialogAction());
		menuItem.setText("Find on Page...");

		JPopupMenu menu = new JPopupMenu();
		menu.add(menuItem);

		menu.show(htmlEditorPane, e.getX(), e.getY());
	}

	private JEditorPane getHTMLEditorPane(JHelpContentViewer contentViewer) {
		//
		// Intimate Knowledge - construction of the viewer:
		// 
		// -BorderLayout
		// -JScrollPane
		// 		-Viewport
		//      	-JHEditorPane extends JEditorPane
		// 				
		//
		Component[] components = contentViewer.getComponents();
		JScrollPane scrollPane = (JScrollPane) components[0];
		JViewport viewport = scrollPane.getViewport();
		return (JEditorPane) viewport.getView();
	}

	private void clearSearchState() {
		startSearchFromBeginning = true;
	}

	private void clearHighlights() {
		((TextHelpModel) helpModel).setHighlights(new DefaultHighlight[0]);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class FindDialogAction extends AbstractAction {

		FindDialogAction() {
			super(FIND_ACTION_NAME);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			Window helpWindow = WindowUtilities.windowForComponent(htmlEditorPane);
			DockingWindowManager.showDialog(helpWindow, findDialog);
		}
	}

	private class Searcher implements FindDialogSearcher {

		@Override
		public CursorPosition getCursorPosition() {
			if (startSearchFromBeginning) {
				startSearchFromBeginning = false;
				return new CursorPosition(0);
			}

			int caretPosition = htmlEditorPane.getCaretPosition();
			return new CursorPosition(caretPosition);
		}

		@Override
		public CursorPosition getStart() {
			return new CursorPosition(0);
		}

		@Override
		public CursorPosition getEnd() {
			int length = htmlEditorPane.getDocument().getLength();
			return new CursorPosition(length - 1);
		}

		@Override
		public void setCursorPosition(CursorPosition position) {
			int cursorPosition = position.getPosition();
			htmlEditorPane.setCaretPosition(cursorPosition);
		}

		@Override
		public void highlightSearchResults(SearchLocation location) {
			if (location == null) {
				((TextHelpModel) helpModel).setHighlights(new DefaultHighlight[0]);
				return;
			}

			int start = location.getStartIndexInclusive();
			DefaultHighlight[] h = new DefaultHighlight[] {
				new DefaultHighlight(start, location.getEndIndexInclusive()) };

			// using setHighlights() instead of removeAll + add
			// avoids one highlighting event
			try {
				settingHighlights = true;
				((TextHelpModel) helpModel).setHighlights(h);
				htmlEditorPane.getCaret().setVisible(true); // bug
			}
			finally {
				settingHighlights = false;
			}

			try {
				Rectangle rectangle = htmlEditorPane.modelToView(start);
				htmlEditorPane.scrollRectToVisible(rectangle);
			}
			catch (BadLocationException e) {
				// shouldn't happen
			}
		}

		@Override
		public SearchLocation search(String text, CursorPosition cursorPosition,
				boolean searchForward, boolean useRegex) {
			ScreenSearchTask searchTask = new ScreenSearchTask(text, useRegex);
			new TaskLauncher(searchTask, htmlEditorPane);

			List<SearchHit> searchResults = searchTask.getSearchResults();
			int position = cursorPosition.getPosition(); // move to the next item

			if (searchForward) {
				Collections.sort(searchResults, searchResultComparator);
				for (SearchHit searchHit : searchResults) {
					int begin = searchHit.getBegin();
					if (begin <= position) {
						continue;
					}
					return new SearchLocation(begin, searchHit.getEnd(), text, searchForward);
				}
			}
			else {
				Collections.sort(searchResults, searchResultReverseComparator);
				for (SearchHit searchHit : searchResults) {
					int begin = searchHit.getBegin();
					if (begin >= position) {
						continue;
					}
					return new SearchLocation(begin, searchHit.getEnd(), text, searchForward);
				}
			}

			return null; // no more matches in the current direction
		}
	}

	private class ScreenSearchTask extends Task {

		private String text;
		private List<SearchHit> searchHits = new ArrayList<>();
		private boolean useRegex;

		ScreenSearchTask(String text, boolean useRegex) {
			super("Help Search Task", true, false, true, true);
			this.text = text;
			this.useRegex = useRegex;
		}

		@Override
		public void run(TaskMonitor monitor) {
			Document document = htmlEditorPane.getDocument();
			try {
				String screenText = document.getText(0, document.getLength());

				if (useRegex) {
					Pattern pattern =
						Pattern.compile(text, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
					Matcher matcher = pattern.matcher(screenText);
					while (matcher.find()) {
						int start = matcher.start();
						int end = matcher.end();
						searchHits.add(new SearchHit(1D, start, end));
					}
				}
				else {
					int start = 0;
					int wordOffset = text.length();
					while (wordOffset < document.getLength()) {
						String searchFor = screenText.substring(start, wordOffset);
						if (text.compareToIgnoreCase(searchFor) == 0) { //Case insensitive
							searchHits.add(new SearchHit(1D, start, wordOffset));
						}
						start++;
						wordOffset++;
					}
				}
			}
			catch (BadLocationException e) {
				// shouldn't happen
				Msg.debug(this, "Unexpected exception retrieving help text", e);
			}
			catch (PatternSyntaxException e) {
				Msg.showError(this, htmlEditorPane, "Regular Expression Syntax Error",
					e.getMessage());
			}
		}

		List<SearchHit> getSearchResults() {
			return searchHits;
		}
	}
//
//	private class IndexerSearchTask extends Task {
//
//		private String text;
//		private List<SearchHit> searchHits = new ArrayList<SearchHit>();
//		private URL pageURL;
//
//		IndexerSearchTask(String text, URL pageURL) {
//			super("Help Search Task", true, false, true, true);
//			this.text = text;
//			this.pageURL = pageURL;
//		}
//
//		@Override
//		public void run(TaskMonitor monitor) {
//			final CountDownLatch finishedLatch = new CountDownLatch(1);
//
//			javax.help.search.SearchQuery searchquery = searchEngine.createQuery();
//			searchquery.addSearchListener(new SearchListener() {
//
//				@Override
//				public void searchStarted(SearchEvent e) {
//					// don't care
//				}
//
//				@Override
//				public void searchFinished(SearchEvent e) {
//					finishedLatch.countDown();
//				}
//
//				@SuppressWarnings("unchecked")
//				@Override
//				public void itemsFound(SearchEvent e) {
//					Enumeration<SearchItem> searchItems = e.getSearchItems();
//					while (searchItems.hasMoreElements()) {
//
//						SearchItem item = searchItems.nextElement();
////						Msg.debug(this, "itemsFound(): " + item.getFilename());
//
//						if (!isCurrentFile(item)) {
//							continue;
//						}
//
//						Msg.debug(this, "itemsFound(): ");
//
//						searchHits.add(new SearchHit(item.getConfidence(), item.getBegin(),
//							item.getEnd()));
//					}
//				}
//			});
//
//			searchquery.start(text, jHelp.getLocale());
//
//			try {
//				finishedLatch.await();
//			}
//			catch (InterruptedException e1) {
//				Msg.debug(this, "Interrupted while waiting for search to complete for: " + text);
//			}
//
//		}
//
//		private boolean isCurrentFile(SearchItem item) {
//			URL base = item.getBase();
//			String filename = item.getFilename();
//			try {
//				URL url = new URL(base, filename);
//				return pageURL.sameFile(url);
//			}
//			catch (MalformedURLException e) {
//				return false;
//			}
//		}
//
//		List<SearchHit> getSearchResults() {
//			return searchHits;
//		}
//	}
}
