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

import java.awt.Component;
import java.awt.Window;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;
import java.time.Duration;
import java.util.*;

import javax.help.*;
import javax.help.search.SearchEngine;
import javax.swing.*;
import javax.swing.text.Document;

import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.actions.KeyBindingUtils;
import docking.widgets.FindDialog;
import docking.widgets.SearchLocation;
import docking.widgets.search.*;
import generic.util.WindowUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Worker;

/**
 * Enables the Find Dialog for searching through the current page of a help document.
 */
class HelpViewSearcher {

	private static final String FIND_ACTION_NAME = "find.action";

	private static KeyStroke FIND_KEYSTROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_F, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

	private JHelp jHelp;
	private SearchEngine searchEngine;

	private JEditorPane htmlEditorPane;

	private FindDialog findDialog;

	HelpViewSearcher(JHelp jHelp) {
		this.jHelp = jHelp;

		grabSearchEngine();

		JHelpContentViewer contentViewer = jHelp.getContentViewer();

		// note: see HTMLEditorKit$LinkController.mouseMoved() for inspiration
		htmlEditorPane = getHTMLEditorPane(contentViewer);

		HtmlTextSearcher searcher = new HtmlTextSearcher(htmlEditorPane);
		findDialog = new FindDialog("Help Find", searcher);

		htmlEditorPane.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				htmlEditorPane.getCaret().setVisible(true);
			}
		});

		installPopup();
		installKeybindings();

// if we ever need any highlight manipulation (currently done by BasicHelpContentViewUI)
//		Highlighter highlighter = htmlEditorPane.getHighlighter();
//		highlighter.addHighlight(0, 0, null)
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

	private class HtmlTextSearcher extends TextComponentSearcher {

		public HtmlTextSearcher(JEditorPane editorPane) {
			super(editorPane);
		}

		@Override
		protected HtmlSearchResults createSearchResults(
				Worker worker, JEditorPane jEditorPane, String searchText,
				TreeMap<Integer, TextComponentSearchLocation> matchesByPosition) {

			HtmlSearchResults results = new HtmlSearchResults(worker, jEditorPane, searchText,
				matchesByPosition);

			TextHelpModel model = jHelp.getModel();
			URL url = model.getCurrentURL();
			results.setUrl(url);
			return results;
		}
	}

	private class HtmlSearchResults extends TextComponentSearchResults {

		private PageLoadedListener pageLoadListener;
		private URL searchUrl;

		// we use the document length to know when our page is finished loading on a reload
		private int fullDocumentLength;

		private String name;

		HtmlSearchResults(Worker worker, JEditorPane editorPane, String searchText,
				TreeMap<Integer, TextComponentSearchLocation> matchesByPosition) {
			super(worker, editorPane, searchText, matchesByPosition);

			pageLoadListener = new PageLoadedListener(this);
			editorPane.addPropertyChangeListener("page", pageLoadListener);

			Document doc = editorPane.getDocument();
			fullDocumentLength = doc.getLength();
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		protected boolean isInvalid(String otherSearchText) {
			if (!isMyHelpPageShowing()) {
				return true;
			}
			return super.isInvalid(otherSearchText);
		}

		private boolean isMyHelpPageShowing() {
			TextHelpModel model = jHelp.getModel();
			URL htmlViewerURL = model.getCurrentURL();
			if (!Objects.equals(htmlViewerURL, searchUrl)) {
				// the help does not have my page
				return false;
			}

			// The document gets loaded asynchronously.  Use the length to know when it is finished
			// loaded.  This will not work correctly when the lengths are the same between two 
			// documents, but that should be a low occurrence event.
			Document doc = editorPane.getDocument();
			int currentLength = doc.getLength();
			return fullDocumentLength == currentLength;
		}

		private void loadMyHelpPage(TaskMonitor m) {
			if (isMyHelpPageShowing()) {
				return; // no need to reload
			}

			// Trigger the URL of the results to load and then activate the results
			jHelp.setCurrentURL(searchUrl);
		}

		/**
		 * Start an asynchronous activation. When we activate, we have to tell the viewer to load a
		 * new html page, which is asynchronous.    
		 * @return the future
		 */
		@Override
		protected ActivationJob createActivationJob() {

			// start a new page load and then wait for it to finish
			return (ActivationJob) super.createActivationJob()
					.thenRun(this::loadMyHelpPage)
					.thenWait(this::isMyHelpPageShowing, Duration.ofSeconds(3));
		}

		@Override
		public void activate() {
			//
			// When we activate, a new page load may get triggered.  When that happens the caret 
			// position will get moved by the help viewer.  We will put back the last active search
			// location after the load has finished.
			//
			SearchLocation lastActiveLocation = getActiveLocation();
			FindJob job = startActivation()
					.thenRunSwing(() -> restoreLocation(lastActiveLocation));

			runActivationJob((ActivationJob) job);
		}

		private void restoreLocation(SearchLocation lastActiveLocation) {
			if (lastActiveLocation != null) {
				setActiveLocation(null);
				setActiveLocation(lastActiveLocation);
			}
		}

		@Override
		public void dispose() {
			editorPane.removePropertyChangeListener("page", pageLoadListener);
			super.dispose();
		}

		void setUrl(URL url) {
			searchUrl = url;
			name = getFilename(searchUrl);
		}

		private URL getUrl() {
			return searchUrl;
		}

		private class PageLoadedListener implements PropertyChangeListener {

			private HtmlSearchResults htmlResults;

			PageLoadedListener(HtmlSearchResults htmlResults) {
				this.htmlResults = htmlResults;
			}

			@Override
			public void propertyChange(PropertyChangeEvent evt) {

				URL newPage = (URL) evt.getNewValue();
				if (!Objects.equals(newPage, htmlResults.getUrl())) {
					htmlResults.deactivate();
				}
			}

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
