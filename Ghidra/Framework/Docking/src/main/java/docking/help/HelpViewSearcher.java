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
import java.io.File;
import java.net.URL;
import java.util.Enumeration;

import javax.help.*;
import javax.help.search.SearchEngine;
import javax.swing.*;

import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.actions.KeyBindingUtils;
import docking.widgets.FindDialog;
import docking.widgets.TextComponentSearcher;
import generic.util.WindowUtilities;
import ghidra.util.exception.AssertException;

/**
 * Enables the Find Dialog for searching through the current page of a help document.
 */
class HelpViewSearcher {

	private static final String DIALOG_TITLE_PREFIX = "Whole Word Search in ";
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

		contentViewer.addHelpModelListener(e -> {
			URL url = e.getURL();
			if (!isValidHelpURL(url)) {
				// invalid file--don't enable searching for it
				return;
			}

			String file = url.getFile();
			int separatorIndex = file.lastIndexOf(File.separator);
			file = file.substring(separatorIndex + 1);
			findDialog.setTitle(DIALOG_TITLE_PREFIX + file);
		});

		// note: see HTMLEditorKit$LinkController.mouseMoved() for inspiration
		htmlEditorPane = getHTMLEditorPane(contentViewer);

		TextComponentSearcher searcher = new TextComponentSearcher(htmlEditorPane);
		findDialog = new FindDialog(DIALOG_TITLE_PREFIX, searcher);

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
