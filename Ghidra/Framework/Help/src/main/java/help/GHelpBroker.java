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
package help;

import java.awt.*;
import java.io.IOException;
import java.net.URL;
import java.util.List;

import javax.help.*;
import javax.swing.*;
import javax.swing.text.Document;

import generic.theme.GIcon;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import resources.Icons;
import resources.MultiIconBuilder;
import resources.icons.EmptyIcon;

// NOTE: for JH 2.0, this class has been rewritten to not
// access the 'frame' and 'dialog' variable directly

/**
 * Ghidra help broker that displays the help set; sets the application icon on the help frame and
 * attempts to maintain the user window size.
 */
public class GHelpBroker extends DefaultHelpBroker {

	// Create the zoom in/out icons that will be added to the default jHelp toolbar.
	private static final Icon ZOOM_OUT_ICON = new GIcon("icon.subtract");
	private static final Icon ZOOM_IN_ICON = Icons.ADD_ICON;

	private Dimension windowSize = new Dimension(1100, 700);

	protected JEditorPane htmlEditorPane;
	private Window activationWindow;
	private boolean initialized;

	/**
	 * Construct a new GhidraHelpBroker.
	 * @param hs java help set associated with this help broker
	 */
	public GHelpBroker(HelpSet hs) {
		super(hs);
	}

	@Override
	// Overridden so that we can call the preferred version of setCurrentURL on the HelpModel,
	// which fixes a bug with the history list (SCR 7639)
	public void setCurrentURL(final URL URL) {

		HelpModel model = getCustomHelpModel();
		if (model != null) {
			model.setCurrentURL(URL, getHistoryName(URL), null);
		}
		else {
			super.setCurrentURL(URL);
		}
	}

	protected List<Image> getApplicationIcons() {
		return null;
	}

	protected HelpModel getCustomHelpModel() {
		return null;
	}

	/* Perform some shenanigans to force Java Help to reload the given URL */
	protected void reloadHelpPage(URL url) {
		clearContentViewer();
		showNavigationAid(url);
		try {
			htmlEditorPane.setPage(url);
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected error loading help page: " + url, e);
		}
	}

	public void reload() {
		clearHighlights();
		initialized = false;
		if (isDisplayed()) {
			setDisplayed(false);
			setDisplayed(true);
		}
	}

	private void clearHighlights() {
		TextHelpModel helpModel = (TextHelpModel) getCustomHelpModel();
		if (helpModel != null) {
			helpModel.removeAllHighlights();
		}
	}

	protected void showNavigationAid(URL url) {
		// this base class does not have a navigation aid
	}

	private void clearContentViewer() {
		htmlEditorPane.getDocument().putProperty(Document.StreamDescriptionProperty, null);
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

	@Override
	public void setDisplayed(boolean b) {
		if (!b) {
			super.setDisplayed(b);
			return;
		}

		// this must be before any call that triggers the help system to create its window
		initializeScreenDevice();

		WindowPresentation windowPresentation = getWindowPresentation();
		updateWindowSize(windowPresentation);

		// this has to be before getHelpWindow() or the value returned will be null
		super.setDisplayed(b);

		initializeUIWindowPresentation(windowPresentation);
	}

	private void initializeScreenDevice() {
		if (initialized) {
			return;
		}

		if (activationWindow == null) {
			// This can happen when we show the 'What's New' help page on a fresh install.  In
			// that case, we were not activated from an existing window, thus, there may
			// be no parent window.
			return;
		}

		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
		GraphicsDevice[] gs = ge.getScreenDevices();
		GraphicsConfiguration config = activationWindow.getGraphicsConfiguration();
		GraphicsDevice parentDevice = config.getDevice();
		for (int i = 0; i < gs.length; i++) {
			if (gs[i] == parentDevice) {
				// update the help window's screen to match that of the parent
				setScreen(i);
			}
		}
	}

	private void initializeUIWindowPresentation(WindowPresentation windowPresentation) {

		Window helpWindow = windowPresentation.getHelpWindow();
		Container contentPane = null;
		if (helpWindow instanceof JFrame) {
			JFrame frame = (JFrame) helpWindow;
			installRootPane(frame);
			List<Image> icons = getApplicationIcons();
			if (icons != null) {
				frame.setIconImages(icons);
			}
			contentPane = frame.getContentPane();
		}
		else if (helpWindow instanceof JDialog) {
			JDialog dialog = (JDialog) helpWindow;
			installRootPane(dialog);
			contentPane = dialog.getContentPane();
		}

		initializeUIComponents(contentPane);
	}

	private void initializeUIComponents(Container contentPane) {

		if (initialized) {
			return;// already initialized
		}

		Component[] components = contentPane.getComponents();
		JHelp jHelp = (JHelp) components[0];
		JHelpContentViewer contentViewer = jHelp.getContentViewer();
		JEditorPane activeHtmlPane = getHTMLEditorPane(contentViewer);
		if (activeHtmlPane == htmlEditorPane && initialized) {
			return; // already initialized
		}

		addCustomToolbarItems(jHelp);
		htmlEditorPane = getHTMLEditorPane(contentViewer);

		// just creating the search wires everything together
		HelpModel helpModel = getCustomHelpModel();
		installHelpSearcher(jHelp, helpModel);
		if (helpModel != null) {
			installHelpSearcher(jHelp, helpModel);
		}

		installActions(jHelp);
		initialized = true;
	}

	protected void installHelpSearcher(JHelp jHelp, HelpModel helpModel) {
		// this base class does not provide an in-page search feature
	}

	/**
	 * Create zoom in/out buttons on the default help window toolbar.
	 * @param jHelp the java help object used to retrieve the help components
	 */
	protected void addCustomToolbarItems(final JHelp jHelp) {

		for (Component component : jHelp.getComponents()) {
			if (component instanceof JToolBar) {
				JToolBar toolbar = (JToolBar) component;
				toolbar.addSeparator();

				ImageIcon icon = new MultiIconBuilder(new EmptyIcon(24, 24))
						.addCenteredIcon(ZOOM_OUT_ICON)
						.build();

				Icon zoomOutIcon = icon;
				JButton zoomOutBtn = new JButton(zoomOutIcon);
				zoomOutBtn.setToolTipText("Zoom out");
				zoomOutBtn.addActionListener(e -> {
					GHelpHTMLEditorKit.zoomOut();

					// Need to reload the page to force the scroll panes to resize properly. A
					// simple revalidate/repaint won't do it.
					reloadHelpPage(getCurrentURL());
				});
				toolbar.add(zoomOutBtn);

				icon = new MultiIconBuilder(new EmptyIcon(24, 24))
						.addCenteredIcon(ZOOM_IN_ICON)
						.build();
				Icon zoomInIcon = icon;
				JButton zoomInBtn = new JButton(zoomInIcon);
				zoomInBtn.setToolTipText("Zoom in");
				zoomInBtn.addActionListener(e -> {
					GHelpHTMLEditorKit.zoomIn();

					// Need to reload the page to force the scroll panes to resize properly. A
					// simple revalidate/repaint won't do it.
					reloadHelpPage(getCurrentURL());
				});
				toolbar.add(zoomInBtn);

				// Once we've found the toolbar we can break out of the loop and stop looking for it.
				break;
			}
		}
	}

	protected void installActions(JHelp help) {
		// subclasses may have actions
	}

	private String getHistoryName(URL URL) {
		String text = URL.getFile();
		int index = text.lastIndexOf('/');
		if (index != -1) {
			// we want just the filename
			text = text.substring(index + 1);
		}

		String ref = URL.getRef();
		if (ref != null) {
			text += " - " + ref;
		}
		return text;
	}

	private void installRootPane(JFrame frame) {
		Component oldGlassPane = frame.getGlassPane();
		if (!(oldGlassPane instanceof GGlassPane)) {
			GGlassPane gGlassPane = new GGlassPane();
			frame.setGlassPane(gGlassPane);
			gGlassPane.setVisible(true);
		}
	}

	private void installRootPane(JDialog dialog) {
		Component oldGlassPane = dialog.getGlassPane();
		if (!(oldGlassPane instanceof GGlassPane)) {
			GGlassPane gGlassPane = new GGlassPane();
			dialog.setGlassPane(gGlassPane);
			gGlassPane.setVisible(true);
		}
	}

	private void updateWindowSize(WindowPresentation presentation) {
		if (windowSize == null) {
			return;
		}

		presentation.createHelpWindow();
		presentation.setSize(windowSize);
	}

	@Override
	public void setActivationWindow(Window window) {
		WindowPresentation windowPresentation = getWindowPresentation();
		Window helpWindow = windowPresentation.getHelpWindow();
		if (helpWindow == null) {
			activationWindow = window;
			super.setActivationWindow(window);
			return;
		}

		windowSize = helpWindow.getSize();// remember the previous size

		boolean wasModal = isModalWindow(helpWindow);
		boolean willBeModal = isModalWindow(window);
		if (!wasModal && willBeModal) {
			// in this condition, a new window will be shown, but the old one is not properly
			// closed by JavaHelp
			helpWindow.setVisible(false);
		}

		super.setActivationWindow(window);
	}

	private boolean isModalWindow(Window window) {
		if (window instanceof Dialog) {
			Dialog dialog = (Dialog) window;
			if (dialog.isModal()) {
				return true;
			}
		}
		return false;
	}
}
