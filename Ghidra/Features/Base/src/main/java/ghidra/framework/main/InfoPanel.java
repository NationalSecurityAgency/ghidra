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
package ghidra.framework.main;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.io.InputStream;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.View;

import docking.DockingUtils;
import docking.widgets.*;
import docking.widgets.label.*;
import generic.util.WindowUtilities;
import ghidra.framework.Application;
import ghidra.framework.ApplicationProperties;
import ghidra.util.*;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;
import utilities.util.FileUtilities;

/**
 * Window to display version information about the current release of 
 * the ghidra application.
 */
class InfoPanel extends JPanel {

	private final static Color RED = new Color(199, 0, 0);

	private final static int MARGIN = 10;

	private String version;
	private String marking;
	private String distributionInfo;

	private Color bgColor; // background color for all panels
	private int imageWidth;
	private final static String SPLASH_FILENAME = "splash.txt";
	private final static String CLOUD_REV_FILENAME = "images/cloudbarReversed.jpg";
	private final static String GHIDRA_FILENAME = "images/GHIDRA_Splash.png";
	private final static String CLOUD_FILENAME = "images/cloudbar.jpg";

	InfoPanel() {
		getAboutInfo();
		bgColor = new Color(243, 250, 255);
		create();
	}

	/**
	 * Create the contents of the window.
	 */
	private void create() {
		setLayout(new BorderLayout());
		add(createImagePanel(), BorderLayout.CENTER);
		add(createSouthPanel(), BorderLayout.SOUTH);
		setBackground(bgColor);
	}

	private Component buildTextPanel() {

		JPanel panel = new JPanel(new VerticalLayout(10));
		panel.setBorder(BorderFactory.createEmptyBorder(MARGIN, MARGIN, MARGIN, MARGIN));
		panel.setBackground(bgColor);

		if (Application.isTestBuild()) {
			panel.add(buildTestBuildLabel());
		}
		panel.add(buildVersionPanel());

		if (marking != null) {
			panel.add(buildMarkingLabel());
		}

		if (distributionInfo != null) {
			panel.add(buildDistributionLabel());
		}

		return panel;
	}

	private Component buildDistributionLabel() {
		String content = distributionInfo;

		// Use java native JLabel and let it auto-detect html content
		JLabel resizer = new JLabel(content);

		final int desiredTextViewWidth = imageWidth - (MARGIN * 2);

		// If the splash.txt file contains non-HTML text, view is null
		View view = (View) resizer.getClientProperty(javax.swing.plaf.basic.BasicHTML.propertyKey);
		if (view == null) {
			// must not be HTML content in the splash screen text (this shouldn't 
			// happen, but let's just protect against this anyway).
			JLabel label = new GDLabel(content) {
				@Override
				public Dimension getPreferredSize() {
					Dimension preferredSize = super.getPreferredSize();
					preferredSize.width = desiredTextViewWidth;
					return preferredSize;
				}
			};
			return label;
		}

		view.setSize(desiredTextViewWidth, 0);
		float w = view.getPreferredSpan(View.X_AXIS);
		float h = view.getPreferredSpan(View.Y_AXIS);

		JLabel distribLabel = new GHtmlLabel(content);
		distribLabel.setPreferredSize(new Dimension((int) Math.ceil(w), (int) Math.ceil(h + 10)));
		return distribLabel;
	}

	private Component buildMarkingLabel() {
		MultiLineLabel markingLabel = new MultiLineLabel(marking, 0, 3, MultiLineLabel.CENTER);
		markingLabel.setForeground(RED);
		return markingLabel;
	}

	private Component buildVersionPanel() {
		JPanel vPanel = new JPanel(new BorderLayout());
		vPanel.setBackground(bgColor);
		vPanel.add(buildVersionLabel(), BorderLayout.CENTER);
		vPanel.add(buildJavaVersionComponent(), BorderLayout.SOUTH);
		return vPanel;
	}

	private Component buildTestBuildLabel() {
		MultiLineLabel testLabel =
			new MultiLineLabel("-- UNSUPPORTED TEST BUILD --", 0, 3, MultiLineLabel.CENTER);
		testLabel.setForeground(RED);
		return testLabel;
	}

	private Component createSouthPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
		ImageIcon cloudRevImage = ResourceManager.loadImage(CLOUD_REV_FILENAME);
		if (cloudRevImage != null) {
			JLabel cloudRevLabel = new GIconLabel(cloudRevImage);
			panel.add(cloudRevLabel, BorderLayout.NORTH);
		}

		ImageIcon cloudImage = ResourceManager.loadImage(CLOUD_FILENAME);
		if (cloudImage != null) {
			JLabel cloudLabel = new GIconLabel(cloudImage);
			panel.add(cloudLabel, BorderLayout.SOUTH);
		}

		panel.add(buildTextPanel(), BorderLayout.CENTER);
		panel.setBackground(bgColor);

		return panel;
	}

	private Component buildVersionLabel() {
		MultiLineLabel versionLabel = new MultiLineLabel(version, 0, 3, MultiLineLabel.CENTER);
		Font font = versionLabel.getFont();
		font = font.deriveFont(14f).deriveFont(Font.BOLD);
		versionLabel.setFont(font);
		versionLabel.setForeground(Color.BLACK);
		return versionLabel;
	}

	private Component createImagePanel() {
		JPanel imagePanel = new JPanel();
		imagePanel.setBackground(bgColor);

		imagePanel.setLayout(new BorderLayout());
		ImageIcon ghidraSplashImage = ResourceManager.loadImage(GHIDRA_FILENAME);

		JLabel l = new GIconLabel(ghidraSplashImage);
		imagePanel.add(l, BorderLayout.CENTER);
		imageWidth = ghidraSplashImage.getIconWidth();
		return imagePanel;
	}

	private HyperlinkComponent buildJavaVersionComponent() {
		String anchorName = "java_version";
		final HyperlinkComponent javaVersionComponent =
			new HyperlinkComponent("<HTML><CENTER>Java Version " + "<A HREF=\"" + anchorName +
				"\">" + System.getProperty("java.version") + "</A></CENTER>");
		javaVersionComponent.addHyperlinkListener(anchorName, e -> {
			if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
				return;
			}

			showJavaHomeInfo(javaVersionComponent);
		});

		DockingUtils.setTransparent(javaVersionComponent);
		return javaVersionComponent;
	}

	private void showJavaHomeInfo(final HyperlinkComponent javaVersionComponent) {
		JToolTip tooltip = new JToolTip();
		tooltip.setTipText(System.getProperty("java.home"));

		Point location = MouseInfo.getPointerInfo().getLocation();
		Window window = WindowUtilities.windowForComponent(javaVersionComponent);
		tooltip.setLocation(location);

		PopupWindow popupWindow = new PopupWindow(window, tooltip);

		SwingUtilities.convertPointFromScreen(location, javaVersionComponent);
		MouseEvent dummyEvent =
			new MouseEvent(javaVersionComponent, (int) System.currentTimeMillis(),
				System.currentTimeMillis(), 0, location.x, location.y, 1, false);
		popupWindow.setCloseWindowDelay(1);
		popupWindow.showPopup(dummyEvent);
	}

	/**
	 * Read the version information from the the resource file.
	 */
	private void getAboutInfo() {

		String releaseName = Application.getApplicationReleaseName();
		String buildInfo = "";
		if (releaseName != null) {
			buildInfo = "\nBuild " + releaseName;
		}

		// set some default values in case we don't have the resource file.
		version = "Version " + Application.getApplicationVersion() +
			(SystemUtilities.isInDevelopmentMode() ? " - DEVELOPMENT" : "") + buildInfo + "\n" +
			Application.getBuildDate();

		marking =
			Application.getApplicationProperty(ApplicationProperties.RELEASE_MARKING_PROPERTY);

		distributionInfo = loadSplashScreenHTML();
	}

	private String loadSplashScreenHTML() {

		try (InputStream in = ResourceManager.getResourceAsStream(SPLASH_FILENAME)) {

			if (in == null) {
				Msg.debug(this, "Unable to find splash screen text from: " + SPLASH_FILENAME);
				return SPLASH_FILENAME + " file is missing!";
			}

			String text = FileUtilities.getText(in);
			if (!HTMLUtilities.isHTML(text)) {
				// our labels to not render correctly when not using HTML
				text = HTMLUtilities.toHTML(text);
			}

			text = text.replace('\n', ' ');
			return text;
		}
		catch (IOException e) {
			// use default splash screen info
			Msg.debug(this, "Unable to read splash screen text from: " + SPLASH_FILENAME, e);
			return SPLASH_FILENAME + " file is unreadable!";
		}
	}

	public static void main(String[] args) {
		JFrame f = new JFrame("Ghidra");
		InfoPanel p = new InfoPanel();
		f.getContentPane().add(p);
		f.pack();
		f.setVisible(true);

		JDialog d = new JDialog(f, "About Ghidra", true);
		d.getContentPane().add(new InfoPanel());
		d.pack();
		d.setVisible(true);
	}
}
