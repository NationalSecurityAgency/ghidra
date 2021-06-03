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
package docking;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.Border;

import org.apache.commons.lang3.StringUtils;
import org.jdesktop.animation.timing.Animator;

import docking.util.AnimationUtils;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import generic.util.WindowUtilities;
import ghidra.util.*;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.MiddleLayout;

/**
 * Provides a status bar panel which has a text area to the left.  The status bar may
 * customized with additional status components added to the right of the status text.
 */
public class StatusBar extends JPanel {

	private static final Border STATUS_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createLoweredBevelBorder(), BorderFactory.createEmptyBorder(1, 2, 1, 2));

	private static final Border STATUS_ITEM_BORDER = BorderFactory.createCompoundBorder(
		BorderFactory.createEmptyBorder(0, 3, 0, 0), STATUS_BORDER);

	private static final int STATUS_BAR_GAP = 3;
	private static final int MESSAGE_QUEUE_MAX_SIZE = 10;

	private Animator animator;

	private JPanel homeButtonPanel;
	private JPanel statusAreaPanel;
	private JLabel statusLabel;
	private int minHeight;

	private LinkedList<String> messageQueue = new LinkedList<>();

	// fading and flashing members
	private Timer messageFadeTimer = new FadeTimer();
	private Timer flashTimer = new FlashTimer();
	private Timer animationDelayTimer = new AnimationDelayTimer();

	/**
	 * Construct a status bar with a single status text area.
	 */
	StatusBar() {

		super(new BorderLayout());

		int borderPadding = STATUS_BAR_GAP;
		setBorder(BorderFactory.createEmptyBorder(borderPadding, 0, 0, 0));

		homeButtonPanel = new JPanel(new BorderLayout());
		add(homeButtonPanel, BorderLayout.WEST);

		statusAreaPanel = new JPanel(new HorizontalLayout(0));
		JPanel eastPanel = createEastPanel(statusAreaPanel);
		add(eastPanel, BorderLayout.EAST);

		statusLabel = new GDLabel(" ");
		statusLabel.setOpaque(true);

		statusLabel.setName("Tool Status");
		statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

		JPanel statusMessagePanel = new JPanel(new BorderLayout());
		statusMessagePanel.setBorder(STATUS_BORDER);
		statusMessagePanel.add(statusLabel, BorderLayout.CENTER);

		add(statusMessagePanel, BorderLayout.CENTER);

		Dimension size = statusLabel.getPreferredSize();
		int topAndBottomPadding = STATUS_BAR_GAP * 2;
		minHeight = size.height + borderPadding + topAndBottomPadding;
	}

	/** The east panel contains the status panel and a spacer */
	private JPanel createEastPanel(JPanel statusPanel) {
		JPanel eastPanel = new JPanel(new HorizontalLayout(0));

		eastPanel.add(statusPanel);
		eastPanel.add(new StatusBarSpacer());

		return eastPanel;
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(400, minHeight);
	}

	void setHomeButton(Icon icon, Runnable callback) {

		int count = homeButtonPanel.getComponentCount();
		SystemUtilities.assertTrue(count == 0, "Can only set the home button once");

		EmptyBorderButton button = new EmptyBorderButton(icon);
		button.addActionListener(e -> callback.run());
		button.setToolTipText("Press to show the primary application window");

		homeButtonPanel.add(button);
	}

	/**
	 * Add a new status item component to the status area.  The preferred height and border
	 * for the component will be altered.
	 * @param c component
	 * @param addBorder true if a border is desired
	 * @param rightSide component will be added to the right-side of the status
	 * area if true, else it will be added immediately after the status text area
	 * if false.
	 */
	void addStatusItem(JComponent c, boolean addBorder, boolean rightSide) {
		JPanel p = new StatusPanel(c, addBorder);
		p.setName(c.getName());
		minHeight = Math.max(minHeight, p.getPreferredSize().height + STATUS_BAR_GAP);
		if (rightSide) {
			statusAreaPanel.add(p);
		}
		else {
			statusAreaPanel.add(p, 0);
		}
	}

	/**
	 * Remove the specified status item.
	 * @param c status component previously added.
	 */
	public void removeStatusItem(JComponent c) {
		statusAreaPanel.remove(c.getParent());
	}

	/**
	 * Returns the current text in this status bar
	 * @return the text
	 */
	public String getStatusText() {
		return statusLabel.getText();
	}

	/**
	 * Deprecated.  Call {@link #setStatusText(String)} instead.
	 * 
	 * @param text the text
	 * @param isActiveWindow this parameter is ignored
	 * @deprecated Call {@link #setStatusText(String)} instead.  Remove after 9.3
	 */
	@Deprecated
	public void setStatusText(String text, boolean isActiveWindow) {
		setStatusText(text);
	}

	/**
	 * Sets the status text
	 * @param text the text
	 */
	public void setStatusText(String text) {
		// Run this later in case we are in the midst of a Java focus transition, such as when a
		// dialog is closing.  If we don't let the focus transition finish, then we will not 
		// correctly locate the active window.
		Swing.runLater(() -> doSetStatusText(text));
	}

	private void doSetStatusText(String text) {
		if (text == null) {
			// do nothing for now so that the previous message stays around
			return;
		}

		addMessageToQueue(text);

		String updatedText = fixupMultilineText(text);
		statusLabel.setText(updatedText);
		statusLabel.setToolTipText(getToolTipText());
		statusLabel.setForeground(Color.BLACK);

		if (StringUtils.isBlank(updatedText)) {
			return;
		}

		Window window = WindowUtilities.windowForComponent(statusLabel);
		if (!window.isActive()) {
			return;
		}

		transitionMessage();

		// flash the status area
		flashTimer.restart();

		// start the fade timer
		messageFadeTimer.restart();
	}

	private void transitionMessage() {
		if (animator != null && animator.isRunning()) {
			// don't start a new animation if one is happening
			return;
		}

		if (animationDelayTimer.isRunning()) {
			// give the user a break; don't show a flurry of animations
			animationDelayTimer.restart();
			return;
		}

		Window activeWindow = WindowUtilities.windowForComponent(statusLabel);
		if (activeWindow == null) {
			// this can happen when the tool is closed when we had a status update buffered
			return;
		}

		animator = AnimationUtils.transitionUserFocusToComponent(activeWindow, statusLabel);
		animationDelayTimer.restart();
	}

	private String fixupMultilineText(String text) {
		String[] lines = text.split("\n");
		if (lines.length == 1) {
			return text;
		}

		return lines[0] + " [more]";
	}

	public void clearStatusMessages() {
		statusLabel.setText("");
		messageQueue.clear();
		repaint();
	}

	private void addMessageToQueue(String message) {
		if (message != null && message.trim().length() != 0) {
			if (message.endsWith("\n")) {
				message = message.substring(0, message.length() - 1);
			}
			messageQueue.add(0, message + " [" + DateUtils.formatCurrentTime() + "]");

			if (messageQueue.size() > MESSAGE_QUEUE_MAX_SIZE) {
				messageQueue.removeLast();
			}
		}
	}

	/**
	 * Overridden to update the tooltip text to display a small history of
	 * status messages.
	 *
	 * @return The new tooltip text.
	 * @see javax.swing.JComponent#getToolTipText()
	 */
	@Override
	public String getToolTipText() {
		if (messageQueue.size() > 0) {
			StringBuffer buffer = new StringBuffer("<HTML>");

			Iterator<String> iter = messageQueue.iterator();
			for (int i = 0; iter.hasNext(); i++) {
				if (i > 0) {
					buffer.append(HTMLUtilities.BR);
				}

				String message = iter.next();
				message = HTMLUtilities.lineWrapWithHTMLLineBreaks(message);
				buffer.append(message);
			}

			return buffer.toString();
		}

		return super.getToolTipText();
	}

	// used to fade the foreground color of the status text so that a message
	// slowly grays out as it ages
	private class FadeTimer extends Timer implements ActionListener {

		private Map<Color, Color> fadeColorMap = new HashMap<>();

		private FadeTimer() {
			super(5000, null);
			addActionListener(this);
			initFadeColors();
		}

		private void initFadeColors() {
			fadeColorMap.put(Color.BLACK, new Color(16, 16, 16));
			fadeColorMap.put(new Color(16, 16, 16), new Color(32, 32, 32));
			fadeColorMap.put(new Color(32, 32, 32), new Color(64, 64, 64));
			fadeColorMap.put(new Color(64, 64, 64), new Color(80, 80, 80));
			fadeColorMap.put(new Color(80, 80, 80), new Color(96, 96, 96));
			fadeColorMap.put(new Color(96, 96, 96), new Color(112, 112, 112));
			fadeColorMap.put(new Color(112, 112, 112), new Color(128, 128, 128));
		}

		@Override
		public void actionPerformed(ActionEvent event) {
			Color nextFadeColor = fadeColorMap.get(statusLabel.getForeground());

			if (nextFadeColor != null) {
				statusLabel.setForeground(nextFadeColor);
			}
			else {
				stop();
			}
		}
	}

	private class AnimationDelayTimer extends Timer implements ActionListener {

		public AnimationDelayTimer() {
			super(5000, null);
			addActionListener(this);
			setRepeats(false);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			// no-op; we just check to see if this timer is running as a marker for when to
			// throttle events
		}
	}

	// used to flash the foreground color of the status text when a message
	// is added to this status bar
	private class FlashTimer extends Timer implements ActionListener {

		private static final int MAX_FLASH_COUNT = 6;
		private Color defaultFGColor;
		int flashCount = 0;

		private FlashTimer() {
			super(500, null);
			addActionListener(this);
		}

		@Override
		public void actionPerformed(ActionEvent event) {
			if (flashCount < MAX_FLASH_COUNT) {
				contrastStatusLabelColors();
				flashCount++;
			}
			else {
				stop();
			}
		}

		@Override
		public void stop() {
			super.stop();
			revertLabelColors();
			flashCount = 0;
		}

		private Color createContrastingColor(Color color) {
			// make sure that our defaults have been initialized
			if (defaultFGColor == null) {
				defaultFGColor = statusLabel.getForeground();
			}

			int red = color.getRed();
			int green = color.getGreen();
			int blue = color.getBlue();
			return new Color((255 - red), (255 - green), (255 - blue));
		}

		private void contrastStatusLabelColors() {
			statusLabel.setForeground(createContrastingColor(statusLabel.getForeground()));
		}

		private void revertLabelColors() {
			statusLabel.setForeground(defaultFGColor);
		}
	}

	static class StatusPanel extends JPanel {
		Dimension prefSize;

		StatusPanel(Component c, boolean addBorder) {
			super(new MiddleLayout());
			if (addBorder) {
				setBorder(StatusBar.STATUS_ITEM_BORDER);
			}
			add(c, BorderLayout.CENTER);
			prefSize = super.getPreferredSize();
		}

		@Override
		public Dimension getPreferredSize() {
			return prefSize;
		}
	}
}
