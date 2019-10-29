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
package ghidra.app.merge;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.label.GIconLabel;
import resources.ResourceManager;

/**
 * The PhaseProgressPanel provides a title, progress bar and message for the current phase that is 
 * in progress
 */
public class PhaseProgressPanel extends JPanel {

	private final static String DEFAULT_INFO = "Merge programs in progress...";
	private ImageIcon INFORM_ICON = ResourceManager.loadImage("images/information.png");

	private JLabel titleLabel;
	private JProgressBar progressBar;
	private JPanel progressMessagePanel;
	private JLabel messageIcon;
	private JLabel messageLabel;
	private boolean isShowingProgress = false;
	private boolean isShowingMessage = false;
	private String title;
	private SpringLayout progressLayout;

	private Timer updateTimer;
	private boolean isTimerRunning;
	private String message;
	private int progress;
	private int lastProgress = -1;

	public PhaseProgressPanel(String title) {
		this.title = title;
		progressLayout = new SpringLayout();
		setLayout(progressLayout);
		createProgressPanel();
		adjustPreferredSize();
	}

	/**
	 * Determines and sets the preferred size of this panel.
	 */
	private void adjustPreferredSize() {
		int width = titleLabel.getPreferredSize().width + 5;
		int height = titleLabel.getPreferredSize().height + 5;
		if (isShowingProgress) {
			height += 5;
			height += progressBar.getPreferredSize().height;
			width = Math.max(width, progressBar.getPreferredSize().width);
		}
		if (isShowingMessage) {
			height += 5;
			height += progressMessagePanel.getPreferredSize().height;
			width = Math.max(width, progressMessagePanel.getPreferredSize().width);
		}
		setPreferredSize(new Dimension(width, height));

	}

	private void createProgressPanel() {

		titleLabel = new GDLabel(title);
		add(titleLabel);
		progressLayout.putConstraint(SpringLayout.WEST, titleLabel, 5, SpringLayout.WEST, this);
		progressLayout.putConstraint(SpringLayout.NORTH, titleLabel, 5, SpringLayout.NORTH, this);

		progressBar = new JProgressBar(SwingConstants.HORIZONTAL);
		Dimension dim = progressBar.getPreferredSize();
		progressBar.setPreferredSize(new Dimension(500, (int) dim.getHeight()));
		progressBar.setMaximum(100);
		progressLayout.putConstraint(SpringLayout.NORTH, progressBar, 5, SpringLayout.SOUTH,
			titleLabel);
		progressLayout.putConstraint(SpringLayout.WEST, progressBar, 0, SpringLayout.WEST,
			titleLabel);
		doSetProgress(0);

		progressMessagePanel = new JPanel(new BorderLayout());
		messageIcon = new GIconLabel(INFORM_ICON);
		messageIcon.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
		messageLabel = new GDLabel(DEFAULT_INFO);
		progressMessagePanel.add(messageIcon, BorderLayout.WEST);
		progressMessagePanel.add(messageLabel, BorderLayout.CENTER);
		doSetMessage(DEFAULT_INFO);

		// Sets up the timer for updating the GUI.
		updateTimer = new Timer(250, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				update();
			}
		});
	}

	// Method for use by the timer to update the progress bar or message.
	private synchronized void update() {
		boolean changed = false;
		if (message != null) {
			doSetMessage(message);
			message = null;
			changed = true;
		}
		if (progress != lastProgress) {
			doSetProgress(progress);
			lastProgress = progress;
			changed = true;
		}
		if (!changed) {
			updateTimer.stop();
			isTimerRunning = false;
		}
	}

	/**
	 * Method to get the panel to update with changes when already on the screen.
	 */
	private void doValidate() {
		invalidate();
		repaint();
		adjustPreferredSize();
	}

	/**
	 * Sets the title line displayed by this panel.
	 * @param newTitle the new title string
	 */
	public void setTitle(String newTitle) {
		titleLabel.setText(newTitle);
		doValidate();
	}

	/**
	 * Sets the progress message within this panel.
	 * @param newMessage the new message text to be displayed.
	 */
	private void doSetMessage(String newMessage) {
		messageLabel.setText(newMessage);
		if (!isShowingMessage) {
			add(progressMessagePanel);
			progressLayout.putConstraint(SpringLayout.WEST, progressMessagePanel, 0,
				SpringLayout.WEST, titleLabel);
			progressLayout.putConstraint(SpringLayout.NORTH, progressMessagePanel, 5,
				SpringLayout.SOUTH, (isShowingProgress ? progressBar : titleLabel));
			isShowingMessage = true;
		}
		doValidate();
	}

	/**
	 * Sets the progress message within this panel.
	 * @param message the new message text to be displayed.
	 */
	public synchronized void setMessage(String message) {
		this.message = message;
		if (!isTimerRunning) {
			updateTimer.start();
			isTimerRunning = true;
		}
	}

	/**
	 * Fills in the progress bar to the indicated percent.
	 * @param progressPercentage total percent of the progress bar that should be filled in.
	 */
	private void doSetProgress(final int progressPercentage) {
		if (progressPercentage < 0 || progressPercentage > 100) {
			throw new RuntimeException(
				"Invalid progress value (" + progressPercentage + "). Must be from 0 to 100.");
		}
		if (!isShowingProgress) {
			add(progressBar);
			isShowingProgress = true;
		}
		progressBar.setValue(progressPercentage);
		doValidate();
	}

	/**
	 * Fills in the progress bar to the indicated percent.
	 * @param progressPercentage total percent of the progress bar that should be filled in.
	 */
	public synchronized void setProgress(int progressPercentage) {
		progress = progressPercentage;
		if (!isTimerRunning) {
			updateTimer.start();
			isTimerRunning = true;
		}
	}

	/**
	 * Removes the message from being displayed by this panel.
	 * Setting the message text will cause it to get added again.
	 */
	public void removeMessage() {
		remove(progressMessagePanel);
		isShowingMessage = false;
		doValidate();
	}

	/**
	 * Removes the progress bar from being displayed by this panel.
	 * Setting progress will cause it to get added again.
	 */
	public void removeProgress() {
		remove(progressBar);
		if (isShowingMessage) {
			progressLayout.putConstraint(SpringLayout.NORTH, messageIcon, 5, SpringLayout.SOUTH,
				titleLabel);
		}
		isShowingProgress = false;
		doValidate();
	}

//	/**
//	 * @param args
//	 */
//	public static void main(String[] args) {
//		PhaseProgressPanel panel = new PhaseProgressPanel("Progress In Current Phase");
//		
////		try {
////			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
////		} catch (Exception e) {
////		}
//		
//		JFrame frame = new JFrame();
//		frame.setSize(800,400);
//		frame.setVisible(true);
//		
//		frame.getContentPane().setLayout(new BorderLayout());
//		frame.getContentPane().add(panel, BorderLayout.CENTER);
//		frame.validate();
//		
//		try {
//			Thread.sleep(2000);
//			panel.setProgress(0);
//			panel.setMessage("Initializing Code Unit Merge...");
//			Thread.sleep(2000);
//			panel.setProgress(20);
//			panel.setMessage("Merging Bytes...");
//			Thread.sleep(2000);
//			panel.setProgress(40);
//			panel.setMessage("Merging Instructions...");
//			Thread.sleep(2000);
//			panel.setProgress(60);
//			panel.setMessage("Merging Data...");
//			Thread.sleep(2000);
//			panel.removeMessage();
//			panel.setProgress(70);
//			Thread.sleep(2000);
//			panel.setMessage("Merging Data Again...");
//			Thread.sleep(2000);
//			panel.setProgress(80);
//			panel.setMessage("Merging Equates...");
//			Thread.sleep(2000);
//			panel.setProgress(100);
//			panel.setMessage("Resolving conflicts...");
//			Thread.sleep(2000);
//			panel.removeProgress();
//			panel.setMessage("The End...");
//			Thread.sleep(2000);
//			panel.removeMessage();
//			Thread.sleep(2000);
//			frame.setVisible(false);
//			System.exit(0);
//		} catch (InterruptedException e) {
//			Err.error(this, null, "Error", "Unexpected Exception: " + e.getMessage(), e);
//		}
//
//	}

}
