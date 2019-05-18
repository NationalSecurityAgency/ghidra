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
package ghidra.framework.task.gui;

import java.awt.*;
import java.lang.reflect.InvocationTargetException;
import java.text.NumberFormat;

import javax.swing.*;

import docking.util.AnimatedIcon;
import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.label.GIconLabel;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.CancelledListener;
import resources.Icons;
import resources.ResourceManager;

// TODO Code duplication - Either eliminate the TaskMonitorComponent or use this inside of it
public class GProgressBar extends JPanel {
	private static final NumberFormat PERCENT_FORMAT = NumberFormat.getPercentInstance();

	private volatile long lastProgress = -1;
	private volatile long progress;
	private volatile long scaleFactor = 1;
	private volatile long lastMax = -1;
	private volatile long max;

	private volatile String lastMessage = null;
	private volatile String message;
	private volatile boolean paintProgressValue = true;
	private boolean showingIcon = true;

	private final float fontSize;
	private JProgressBar progressBar;
	private JLabel messageLabel;
	private JLabel imageLabel;
	private JPanel progressPanel;
	private JPanel activeProgressPanel;
	private JPanel eastButtonPanel;

	private Timer updateTimer;

	private EmptyBorderButton cancelButton;
	private CancelledListener cancelledListener;

	public GProgressBar(CancelledListener cancelledListener, boolean includeTextField,
			boolean includeCancelButton, boolean includeAnimatedIcon, float fontSize) {
		super(new BorderLayout(5, 1));
		this.cancelledListener = cancelledListener;
		this.fontSize = fontSize;

		buildProgressPanel(includeTextField, includeCancelButton, includeAnimatedIcon);

		updateTimer = new Timer(250, e -> update());
		updateTimer.setRepeats(false);
	}

	public void setBackgroundColor(Color bg) {
		setBackground(bg);
		progressPanel.setBackground(bg);
		messageLabel.setBackground(bg);
		activeProgressPanel.setBackground(bg);
		if (eastButtonPanel != null) {
			eastButtonPanel.setBackground(bg);
		}
	}

	public void initialize(long maximum) {
		this.progress = 0;
		this.max = maximum;
		this.message = null;
		update();
	}

	public void setProgress(long progress) {
		if (progress == this.progress) {
			return;
		}
		this.progress = progress;
		if (progress > this.max) {
			progress = max;
		}
		startUpdateTimer();
	}

	public void setMaximum(long max) {
		if (this.max == max) {
			return;
		}
		this.max = max;
		if (progress > this.max) {
			progress = max;
		}
		startUpdateTimer();
	}

	public void incrementProgress(long incrementAmount) {
		setProgress(progress + incrementAmount);
	}

	public long getProgress() {
		return progress;
	}

	public long getMax() {
		return max;
	}

	public synchronized void setMessage(String message) {
		if (message == this.message) {
			return;
		}
		this.message = message;
		startUpdateTimer();
	}

	public String getMessage() {
		return message;
	}

	/**
	 * Sets the <code>indeterminate</code> property of the progress bar,
	 * which determines whether the progress bar is in determinate
	 * or indeterminate mode.
	 * An indeterminate progress bar continuously displays animation
	 * indicating that an operation of unknown length is occurring.
	 * By default, this property is <code>false</code>.
	 * Some look and feels might not support indeterminate progress bars;
	 * they will ignore this property.
	 *
	 * @see JProgressBar
	 */
	public void setIndeterminate(final boolean indeterminate) {
		SystemUtilities.runSwingNow(() -> {
			progressBar.setIndeterminate(indeterminate);
			progressBar.setStringPainted(!indeterminate);
		});
	}

	/**
	 * Show or not show the progress icon (spinning globe) according to
	 * the showIcon param.
	 */
	public void showProgressIcon(final boolean showIcon) {
		if (showIcon == showingIcon) {
			return;
		}
		Runnable r = () -> {
			if (showIcon) {
				activeProgressPanel.add(imageLabel, BorderLayout.EAST);
			}
			else {
				activeProgressPanel.remove(imageLabel);
			}
			showingIcon = showIcon;
		};
		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
		}
		else {
			try {
				SwingUtilities.invokeAndWait(r);
			}
			catch (InterruptedException e) {
				// shouldn't happen
			}
			catch (InvocationTargetException e) {
				Msg.showError(this, null, "Error in Progress icon", "error", e);
			}
		}
	}

	/**
	 * True (the default) signals to paint the progress information inside of the progress bar.
	 *
	 * @param showProgressValue true to paint the progress value; false to not
	 */
	public void setShowProgressValue(boolean showProgressValue) {
		this.paintProgressValue = showProgressValue;
		startUpdateTimer();
	}

	public void cancel() {
		if (cancelledListener != null) {
			cancelledListener.cancelled();
		}
	}

	public void setCancelledListener(CancelledListener listener) {
		this.cancelledListener = listener;
	}

	private void buildProgressPanel(boolean includeTextField, boolean includeCancelButton,
			boolean includeAnimatedIcon) {
		messageLabel = new GDHtmlLabel("               ") {
			@Override
			public void invalidate() {
				// don't care
			}
		};
		messageLabel.setFont(messageLabel.getFont().deriveFont(fontSize));
		Dimension d = messageLabel.getPreferredSize();
		d.width = 180;
		messageLabel.setPreferredSize(d);
		progressBar = new JProgressBar() {
			@Override
			public String getToolTipText() {
				if (isStringPainted()) {
					return getString();
				}

				return createProgressString();
			}
		};

		progressBar.setStringPainted(true);
		progressBar.setValue(59); // arbitrary value to make it obvious that it wasn't initialized
		ToolTipManager.sharedInstance().registerComponent(progressBar);

		progressPanel = new JPanel(new VerticalLayout(0));
		progressPanel.add(progressBar);
		if (includeTextField) {
			progressPanel.add(messageLabel);
			progressBar.setPreferredSize(new Dimension(180, 12));
		}
		else {
			progressBar.setBorderPainted(true);
			Dimension size = progressBar.getPreferredSize();
			progressPanel.setBorder(BorderFactory.createEmptyBorder(
				(imageLabel.getPreferredSize().height - size.height) / 2, 0, 0, 8));
		}

		activeProgressPanel = new JPanel(new BorderLayout());
		activeProgressPanel.add(progressPanel, BorderLayout.CENTER);
		if (includeAnimatedIcon) {
			createAnimatedIcon();
			activeProgressPanel.add(imageLabel, BorderLayout.EAST);
		}

		ImageIcon icon = Icons.STOP_ICON;
		cancelButton = new EmptyBorderButton(icon);

		cancelButton.setName("CANCEL_TASK");
		cancelButton.setPreferredSize(new Dimension(icon.getIconWidth(), icon.getIconHeight()));
		cancelButton.addActionListener(e -> cancel());
		cancelButton.setFocusable(false);
		cancelButton.setRolloverEnabled(true);

		add(activeProgressPanel, BorderLayout.CENTER);

		if (includeCancelButton) {
			eastButtonPanel = new JPanel();
			eastButtonPanel.setLayout(new BoxLayout(eastButtonPanel, BoxLayout.Y_AXIS));
			//	eastButtonPanel.add(Box.createVerticalGlue());
			eastButtonPanel.add(cancelButton);
			eastButtonPanel.add(Box.createVerticalGlue());
			add(eastButtonPanel, BorderLayout.EAST);
		}
	}

	private synchronized void startUpdateTimer() {
		if (!updateTimer.isRunning()) {
			updateTimer.start();
		}
	}

	private synchronized void update() {
		if (message != lastMessage) {
			messageLabel.setText(message == null ? "" : message);
			lastMessage = message;
		}

		if (max != lastMax) {
			setMaxValueInProgressBar(max);
			lastMax = max;
		}

		if (progress != lastProgress) {
			setValueInProgressBar(progress);
			lastProgress = progress;
		}
	}

	private void setValueInProgressBar(long value) {
		progressBar.setValue((int) (value / scaleFactor));

		if (progressBar.isIndeterminate()) {
			return;
		}

		progressBar.setString(createProgressString());
	}

	private void setMaxValueInProgressBar(long max) {
		scaleFactor = computeScaleFactor(max);
		progressBar.setMaximum((int) (max / scaleFactor));
		if (progressBar.isIndeterminate()) {
			return;
		}
		progressBar.setString(createProgressString());
	}

	private long computeScaleFactor(long value) {
		long scale = 1;
		while (value > Integer.MAX_VALUE) {
			value /= 10;
			scale *= 10;
		}
		return scale;
	}

	private String createProgressString() {
		long currentProgress = progress;

		if (currentProgress <= 0) {
			return "0%";
		}

		long maximum = max;
		if (currentProgress >= maximum) {
			return "100%";
		}

		float percent = ((float) currentProgress / (float) maximum);
		String formattedPercent = PERCENT_FORMAT.format(percent);
		if (!paintProgressValue) {
			return formattedPercent;
		}

		return formattedPercent + " (" + currentProgress + " of " + maximum + ")";
	}

	private void createAnimatedIcon() {

		String[] filenames = { "images/hourglass24_01.png", "images/hourglass24_02.png",
			"images/hourglass24_02.png", "images/hourglass24_03.png", "images/hourglass24_03.png",
			"images/hourglass24_04.png", "images/hourglass24_04.png", "images/hourglass24_05.png",
			"images/hourglass24_05.png", "images/hourglass24_06.png", "images/hourglass24_06.png",
			"images/hourglass24_07.png", "images/hourglass24_07.png", "images/hourglass24_08.png",
			"images/hourglass24_08.png", "images/hourglass24_09.png", "images/hourglass24_10.png",
			"images/hourglass24_11.png" };

		imageLabel =
			new GIconLabel(new AnimatedIcon(ResourceManager.loadImages(filenames), 150, 0));
	}

}
