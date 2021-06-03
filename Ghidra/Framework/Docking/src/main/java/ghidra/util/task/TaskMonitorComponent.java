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
package ghidra.util.task;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.text.NumberFormat;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.OptionDialog;
import docking.widgets.label.GDHtmlLabel;
import ghidra.util.Swing;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;

/**
 * Component that contains a progress bar, a progress icon, and a cancel
 * button to cancel the task that is associated with this task monitor.
 * <p>
 * By default the progress bar and progress icon (spinning globe) are visible.
 */
public class TaskMonitorComponent extends JPanel implements TaskMonitor {

	private WeakSet<CancelledListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	private JProgressBar progressBar;
	private JButton cancelButton;

	private JPanel cancelPanel;
	private JPanel progressBarPanel;
	private JPanel mainContentPanel;
	private JPanel progressPanel;

	private String progressMessage;
	private String taskName;

	private JLabel messageLabel;

	private volatile boolean isCancelled;

	private long lastProgress = -1;
	private long progress;
	private long lastMaxProgress = -1;
	private long maxProgress;
	private long scaleFactor = 1;

	private Runnable updateProgressPanelRunnable;
	private Runnable updateCancelButtonRunnable;
	private Runnable updateToolTipRunnable;
	private Runnable shouldCancelRunnable;

	private boolean showingProgress = true;
	private boolean showingIcon = true;
	private boolean showingCancelButton = true;
	private boolean cancelEnabled = true;
	private boolean paintProgressValue = true;

	private AtomicBoolean isIndeterminate = new AtomicBoolean(false);
	private AtomicInteger taskID = new AtomicInteger();

	private Timer updateTimer;

	private NumberFormat percentFormat = NumberFormat.getPercentInstance();

	/**
	 * Constructor
	 */
	public TaskMonitorComponent() {
		this(true, true);
	}

	/**
	 * Constructor
	 *
	 * @param includeTextField if true, the dialog can display a status progressMessage with progress details
	 * @param includeCancelButton if true, a cancel button will be displayed
	 */
	public TaskMonitorComponent(boolean includeTextField, boolean includeCancelButton) {
		updateProgressPanelRunnable = () -> updateProgressPanel();
		updateCancelButtonRunnable = () -> updateCancelButton();
		updateToolTipRunnable = () -> updateToolTip();
		updateTimer = new Timer(250, e -> update());
		updateTimer.setRepeats(false);

		shouldCancelRunnable = () -> {
			int currentTaskID = taskID.get();

			boolean userSaysYes = OptionDialog.showYesNoDialog(null, "Cancel?",
				"Do you really want to cancel " + getTaskName() + "?") == OptionDialog.OPTION_ONE;

			if (userSaysYes && currentTaskID == taskID.get()) {
				cancel();
			}
		};

		buildProgressPanel(includeTextField, includeCancelButton);
	}

	@Override
	public void addCancelledListener(CancelledListener mcl) {
		listeners.add(mcl);
	}

	@Override
	public void removeCancelledListener(CancelledListener mcl) {
		listeners.remove(mcl);
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		setProgress(progress + incrementAmount);
	}

	@Override
	public long getProgress() {
		return progress;
	}

	@Override
	public boolean isCancelled() {
		return isCancelled;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled) {
			throw new CancelledException();
		}
	}

	@Override
	public synchronized void setMessage(String message) {
		this.progressMessage = message;
		startUpdateTimer();
	}

	@Override
	public synchronized String getMessage() {
		return progressMessage;
	}

	@Override
	public synchronized void setProgress(long value) {
		if (progress == value) {
			return;
		}
		progress = value;
		startUpdateTimer();
	}

	@Override
	public void initialize(long maxValue) {
		setMaximum(maxValue);
		setProgress(0);
	}

	@Override
	public void setMaximum(long max) {
		this.maxProgress = max;
		if (progress > this.maxProgress) {
			progress = max;
		}
		startUpdateTimer();
	}

	/**
	 * Sets the <code>indeterminate</code> property of the progress bar,
	 * which determines whether the progress bar is in determinate
	 * or indeterminate mode.
	 * <p>
	 * An indeterminate progress bar continuously displays animation
	 * indicating that an operation of unknown length is occurring.
	 * By default, this property is <code>false</code>.
	 * Some look and feels might not support indeterminate progress bars;
	 * they will ignore this property.
	 *
	 * @see JProgressBar
	 */
	@Override
	public void setIndeterminate(boolean indeterminate) {
		//
		// Note: if the caller of this method is not on the Swing thread (like when on
		//       a task thread), then we do not want to invokeAndWait(), as this prevents
		//       background tasks from working while the TaskDialog attempts to give them
		//       a chance to do so.  In other words, the background thread will end up
		//       blocking instead of working, which defeats our attempts to never show
		//       a task dialog for fast background tasks.
		//
		isIndeterminate.set(indeterminate);
		Swing.runIfSwingOrRunLater(() -> {
			boolean newValue = isIndeterminate.get();
			progressBar.setIndeterminate(newValue);
			progressBar.setStringPainted(!newValue);
		});
	}

	@Override
	public synchronized void setCancelEnabled(boolean enable) {
		if (cancelEnabled != enable) {
			cancelEnabled = enable;
			Swing.runLater(updateCancelButtonRunnable);
		}
	}

	@Override
	public synchronized boolean isCancelEnabled() {
		return cancelEnabled;
	}

	@Override
	public void cancel() {
		synchronized (this) {
			if (isCancelled) {
				return;
			}
			isCancelled = true;
		}

		notifyCancelListeners();
	}

	@Override
	public void clearCanceled() {
		synchronized (this) {
			isCancelled = false;
		}
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		this.paintProgressValue = showProgressValue;
		startUpdateTimer();
	}

	@Override
	public long getMaximum() {
		return maxProgress;
	}

	/**
	 * Reset this monitor so that it can be reused
	 */
	public synchronized void reset() {
		isCancelled = false;
		taskID.incrementAndGet();
	}

	/**
	 * Returns true if {@link #setIndeterminate(boolean)} with a value of <code>true</code> has
	 * been called.
	 *
	 * @return true if {@link #setIndeterminate(boolean)} with a value of <code>true</code> has
	 * been called.
	 */
	@Override
	public boolean isIndeterminate() {
		return isIndeterminate.get();
	}

	/**
	 * Set whether the progress bar should be visible
	 *
	 * @param show true if the progress bar should be visible
	 */
	public synchronized void showProgress(boolean show) {
		if (show != showingProgress) {
			showingProgress = show;
			Swing.runLater(updateProgressPanelRunnable);
		}
	}

	/**
	 * Set the name of the task; the name shows up in the tool tip for
	 * the cancel button.
	 *
	 * @param name the name of the task
	 */
	public void setTaskName(String name) {
		taskName = name;
		Swing.runLater(updateToolTipRunnable);
	}

	/**
	 * Set the visibility of the cancel button
	 *
	 * @param visible if true, show the cancel button; false otherwise
	 */
	public void setCancelButtonVisibility(boolean visible) {

		if (visible == showingCancelButton) {
			return;
		}

		if (visible) {
			add(cancelPanel, BorderLayout.EAST);
		}
		else {
			remove(cancelPanel);
		}

		repaint();
		showingCancelButton = visible;
	}

	/**
	 * Sets the visibility of the progress icon
	 *
	 * @param visible if true, display the progress icon
	 */
	public void showProgressIcon(boolean visible) {
		if (visible == showingIcon) {
			return;
		}
		Runnable r = () -> {
			if (visible) {
				mainContentPanel.add(progressPanel, BorderLayout.EAST);
			}
			else {
				mainContentPanel.remove(progressPanel);
			}
			showingIcon = visible;
		};

		Swing.runNow(r);
	}

	protected void notifyCancelListeners() {
		Runnable r = () -> {
			for (CancelledListener mcl : listeners) {
				mcl.cancelled();
			}
		};
		Swing.runLater(r);
	}

	private synchronized void startUpdateTimer() {
		if (!updateTimer.isRunning()) {
			updateTimer.start();
		}
	}

	private synchronized void update() {

		if (progressMessage != null) {
			messageLabel.setText(progressMessage);
			progressMessage = null;
		}

		if (maxProgress != lastMaxProgress) {
			setMaxValueInProgressBar(maxProgress);
			lastMaxProgress = maxProgress;
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
		long currentProgress = getProgress();
		if (currentProgress <= 0) {
			return "0%";
		}

		long maximum = getMaximum();
		if (currentProgress >= maximum) {
			return "100%";
		}

		float percent = ((float) currentProgress / (float) maximum);
		String formattedPercent = percentFormat.format(percent);
		if (!paintProgressValue) {
			return formattedPercent;
		}

		return formattedPercent + " (" + currentProgress + " of " + maximum + ")";
	}

	private synchronized void updateProgressPanel() {
		if (showingProgress) {
			progressBarPanel.add(progressBar, BorderLayout.NORTH);
		}
		else {
			progressBarPanel.remove(progressBar);
		}
	}

	private void updateToolTip() {
		cancelButton.setToolTipText("Cancel " + getTaskName());
	}

	private String getTaskName() {
		return (taskName == null) ? "" : "\"" + taskName + "\"";
	}

	private synchronized void updateCancelButton() {
		cancelButton.setEnabled(cancelEnabled);
	}

	private void buildProgressPanel(boolean includeTextField, boolean includeCancelButton) {
		setLayout(new BorderLayout(5, 1));
		messageLabel = new GDHtmlLabel("               ") {
			@Override
			public void invalidate() {
				// don't care
			}
		};
		messageLabel.setFont(messageLabel.getFont().deriveFont((float) 10.0));
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
		ToolTipManager.sharedInstance().registerComponent(progressBar);

		progressPanel = new HourglassAnimationPanel();

		progressBarPanel = new JPanel(new VerticalLayout(0));
		progressBarPanel.add(progressBar);
		if (includeTextField) {
			progressBarPanel.add(messageLabel);
			progressBar.setPreferredSize(new Dimension(180, 12));
		}
		else {
			progressBar.setBorderPainted(true);
			Dimension size = progressBar.getPreferredSize();
			progressBarPanel.setBorder(BorderFactory.createEmptyBorder(
				(progressPanel.getPreferredSize().height - size.height) / 2, 0, 0, 8));
		}

		mainContentPanel = new JPanel(new BorderLayout());
		mainContentPanel.add(progressBarPanel, BorderLayout.CENTER);
		mainContentPanel.add(progressPanel, BorderLayout.EAST);

		ImageIcon icon = Icons.STOP_ICON;
		cancelButton = new EmptyBorderButton(icon);

		cancelButton.setName("CANCEL_TASK");
		cancelButton.setPreferredSize(new Dimension(icon.getIconWidth(), icon.getIconHeight()));
		cancelButton.addActionListener(e -> Swing.runLater(shouldCancelRunnable));
		cancelButton.setFocusable(false);
		cancelButton.setRolloverEnabled(true);

		add(mainContentPanel, BorderLayout.CENTER);

		if (includeCancelButton) {
			cancelPanel = new JPanel();
			cancelPanel.setLayout(new BoxLayout(cancelPanel, BoxLayout.Y_AXIS));
			cancelPanel.add(Box.createVerticalGlue());
			cancelPanel.add(cancelButton);
			cancelPanel.add(Box.createVerticalGlue());
			add(cancelPanel, BorderLayout.EAST);
		}
	}
}
