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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import docking.ToolTipManager;
import docking.util.AnimatedIcon;
import docking.widgets.EmptyBorderButton;
import docking.widgets.OptionDialog;
import ghidra.util.Issue;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;
import resources.ResourceManager;

/**
 * Component that contains a progress bar, a progress icon, and a cancel
 * button to cancel the task that is associated with this task monitor.
 * By default the progress bar and progress icon (spinning globe) are visible.
 */
public class TaskMonitorComponent extends JPanel implements TaskMonitor {

	private WeakSet<CancelledListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private WeakSet<IssueListener> issueListeners;
	private JButton cancelButton;
	private JPanel eastButtonPanel;
	private JProgressBar progressBar;
	private JPanel progressPanel;
	private JPanel activeProgressPanel;
	private JLabel imageLabel;

	private String taskName;
	private volatile boolean isCancelled;
	private String message;

	private long lastProgress = -1;
	private long progress;
	private long lastMax = -1;
	private long max;

	private Runnable updateProgressPanelRunnable;
	private Runnable updateCancelButtonRunnable;
	private Runnable updateToolTipRunnable;
	private JLabel messageLabel;

	private boolean showingProgress = true;
	private boolean showingIcon = true;
	private boolean showingCancelButton = true;
	private boolean cancelEnabled = true;
	private AtomicBoolean isIndeterminate = new AtomicBoolean(false);
	private AtomicInteger taskID = new AtomicInteger();

	private Timer updateTimer;
	private Runnable shouldCancelRunnable;

	private boolean paintProgressValue = true;
	private NumberFormat percentFormat = NumberFormat.getPercentInstance();
	private long scaleFactor = 1;

	/**
	 * Construct a new TaskMonitorComponent.
	 * @param l listener that is notified when the task completes or the
	 * user cancels the task
	 */

	public TaskMonitorComponent() {
		this(true, true);
	}

	public TaskMonitorComponent(boolean includeTextField, boolean includeCancelButton) {
		updateProgressPanelRunnable = () -> updateProgressPanel();
		updateCancelButtonRunnable = () -> updateCancelButton();
		updateToolTipRunnable = () -> updateToolTip();
		updateTimer = new Timer(250, e -> update());
		updateTimer.setRepeats(false);

		shouldCancelRunnable = () -> {
			int currentTaskID = taskID.get();

			boolean userSaysYes = OptionDialog.showYesNoDialog(TaskMonitorComponent.this, "Cancel?",
				"Do you really want to cancel " + getTaskName() + "?") == OptionDialog.OPTION_ONE;

			if (userSaysYes && currentTaskID == taskID.get()) {
				cancel();
			}
		};

		buildProgressPanel(includeTextField, includeCancelButton);
	}

	/**
	 * Reset this monitor so that it can be reused.
	 */
	public synchronized void reset() {
		isCancelled = false;
		taskID.incrementAndGet();
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
		this.message = message;
		startUpdateTimer();
	}

	@Override
	public synchronized void setProgress(long value) {
		if (progress == value) {
			return;
		}
		progress = value;
		startUpdateTimer();
	}

	private synchronized void startUpdateTimer() {
		if (!updateTimer.isRunning()) {
			updateTimer.start();
		}
	}

	@Override
	public void initialize(long maxValue) {
		setMaximum(maxValue);
		setProgress(0);
	}

	@Override
	public void setMaximum(long max) {
		this.max = max;
		if (progress > this.max) {
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
		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			boolean newValue = isIndeterminate.get();
			progressBar.setIndeterminate(newValue);
			progressBar.setStringPainted(!newValue);
		});
	}

	/**
	 * Returns true if {@link #setIndeterminate(boolean)} with a value of <tt>true</tt> has
	 * been called.
	 * 
	 * @return true if {@link #setIndeterminate(boolean)} with a value of <tt>true</tt> has
	 * been called.
	 */
	public boolean isIndeterminate() {
		return isIndeterminate.get();
	}

	@Override
	public synchronized void setCancelEnabled(boolean enable) {
		if (cancelEnabled != enable) {
			cancelEnabled = enable;
			SystemUtilities.runSwingLater(updateCancelButtonRunnable);
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

		notifyChangeListeners();
	}

	@Override
	public void clearCanceled() {
		synchronized (this) {
			isCancelled = false;
		}
	}

	/**
	 * Set whether the progress bar should be visible.
	 * @param b true if the progress bar should be visible
	 */
	public synchronized void showProgress(boolean b) {
		if (b != showingProgress) {
			showingProgress = b;
			SystemUtilities.runSwingLater(updateProgressPanelRunnable);
		}
	}

	/**
	 * Set the name of the task; the name shows up in the tool tip for
	 * the cancel button.
	 * @param name the name of the task
	 */
	public void setTaskName(String name) {
		taskName = name;
		SystemUtilities.runSwingLater(updateToolTipRunnable);
	}

	/**
	 * Show or not show the cancel button according to the showCancel param.
	 */
	public void showCancelButton(boolean showCancel) {

		if (showCancel == showingCancelButton) {
			return;
		}

		if (showCancel) {
			add(eastButtonPanel, BorderLayout.EAST);
		}
		else {
			remove(eastButtonPanel);
		}
		showingCancelButton = showCancel;
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

		SystemUtilities.runSwingNow(r);
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		this.paintProgressValue = showProgressValue;
		startUpdateTimer();
	}

	@Override
	public long getMaximum() {
		return max;
	}

	private synchronized void update() {

		if (message != null) {
			messageLabel.setText(message);
			message = null;
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
			progressPanel.add(progressBar, BorderLayout.NORTH);
		}
		else {
			progressPanel.remove(progressBar);
		}
	}

	private void updateToolTip() {
		ToolTipManager.setToolTipText(cancelButton, "Cancel " + getTaskName());
	}

	private String getTaskName() {
		return (taskName == null) ? "" : "\"" + taskName + "\"";
	}

	private synchronized void updateCancelButton() {
		cancelButton.setEnabled(cancelEnabled);
	}

	private void buildProgressPanel(boolean includeTextField, boolean includeCancelButton) {
		setLayout(new BorderLayout(5, 1));
		messageLabel = new JLabel("               ") {
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

		createAnimatedIcon();

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
		activeProgressPanel.add(imageLabel, BorderLayout.EAST);

		ImageIcon icon = Icons.STOP_ICON;
		cancelButton = new EmptyBorderButton(icon);

		cancelButton.setName("CANCEL_TASK");
		cancelButton.setPreferredSize(new Dimension(icon.getIconWidth(), icon.getIconHeight()));
		cancelButton.addActionListener(e -> SwingUtilities.invokeLater(shouldCancelRunnable));
		cancelButton.setFocusable(false);
		cancelButton.setRolloverEnabled(true);

		add(activeProgressPanel, BorderLayout.CENTER);

		if (includeCancelButton) {
			eastButtonPanel = new JPanel();
			eastButtonPanel.setLayout(new BoxLayout(eastButtonPanel, BoxLayout.Y_AXIS));
			eastButtonPanel.add(Box.createVerticalGlue());
			eastButtonPanel.add(cancelButton);
			eastButtonPanel.add(Box.createVerticalGlue());
			add(eastButtonPanel, BorderLayout.EAST);
		}
	}

	private void createAnimatedIcon() {
		List<Icon> iconList = new ArrayList<>();
		iconList.add(ResourceManager.loadImage("images/hourglass24_01.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_02.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_02.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_03.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_03.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_04.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_04.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_05.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_05.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_06.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_06.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_07.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_07.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_08.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_08.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_09.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_10.png"));
		iconList.add(ResourceManager.loadImage("images/hourglass24_11.png"));
		AnimatedIcon progressIcon = new AnimatedIcon(iconList, 150, 0);
		imageLabel = new JLabel(progressIcon);
	}

	/**
	 * Simple test for the TaskMonitorComponent class.
	 * @param args not used
	 */
	public static void main(String[] args) {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		}
		catch (Exception e) {
			// don't care
		}

		JFrame f = new JFrame();
		f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		f.getContentPane().setLayout(new BorderLayout());
		final TaskMonitorComponent tm = new TaskMonitorComponent();
		f.getContentPane().add(tm);
		tm.showCancelButton(true);
		f.pack();
		f.setVisible(true);

//		tm.initialize(78);
//		TaskMonitor monitor = new UnknownProgressWrappingTaskMonitor(tm, 10);
//
//		for (int i = 0; i < 78; i++) {
//			try {
//				Thread.sleep(250);
//				monitor.setProgress(i);
//				System.out.println("set progress to " + i);
//			}
//			catch (InterruptedException e) {
//				e.printStackTrace();
//			}
//		}
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		setProgress(progress + incrementAmount);
	}

	@Override
	public long getProgress() {
		return progress;
	}

	protected void notifyChangeListeners() {
		Runnable r = () -> {
			synchronized (listeners) {
				for (CancelledListener mcl : listeners) {
					mcl.cancelled();
				}
			}
		};
		SwingUtilities.invokeLater(r);
	}

	@Override
	public void addCancelledListener(CancelledListener mcl) {
		synchronized (listeners) {
			listeners.add(mcl);
		}
	}

	@Override
	public void removeCancelledListener(CancelledListener mcl) {
		synchronized (listeners) {
			listeners.remove(mcl);
		}
	}

	@Override
	public void addIssueListener(IssueListener listener) {
		if (issueListeners == null) {
			issueListeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();
		}
	}

	@Override
	public void removeIssueListener(IssueListener listener) {
		if (issueListeners != null) {
			issueListeners.remove(listener);
		}

	}

	@Override
	public void reportIssue(Issue issue) {
		if (issueListeners != null) {
			for (IssueListener listener : issueListeners) {
				listener.issueReported(issue);
			}
		}
	}
}
