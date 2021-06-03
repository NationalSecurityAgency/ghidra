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

import java.awt.CardLayout;
import java.awt.Component;

import javax.swing.*;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;

/**
 * Helper class to execute a Runnable in a separate thread and provides a
 * progress monitor component that is shown as needed. This class can support several
 * different scheduling models described below.
 * <p>
 * 1) Only allow one runnable at any given time.  In this model, a new runnable will cause any running
 * runnable to be cancelled and the new runnable will begin running. Because of this, there will
 * never be any runnables waiting in the queue. Use the {@link #runNow(MonitoredRunnable, String)} 
 * method to get this behavior.
 * <p>
 * 2) Allow one running runnable and one pending runnable.  In this mode, any running runnable will be
 * allowed to complete, but any currently pending runnable will be replaced by the new runnable. Use
 * the {@link #runNext(MonitoredRunnable, String)} method to get this behavior.
 * <p>
 * 3) Run all scheduled runnables in the order they are scheduled.  Use the 
 * {@link #runLater(MonitoredRunnable, String, int)} for this behavior.
 * <p>
 * If the given runnable has Swing work to perform after the main Runnable.run() method completes
 * (e.g., updating Swing components),
 * the runnable should implement the {@link SwingRunnable} interface and perform this work in
 * {@link SwingRunnable#swingRun(boolean)}.
 * <p>
 * The progress monitor component, retrieved via {@link #getMonitorComponent()}, can be placed
 * into a Swing widget.  This RunManager will show and hide this progress component as necessary
 * when runnables are being run.
 *
 * @see SwingRunnable
 */
public class RunManager {

	private static final int SHOW_PROGRESS_DELAY = 500;
	private final static String DEFAULT = "Default Panel";
	private final static String PROGRESS = "Progress Panel";

	private CardLayout cardLayout; // layout for progress panel
	private JPanel progressPanel;
	private final Component defaultComponent;
	private TaskMonitorComponent monitor;
	private final Worker worker;
	private final String runManagerName;
	private TaskListener taskListener;

	public RunManager() {
		this(null, null, null);
	}

	public RunManager(TaskListener listener) {
		this(null, null, listener);
	}

	public RunManager(String name, Component defaultComponent) {
		this(name, defaultComponent, null);
	}

	public RunManager(String name, Component defaultComponent, TaskListener listener) {
		this.runManagerName = name;
		this.defaultComponent = defaultComponent;
		this.taskListener = listener;

		createProgressPanel();

		worker = new Worker(name == null ? "Run Manager Worker" : "Run Manager Worker: " + name,
			monitor);
		worker.setBusyListener(busy -> {
			if (!busy) {
				Runnable r = () -> showProgressPanel(false);
				SwingUtilities.invokeLater(r);
			}
		});
	}

	private void createProgressPanel() {
		cardLayout = new CardLayout();
		progressPanel = new JPanel(cardLayout);

		if (defaultComponent == null) {
			progressPanel.setVisible(false);
		}
		else {
			progressPanel.add(defaultComponent, DEFAULT);
		}

		monitor = new TaskMonitorComponent();
		progressPanel.add(monitor, PROGRESS);
	}

	private void showProgressPanel(boolean showProgress) {
		if (defaultComponent == null) {
			progressPanel.setVisible(showProgress);
		}
		else {
			cardLayout.show(progressPanel, showProgress ? PROGRESS : DEFAULT);
		}
	}

	private void cancelRunnables() {
		worker.clearAllJobsWithInterrupt_IKnowTheRisks();
	}

//==================================================================================================
// Public Methods
//==================================================================================================

	public JComponent getMonitorComponent() {
		return progressPanel;
	}

	public void dispose() {
		worker.dispose();
	}

	/**
	 * A convenience method to cancel the any currently running job and any scheduled jobs.  Note:
	 * this method does not block or wait for the currently running job to finish.
	 */
	public void cancelAllRunnables() {
		worker.clearAllJobs();
	}

	public void waitForNotBusy(int maxWaitMillis) {
		worker.waitUntilNoJobsScheduled(maxWaitMillis);
	}

	/**
	 * Cancels any currently running runnable, clears any queued runnables, and then runs the given
	 * runnable.
	 * <p>
	 * See the class header for more info.
	 *
	 * @param runnable Runnable to execute
	 * @param taskName name of runnable; may be null (this will appear in the progress panel)
	 */
	public void runNow(MonitoredRunnable runnable, String taskName) {
		runNow(runnable, runManagerName, SHOW_PROGRESS_DELAY);
	}

	/**
	 * Cancels any currently running runnable, clears any queued runnables, and then runs the given
	 * runnable.
	 * <p>
	 * See the class header for more info.
	 *
	 * @param runnable Runnable to execute
	 * @param taskName name of runnable; may be null (this will appear in the progress panel)
	 * @param showProgressDelay the amount of time (in milliseconds) before showing the progress
	 *        panel
	 */
	public void runNow(MonitoredRunnable runnable, String taskName, int showProgressDelay) {
		if (runnable == null) {
			throw new IllegalArgumentException("Runnable cannot be null!");
		}

		cancelRunnables();
		worker.schedule(new RunnerJob(this, taskName, runnable, showProgressDelay));
	}

	/**
	 * Allows any currently running runnable to finish, clears any queued runnables,
	 * and then queues the given runnable to be run after the current runnable finishes.
	 * <p>
	 * This call will use the default {@link #SHOW_PROGRESS_DELAY delay} of
	 * {@value #SHOW_PROGRESS_DELAY}.
	 * <p>
	 * See the class header for more info.
	 *
	 * @param runnable Runnable to execute
	 * @param taskName name of runnable; may be null (this will appear in the progress panel)
	 */
	public void runNext(MonitoredRunnable runnable, String taskName) {
		runNext(runnable, taskName, SHOW_PROGRESS_DELAY);
	}

	/**
	 * Allows any currently running runnable to finish, clears any queued runnables,
	 * and then queues the given runnable to be run after the current runnable finishes.
	 * <p>
	 * See the class header for more info.
	 *
	 * @param runnable Runnable to execute
	 * @param taskName name of runnable; may be null (this will appear in the progress panel)
	 * @param showProgressDelay the amount of time (in milliseconds) before showing the progress
	 *        panel
	 */
	public void runNext(MonitoredRunnable runnable, String taskName, int showProgressDelay) {
		if (runnable == null) {
			throw new IllegalArgumentException("Runnable cannot be null!");
		}

		worker.clearPendingJobs();
		worker.schedule(new RunnerJob(this, taskName, runnable, showProgressDelay));
	}

	/**
	 * Schedules this runnable to be run after all runnables currently queued.
	 * <P>
	 * This method differs from the {@link #runNow(MonitoredRunnable, String, int)} methods in that it will
	 * not cancel any currently running jobs.  This allows you to add new jobs to this run
	 * manager, which lets them queue up. See header docs for details.
	 *
	 * @param runnable The runnable to run
	 * @param taskName The name of the task to run
	 * @param showProgressDelay The amount of time to wait before showing a progress monitor.
	 */
	public void runLater(MonitoredRunnable runnable, String taskName, int showProgressDelay) {
		if (runnable == null) {
			throw new IllegalArgumentException("Runnable cannot be null!");
		}

		worker.schedule(new RunnerJob(this, taskName, runnable, showProgressDelay));
	}

	public boolean isInProgress() {
		return worker.isBusy();
	}

	/**
	 * Show the cancel button according to the showCancel parameter.
	 * @param showCancel true means to show the cancel button
	 */
	public void showCancelButton(boolean showCancel) {
		monitor.setCancelButtonVisibility(showCancel);
	}

	/**
	 * Show the progress bar according to the showProgress parameter.
	 * @param showProgress true means to show the progress bar
	 */
	public void showProgressBar(boolean showProgress) {
		monitor.showProgress(showProgress);
	}

	/**
	 * Show the progress icon according to the showIcon parameter.
	 * @param showIcon true means to show the progress icon
	 */
	public void showProgressIcon(boolean showIcon) {
		monitor.showProgressIcon(showIcon);
	}

	private void notifyTaskCompleted(final MonitoredRunnable monitoredRunnable) {
		if (taskListener == null) {
			return;
		}

		Runnable runnable = () -> taskListener.taskCompleted(null);
		SwingUtilities.invokeLater(runnable);
	}

	private void notifyTaskCancelled(final MonitoredRunnable monitoredRunnable) {
		if (taskListener == null) {
			return;
		}

		Runnable runnable = () -> taskListener.taskCancelled(null);
		SwingUtilities.invokeLater(runnable);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class RunnerJob extends Job {

		private volatile boolean progressDone;

		private final RunManager runManager;
		private final MonitoredRunnable runnable;
		private final String name;
		private Timer showTimer;
		private final int delay;

		RunnerJob(RunManager runManager, String taskName, MonitoredRunnable runnable, int delay) {
			this.runManager = runManager;
			this.name = taskName;
			this.runnable = runnable;
			this.delay = delay;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				doExecute(monitor);
			}
			catch (Exception e) {
				progressDone = true;
				Msg.error(this, "Unexpected error processing runnable: " + name, e);
			}
			finally {
				if (monitor.isCancelled()) {
					runManager.notifyTaskCancelled(runnable);
				}
				else {
					runManager.notifyTaskCompleted(runnable);
				}
			}
		}

		private void doExecute(TaskMonitor monitor) {

			trace("execute() - initialize monitor");
			initializeMonitor(monitor);

			trace("showProgress()");
			showProgress();

			trace("running runnable");
			runnable.monitoredRun(monitor);

			trace("progress = true");
			progressDone = true;

			trace("calling SwingRunnable callback");
			SystemUtilities.runSwingNow(new SwingRunner(monitor.isCancelled()));

			trace("completed = true");

			trace("exiting");
		}

		private void initializeMonitor(TaskMonitor monitor) {
			String text = name == null ? "" : name;
			monitor.setMessage(text);
		}

		private void showProgress() {
			Runnable showProgressRunnable = () -> {
				trace("showProgress() invokeLater() posted");

				if (delay <= 0) {
					runManager.showProgressPanel(true);
				}
				else {
					showTimer = new Timer(delay, event -> {
						if (!progressDone) {
							runManager.showProgressPanel(true);
							showTimer = null;
						}
					});
					showTimer.setInitialDelay(delay);
					showTimer.setRepeats(false);
					showTimer.start();
				}
			};
			SwingUtilities.invokeLater(showProgressRunnable);
		}

		private class SwingRunner implements Runnable {
			private boolean wasCancelled;

			public SwingRunner(boolean cancelledWhileRunning) {
				// cancelledWhileRunning is true if we were started and then cancelled; 
				// isCancelled() is true if we were never started, but cancelled
				boolean cancelledBeforeStarted = isCancelled();
				this.wasCancelled = cancelledWhileRunning || cancelledBeforeStarted;
			}

			@Override
			public void run() {

				if (runnable instanceof SwingRunnable) {
					SwingRunnable swingRunnable = (SwingRunnable) runnable;

					try {
						swingRunnable.swingRun(wasCancelled);
					}
					catch (Throwable t) {
						Msg.error(runManager, "Unexpected Exception Running Job", t);
					}
				}
			}
		}

		private void trace(String message) {
//			No trace for you!
//			Msg.debug(this, message);
		}
	}

}
