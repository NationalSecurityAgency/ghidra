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
import java.awt.Component;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.timer.GTimer;

/**
 * Dialog that is displayed to show activity for a Task that is running outside of the 
 * Swing Thread.
 * 
 * <p>Implementation note: 
 * if this class is constructed with a {@code hasProgress} value of {@code false},
 * then an activity component will be shown, not a progress monitor.   Any calls to update 
 * progress will not affect the display.   However, the display can be converted to use progress
 * by first calling {@link #setIndeterminate(boolean)} with a {@code false} value and then calling
 * {@link #initialize(long)}.    Once this has happened, this dialog will no longer use the
 * activity display--the progress bar is in effect for the duration of this dialog's usage.   
 * 
 * <p>This dialog can be toggled between indeterminate mode and progress mode via calls to 
 * {@link #setIndeterminate(boolean)}.
 */
public class TaskDialog extends DialogComponentProvider implements TaskMonitor {

	/** Timer used to give the task a chance to complete */
	private static final int SLEEPY_TIME = 10;

	/** Amount of time to wait before showing the monitor dialog */
	private final static int MAX_DELAY = 200000;

	public final static int DEFAULT_WIDTH = 275;

	private Timer showTimer;
	private AtomicInteger taskID = new AtomicInteger();
	private Runnable closeDialog;
	private Component centerOnComp;
	private Runnable shouldCancelRunnable;
	private boolean taskDone;
	private boolean supportsProgress;

	private JPanel mainPanel;
	private JPanel activityPanel;
	private TaskMonitorComponent monitorComponent;

	/** If not null, then the value of the string has yet to be rendered */
	private AtomicReference<String> newMessage = new AtomicReference<>();
	private SwingUpdateManager messageUpdater =
		new SwingUpdateManager(100, 250, () -> setStatusText(newMessage.getAndSet(null)));

	/** 
	 * Constructor
	 * 
	 * @param centerOnComp component to be centered over when shown,
	 * otherwise center over parent.  If both centerOnComp and parent
	 * are null, dialog will be centered on screen.
	 * @param task the Task that this dialog will be associated with
	 */
	public TaskDialog(Component centerOnComp, Task task) {
		this(centerOnComp, task.getTaskTitle(), task.isModal(), task.canCancel(),
			task.hasProgress());
	}

	/**
	 * Constructor
	 *  
	 * @param task the Task that this dialog will be associated with
	 */
	public TaskDialog(Task task) {
		this(task.getTaskTitle(), task.canCancel(), task.isModal(), task.hasProgress());
	}

	/**
	 * Constructor
	 * 
	 * @param title title for the dialog
	 * @param canCancel true if the task can be canceled
	 * @param isModal true if the dialog should be modal
	 * @param hasProgress true if the dialog should show a progress bar
	 */
	public TaskDialog(String title, boolean canCancel, boolean isModal, boolean hasProgress) {
		this(null, title, isModal, canCancel, hasProgress);
	}

	/**
	 * Constructor
	 * 
	 * @param centerOnComp component to be centered over when shown, otherwise center over 
	 *        parent.  If both centerOnComp is null, then the active window will be used
	 * @param title title for the dialog
	 * @param isModal true if the dialog should be modal
	 * @param canCancel true if the task can be canceled
	 * @param hasProgress true if the dialog should show a progress bar
	 */
	private TaskDialog(Component centerOnComp, String title, boolean isModal, boolean canCancel,
			boolean hasProgress) {
		super(title, isModal, true, canCancel, true);
		this.centerOnComp = centerOnComp;
		this.supportsProgress = hasProgress;
		setup(canCancel);
	}

	private void setup(boolean canCancel) {
		monitorComponent = new TaskMonitorComponent(false, false);
		activityPanel = new ChompingBitsAnimationPanel();

		setCancelEnabled(canCancel);
		setRememberLocation(false);
		setRememberSize(false);
		setTransient(true);
		closeDialog = () -> {
			close();
			dispose();
		};

		shouldCancelRunnable = () -> {
			int currentTaskID = taskID.get();

			boolean doCancel = promptToVerifyCancel();
			if (doCancel && currentTaskID == taskID.get()) {
				cancel();
			}
		};

		mainPanel = new JPanel(new BorderLayout());
		addWorkPanel(mainPanel);

		if (supportsProgress) {
			installProgressMonitor();
		}
		else {
			installActivityDisplay();
		}

		if (canCancel) {
			addCancelButton();
		}

		// SPLIT the help for this dialog should not be in the front end plugin.
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "TaskDialog"));
	}

	/**
	 * Shows a dialog asking the user if they really, really want to cancel the task
	 * 
	 * @return true if the task should be cancelled
	 */
	private boolean promptToVerifyCancel() {
		boolean userSaysYes = OptionDialog.showYesNoDialog(getComponent(), "Cancel?",
			"Do you really want to cancel \"" + getTitle() + "\"?") == OptionDialog.OPTION_ONE;
		return userSaysYes;
	}

	/**
	 * Adds the panel that contains the progress bar to the dialog
	 */
	private void installProgressMonitor() {
		Swing.runIfSwingOrRunLater(() -> {
			mainPanel.removeAll();
			mainPanel.add(monitorComponent, BorderLayout.CENTER);
			repack();
		});
	}

	/**
	 * Adds the panel that contains the activity panel (e.g., the eating bits animation) to the 
	 * dialog. This should only be called if the dialog has no need to display progress.
	 */
	private void installActivityDisplay() {
		Swing.runIfSwingOrRunLater(() -> {
			mainPanel.removeAll();
			mainPanel.add(activityPanel, BorderLayout.CENTER);
			repack();
		});
	}

	@Override
	protected void dialogShown() {
		// our task may have completed while we were queued up to be shown
		if (isCompleted()) {
			close();
		}
	}

	@Override
	protected void dialogClosed() {
		close();
	}

	@Override
	protected void cancelCallback() {
		SwingUtilities.invokeLater(shouldCancelRunnable);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		monitorComponent.setCancelEnabled(enable);
		Swing.runLater(() -> super.setCancelEnabled(enable));
	}

	@Override
	public boolean isCancelEnabled() {
		return monitorComponent.isCancelEnabled();
	}

	public synchronized void taskProcessed() {
		taskDone = true;
		monitorComponent.notifyChangeListeners();
		SwingUtilities.invokeLater(closeDialog);
	}

	public synchronized void reset() {
		taskDone = false;
		taskID.incrementAndGet();
	}

	public synchronized boolean isCompleted() {
		return taskDone;
	}

	/**
	 * Shows the dialog window centered on the parent window.
	 * Dialog display is delayed if delay greater than zero.
	 * @param delay number of milliseconds to delay displaying of the task dialog.  If the delay is
	 * greater than {@link #MAX_DELAY}, then the delay will be {@link #MAX_DELAY};
	 */
	public void show(int delay) {
		if (isModal()) {
			doShowModal(delay);
		}
		else {
			doShowNonModal(delay);
		}

	}

	private void doShowModal(int delay) {
		//
		// Note: we must block, since we are modal.  Clients want us to finish the task before
		//       returning
		//
		giveTheTaskThreadAChanceToComplete(delay);

		if (isCompleted()) {
			return;
		}

		doShow();
	}

	private void doShowNonModal(int delay) {
		//
		// Note: we must not block, as we are not modal.  Clients want control back.  Our job is
		//       only to show a progress dialog if enough time has elapsed.
		//
		GTimer.scheduleRunnable(delay, () -> {
			if (isCompleted()) {
				return;
			}

			doShow();
		});
	}

	protected void doShow() {
		Swing.runIfSwingOrRunLater(() -> {
			DockingWindowManager.showDialog(centerOnComp, TaskDialog.this);
		});
	}

	private void giveTheTaskThreadAChanceToComplete(int delay) {

		delay = Math.min(delay, MAX_DELAY);
		int elapsedTime = 0;
		while (!isCompleted() && elapsedTime < delay) {
			try {
				Thread.sleep(SLEEPY_TIME);
			}
			catch (InterruptedException e) {
				// don't care; we will try again
			}
			elapsedTime += SLEEPY_TIME;
		}
	}

	public void dispose() {

		Runnable disposeTask = () -> {
			if (showTimer != null) {
				showTimer.stop();
				showTimer = null;
			}
		};

		Swing.runNow(disposeTask);
	}

//==================================================================================================
// TaskMonitor Methods
//==================================================================================================

	@Override
	public void setMessage(String str) {
		newMessage.set(str);
		messageUpdater.update();
	}

	@Override
	public String getMessage() {
		return getStatusText();
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		monitorComponent.setShowProgressValue(showProgressValue);
	}

	@Override
	public void setProgress(long progress) {
		monitorComponent.setProgress(progress);
	}

	@Override
	public void initialize(long max) {

		if (!supportsProgress) {
			return;
		}

		if (!monitorComponent.isShowing()) {
			installProgressMonitor();
		}

		monitorComponent.initialize(max);
	}

	@Override
	public void setMaximum(long max) {
		monitorComponent.setMaximum(max);
	}

	@Override
	public long getMaximum() {
		return monitorComponent.getMaximum();
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		supportsProgress = !indeterminate;
		monitorComponent.setIndeterminate(indeterminate);
	}

	@Override
	public boolean isIndeterminate() {
		return monitorComponent.isIndeterminate();
	}

	@Override
	public boolean isCancelled() {
		return monitorComponent.isCancelled();
	}

	@Override
	public synchronized void cancel() {
		if (monitorComponent.isCancelled()) {
			return;
		}
		// Mark as cancelled, must be detected by task which should terminate
		// and invoke setCompleted which will dismiss dialog.
		monitorComponent.cancel();
	}

	@Override
	public synchronized void clearCanceled() {
		monitorComponent.clearCanceled();
	}

	@Override
	public void checkCanceled() throws CancelledException {
		monitorComponent.checkCanceled();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		monitorComponent.incrementProgress(incrementAmount);
	}

	@Override
	public long getProgress() {
		return monitorComponent.getProgress();
	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		monitorComponent.addCancelledListener(listener);
	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		monitorComponent.removeCancelledListener(listener);
	}

//==================================================================================================
// End TaskMonitor Methods
//==================================================================================================
}
