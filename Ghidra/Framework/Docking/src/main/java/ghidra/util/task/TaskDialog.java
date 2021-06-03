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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

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

	/** Amount of time to wait before showing the monitor dialog */
	private final static int MAX_DELAY = 200000;

	public final static int DEFAULT_WIDTH = 275;

	/*
	 * Note: all paths of finishing should end up calling this runnable.
	 * 
	 * Workflow:
	 * 
	 * Dialog Close Button Pressed:
	 * 	-calls cancelCallback()
	 *  -calls verifyCancel runnable
	 *  -calls iternalCancel()
	 *  -triggers taskProcessed()
	 *  -calls closeDialog runnable
	 *  
	 * Cancel Button Pressed:
	 * 	-(same as Dialog Close Button Pressed)
	 * 
	 * Task Monitor Stop Button Pressed:
	 *  -triggers taskProcessed()
	 *  -calls closeDialog runnable
	 *  
	 * Public API dispose() is Called:
	 *  -calls iternalCancel()
	 *  -triggers taskProcessed()
	 *  -calls closeDialog runnable
	 *  
	 * Task Monitor Cancelled by API:
	 *  -triggers taskProcessed()
	 *  -calls closeDialog runnable
	 *  
	 * Task Finishes Normally:
	 *  -triggers taskProcessed()
	 *  -calls closeDialog runnable
	 * 
	 * 
	 */
	private Runnable closeDialog = () -> {
		close();
		cleanup();
	};
	private Runnable verifyCancel = () -> {
		if (promptToVerifyCancel()) {
			internalCancel();
		}
	};

	private GTimerMonitor showTimer = GTimerMonitor.DUMMY;
	private CountDownLatch finished = new CountDownLatch(1);
	private boolean supportsProgress;

	private JPanel mainPanel;
	private JPanel activityPanel;
	private TaskMonitorComponent monitorComponent;
	private Component centerOnComponent;

	/** If not null, then the value of the string has yet to be rendered */
	private AtomicReference<String> newMessage = new AtomicReference<>();
	private SwingUpdateManager messageUpdater =
		new SwingUpdateManager(100, 250, () -> setStatusText(newMessage.getAndSet(null)));

	private AtomicBoolean shown = new AtomicBoolean();

	/**
	 * Constructor
	 *
	 * @param centerOnComp component to be centered over when shown, otherwise center over parent.
	 * If both centerOnComp and parent are null, dialog will be centered on screen.
	 * @param task the Task that this dialog will be associated with
	 * @param finished overrides the latch used by this dialog to know when the task is finished
	 */
	TaskDialog(Component centerOnComp, Task task, CountDownLatch finished) {
		this(centerOnComp, task.getTaskTitle(), task.isModal(), task.canCancel(),
			task.hasProgress());
		this.finished = finished;
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
		this.centerOnComponent = centerOnComp;
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

	private boolean isInstalled(Component c) {
		Component[] components = mainPanel.getComponents();
		for (Component component : components) {
			if (c == component) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Adds the panel that contains the progress bar to the dialog
	 */
	private void installProgressMonitor() {
		Swing.runIfSwingOrRunLater(() -> {

			if (isInstalled(monitorComponent)) {
				return;
			}

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

			if (isInstalled(activityPanel)) {
				return;
			}

			mainPanel.removeAll();
			mainPanel.add(activityPanel, BorderLayout.CENTER);
			repack();
		});
	}

	@Override
	protected void cancelCallback() {
		// note: this is called from the cancel button and when the dialog close button is pressed
		Swing.runLater(verifyCancel);
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

	/**
	 * Called after the task has been executed or when the task is cancelled
	 */
	public void taskProcessed() {
		finished.countDown();
		Swing.runLater(closeDialog);
	}

	/**
	 * Returns true if this dialog's task has completed normally or been cancelled
	 * @return true if this dialog's task has completed normally or been cancelled
	 */
	public boolean isCompleted() {
		return finished.getCount() == 0 || isCancelled();
	}

	/**
	 * Shows the dialog window centered on the parent window. Dialog display is delayed if delay
	 * greater than zero.
	 *
	 * @param delay number of milliseconds to delay displaying of the task dialog.  If the delay is
	 * greater than {@link #MAX_DELAY}, then the delay will be {@link #MAX_DELAY};
	 * @throws IllegalArgumentException if {@code delay} is negative
	 */
	public void show(int delay) {
		if (delay < 0) {
			throw new IllegalArgumentException("Task Dialog delay cannot be negative");
		}
		if (isModal()) {
			doShowModal(delay);
		}
		else {
			doShowNonModal(delay);
		}
	}

	/**
	 * Returns true if this dialog was ever made visible
	 * @return true if shown
	 */
	public boolean wasShown() {
		return shown.get();
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
		int waitTime = Math.min(delay, MAX_DELAY);
		showTimer = GTimer.scheduleRunnable(waitTime, () -> {
			if (isCompleted()) {
				return;
			}

			doShow();
		});
	}

	protected void doShow() {

		Swing.runIfSwingOrRunLater(() -> {
			if (!isCompleted()) {
				shown.set(true);
				DockingWindowManager.showDialog(centerOnComponent, TaskDialog.this);
			}
		});
	}

	private void giveTheTaskThreadAChanceToComplete(int delay) {

		int waitTime = Math.min(delay, MAX_DELAY);
		try {
			finished.await(waitTime, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			Msg.debug(this, "Interrupted waiting for task '" + getTitle() + "'", e);
		}
	}

	/**
	 * Cancels the task and closes this dialog
	 */
	public void dispose() {
		internalCancel();
	}

	private void cleanup() {
		showTimer.cancel();
		messageUpdater.dispose();
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

		if (max <= 0) {
			return;
		}

		monitorComponent.initialize(max);
		if (!supportsProgress) {
			supportsProgress = true;
			setIndeterminate(false);
		}

		// Note: it is not clear why we only wish to show progress if the monitor is not 
		// visible.  This seems wrong.   If someone knows, please update this code.
		//if (!monitorComponent.isShowing()) {
		installProgressMonitor();
		//}
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

		// Assumption: if the client calls this method to show progress, then we should honor 
		// that request.  If we find that nested monitor usage causes dialogs to incorrectly
		// toggle monitors, then we need to update those clients to use a wrapping style
		// monitor that prevents the behavior.
		if (supportsProgress) {
			installProgressMonitor();
		}
		else {
			installActivityDisplay();
		}
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
		internalCancel();
	}

	private void internalCancel() {
		if (monitorComponent.isCancelled()) {
			return;
		}

		// mark as cancelled; the task will terminate and the callback will dismiss this dialog
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
