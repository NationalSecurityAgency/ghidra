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

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.util.AnimatedIcon;
import docking.widgets.OptionDialog;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.timer.GTimer;
import resources.ResourceManager;

/**
 * Dialog that is displayed to show activity for a Task that is running outside of the 
 * Swing Thread.
 */
public class TaskDialog extends DialogComponentProvider implements TaskMonitor {

	private static final int SLEEPY_TIME = 10;
	private final static int MAX_DELAY = 200000;
	public final static int DEFAULT_WIDTH = 275;

	private Timer showTimer;
	private TaskMonitorComponent monitorComponent;
	private AtomicInteger taskID = new AtomicInteger();
	private boolean canCancel;
	private Runnable updateMessage;
	private Runnable closeDialog;
	private Runnable enableCancelButton;
	private String newMessage;
	private boolean cancelState = true;
	private Component centerOnComp;
	private Runnable shouldCancelRunnable;
	private boolean done;
	private JPanel mainPanel;

	/** Creates new TaskDialog
	 * @param centerOnComp component to be centered over when shown,
	 * otherwise center over parent.  If both centerOnComp and parent
	 * are null, dialog will be centered on screen.
	 * @param task the Task that this dialog will be associated with
	 */
	public TaskDialog(Component centerOnComp, Task task) {
		this(centerOnComp, task.getTaskTitle(), task.isModal(), task.canCancel(),
			task.hasProgress());
	}

	/** Creates a new TaskDialog.
	 * @param task the Task that this dialog will be associated with
	 */
	public TaskDialog(Task task) {
		this(task.getTaskTitle(), task.canCancel(), task.isModal(), task.hasProgress());
	}

	/**
	 * Construct new TaskDialog.
	 * @param title title for the dialog
	 * @param canCancel true if the task can be canceled
	 * @param isModal true if the dialog should be modal
	 * @param hasProgress true if the dialog should show a progress bar
	 */
	public TaskDialog(String title, boolean canCancel, boolean isModal, boolean hasProgress) {
		this(null, title, isModal, canCancel, true /*hasProgress*/);
	}

	/**
	 * Construct new TaskDialog.
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
		setup(canCancel, hasProgress);
	}

	private void setup(boolean canCancel, boolean hasProgress) {
		this.canCancel = canCancel;
		setRememberLocation(false);
		setRememberSize(false);
		setTransient(true);
		closeDialog = () -> {
			close();
			dispose();
		};
		updateMessage = () -> {
			setStatusText(newMessage);
			synchronized (TaskDialog.this) {
				newMessage = null;
			}
		};
		enableCancelButton = () -> TaskDialog.super.setCancelEnabled(cancelState);
		shouldCancelRunnable = () -> {
			int currentTaskID = taskID.get();

			boolean doCancel = promptToVerifyCancel();
			if (doCancel && currentTaskID == taskID.get()) {
				cancel();
			}
		};

		monitorComponent = new TaskMonitorComponent(false, false);
		mainPanel = new JPanel(new BorderLayout());
		addWorkPanel(mainPanel);
		if (hasProgress) {
			installProgressMonitor();
		}
		else {
			installActivityDisplay();
		}

		if (canCancel) {
			addCancelButton();
		}

		// SPLIT the help for this dialog should not be in the front end plugin.
		setHelpLocation(new HelpLocation("Tool", "TaskDialog"));
	}

	protected boolean promptToVerifyCancel() {
		boolean userSaysYes = OptionDialog.showYesNoDialog(getComponent(), "Cancel?",
			"Do you really want to cancel \"" + getTitle() + "\"?") == OptionDialog.OPTION_ONE;

		return userSaysYes;
	}

	/**
	 * Creates the main work panel for the dialog
	 */
	private void installProgressMonitor() {
		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			mainPanel.removeAll();

			JPanel panel = new JPanel(new BorderLayout());
			panel.setBorder(BorderFactory.createEmptyBorder(20, 10, 5, 10));
			panel.add(monitorComponent);
			mainPanel.add(panel, BorderLayout.NORTH);

			repack();
		});
	}

	private void installActivityDisplay() {
		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			mainPanel.removeAll();

			List<Icon> iconList = new ArrayList<>();
			iconList.add(ResourceManager.loadImage("images/eatbits1.png"));
			iconList.add(ResourceManager.loadImage("images/eatbits2.png"));
			iconList.add(ResourceManager.loadImage("images/eatbits3.png"));
			iconList.add(ResourceManager.loadImage("images/eatbits4.png"));
			iconList.add(ResourceManager.loadImage("images/eatbits5.png"));
			iconList.add(ResourceManager.loadImage("images/eatbits6.png"));
			iconList.add(ResourceManager.loadImage("images/eatbits7.png"));
			AnimatedIcon icon = new AnimatedIcon(iconList, 200, 0);
			JPanel panel = new JPanel(new BorderLayout());
			panel.setSize(new Dimension(200, 100));
			panel.add(new JLabel(icon));
			mainPanel.add(panel, BorderLayout.CENTER);

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
	public void setShowProgressValue(boolean showProgressValue) {
		monitorComponent.setShowProgressValue(showProgressValue);
	}

	/** Sets the percentage done.
	 * @param param The percentage of the task completed.
	 */
	@Override
	public void setProgress(long param) {
		monitorComponent.setProgress(param);
	}

	@Override
	public void initialize(long max) {
		if (monitorComponent.isIndeterminate()) {
			// don't show the progress bar if we have already been marked as indeterminate (this
			// allows us to prevent low-level algorithms from changing the display settings).
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
	@Override
	public void setIndeterminate(final boolean indeterminate) {
		monitorComponent.setIndeterminate(indeterminate);
	}

	/** Called if the user presses the cancel button on
	 * the dialog
	 */
	@Override
	protected void cancelCallback() {
		synchronized (this) {
			if (!monitorComponent.isCancelEnabled() || monitorComponent.isCancelled()) {
				return;
			}
		}

		SwingUtilities.invokeLater(shouldCancelRunnable);
	}

	/** Sets the message in the TaskDialog dialog
	 * @param str The message string to be displayed
	 */
	@Override
	synchronized public void setMessage(String str) {
		boolean invoke = (newMessage == null);
		newMessage = str;
		if (invoke) {
			SwingUtilities.invokeLater(updateMessage);
		}
	}

	/**
	 * Set the enable state of the Cancel button.
	 * @param enable the state to set the cancel button.
	 */
	@Override
	public void setCancelEnabled(boolean enable) {
		if (canCancel) {
			monitorComponent.setCancelEnabled(enable);
			SwingUtilities.invokeLater(enableCancelButton);
		}
	}

	@Override
	public boolean isCancelEnabled() {
		return canCancel && cancelState;
	}

	public synchronized void taskProcessed() {
		done = true;
		monitorComponent.notifyChangeListeners();
		SwingUtilities.invokeLater(closeDialog);
	}

	public synchronized void reset() {
		done = false;
		taskID.incrementAndGet();
	}

	public synchronized boolean isCompleted() {
		return done;
	}

	@Override
	public boolean isCancelled() {
		return monitorComponent.isCancelled();
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
		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
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

		SystemUtilities.runSwingNow(disposeTask);
	}

	@Override
	public synchronized void cancel() {
		if (!canCancel || monitorComponent.isCancelled()) {
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

	@Override
	public void addIssueListener(IssueListener listener) {
		monitorComponent.addIssueListener(listener);
	}

	@Override
	public void removeIssueListener(IssueListener listener) {
		monitorComponent.removeIssueListener(listener);

	}

	@Override
	public void reportIssue(Issue issue) {
		monitorComponent.reportIssue(issue);
	}
}
