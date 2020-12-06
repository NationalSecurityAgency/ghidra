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

import java.util.HashSet;
import java.util.Set;

import javax.swing.SwingConstants;

import ghidra.util.*;
import ghidra.util.exception.CancelledException;

/**
 * Base class for Tasks to be run in separate threads
 */
public abstract class Task implements MonitoredRunnable {
	private String title;
	private boolean canCancel;
	private boolean hasProgress;
	private boolean isModal;
	protected boolean waitForTaskCompleted = false;
	private Set<TaskListener> listeners = new HashSet<>();
	protected TaskMonitor taskMonitor = TaskMonitor.DUMMY;

	/**
	 * Creates new Task.
	 *
	 * @param title the title associated with the task
	 */
	public Task(String title) {
		this(title, true, false, false, false);
	}

	/**
	 * Construct a new Task.
	 * @param title title the title associated with the task
	 * @param canCancel true means that the user can cancel the task
	 * @param hasProgress true means that the dialog should show a
	 * progress indicator
	 * @param isModal true means that the dialog is modal and the task has to
	 * complete or be canceled before any other action can occur
	 */
	public Task(String title, boolean canCancel, boolean hasProgress, boolean isModal) {

		this(title, canCancel, hasProgress, isModal, false);
	}

	/**
	 * Construct a new Task.
	 * @param title title the title associated with the task
	 * @param canCancel true means that the user can cancel the task
	 * @param hasProgress true means that the dialog should show a
	 * progress indicator
	 * @param isModal true means that the dialog is modal and the task has to
	 * complete or be canceled before any other action can occur
	 * @param waitForTaskCompleted true causes the running thread to block until the finish or 
	 *  	  cancelled callback has completed on the swing thread.  Note: passing true 
	 *  	  only makes sense if the task is modal.
	 */
	public Task(String title, boolean canCancel, boolean hasProgress, boolean isModal,
			boolean waitForTaskCompleted) {

		this.title = title;
		this.canCancel = canCancel;
		this.hasProgress = hasProgress;
		this.isModal = isModal;
		if (waitForTaskCompleted && !isModal) {
			throw new IllegalStateException(
				"waitForTaskCompleted only makes sense if the task is modal");
		}
		this.waitForTaskCompleted = waitForTaskCompleted;
	}

	/**
	 * Get the title associated with the task
	 * @return String title shown in the dialog
	 */
	public final String getTaskTitle() {
		return title;
	}

	/**
	 * Returns the alignment of the text displayed in the modal dialog.  The default is
	 * {@link SwingConstants#CENTER}.   For status updates where the initial portion of the
	 * text does not change, {@link SwingConstants#LEADING} is recommended.  To change the
	 * default value, simply override this method and return one of {@link SwingConstants}
	 * CENTER, LEADING or TRAILING.
	 *
	 * @return the alignment of the text displayed
	 */
	public int getStatusTextAlignment() {
		return SwingConstants.CENTER;
	}

	/**
	 * When an object implementing interface <code>Runnable</code> is used to create a thread, 
	 * starting the thread causes the object's <code>run</code> method to be called in that 
	 * separately executing thread.
	 * 
	 * @param monitor the task monitor
	*/
	@Override
	public final void monitoredRun(TaskMonitor monitor) {
		this.taskMonitor = monitor;

		// this will be removed from SystemUtilities in Task.run() after the task is finished
		TaskUtilities.addTrackedTask(this, monitor);

		boolean isCancelled = false;
		try {
			run(monitor);
			isCancelled = monitor.isCancelled();
		}
		catch (CancelledException e) {
			Msg.debug(this, "Task cancelled: " + getTaskTitle());
		}
		catch (Throwable t) {
			Msg.showError(this, null, "Task Error",
				getTaskTitle() + " - Uncaught Exception: " + t.toString(), t);
		}
		finally {
			TaskUtilities.removeTrackedTask(this);
			this.taskMonitor = null;
		}

		notifyTaskListeners(isCancelled);
	}

	public void cancel() {
		if (taskMonitor != null) {
			taskMonitor.cancel();
		}
	}

	protected void notifyTaskListeners(final boolean wasCancelled) {
		if (listeners.isEmpty()) {
			return;
		}

		Runnable r = () -> {
			for (TaskListener listener : listeners) {
				if (wasCancelled) {
					listener.taskCancelled(Task.this);
				}
				else {
					listener.taskCompleted(Task.this);
				}
			}
		};

		if (waitForTaskCompleted) {
			Swing.runNow(r);
		}
		else {
			Swing.runLater(r);
		}
	}

	/**
	 * This is the method that will be called to do the work
	 * 
	 * <P>Note: The run(TaskMonitor) method should not make any calls directly
	 * on Swing components, as these calls are not thread safe. Place Swing
	 * calls in a Runnable, then call {@link Swing#runLater(Runnable)} or
	 * {@link Swing#runNow(Runnable)}to schedule the Runnable inside of
	 * the AWT Event Thread.
	 * 
	 * @param monitor The TaskMonitor that will monitor the executing Task
	 * @throws CancelledException if the task is cancelled.  Subclasses can trigger this exception
	 *                            by calling {@link TaskMonitor#checkCanceled()}.  This allows 
	 *                            them to break out of the current work stack. 
	 */
	public abstract void run(TaskMonitor monitor) throws CancelledException;

	/**
	 * Return true if the task has a progress indicator.
	 * @return boolean true if the task shows progress
	 */
	public boolean hasProgress() {
		return hasProgress;
	}

	/**
	 * Sets this task to have progress or not.  Note: changing this value after launching the
	 * task will have no effect.
	 * @param b true to show progress, false otherwise.
	 */
	public void setHasProgress(boolean b) {
		this.hasProgress = b;
	}

	/**
	 * Returns true if the task can be canceled.
	 * @return boolean true if the user can cancel the task
	 */
	public boolean canCancel() {
		return canCancel;
	}

	/**
	 * Returns true if the dialog associated with the task is modal.
	 * @return boolean true if the associated dialog is modal
	 */
	public boolean isModal() {
		return isModal;
	}

	/**
	 * Sets the task listener on this task.  It is a programming error to call this method more
	 * than once or to call this method if a listener was passed into the constructor of this class.
	 * @param listener the listener
	 */
	public void addTaskListener(TaskListener listener) {
		if (listener != null) {
			listeners.add(listener);
		}
	}
}
