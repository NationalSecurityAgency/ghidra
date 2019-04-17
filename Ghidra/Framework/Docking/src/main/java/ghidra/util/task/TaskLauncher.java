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

import java.awt.Component;

import javax.swing.SwingUtilities;

import generic.util.WindowUtilities;
import ghidra.util.*;

/**
 * Class to initiate a Task in a new Thread, and to show a progress dialog that indicates
 * activity.  The progress dialog will show an animation in the event that the task of this class
 * cannot show progress.
 *
 * <p>For complete control of how this class functions, use
 * {@link #TaskLauncher(Task, Component, int, int)}.  Alternatively, for simpler uses,
 * see one of the many static convenience methods.
 *
 * <a name="modal_usage"></a>
 * <p><a name="modal_usage"></a>Most clients of this class should not be concerned with where 
 * the dialog used by this class will appear.  By default, it will be shown over 
 * the active window, which is the desired
 * behavior for most uses.  If you should need a dialog to appear over a non-active window,
 * then either specify that window, or a child component of that window, by calling a
 * constructor that takes in a {@link Component}.  Further, if you task is modal, then the
 * progress dialog should always be shown over the active window so that users understand that
 * their UI is blocked.  In this case, there is no need to specify a component over which to
 * show the dialog.
 *
 * <P>An alternative to using this class is to use the {@link TaskBuilder}, which offers a
 * more <i>Fluent API</i> approach for your tasking needs.
 */
public class TaskLauncher {

//==================================================================================================
// Static Launcher Methods
//==================================================================================================

	/**
	 * Directly launches a {@link Task} via a new {@link TaskLauncher} instance, with
	 * a progress dialog.
	 * <p>
	 * See also {@link TaskLauncher#TaskLauncher(Task, Component)}
	 *
	 * @param task {@link Task} to run in another thread
	 * @return the original {@link Task} (for chaining)
	 */
	public static <T extends Task> T launch(T task) {
		new TaskLauncher(task);
		return task;
	}

	/**
	 * A convenience method to directly run a {@link MonitoredRunnable} in a separate
	 * thread as a {@link Task}, displaying a non-modal progress dialog.
	 * <p>
	 * <code>
	 * TaskLauncher.launchNonModal( "My task", <br>
	 *  &nbsp;&nbsp;null, // parent<br>
	 * 	&nbsp;&nbsp;monitor -> { while ( !monitor.isCanceled() ) { longRunningWork(); } }<br>
	 * );
	 * </code>
	 *
	 * <p>Note: the task created by this call will be both cancellable and have progress.  If
	 * you task cannot be cancelled or does not have progress, then do not use this
	 * convenience method, but rather call one of the constructors of this class.
	 *
	 * <p>See <a href="#modal_usage">notes on non-modal usage</a>
	 *
	 * @param title name of the task thread that will be executing this task.
	 * @param runnable {@link MonitoredRunnable} that takes a {@link TaskMonitor}.
	 */
	public static void launchNonModal(String title, MonitoredRunnable runnable) {

		new TaskLauncher(new Task(title, true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				runnable.monitoredRun(monitor);
			}
		}, null, INITIAL_DELAY);
	}

	/**
	 * A convenience method to directly run a {@link MonitoredRunnable} in a separate
	 * thread as a {@link Task}, displaying a <b>modal</b> progress dialog.
	 * <p>
	 * <code>
	 * TaskLauncher.launchModal( "My task", <br>
	 *  &nbsp;&nbsp;null, // parent<br>
	 * 	&nbsp;&nbsp;monitor -> { while ( !monitor.isCanceled() ) { longRunningWork(); } }<br>
	 * );
	 * </code>
	 *
	 * <p>Note: the task created by this call will be both cancellable and have progress.  If
	 * you task cannot be cancelled or does not have progress, then do not use this
	 * convenience method, but rather call one of the constructors of this class or
	 * {@link #launchModal(String, MonitoredRunnable)}.
	 *
	 * @param title name of the task thread that will be executing this task.
	 * @param runnable {@link MonitoredRunnable} that takes a {@link TaskMonitor}.
	 */
	public static void launchModal(String title, MonitoredRunnable runnable) {

		new TaskLauncher(new Task(title, true, true, true) {
			@Override
			public void run(TaskMonitor monitor) {
				runnable.monitoredRun(monitor);
			}
		}, null, INITIAL_MODAL_DELAY);
	}

	/**
	 * A convenience method to directly run a {@link Runnable} in a separate
	 * thread as a {@link Task}, displaying a non-modal progress dialog.
	 *
	 * <p>This modal will be launched immediately, without delay.  Typically this launcher will
	 * delay showing the modal dialog in order to prevent the dialog from being show, just
	 * to have it immediately go away.  If you desire this default behavior, then do not use
	 * this convenience method.
	 *
	 * <p><code>
	 * TaskLauncher.launchModal( "My task", <br>
	 * 	&nbsp;&nbsp;monitor -> { { foo(); }<br>
	 * );
	 * </code>
	 *
	 * <p>Note: the task created by this call will not be cancellable nor have progress.  If
	 * you need either of these behaviors, the do not use this
	 * convenience method, but rather call one of the constructors of this class.
	 *
	 * @param title name of the task thread that will be executing this task.
	 * @param runnable {@link Runnable} to be called in a background thread
	 */
	public static void launchModal(String title, Runnable runnable) {
		Task t = new Task(title, false, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				runnable.run();
			}
		};

		int delay = 0;
		new TaskLauncher(t, null, delay);
	}

//==================================================================================================
// End Static Launcher Methods
//==================================================================================================

	static final int INITIAL_DELAY = 1000;// 1 second

	/** The time, for modal tasks, to try and run before blocking and showing a dialog */
	public static final int INITIAL_MODAL_DELAY = 500;

	protected Task task;
	private TaskDialog taskDialog;
	private Thread taskThread;
	private CancelledListener monitorChangeListener = () -> {
		if (task.isInterruptible()) {
			taskThread.interrupt();
		}
		if (task.isForgettable()) {
			taskDialog.close(); // close the dialog and forget about the task
		}
	};

	private static Component getParent(Component parent) {
		if (parent == null) {
			return null;
		}

		return (parent.isVisible() ? parent : null);
	}

	/**
	 * Constructor for TaskLauncher.
	 *
	 * <p>This constructor assumes that if a progress dialog is needed, then it should appear
	 * over the active window.  If you should need a dialog to appear over a non-active window,
	 * then either specify that window or a component within that window by calling a
	 * constructor that takes in a {@link Component}.
	 *
	 * @param task task to run in another thread (other than the Swing Thread)
	 *
	 */
	public TaskLauncher(Task task) {
		this(task, null, task.isModal() ? INITIAL_MODAL_DELAY : INITIAL_DELAY);
	}

	/**
	 * Constructor for TaskLauncher.
	 *
	 * <p>See <a href="#modal_usage">notes on modal usage</a>
	 *
	 * @param task task to run in another thread (other than the Swing Thread)
	 * @param parent component whose window to use to parent the dialog.
	 */
	public TaskLauncher(Task task, Component parent) {
		this(task, getParent(parent), task.isModal() ? INITIAL_MODAL_DELAY : INITIAL_DELAY);
	}

	/**
	 * Construct a new TaskLauncher.
	 *
	 * <p>See <a href="#modal_usage">notes on modal usage</a>
	 *
	 * @param task task to run in another thread (other than the Swing Thread)
	 * @param parent component whose window to use to parent the dialog; null centers the task
	 *        dialog over the current window
	 * @param delay number of milliseconds to delay until the task monitor is displayed
	 */
	public TaskLauncher(Task task, Component parent, int delay) {
		this(task, parent, delay, TaskDialog.DEFAULT_WIDTH);
	}

	/**
	 * Construct a new TaskLauncher.
	 *
	 * <p>See <a href="#modal_usage">notes on modal usage</a>
	 *
	 * @param task task to run in another thread (other than the Swing Thread)
	 * @param parent component whose window to use to parent the dialog; null centers the task
	 *        dialog over the current window
	 * @param delay number of milliseconds to delay until the task monitor is displayed
	 * @param dialogWidth The preferred width of the dialog (this allows clients to make a wider
	 *        dialog, which better shows long messages).
	 */
	public TaskLauncher(Task task, Component parent, int delay, int dialogWidth) {

		this.task = task;
		this.taskDialog = buildTaskDialog(parent, dialogWidth);

		startBackgroundThread(taskDialog);

		taskDialog.show(Math.max(delay, 0));

		waitForModalIfNotSwing();
	}

	private void waitForModalIfNotSwing() {
		if (SwingUtilities.isEventDispatchThread() || !task.isModal()) {
			return;
		}

		try {
			taskThread.join();
		}
		catch (InterruptedException e) {
			Msg.debug(this, "Task Launcher unexpectedly interrupted waiting for task thread", e);
		}
	}

	/**
	 * Constructor where an external taskMonitor is used.  Normally, this class will provide
	 * the {@link TaskDialog} as the monitor.  This constructor is useful when you want to run
	 * the task and use a monitor that is embedded in some other component.
	 *
	 * <p>See <a href="#modal_usage">notes on modal usage</a>
	 *
	 * @param task task to run in another thread (other than the Swing Thread)
	 * @param taskMonitor the monitor to use while running the task.
	 */
	public TaskLauncher(Task task, TaskMonitor taskMonitor) {

		this.task = task;

		startBackgroundThread(taskMonitor);

	}

	private TaskDialog buildTaskDialog(Component comp, int dialogWidth) {

		//
		// This class may be used by background threads.  Make sure that our GUI creation is
		// on the Swing thread to prevent exceptions while painting (as seen when using the
		// Nimbus Look and Feel).
		//

		SystemUtilities.runSwingNow(() -> {
			taskDialog = createTaskDialog(comp);
			taskDialog.setMinimumSize(dialogWidth, 0);
		});

		if (task.isInterruptible() || task.isForgettable()) {
			taskDialog.addCancelledListener(monitorChangeListener);
		}

		taskDialog.setStatusJustification(task.getStatusTextAlignment());

		return taskDialog;
	}

	private void startBackgroundThread(TaskMonitor monitor) {

		// add the task here, so we can track it before it is actually started by the thread
		TaskUtilities.addTrackedTask(task, monitor);

		String name = "Task - " + task.getTaskTitle();
		taskThread = new Thread(() -> {
			task.monitoredRun(monitor);
			taskProcessed();
		}, name);
		taskThread.setPriority(Thread.MIN_PRIORITY);
		taskThread.start();
	}

	private void taskProcessed() {
		if (taskDialog != null) {
			taskDialog.taskProcessed();
		}
	}

	protected TaskDialog createTaskDialog(Component comp) {
		Component parent = comp;
		if (parent != null) {
			parent = WindowUtilities.windowForComponent(comp);
		}

		if (parent == null) {
			return new TaskDialog(task);
		}
		return new TaskDialog(comp, task);
	}
}
