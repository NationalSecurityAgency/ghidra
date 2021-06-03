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

import static javax.swing.SwingConstants.*;

import java.awt.Component;
import java.util.Objects;

import javax.swing.SwingConstants;

import ghidra.util.SystemUtilities;
import util.CollectionUtils;

/**
 * A builder object that allows clients to launch tasks in the background, with a progress
 * dialog representing the task.
 *
 * <P>Using this class obviates the need for clients to create full class objects to implement
 * the {@link Task} interface, which means less boiler-plate code.
 *
 * <P>An example of usage:
 * <pre>
 * {@literal
 * MonitoredRunnable r =
 *     monitor -> doWork(parameter, monitor);
 *     
 * new TaskBuilder("Task Title", r)
 *    .setHasProgress(true)
 *    .setCanCancel(true)
 *    .setStatusTextAlignment(SwingConstants.LEADING)
 *    .launchModal();
 * }</pre>
 *
 * Or,
 *
 * <pre>
 * {@literal
 * TaskBuilder.withRunnable(monitor -> doWork(parameter, monitor))
 *     .setTitle("Task Title")
 *     .setHasProgress(true)
 *     .setCanCancel(true)
 *     .setStatusTextAlignment(SwingConstants.LEADING)
 *     .launchModal();
 * }</pre>
 *
 *  Or,
 *
 * <pre>
 * TaskBuilder.withTask(new AwesomeTask(awesomeStuff)).launchModal();
 * </pre>
 *
 * Or,
 *
 * <pre>
 * {@link TaskLauncher#launch(Task) TaskLauncher.launch}(new AwesomeTask(awesomeStuff));
 * </pre>
 *
 *
 * <p>Note: this class will check to see if it is in a headless environment before launching
 * its task.  This makes it safe to use this class in headed or headless environments.
 */
public class TaskBuilder {

	private String title;
	private MonitoredRunnable runnable;

	private Component parent;
	private int launchDelay = -1;
	private int dialogWidth = TaskDialog.DEFAULT_WIDTH;
	private boolean hasProgress = true;
	private boolean canCancel = true;
	private boolean waitForTaskCompletion = false;
	private int statusTextAlignment = SwingConstants.CENTER;

	/**
	 * A convenience method to start a builder using the given runnable.  After calling this
	 * method you are still required to call {@link #setTitle(String)}.
	 *
	 * <p>This method allows for a more attractive fluent API usage than does the constructor
	 * (see the javadoc header).
	 *
	 * @param r the runnable
	 * @return this builder
	 */
	public static TaskBuilder withRunnable(MonitoredRunnable r) {
		return new TaskBuilder(r);
	}

	/**
	 * A convenience method to start a builder using the given task.  The
	 * {@link #setTitle(String) title} of the task will be the value of
	 * {@link Task#getTaskTitle()}.
	 *
	 * <p>This method allows for a more attractive fluent API usage than does the constructor
	 * (see the javadoc header).
	 *
	 * @param t the task
	 * @return this builder
	 */
	public static TaskBuilder withTask(Task t) {
		return new TaskBuilder(t.getTaskTitle(), t);
	}

	private TaskBuilder(MonitoredRunnable r) {
		this.runnable = Objects.requireNonNull(r);
	}

	/**
	 * Constructor
	 *
	 * @param title the required title for your task.  This will appear as the title of the
	 *        task dialog
	 * @param runnable the runnable that will be called when the task is run
	 */
	public TaskBuilder(String title, MonitoredRunnable runnable) {
		this.title = Objects.requireNonNull(title);
		this.runnable = Objects.requireNonNull(runnable);
	}

	/**
	 * Sets the title of this task.  The title must be set before calling any of the
	 * <code>launch</code> methods.
	 *
	 * @param title the title
	 * @return this builder
	 */
	public TaskBuilder setTitle(String title) {
		this.title = Objects.requireNonNull(title);
		return this;
	}

	/**
	 * Sets whether this task reports progress.   The default is <code>true</code>.
	 *
	 * @param hasProgress true if the task reports progress
	 * @return this builder
	 */
	public TaskBuilder setHasProgress(boolean hasProgress) {
		this.hasProgress = hasProgress;
		return this;
	}

	/**
	 * Sets whether the task can be cancelled.  The default is <code>true</code>.
	 *
	 * @param canCancel true if the task can be cancelled.
	 * @return this builder
	 */
	public TaskBuilder setCanCancel(boolean canCancel) {
		this.canCancel = canCancel;
		return this;
	}

	/**
	 * Sets the component over which the task dialog will be shown.  The default is <code>null</code>,
	 * which shows the dialog over the active window.
	 *
	 * @param parent the parent
	 * @return this builder
	 */
	public TaskBuilder setParent(Component parent) {
		this.parent = parent;
		return this;
	}

	/**
	 * Sets the amount of time that will pass before showing the dialog.  The default is
	 * {@link TaskLauncher#INITIAL_DELAY_MS} for non-modal tasks and
	 * {@link TaskLauncher#INITIAL_MODAL_DELAY_MS} for modal tasks.
	 *
	 * @param delay the delay time
	 * @return this builder
	 */
	public TaskBuilder setLaunchDelay(int delay) {
		SystemUtilities.assertTrue(delay >= 0, "Launch delay must be greater than 0");
		this.launchDelay = delay;
		return this;
	}

	/**
	 * The desired width of the dialog.  The default is {@link TaskDialog#DEFAULT_WIDTH}.
	 *
	 * @param width the width
	 * @return this builder
	 */
	public TaskBuilder setDialogWidth(int width) {
		SystemUtilities.assertTrue(width > 0, "Dialog width must be greater than 0");

		this.dialogWidth = width;
		return this;
	}

	/**
	 * Sets the horizontal text alignment of messages shown in the task dialog.  The
	 * default is {@link SwingConstants#CENTER}.  Valid values are {@link SwingConstants}
	 * LEADING, CENTER and TRAILING.
	 *
	 * @param alignment the alignment
	 * @return this builder
	 */
	public TaskBuilder setStatusTextAlignment(int alignment) {
		boolean isValid = CollectionUtils.isOneOf(alignment, LEADING, CENTER, TRAILING);
		SystemUtilities.assertTrue(isValid, "Illegal alignment argument: " + alignment);

		this.statusTextAlignment = alignment;
		return this;
	}

	/**
	 * Launches the task built by this builder, using a blocking modal dialog.  The task will
	 * be run in the current thread if in a headless environment.
	 */
	public void launchModal() {
		validate();

		boolean isModal = true;
		Task t = new TaskBuilderTask(isModal);
		if (SystemUtilities.isInHeadlessMode()) {
			t.monitoredRun(TaskMonitor.DUMMY);
			return;
		}

		// note: just calling the launcher will trigger the work
		int delay = getDelay(launchDelay, isModal);
		new TaskLauncher(t, parent, delay, dialogWidth);
	}

	/**
	 * Launches the task built by this builder, using a non-blocking dialog.  The task will
	 * be run in the current thread if in a headless environment.
	 */
	public void launchNonModal() {
		validate();

		boolean isModal = false;
		Task t = new TaskBuilderTask(isModal);
		if (SystemUtilities.isInHeadlessMode()) {
			t.monitoredRun(TaskMonitor.DUMMY);
			return;
		}

		// note: just calling the launcher will trigger the work
		int delay = getDelay(launchDelay, isModal);
		new TaskLauncher(t, parent, delay, dialogWidth);
	}

	/**
	 * Runs the task in a background thread with the given monitor that cannot be null.  This
	 * is a special case for clients that already have a task monitor widget in their UI and
	 * they wish to let it show the progress of the given task while not blocking the Swing
	 * thread.
	 *
	 * @param monitor the task monitor; may not be null
	 */
	public void launchInBackground(TaskMonitor monitor) {
		// validate(); // not needed since we are in the background
		Objects.requireNonNull(monitor);
		BackgroundThreadTaskLauncher launcher =
			new BackgroundThreadTaskLauncher(new TaskBuilderTask(false));
		launcher.run(monitor);
	}

	private void validate() {
		if (title == null) {
			throw new NullPointerException("Task title cannot be null");
		}
	}

	private static int getDelay(int userDelay, boolean isModal) {
		if (userDelay >= 0) {
			return userDelay;
		}

		if (isModal) {
			return TaskLauncher.INITIAL_MODAL_DELAY_MS;
		}
		return TaskLauncher.INITIAL_DELAY_MS;
	}

	private class TaskBuilderTask extends Task {
		TaskBuilderTask(boolean isModal) {
			super(title, canCancel, hasProgress, isModal, waitForTaskCompletion);
		}

		@Override
		public int getStatusTextAlignment() {
			return statusTextAlignment;
		}

		@Override
		public void run(TaskMonitor monitor) {
			runnable.monitoredRun(monitor);
		}
	}
}
