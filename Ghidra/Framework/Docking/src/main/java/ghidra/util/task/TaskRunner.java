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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;

import generic.concurrent.GThreadPool;
import generic.util.WindowUtilities;
import ghidra.util.*;

/**
 * Helper class to launch the given task in a background thread, showing a task dialog if 
 * this task takes to long. See {@link TaskLauncher}.
 */
class TaskRunner {

	private Task task;
	private Component parent;
	private int delayMs;
	private int dialogWidth;

	private TaskDialog taskDialog;
	private CountDownLatch finished = new CountDownLatch(1);

	TaskRunner(Task task, Component parent, int delayMs, int dialogWidth) {
		this.task = task;
		this.parent = parent;
		this.delayMs = delayMs;
		this.dialogWidth = dialogWidth;
	}

	void run() {

		BasicTaskMonitor internalMonitor = new BasicTaskMonitor();
		WrappingTaskMonitor monitor = new WrappingTaskMonitor(internalMonitor);
		startTaskThread(monitor);

		Swing.runIfSwingOrRunLater(() -> showTaskDialog(monitor));
		waitForModalTask();
	}

	private void waitForModalTask() {

		if (!task.isModal()) {
			return; // we do not wait for non-modal tasks
		}

		try {
			// fun note: if this is the Swing thread, then it will not wait, as the Swing thread
			// was blocked by the modal dialog in the call before this one
			finished.await();
		}
		catch (InterruptedException e) {
			Msg.debug(this, "Task Launcher unexpectedly interrupted waiting for task thread", e);
		}
	}

	// protected to allow for dependency injection
	protected TaskDialog buildTaskDialog(Component comp, TaskMonitor monitor) {

		TaskDialog dialog = createTaskDialog(comp);
		dialog.setMinimumSize(dialogWidth, 0);
		dialog.setStatusJustification(task.getStatusTextAlignment());
		return dialog;
	}

	private void startTaskThread(TaskMonitor monitor) {

		// add the task here, so we can track it before it is actually started by the thread
		TaskUtilities.addTrackedTask(task, monitor);

		String name = "Task - " + task.getTaskTitle();
		GThreadPool pool = GThreadPool.getSharedThreadPool(Swing.GSWING_THREAD_POOL_NAME);
		Executor executor = pool.getExecutor();
		executor.execute(() -> {
			Thread.currentThread().setName(name);

			try {
				task.monitoredRun(monitor);
			}
			finally {
				taskFinished();
			}
		});
	}

	private TaskDialog createTaskDialog(Component comp) {
		Component centerOverComponent = comp;
		Component currentParent = centerOverComponent;
		if (currentParent != null) {
			currentParent = WindowUtilities.windowForComponent(comp);
		}

		if (currentParent == null) {
			centerOverComponent = null;
		}

		return new TaskDialog(centerOverComponent, task) {

			// note: we override this method here to help with the race condition where the 
			//       TaskRunner does not yet know about the task dialog, but the background
			//       thread has actually finished the work.
			@Override
			public synchronized boolean isCompleted() {
				return super.isCompleted() || isFinished();
			}
		};
	}

	private void showTaskDialog(WrappingTaskMonitor monitor) {

		Swing.assertSwingThread("Must be on the Swing thread build the Task Dialog");

		taskDialog = buildTaskDialog(parent, monitor);
		monitor.setDelegate(taskDialog); // initialize the dialog to the current state of the monitor
		taskDialog.show(Math.max(delayMs, 0));
	}

	/*testing*/ boolean isFinished() {
		return finished.getCount() == 0;
	}

	private void taskFinished() {
		finished.countDown();

		// Do this later on the Swing thread to handle the race condition where the dialog 
		// did not exist at the time of this call, but was in the process of being created
		Swing.runLater(() -> {
			if (taskDialog != null) {
				taskDialog.taskProcessed();
			}
		});
	}
}
