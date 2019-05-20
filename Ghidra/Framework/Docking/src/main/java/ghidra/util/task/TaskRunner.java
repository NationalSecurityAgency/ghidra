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
import java.util.concurrent.Executor;

import generic.concurrent.GThreadPool;
import generic.util.WindowUtilities;
import ghidra.util.Swing;
import ghidra.util.TaskUtilities;

/**
 * Helper class to launch the given task in a background thread, showing a task dialog if 
 * this task takes to long. See {@link TaskLauncher}.
 */
class TaskRunner {

	protected Task task;
	private Component parent;
	private int delay;
	private int dialogWidth;
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

	TaskRunner(Task task, Component parent, int delay, int dialogWidth) {
		this.task = task;
		this.parent = parent;
		this.delay = delay;
		this.dialogWidth = dialogWidth;
	}

	void run() {

		// note: we need to be on the Swing thread to create our UI widgets
		Swing.assertThisIsTheSwingThread(
			"The Task runner is required to be run from the Swing thread");

		this.taskDialog = buildTaskDialog(parent);

		startBackgroundThread(taskDialog);

		taskDialog.show(Math.max(delay, 0));
	}

	protected TaskDialog buildTaskDialog(Component comp) {

		//
		// This class may be used by background threads.  Make sure that our GUI creation is
		// on the Swing thread to prevent exceptions while painting (as seen when using the
		// Nimbus Look and Feel).
		//
		taskDialog = createTaskDialog(comp);
		taskDialog.setMinimumSize(dialogWidth, 0);

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
		GThreadPool pool = GThreadPool.getSharedThreadPool(Swing.GSWING_THREAD_POOL_NAME);
		Executor executor = pool.getExecutor();
		executor.execute(() -> {
			Thread.currentThread().setName(name);
			task.monitoredRun(monitor);
			taskDialog.taskProcessed();
		});
	}

	private TaskDialog createTaskDialog(Component comp) {
		Component currentParent = comp;
		if (currentParent != null) {
			currentParent = WindowUtilities.windowForComponent(comp);
		}

		if (currentParent == null) {
			return new TaskDialog(task);
		}
		return new TaskDialog(comp, task);
	}
}
