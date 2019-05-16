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
 * Helper class to launch the given task in a background thread, showing a task dialog if 
 * this task takes to long. See {@link TaskLauncher}.
 */
class SwingTaskLauncher {

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

	SwingTaskLauncher(Task task, Component parent, int delay, int dialogWidth) {
		this.task = task;
		this.parent = parent;
		this.delay = delay;
		this.dialogWidth = dialogWidth;
	}

	void run() {
		this.taskDialog = buildTaskDialog(parent);

		startBackgroundThread(taskDialog);

		taskDialog.show(Math.max(delay, 0));

		waitIfNotSwing();
	}

	private void waitIfNotSwing() {
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

	protected TaskDialog buildTaskDialog(Component comp) {

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
