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
import java.util.concurrent.atomic.AtomicReference;

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

	private Thread taskThread;
	private CancelledListener monitorChangeListener = () -> {
		if (task.isInterruptible()) {
			taskThread.interrupt();
		}
		if (task.isForgettable()) {
			closeDialog(); // close the dialog and forget about the task
		}
	};

	private AtomicReference<TaskDialog> taskDialog = new AtomicReference<>();
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
		startBackgroundThread(monitor);

		showDialogIfSwingOrShowLaterAndWait(monitor);
	}

	private void showDialogIfSwingOrShowLaterAndWait(WrappingTaskMonitor monitor) {

		Swing.runIfSwingOrRunLater(() -> showTaskDialog(monitor));
		waitForModalIfNotSwing();
	}

	private void waitForModalIfNotSwing() {
		if (Swing.isSwingThread() || !task.isModal()) {
			// if this is the Swing thread, then the work is already done at this point; otherwise,
			// the task is not modal, so do not block
			return;
		}

		try {
			finished.await();
		}
		catch (InterruptedException e) {
			Msg.debug(this, "Task Launcher unexpectedly interrupted waiting for task thread", e);
		}
	}

	// protected to allow for dependency injection
	protected TaskDialog buildTaskDialog(Component comp) {

		//
		// This class may be used by background threads.  Make sure that our GUI creation is
		// on the Swing thread to prevent exceptions while painting (as seen when using the
		// Nimbus Look and Feel).
		//
		TaskDialog dialog = createTaskDialog(comp);
		dialog.setMinimumSize(dialogWidth, 0);

		if (task.isInterruptible() || task.isForgettable()) {
			dialog.addCancelledListener(monitorChangeListener);
		}

		dialog.setStatusJustification(task.getStatusTextAlignment());

		return dialog;
	}

	private void showTaskDialog(WrappingTaskMonitor monitor) {

		Swing.assertThisIsTheSwingThread("Must be on the Swing thread build the Task Dialog");

		if (finished.getCount() == 0) {
			return;
		}

		TaskDialog dialog = buildTaskDialog(parent);
		taskDialog.set(dialog);
		monitor.setDelegate(dialog); // initialize the dialog to the current state of the monitor
		dialog.show(Math.max(delayMs, 0));
	}

	private void startBackgroundThread(TaskMonitor monitor) {

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

	private void taskFinished() {
		finished.countDown();
		TaskDialog dialog = taskDialog.get();
		if (dialog != null) {
			dialog.taskProcessed();
		}
	}

	private void closeDialog() {
		TaskDialog dialog = taskDialog.get();
		if (dialog != null) {
			dialog.close();
		}
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
