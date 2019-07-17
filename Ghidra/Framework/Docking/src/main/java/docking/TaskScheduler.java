/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Calls a method on the Ghidra Dialog to get a TaskManager.
 * The dialog shows a progress bar; this class schedules a task to run;
 * when the task completes notify the dialog to hide the progress bar.
 * 
 * 
 * 
 */
public class TaskScheduler implements Runnable {

	private DialogComponentProvider comp;
	private Task scheduledTask;
	private int scheduledDelay;
	private Task currentTask;
	private int currentDelay;
	private Thread taskThread;

	/**
	 * Constructs a new TaskScheduler
	 * @param comp the 
	 */

	TaskScheduler(DialogComponentProvider comp) {
		this.comp = comp;
	}

	/**
	 * Set the next task to run; does not affect a currently running
	 * task.
	 * @param task the next task to run.
	 * @param delay time in milliseconds to delay showing progress or activity.
	 */
	synchronized void set(Task task, int delay) {
		scheduledTask = task;
		scheduledDelay = delay;
		if (taskThread == null) {
			taskThread = new Thread(this, "Dialog Task Thread: " + comp.getTitle());
			taskThread.setPriority(Thread.MIN_PRIORITY);
			taskThread.start();
		}
	}

	/**
	 * @see java.lang.Runnable#run()
	 */
	@Override
	public void run() {

		while (hasTask()) {

			TaskMonitor tm = comp.showProgress(currentTask, currentDelay);
			currentTask.monitoredRun(tm);
		}
	}

	/**
	 * Get the currently running thread.
	 * @return null if no thread is running.
	 */
	public synchronized Thread getCurrentThread() {
		return taskThread;
	}

	/**
	 * Blocks until the current task completes.
	 *
	 */
	public void waitForCurrentTask() {
		Thread t = getCurrentThread();
		if (t != null) {
			try {
				t.join();
			}
			catch (InterruptedException e) {
				// guess we don't care
			}
		}
	}

	/**
	 * Clear the scheduled task; does not affect the currently running task.
	 *
	 */
	synchronized void clearScheduledTask() {
		scheduledTask = null;
	}

	/**
	 * Returns true if this task scheduler is in the process of running a task or has a pending
	 * task.
	 * @return true if this task scheduler is in the process of running a task or has a pending
	 * task.
	 */
	public synchronized boolean isBusy() {
		return taskThread != null || scheduledTask != null;
	}

	/**
	 * Return true if there is another task scheduled to run.
	 */
	private synchronized boolean hasTask() {
		if (scheduledTask == null) {
			taskThread = null;
			currentTask = null;
			return false;
		}
		currentTask = scheduledTask;
		currentDelay = scheduledDelay;
		scheduledTask = null;
		return true;
	}

}
