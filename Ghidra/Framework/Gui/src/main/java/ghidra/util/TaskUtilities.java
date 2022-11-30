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
package ghidra.util;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class TaskUtilities {

	private static Map<Task, TaskMonitor> runningTasks = new ConcurrentHashMap<>();
	private static List<TrackedTaskListener> listeners = new CopyOnWriteArrayList<>();

	/**
	 * Adds a listener that will be notified when tasks are tracked (when they are added and
	 * removed from tracking).
	 * @param listener The listener to add.
	 */
	public static void addTrackedTaskListener(TrackedTaskListener listener) {
		listeners.remove(listener); // don't double-add the listener
		listeners.add(listener);
	}

	/**
	 * Removes the given listener added via {@link #addTrackedTask(Task,TaskMonitor)}.
	 * @param listener The listener that needs to be removed.
	 */
	public static void removeTrackedTaskListener(TrackedTaskListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Adds a Task to the list of tasks that have not yet finished running.  
	 * <P>
	 * Note: it is safe to add the same task more than once, as it will not be repeatedly 
	 * tracked.
	 * 
	 * @param task The task to watch
	 * @param monitor the task monitor for the given task
	 */
	public static void addTrackedTask(Task task, TaskMonitor monitor) {
		if (!SystemUtilities.isInTestingMode()) {
			return;
		}

		if (runningTasks.containsKey(task)) {
			return;
		}

		runningTasks.put(task, monitor);
		for (TrackedTaskListener listener : listeners) {
			listener.taskAdded(task);
		}
	}

	/**
	 * Removes the Task to the list of tasks that have not yet finished running.
	 * @param task The task to stop watching.
	 */
	public static void removeTrackedTask(Task task) {
		if (!SystemUtilities.isInTestingMode()) {
			return;
		}

		runningTasks.remove(task);
		for (TrackedTaskListener listener : listeners) {
			listener.taskRemoved(task);
		}
	}

	/**
	 * Returns true if there are tasks that are running or need to be run.
	 * @return true if there are tasks that are running or need to be run.
	 */
	public static boolean isExecutingTasks() {
		if (SystemUtilities.isInTestingMode()) {
			return runningTasks.size() > 0;
		}

		return false;
	}

	/**
	 * Returns true if the task with the indicated title is running.
	 * @param title the title of the desired task
	 * @return true if the task with the indicated title is running.
	 */
	public static boolean isTaskRunning(String title) {
		if (!SystemUtilities.isInTestingMode()) {
			return false;
		}

		Task[] tasks = runningTasks.keySet().toArray(new Task[runningTasks.size()]);
		for (Task task : tasks) {
			if (task.getTaskTitle().equals(title)) {
				return true;
			}
		}
		return false;
	}
}
