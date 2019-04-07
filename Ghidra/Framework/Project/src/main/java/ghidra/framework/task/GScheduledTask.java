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
package ghidra.framework.task;

/**
 * Class for tracking scheduled GTasks.  When tasks are scheduled, they are assigned to a GTaskGroup,
 * given a priority, assigned a one-up ID, given a GTaskMonitor.  This class is used to keep all
 * that information together.
 * <p>
 */
public class GScheduledTask implements Comparable<GScheduledTask> {
	private static long nextID = 1;  // Used so that tasks of equal priority are sorted in the order
									// they are added.
	private GTask task;
	private int priority;
	private Thread thread;
	private long id;
	private GTaskGroup group;
	private GTaskMonitor monitor;

	/**
	 * Create a new GScheduledTask when a task is scheduled with the GTaskManager.
	 * @param group the group that this task belongs to.
	 * @param task the task being scheduled.
	 * @param priority the priority at which this task is to be executed relative to other 
	 * scheduled tasks.  Lower numbers are run before higher numbers.
	 */
	public GScheduledTask(GTaskGroup group, GTask task, int priority) {
		this.group = group;
		this.task = task;
		this.priority = priority;
		id = nextID++;
		this.monitor = new GTaskMonitor();
	}

	/**
	 * Returns the GTask that is scheduled.
	 * @return the GTask that is scheduled.
	 */
	public GTask getTask() {
		return task;
	}

	/**
	 * Returns the priority at which the task was scheduled. Lower numbers have higher priority.
	 * @return the priority at which the task was scheduled.
	 */
	public int getPriority() {
		return priority;
	}

	/**
	 * Returns the GTaskMonitor that will be used for this task.
	 * @return the GTaskMonitor that will be used for this task.
	 */
	public GTaskMonitor getTaskMonitor() {
		return monitor;
	}

	// Note: this compareTo is compatible with default equals and hashcode because it only
	// returns 0 when the instances are the same;
	@Override
	public int compareTo(GScheduledTask other) {
		if (this == other) {
			return 0;
		}
		if (priority == other.priority) {
			return id > other.id ? 1 : -1;
		}
		return priority - other.priority;
	}

	void setThread(Thread thread) {
		this.thread = thread;
	}

	boolean isRunningInCurrentThread() {
		return thread == Thread.currentThread();
	}

	@Override
	public String toString() {
		return task.getName() + " : " + priority;
	}

	/**
	 * Return GTaskGroup for this task.
	 * @return the GTaskGroup 
	 */
	public GTaskGroup getGroup() {
		return group;
	}

	/**
	 * Returns the description for the scheduled GTask.
	 * @return the description for the scheduled GTask.
	 */
	public String getDescription() {
		return task.getName();
	}
}
