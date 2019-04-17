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

import java.util.*;

/**
 * Class for grouping several {@link GTask}s that all should be 
 * executed before any new group of tasks are
 * executed, regardless of priority.
 * 
 * @see GTaskManager
 */
public class GTaskGroup {
	private static long nextID = 0; // used to order groups in the order they are created.

	private long id = nextID++;
	private String description;

	private List<GScheduledTask> taskList = new ArrayList<GScheduledTask>();

	private boolean startNewTransaction;
	private volatile boolean cancelled = false;
	private GTaskMonitor monitor;

	private boolean scheduled = false; // true when scheduled in GTaskManager; prevents new tasks being added

	/**
	 * Creates a new named GTaskGroup.
	 * @param description the display name for the group.
	 * @param startNewTransaction if true, any existing transaction (if there is one) will be closed
	 * and a new transaction will be created.  Otherwise, the tasks in this group will be executed
	 * in the same transaction as the previous group. Note that this can only happen if there was
	 * a previous group executing at the time this group is scheduled.
	 */
	public GTaskGroup(String description, boolean startNewTransaction) {
		this.description = description;
		this.startNewTransaction = startNewTransaction;
		this.monitor = new GTaskMonitor();
	}

	/**
	 * Add a task to this group with the given priority.  Tasks can only be added to this group
	 * before the group is added to the GTaskManager.  After that, an IllegalStateException will
	 * be thrown.
	 * @param task the task being added to this group.
	 * @param priority the priority for the task within the group.
	 * @return the GScheduledTask created to schedule this task within the group.
	 * @throws IllegalStateException if this method is called after the group has been added to
	 * the GTaskManager.
	 */
	public GScheduledTask addTask(GTask task, int priority) {
		if (scheduled) {
			throw new IllegalStateException("Can't directly add new tasks on a group that has "
				+ "been scheduled with a GTaskManager");
		}
		return doAddTask(task, priority);
	}

	GScheduledTask doAddTask(GTask task, int priority) {
		GScheduledTask scheduledTask = new GScheduledTask(this, task, priority);
		taskList.add(scheduledTask);
		monitor.setMaximum(taskList.size());
		return scheduledTask;
	}

	/**
	 * Returns a list scheduled tasks in the group.
	 * @return a list scheduled tasks in the group.
	 */
	public List<GScheduledTask> getTasks() {
		ArrayList<GScheduledTask> list = new ArrayList<GScheduledTask>(taskList);
		Collections.sort(list);
		return list;
	}

	/**
	 * Returns the TaskMonitor that will be used to track the overall progress of tasks within this 
	 * group.
	 * @return the TaskMonitor that will be used to track the overall progress of tasks within this 
	 * group.
	 */
	public GTaskMonitor getTaskMonitor() {
		return monitor;
	}

	/**
	 * Returns true if this group wants to start a new transaction when it runs.  Otherwise, the
	 * group will add-on to any existing transaction from the previous group.
	 * @return true if a new transaction should be started for this group.
	 */
	public boolean wantsNewTransaction() {
		return startNewTransaction;
	}

	/**
	 * Returns a description for the group.
	 * @return a description for this group.
	 */
	public String getDescription() {
		return description;
	}

	// Note that this is compatible with the default equals and hashcode.
	public int compareTo(GTaskGroup group) {
		return (int) (id - group.id);
	}

	@Override
	public String toString() {
		return "Task Group: " + description;
	}

	/**
	 * Cancels the group.  Any tasks that haven't yet started will never run.
	 */
	public void setCancelled() {
		cancelled = true;
	}

	/**
	 * Returns true if this group was cancelled.
	 * @return true if this group was cancelled.
	 */
	public boolean wasCancelled() {
		return cancelled;
	}

	/**
	 * Notification that a task in the group has been completed.  The group keeps track of the overall
	 * progress of the tasks completed in this group.  This call is used to notify the group that
	 * another one of its tasks was completed.
	 * 
	 */
	public void taskCompleted() {
		monitor.incrementProgress(1);
	}

	public void setScheduled() {
		scheduled = true;
	}
}
