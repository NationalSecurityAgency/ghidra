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
 * Interface used to track the state of a GTaskManager
 */
public interface GTaskListener {

	/** 
	 * Called when a task listener is added so that the listener can get all the initial state of
	 * the taskManger while the taskManager is in a locked state where nothing will change.
	 */
	public void initialize();

	/**
	 * Notification that a task is starting to run
	 * @param task the GTask that is starting to run
	 */
	public void taskStarted(GScheduledTask task);

	/**
	 * Notification that a task is no longer running regardless of whether it completed normally,
	 * was cancelled, or threw an unhandled exception.
	 * 
	 * @param task the ScheduledTask that was running.
	 * @param result the result state for the task.
	 */
	public void taskCompleted(GScheduledTask task, GTaskResult result);

	/**
	 * Notification that a GTaskGroup has been scheduled.
	 * @param group the GTaskGroup that has been scheduled to run.
	 */
	public void taskGroupScheduled(GTaskGroup group);

	/**
	 * Notification that a new GTask has been scheduled to run.
	 * @param scheduledTask the GScheduledTask that wraps the GTask with scheduling information.
	 */
	public void taskScheduled(GScheduledTask scheduledTask);

	/**
	 * Notification that a new GTaskGroup has started to run.
	 * @param taskGroup the new GTaskGroup that is running.
	 */
	public void taskGroupStarted(GTaskGroup taskGroup);

	/**
	 * Notification that the GTaskGroup has completed running.
	 * @param taskGroup the GTaskGroup that has completed running.
	 */
	public void taskGroupCompleted(GTaskGroup taskGroup);

	/**
	 * Notification that the GTaskManager has been suspended or resumed.
	 * 
	 * @param suspended true if the GTaskManger has been suspended, or false if it has been resumed.
	 */
	public void suspendedStateChanged(boolean suspended);

}
