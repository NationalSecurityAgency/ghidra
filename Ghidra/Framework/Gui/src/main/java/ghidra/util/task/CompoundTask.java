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

import ghidra.util.exception.CancelledException;

/**
 * Combines multiple Tasks into a single task.  All tasks should have the same cancel, progress, and modality.
 */
public class CompoundTask extends Task {
	private Task[] tasks;

	/**
	 * Create a CompoundTask from an array of tasks.
	 * @param tasks the array of tasks.
	 * @param title the title for this task.
	 */
	public CompoundTask(Task[] tasks, String title) {
		super(title, tasks[0].canCancel(), tasks[0].hasProgress(), tasks[0].isModal());
		this.tasks = tasks;
	}

	/**
	 * The task run method
	 * 
	 * @throws CancelledException if any task is cancelled 
	 */
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		TaskMonitor[] subMonitors = TaskMonitorSplitter.splitTaskMonitor(monitor, tasks.length);
		for (int i = 0; i < tasks.length; i++) {
			tasks[i].run(subMonitors[i]);
		}
	}

}
