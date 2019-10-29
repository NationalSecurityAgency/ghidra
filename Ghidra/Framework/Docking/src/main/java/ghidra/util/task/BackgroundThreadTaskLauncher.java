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

import java.util.concurrent.Executor;

import generic.concurrent.GThreadPool;
import ghidra.util.Swing;
import ghidra.util.TaskUtilities;

/**
 * Helper class to launch the given task in a background thread  This helper will not 
 * show a task dialog. 
 * 
 * <p>This class is useful when you want to run the task and use a monitor that is embedded 
 * in some other component.
 * 
 * <p>See {@link TaskLauncher}.
 */
class BackgroundThreadTaskLauncher {

	private Task task;

	BackgroundThreadTaskLauncher(Task task) {
		this.task = task;
	}

	void run(TaskMonitor monitor) {
		// add the task here, so we can track it before it is actually started by the thread
		TaskUtilities.addTrackedTask(task, monitor);

		String name = "Task - " + task.getTaskTitle();
		GThreadPool pool = GThreadPool.getSharedThreadPool(Swing.GSWING_THREAD_POOL_NAME);
		Executor executor = pool.getExecutor();
		executor.execute(() -> {
			Thread.currentThread().setName(name);
			task.monitoredRun(monitor);
		});

	}
}
