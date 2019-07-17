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
package ghidra.util.worker;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class Job {

	private volatile boolean completed;
	private volatile boolean cancelled;
	private volatile Throwable error;
	private volatile TaskMonitor taskMonitor;

	/**
	 * The method that gets called by the Worker when this job is selected to be run
	 * by the Worker.
	 */
	public abstract void run(TaskMonitor monitor) throws CancelledException;

	public boolean isCompleted() {
		return completed;
	}

	public void setCompleted() {
		completed = true;
	}

	public boolean isCancelled() {
		return cancelled;
	}

	public void setError(Throwable t) {
		this.error = t;
	}

	public boolean hasError() {
		return error != null;
	}

	public Throwable getError() {
		return error;
	}

	public void cancel() {
		cancelled = true;
		if (taskMonitor != null) {
			taskMonitor.cancel();
		}
	}

	protected void setTaskMonitor(TaskMonitor monitor) {
		this.taskMonitor = monitor;
	}
}
