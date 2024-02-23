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
package ghidra.app.plugin.core.debug.gui.control;

import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.app.services.ProgressService;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A task for executing a target {@link ActionEntry}.
 * 
 * <p>
 * This also has some static convenience methods for scheduling this and other types of tasks in the
 * Debugger tool.
 */
public class TargetActionTask extends Task {

	static class FutureTask extends Task {
		private final Task delegate;
		final CompletableFuture<Void> future = new CompletableFuture<>();

		public FutureTask(Task delegate) {
			super(delegate.getTaskTitle(), delegate.canCancel(), delegate.hasProgress(),
				delegate.isModal(), delegate.getWaitForTaskCompleted());
			this.delegate = delegate;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				delegate.run(monitor);
				future.complete(null);
			}
			catch (CancelledException e) {
				future.cancel(false);
			}
			catch (Throwable e) {
				future.completeExceptionally(e);
			}
		}
	}

	/**
	 * Execute a task
	 * 
	 * <p>
	 * If available, this simply delegates to {@link ProgressService#execute(Task)}. If not, then
	 * this falls back to {@link PluginTool#execute(Task)}.
	 * 
	 * @param tool the tool in which to execute
	 * @param task the task to execute
	 * @return a future that completes (perhaps exceptionally) when the task is finished or
	 *         cancelled
	 */
	public static CompletableFuture<Void> executeTask(PluginTool tool, Task task) {
		ProgressService progressService = tool.getService(ProgressService.class);
		if (progressService != null) {
			return progressService.execute(task);
		}
		FutureTask wrapper = new FutureTask(task);
		tool.execute(wrapper);
		return wrapper.future;
	}

	/**
	 * Execute an {@link ActionEntry}
	 * 
	 * @param tool the tool in which to execute
	 * @param title the title, often {@link ActionEntry#display()}
	 * @param entry the action to execute
	 * @return a future that completes (perhaps exceptionally) when the task is finished or
	 *         cancelled
	 */
	public static CompletableFuture<Void> runAction(PluginTool tool, String title,
			ActionEntry entry) {
		return executeTask(tool, new TargetActionTask(tool, title, entry));
	}

	private final PluginTool tool;
	private final ActionEntry entry;

	/**
	 * Construct a task fore the given action
	 * 
	 * @param tool the plugin tool
	 * @param title the title, often {@link ActionEntry#display()}
	 * @param entry the action to execute
	 */
	public TargetActionTask(PluginTool tool, String title, ActionEntry entry) {
		super(title, false, false, false);
		this.tool = tool;
		this.entry = entry;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			entry.run(false);
		}
		catch (Throwable e) {
			reportError(e);
		}
	}

	private void reportError(Throwable error) {
		DebuggerConsoleService consoleService = tool.getService(DebuggerConsoleService.class);
		if (consoleService != null) {
			consoleService.log(DebuggerResources.ICON_LOG_ERROR, error.getMessage(), error);
		}
		else {
			Msg.showError(this, null, "Control Error", error.getMessage(), error);
		}
	}
}
