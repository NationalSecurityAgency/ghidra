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
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.app.services.ProgressService;
import ghidra.async.AsyncUtils;
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

	static class FutureAsTask<T> extends Task {
		final CompletableFuture<T> future = new CompletableFuture<>();
		private final Function<TaskMonitor, CompletableFuture<T>> futureSupplier;

		public FutureAsTask(String title, boolean canCancel, boolean hasProgress, boolean isModal,
				Function<TaskMonitor, CompletableFuture<T>> futureSupplier) {
			super(title, canCancel, hasProgress, isModal);
			this.futureSupplier = futureSupplier;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			CompletableFuture<T> future = futureSupplier.apply(monitor);
			future.handle(AsyncUtils.copyTo(this.future));
			try {
				future.get();
			}
			catch (InterruptedException | ExecutionException e) {
				// Client should get it via the copyTo
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
	 * Execute an asynchronous task
	 * 
	 * @param tool the tool in which to execute
	 * @param title the title of the task
	 * @param canCancel if the task can be cancelled
	 * @param hasProgress if the task displays progress
	 * @param isModal if the task is modal
	 * @param futureSupplier the task, a function of the monitor returning the future
	 * @return a future which completes in the same way as the one returned by the supplier
	 */
	public static <T> CompletableFuture<T> executeTask(PluginTool tool, String title,
			boolean canCancel, boolean hasProgress, boolean isModal,
			Function<TaskMonitor, CompletableFuture<T>> futureSupplier) {
		ProgressService progressService = tool.getService(ProgressService.class);
		if (progressService != null) {
			return progressService.execute(canCancel, hasProgress, isModal, futureSupplier);
		}
		FutureAsTask<T> task =
			new FutureAsTask<>(title, canCancel, hasProgress, isModal, futureSupplier);
		tool.execute(task);
		return task.future;
	}

	/**
	 * Execute an {@link ActionEntry}
	 * 
	 * <p>
	 * If the {@link ProgressService} is available, we will not enforce a timeout, because it should
	 * be relatively easy for the user to manage the pending tasks. Otherwise, we'll enforce the
	 * timeout. The rationale here is that some tasks do actually take a good bit of time. For
	 * example, some targets just have a large module list. Often a GUI component is asking for a
	 * reason, and if we time it out, that thing doesn't get what it needs. Furthermore, the entry
	 * disappears from the task list, even though the back-end is likely still working on it. That's
	 * not good, actually. Since we have a cancel button, let the user decide when it's had enough
	 * time.
	 * 
	 * @param tool the tool in which to execute
	 * @param title the title, often {@link ActionEntry#display()}
	 * @param entry the action to execute
	 * @return a future that completes (perhaps exceptionally) when the task is finished or
	 *         cancelled
	 */
	public static CompletableFuture<Void> runAction(PluginTool tool, String title,
			ActionEntry entry) {
		return executeTask(tool, new TargetActionTask(tool, title, entry,
			tool.getService(ProgressService.class) == null));
	}

	private final PluginTool tool;
	private final ActionEntry entry;
	private final boolean timeout;

	/**
	 * Construct a task fore the given action
	 * 
	 * @param tool the plugin tool
	 * @param title the title, often {@link ActionEntry#display()}
	 * @param entry the action to execute
	 * @param timeout whether or not to enforce the timeout
	 */
	public TargetActionTask(PluginTool tool, String title, ActionEntry entry, boolean timeout) {
		super(title, false, false, false);
		this.tool = tool;
		this.entry = entry;
		this.timeout = timeout;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			if (timeout) {
				entry.run(entry.requiresPrompt());
			}
			else {
				entry.invokeAsyncWithoutTimeout(entry.requiresPrompt()).get();
			}
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
