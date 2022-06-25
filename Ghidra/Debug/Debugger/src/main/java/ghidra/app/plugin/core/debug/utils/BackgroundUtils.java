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
package ghidra.app.plugin.core.debug.utils;

import java.util.List;
import java.util.concurrent.*;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.async.AsyncUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public enum BackgroundUtils {
	;

	public static class AsyncBackgroundCommand<T extends UndoableDomainObject>
			extends BackgroundCommand {
		private CompletableFuture<?> promise;

		private final CancelledListener cancelledListener = this::cancelled;
		private final BiFunction<T, TaskMonitor, CompletableFuture<?>> futureProducer;

		private AsyncBackgroundCommand(String name, boolean hasProgress, boolean canCancel,
				boolean isModal, BiFunction<T, TaskMonitor, CompletableFuture<?>> futureProducer) {
			super(name, hasProgress, canCancel, isModal);
			this.futureProducer = futureProducer;
		}

		private void cancelled() {
			promise.cancel(true);
		}

		@Override
		@SuppressWarnings("unchecked")
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			promise = futureProducer.apply((T) obj, monitor);
			monitor.addCancelledListener(cancelledListener);
			try {
				promise.get();
				return true;
			}
			catch (InterruptedException e) {
				setStatusMsg("Interrupted");
				return false;
			}
			catch (ExecutionException e) {
				setStatusMsg(e.getMessage());
				if (!(e.getCause() instanceof CancellationException)) {
					return ExceptionUtils.rethrow(e.getCause());
				}
				return false;
			}
			catch (CancellationException e) {
				setStatusMsg("Cancelled");
				return false;
			}
		}
	}

	/**
	 * Launch a task with an attached monitor dialog
	 * 
	 * <p>
	 * The returned future includes error handling, so even if the task completes in error, the
	 * returned future will just complete with null. If further error handling is required, then the
	 * {@code futureProducer} should make the future available. Because this uses the tool's task
	 * scheduler, only one task can be pending at a time, even if the current stage is running on a
	 * separate executor, because the tool's task execution thread will wait on the future result.
	 * You may run stages in parallel, or include stages on which the final stage does not depend;
	 * however, once the final stage completes, the dialog will disappear, even though other stages
	 * may remain executing in the background. See
	 * {@link #asyncModal(PluginTool, String, boolean, boolean, Function)}.
	 * 
	 * @param <T> the type of the result
	 * @param tool the tool for displaying the dialog and scheduling the task
	 * @param obj an object on which to open a transaction
	 * @param name a name / title for the task
	 * @param hasProgress true if the task has progress
	 * @param canCancel true if the task can be cancelled
	 * @param isModal true to display a modal dialog, false to use the tool's background monitor
	 * @param futureProducer a function to start the task
	 * @return a future which completes when the task is finished.
	 */
	public static <T extends UndoableDomainObject> AsyncBackgroundCommand<T> async(PluginTool tool,
			T obj, String name, boolean hasProgress, boolean canCancel, boolean isModal,
			BiFunction<T, TaskMonitor, CompletableFuture<?>> futureProducer) {
		AsyncBackgroundCommand<T> cmd =
			new AsyncBackgroundCommand<>(name, hasProgress, canCancel, isModal, futureProducer);
		tool.executeBackgroundCommand(cmd, obj);
		return cmd;
	}

	/**
	 * Launch a task with an attached monitor dialog
	 * 
	 * <p>
	 * The returned future includes error handling, so even if the task completes in error, the
	 * returned future will just complete with null. If further error handling is required, then the
	 * {@code futureProducer} should make the future available. This differs from
	 * {@link #async(PluginTool, UndoableDomainObject, String, boolean, boolean, boolean, BiFunction)}
	 * in that it doesn't use the tool's task manager, so it can run in parallel with other tasks.
	 * There is not currently a supported method to run multiple non-modal tasks concurrently, since
	 * they would have to share a single task monitor component.
	 * 
	 * @param <T> the type of the result
	 * @param tool the tool for displaying the dialog
	 * @param name a name / title for the task
	 * @param hasProgress true if the dialog should include a progress bar
	 * @param canCancel true if the dialog should include a cancel button
	 * @param futureProducer a function to start the task
	 * @return a future which completes when the task is finished.
	 */
	public static <T> CompletableFuture<T> asyncModal(PluginTool tool, String name,
			boolean hasProgress, boolean canCancel,
			Function<TaskMonitor, CompletableFuture<T>> futureProducer) {
		var dialog = new TaskDialog(name, canCancel, true, hasProgress) {
			CancelledListener cancelledListener = this::cancelled;
			CompletableFuture<T> orig = futureProducer.apply(this);
			CompletableFuture<T> future = orig.exceptionally(ex -> {
				if (AsyncUtils.unwrapThrowable(ex) instanceof CancellationException) {
					return null;
				}
				Msg.showError(this, null, name, "Error running asynchronous background task", ex);
				return null;
			}).thenApply(v -> {
				Swing.runIfSwingOrRunLater(() -> close());
				return v;
			});

			{
				addCancelledListener(cancelledListener);
			}

			private void cancelled() {
				future.cancel(true);
				close();
			}

		};
		if (!dialog.orig.isDone()) {
			tool.showDialog(dialog);
		}
		return dialog.future;
	}

	public static class PluginToolExecutorService extends AbstractExecutorService {
		private final PluginTool tool;
		private String name;
		private boolean canCancel;
		private boolean hasProgress;
		private boolean isModal;
		private final int delay;

		public PluginToolExecutorService(PluginTool tool, String name, boolean canCancel,
				boolean hasProgress, boolean isModal, int delay) {
			this.tool = tool;
			this.name = name;
			this.canCancel = canCancel;
			this.hasProgress = hasProgress;
			this.isModal = isModal;
			this.delay = delay;
		}

		@Override
		public void shutdown() {
			throw new UnsupportedOperationException();
		}

		@Override
		public List<Runnable> shutdownNow() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isShutdown() {
			return false;
		}

		@Override
		public boolean isTerminated() {
			return false;
		}

		@Override
		public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void execute(Runnable command) {
			Task task = new Task(name, canCancel, hasProgress, isModal) {
				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					command.run();
				}
			};
			tool.execute(task, delay);
		}
	}
}
