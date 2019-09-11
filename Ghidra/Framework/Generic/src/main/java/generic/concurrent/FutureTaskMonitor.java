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
package generic.concurrent;

import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * This is the FutureTask that will be used to call the {@link QCallback} to work on
 * an item from a ConcurrentQ. It has been overridden to serve as an individual
 * TaskMonitor for the task as well as notifying the ConcurrentQ when a task
 * has been completed or cancelled so that additional tasks can be sent to the
 * thread pool.
 * <P>
 * If it was cancelled, then the done() callback will occur in the thread that cancelled this
 * task, otherwise it will be called by the thread from the thread pool that
 * executed the task.  Note that when this task is cancelled, it is up to the
 * executing thread to check if it was cancelled and terminate the task execution gracefully.
 * Even if the executing task never checks the cancelled and completes the task,
 * the return value will be ignored as this task has already been considered done
 * and any threads waiting on the return will have already been told it was cancelled.
 * <P>
 * On ConcurrentQs that only allow one task to run at a time, when a task is cancelled,
 * the next task can begin.  Most likely, the thread that was running the cancelled
 * task won't be free, and a new thread will be used to start running the next task.
 * 
 * @param <I> the input type 
 * @param <R> the output type
 */
class FutureTaskMonitor<I, R> extends FutureTask<R> implements TaskMonitor {

	private final ConcurrentQ<I, R> queue;
	private final I item;
	private final long id;
	private volatile String lastMessage;
	private volatile long currentProgress;
	private volatile long maxProgress;
	private volatile CancelledListener cancelledListener;
	private volatile boolean isIndeterminate;

	FutureTaskMonitor(ConcurrentQ<I, R> queue, Callable<R> callable, I item, long id) {
		super(callable);
		this.queue = queue;
		this.id = id;
		this.item = item;
	}

	I getItem() {
		return item;
	}

	long getID() {
		return id;
	}

	@Override
	public void run() {
		super.run();

		QResult<I, R> result = new QResult<>(item, this);
		queue.itemProcessed(this, result);
	}

	@Override
	public void setMaximum(long max) {
		this.maxProgress = max;
		queue.maxProgressChanged(id, item, max);
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		currentProgress += incrementAmount;
		queue.progressChanged(id, item, currentProgress);
	}

	@Override
	public void setProgress(long value) {
		currentProgress = value;
		queue.progressChanged(id, item, currentProgress);
	}

	@Override
	public void checkCanceled() throws CancelledException {
		if (isCancelled()) {
			throw new CancelledException();
		}
	}

	@Override
	public void setMessage(String message) {
		queue.progressMessageChanged(id, item, message);
	}

	@Override
	public String getMessage() {
		return lastMessage;
	}

	@Override
	public void initialize(long max) {
		currentProgress = 0;
		maxProgress = max;
		queue.maxProgressChanged(id, item, max);
		queue.progressChanged(id, item, currentProgress);
	}

	@Override
	public long getMaximum() {
		return maxProgress;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// nothing to do
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		this.isIndeterminate = indeterminate;
		queue.progressModeChanged(id, item, indeterminate);
	}

	@Override
	public boolean isIndeterminate() {
		return isIndeterminate;
	}

	@Override
	public long getProgress() {
		return currentProgress;
	}

	@Override
	public boolean cancel(boolean mayInterruptIfRunning) {
		boolean result = super.cancel(mayInterruptIfRunning);

		// copy into temp variable so that the null check and the call are atomic.
		CancelledListener listener = this.cancelledListener;
		if (listener != null) {
			listener.cancelled();
		}

		return result;
	}

	@Override
	public void cancel() {
		cancel(true);
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isCancelEnabled() {
		return true;
	}

	@Override
	public void clearCanceled() {
		throw new UnsupportedOperationException();

	}

	@Override
	public synchronized void addCancelledListener(CancelledListener listener) {
		if (cancelledListener == null) {
			cancelledListener = listener;
		}
		else {
			cancelledListener = new ChainedCancelledListener(cancelledListener, listener);
		}
	}

	@Override
	public synchronized void removeCancelledListener(CancelledListener listener) {
		if (cancelledListener == listener) {
			cancelledListener = null;
		}
		else if (cancelledListener instanceof ChainedCancelledListener) {
			cancelledListener =
				((ChainedCancelledListener) cancelledListener).removeListener(listener);
		}
	}

	private static class ChainedCancelledListener implements CancelledListener {
		private volatile CancelledListener listener1;
		private volatile CancelledListener listener2;

		public ChainedCancelledListener(CancelledListener listener1, CancelledListener listener2) {
			this.listener1 = listener1;
			this.listener2 = listener2;
		}

		public CancelledListener removeListener(CancelledListener listener) {
			if (listener1 == listener) {
				return listener2;
			}
			else if (listener2 == listener) {
				return listener1;
			}

			if (listener1 instanceof ChainedCancelledListener) {
				listener1 = ((ChainedCancelledListener) listener1).removeListener(listener);
			}
			if (listener2 instanceof ChainedCancelledListener) {
				listener2 = ((ChainedCancelledListener) listener2).removeListener(listener);
			}
			return this;
		}

		@Override
		public void cancelled() {
			listener1.cancelled();
			listener2.cancelled();
		}
	}
}
