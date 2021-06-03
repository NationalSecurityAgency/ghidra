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

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import generic.concurrent.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.ClosedException;
import ghidra.util.task.BusyListener;
import ghidra.util.task.TaskMonitor;

/**
 * Class that uses a single thread to execute scheduled jobs.
 * <p>
 * Subclasses provide the {@link BlockingQueue} implementation, which allows for controlling
 * how jobs get scheduled (e.g., FIFO or priority-based).
 */
public abstract class AbstractWorker<T extends Job> {
	private ConcurrentQ<T, Object> concurrentQ;
	private volatile BusyListener busyListener;
	private volatile boolean isDisposed;
	private AtomicBoolean isBusy = new AtomicBoolean(false);
	private QProgressListener<T> qProgressListener;

	/**
	 * Constructs a new Worker with the given name.
	 * 
	 * @param queue the queue into which jobs will be place.  e.g. PriorityBlockingQueue or 
	 *              LinkedBlockingQueue
	 * @param isPersistentThread if true, the worker thread will stay around when idle;
	 *             false means that the thread will go away if not needed. Should be true for 
	 *             high frequency usage.
	 * @param name the name of this worker. The thread that executes the jobs will have this
	 *             name.
	 * @param shareThreadPool true signals to use the given name to find/create a thread pool 
	 *             that can be shared throughout the system.
	 * @param monitor the task monitor that allows for cancelling of jobs. 
	 */
	protected AbstractWorker(BlockingQueue<T> queue, boolean isPersistentThread, String name,
			boolean shareThreadPool, TaskMonitor monitor) {

		GThreadPool threadPool = shareThreadPool ? GThreadPool.getSharedThreadPool(name)
				: GThreadPool.getPrivateThreadPool(name);

		if (isPersistentThread) {
			threadPool.setMinThreadCount(1);
		}

		JobCallback<T> callback = new JobCallback<>();

		// @formatter:off
		concurrentQ = new ConcurrentQBuilder<T, Object>()
			.setThreadPool(threadPool)
			.setQueue(queue)
			.setCancelClearsAllJobs(false)
			.setJobsReportProgress(true)
			.setMaxInProgress(1)
			.build(callback);		
		// @formatter:on

		qProgressListener = new ProgressListener();
		concurrentQ.addProgressListener(qProgressListener);
		concurrentQ.setMonitor(monitor, false);
	}

	public void setTaskMonitor(TaskMonitor monitor) {
		concurrentQ.setMonitor(monitor, false);
	}

	class ProgressListener implements QProgressListener<T> {

		@Override
		public void taskStarted(long id, T Item) {
			setBusy(true);
		}

		@Override
		public void taskEnded(long id, T Item, long totalCount, long completedCount) {
			if (concurrentQ.isEmpty()) {
				setBusy(false);
			}
		}

		@Override
		public void progressChanged(long id, T Item, long currentProgress) {
			// do nothing here
		}

		@Override
		public void progressModeChanged(long id, T item, boolean indeterminate) {
			// do nothing here
		}

		@Override
		public void progressMessageChanged(long id, T item, String message) {
			// do nothing here
		}

		@Override
		public void maxProgressChanged(long id, T item, long maxProgress) {
			// do nothing here
		}
	}

	private static class JobCallback<K extends Job> implements QCallback<K, Object> {

		@Override
		public Object process(K job, TaskMonitor monitor) {
			job.setTaskMonitor(monitor);
			if (job.isCancelled()) {
				monitor.cancel();
				return null;
			}
			try {
				job.run(monitor);
			}
			catch (CancelledException e) {
				// it will be handled above us.
			}
			catch (Throwable t) {
				reportException(t, job, monitor.isCancelled());
			}
			finally {
				job.setTaskMonitor(null);
				if (monitor.isCancelled()) {
					job.cancel();
				}
				else {
					job.setCompleted();
				}
			}
			return null;
		}
	}

	private static <K> void reportException(Throwable t, K job, boolean isCancelled) {
		if (canSquashException(t, isCancelled)) {
			return;
		}

		String jobName = job.getClass().getSimpleName();
		Msg.error(AbstractWorker.class, "Unexpected error processing job: " + jobName, t);
	}

	private static <K> boolean canSquashException(Throwable t, boolean isCancelled) {
		//
		// We have a policy of ignoring DB closed exceptions when a task has already 
		// been cancelled, as this can happen when shutting down Ghidra.
		//
		if (!isCancelled) {
			return false;
		}

		if (t instanceof CancelledException) {
			return true;
		}

		if (t instanceof ClosedException) {
			return true;
		}

		// sometimes ClosedExceptions are wrapped in RuntimeExceptions
		Throwable cause = t.getCause();
		if (cause != null) {
			return canSquashException(cause, isCancelled);
		}

		return false;
	}

	/**
	 * Schedules the job for execution.  Jobs will be processed in priority order.  The
	 * highest priority jobs are those with the lowest value return by the job's getPriority()
	 * method. (i.e. the job with priority 0 will be processed before the job with priority 1)
	 * @param job the job to be executed.
	 */
	public void schedule(T job) {
		if (isDisposed) {
			Msg.trace(this, "A job was scheduled after this worker was disposed - " + job);
			return;
		}

		setBusy(true);
		concurrentQ.add(job);
	}

	/**
	 * Clears any pending jobs and cancels any currently executing job.
	 */
	public void clearAllJobs() {
		clearAllJobs(false);
	}

	/**
	 *  Clears any pending jobs and cancels any currently executing job.
	 *  <p>
	 *  <b>Warning: Calling this method may leave the program in a bad
	 *  state.  Thus, it is recommended that you only do so when you known that any job that
	 *  could possibly be scheduled does not manipulate sensitive parts of the program; for 
	 *  example, opening file handles that should be closed before finishing.</b>  
	 *  <p><b>
	 *  If you are unsure 
	 *  about whether your jobs handle interrupt correctly, then don't use this method.
	 *  </b> 
	 */
	public void clearAllJobsWithInterrupt_IKnowTheRisks() {
		clearAllJobs(true);
	}

	private void clearAllJobs(boolean interruptRuningJob) {
		List<T> pendingJobs = concurrentQ.cancelAllTasks(interruptRuningJob);
		for (T job : pendingJobs) {
			job.cancel();
		}
	}

	/**
	 * Clears any jobs from the queue <b>that have not yet been run</b>.  This does not cancel 
	 * the currently running job.
	 */
	public void clearPendingJobs() {
		concurrentQ.removeUnscheduledJobs();
	}

	/**
	 * Disposes this worker and terminates its thread.
	 */
	public void dispose() {
		concurrentQ.setMonitor(null, false);
		concurrentQ.cancelAllTasks(true);
		isDisposed = true;
	}

	public boolean isDisposed() {
		return isDisposed;
	}

	private void setBusy(boolean b) {
		boolean changed = isBusy.compareAndSet(!b, b);
		if (busyListener != null && changed) {
			busyListener.setBusy(isBusy.get());
		}
	}

	public void setBusyListener(BusyListener listener) {
		this.busyListener = listener;
	}

	public boolean isBusy() {
		return isBusy.get();
	}

	/**
	 * This method will block until there are no scheduled jobs in this worker. This
	 * method assumes that all jobs have a priority less than Long.MAX_VALUE.   
	 * <p>
	 * For a non-priority
	 * queue, this call will not wait for jobs that are scheduled after this call was made.
	 */
	public void waitUntilNoJobsScheduled(int maxWait) {
		try {
			concurrentQ.waitUntilDone(maxWait, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			// don't care
		}
	}

}
