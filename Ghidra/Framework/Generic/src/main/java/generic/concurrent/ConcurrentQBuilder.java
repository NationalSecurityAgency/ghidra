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

import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

import ghidra.util.task.TaskMonitor;

/**
 * A helper class to build up the potentially complicated {@link ConcurrentQ}.
 * <P>
 * Note: you must supply either a {@link GThreadPool} instance or a thread pool name.  Further, 
 * if you supply the name of a thread pool, then a private, non-shared pool will be used.  If you
 * wish to make use of a shared pool, then you need to create that thread pool yourself.  See
 * {@link GThreadPool#getSharedThreadPool(String)}.
 * 
 * <P>
 * Examples:
 * <p>
 * <pre>{@literal
 * QCallback<I, R> callback = new AbstractQCallback<I, R>() {
 *     public R process(I item, TaskMonitor monitor) {
 *         // do work here...
 *     }
 * };
 * 
 * ConcurrentQBuilder<I, R> builder = new ConcurrentQBuilder<I, R>();
 * builder.setThreadPoolName("Thread Pool Name");
 * builder.setQueue(new PriorityBlockingQueue());
 * concurrentQ = builder.build(callback);
 * 
 * // OR, you can chain the builder calls:
 * ConcurrentQBuilder<I, R> builder = new ConcurrentQBuilder<I, R>();
 * queue = builder.setThreadPoolName("Thread Pool Name").
 * 				setQueue(new PriorityBlockingQueue()).
 * 				setMaxInProgress(1).
 * 				build(callback);
 * 
 * }</pre>
 * <p>
 *  
 * Note: if you wish to take advantage of blocking when adding items to the {@link ConcurrentQ}, 
 *       see {@link #setQueue(Queue)}.
 *	
 *
 *
 * @param <I> The type of the items to be processed.
 * @param <R> The type of objects resulting from processing an item
 */
public class ConcurrentQBuilder<I, R> {
	private Queue<I> queue;
	private String threadPoolName;
	private GThreadPool threadPool;
	private QItemListener<I, R> listener;
	private boolean collectResults;
	private int maxInProgress;
	private boolean jobsReportProgress = false;
	private TaskMonitor monitor = TaskMonitor.DUMMY;
	private boolean cancelClearsAllJobs = true;

	/**
	 * Sets the queue to be used by the {@link ConcurrentQ}.  If you would like advanced features, 
	 * like a queue that blocks when too many items have been placed in it, then use an 
	 * advanced queue here, such as a {@link LinkedBlockingQueue}.
	 * <p>
	 * Note: if you wish to take advantage of blocking when adding items to the {@link ConcurrentQ}, 
	 *       then be sure to call the appropriate method, such as 
	 *       {@link ConcurrentQ#offer(java.util.Iterator)}.
	 * 
	 * @param queue the queue to be used by the {@link ConcurrentQ}
	 * @return this builder
	 */
	public ConcurrentQBuilder<I, R> setQueue(Queue<I> queue) {
		this.queue = queue;
		return this;
	}

	/**
	 * Specifies the maximum number of items that can be process at a time.  
	 * If this is set to 0, then the concurrent queue will attempt to execute as many 
	 * items at a time as there are threads in the given threadPool.  Setting 
	 * this parameter to 1 will have the effect of guaranteeing that
	 * all times are processed one at a time in the order they were submitted.
	 * Any other positive value will run that many items concurrently, 
	 * up to the number of available threads.
	 * 
	 * @param max the max number of items to execute at one time; defaults to 0
	 * @return this builder instance
	 */
	public ConcurrentQBuilder<I, R> setMaxInProgress(int max) {
		this.maxInProgress = max;
		return this;
	}

	/**
	 * Sets the name to be used when creating a <b>private thread pool</b>.  If you wish to use
	 * a <i>shared thread pool</i>, then you need to create that thread pool youself and call
	 * {@link #setThreadPool(GThreadPool)}.
	 * 
	 * @param name the name of the thread pool.
	 * @return this builder instance
	 * @see GThreadPool#getSharedThreadPool(String)
	 */
	public ConcurrentQBuilder<I, R> setThreadPoolName(String name) {
		threadPoolName = name;
		return this;
	}

	/**
	 * Use the given thread pool for processing the work items.  If you do not care to configure
	 * the thread pool used and you do not wish to make use of shared thread pools, then you 
	 * can call {@link #setThreadPoolName(String)} instead of this method.
	 * 
	 * @param threadPool the thread pool to use
	 * @return this builder instance
	 * @see GThreadPool#getSharedThreadPool(String)
	 */
	public ConcurrentQBuilder<I, R> setThreadPool(GThreadPool threadPool) {
		this.threadPool = threadPool;
		return this;
	}

	/**
	 * Specifies if the concurrent queue should collect the results as items are processed
	 * so they can be returned in a {@link ConcurrentQ#waitForResults()} call. 
	 * @param collectResults true signals to collect the generated results; defaults to false
	 * @return this builder instance
	 */
	public ConcurrentQBuilder<I, R> setCollectResults(boolean collectResults) {
		this.collectResults = collectResults;
		return this;
	}

	/**
	 * True signals that the jobs run by the client wish to report progress.  The default value 
	 * is false.
	 * <p>
	 * The default of false is good for clients that have a known amount of work to be processed.
	 * In this case, a total count of work jobs is maintained by the queue.  As items are 
	 * completed, the queue will update the monitor provided to it at construction time to reflect
	 * the number of jobs completed as work is done.  On the other hand, some clients have 
	 * known known number of jobs to complete, but simply add work to the queue as it arrives.  
	 * In that case, the client should update its monitor for progress, as the queue cannot 
	 * do so in a meaningful way.
	 * 
	 * @param reportsProgress true signals that the client will update progress; false signals 
	 *        that the queue should do so
	 * @return this builder instance
	 */
	public ConcurrentQBuilder<I, R> setJobsReportProgress(boolean reportsProgress) {
		this.jobsReportProgress = reportsProgress;
		return this;
	}

	public ConcurrentQBuilder<I, R> setListener(QItemListener<I, R> listener) {
		this.listener = listener;
		return this;
	}

	public ConcurrentQBuilder<I, R> setMonitor(TaskMonitor monitor) {
		this.monitor = monitor;
		return this;
	}

	/**
	 * Sets whether a cancel will clear all jobs (current and pending) or just the 
	 * current jobs being processed.  The default value is {@code true}.
	 * 
	 * @param clearAllJobs if true, cancelling the monitor will cancel all items currently being 
	 *        processed by a thread and clear the scheduled items that haven't yet run. If false, 
	 *        only the items currently being processed will be cancelled. 
	 * @return this builder
	 * @see ConcurrentQ#setMonitor(TaskMonitor, boolean)
	 */
	public ConcurrentQBuilder<I, R> setCancelClearsAllJobs(boolean clearAllJobs) {
		this.cancelClearsAllJobs = clearAllJobs;
		return this;
	}

	public ConcurrentQ<I, R> build(QCallback<I, R> callback) {

		ConcurrentQ<I, R> concurrentQ =
			new ConcurrentQ<>(callback, getQueue(), getThreadPool(), listener, collectResults,
				maxInProgress, jobsReportProgress);

		if (monitor != null) {
			concurrentQ.setMonitor(monitor, cancelClearsAllJobs);
		}
		return concurrentQ;
	}

	private GThreadPool getThreadPool() {
		if (threadPool != null) {
			return threadPool;
		}

		if (threadPoolName != null) {
			return GThreadPool.getPrivateThreadPool(threadPoolName);
		}

		throw new IllegalStateException("Must either set a GThreadPool or set a thread pool name");
	}

	private Queue<I> getQueue() {
		if (queue != null) {
			return queue;
		}
		return new LinkedList<>();
	}
}
