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

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;

/**
 * A queue for easily scheduling tasks to be run in parallel (or sequentially)
 * via a thread pool.  This class provides a clean separation of items that need to
 * be processed from the algorithm that does the processing, making it easy to parallelize
 * the processing of multiple items.   Further, you can control the maximum number of items that
 * can be processed concurrently.  This is useful to throttle operations that may starve the
 * other threads in the system.  You may also control how many items get placed into the queue
 * at one time, blocking if some threshold is exceeded.
 * <p>
 * Examples:
 * <hr>
 * <p>
 * <u>Put and Forget:</u>
 * <pre>{@literal
 * QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>() {
 *     public RESULT process(ITEM item, TaskMonitor monitor) {
 *         // do work here...
 *     }
 * };
 * 
 * ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>();
 * builder.setThreadPoolName("Thread Pool Name");
 * concurrentQ = builder.getQueue(callback);
 * ...
 * ...
 * concurrentQ.add(item); // where item is one of the instances of ITEM
 * 
 * }</pre>
 * <hr>
 * <p>
 * <u>Put Items and Handle Results in Any Order as They Available:</u>
 * <pre>
 * {@literal QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>()} {
 *     public RESULT process(ITEM item, TaskMonitor monitor) {
 *         // do work here...
 *     }
 * };
 * 
 * {@literal QItemListener<ITEM, RESULT> itemListener = new QItemListener<ITEM, RESULT>()} {
 *     {@literal public void itemProcessed(QResult<ITEM, RESULT> result)} {
 *         RESULT result = result.getResult();
 *             <span style="color:blue"><b>// work on my result...</b></span>
 *         }
 * };
 * 
 * {@literal ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>()};
 * builder.setThreadPoolName("Thread Pool Name");
 * <span style="color:blue"><b>builder.setListener(itemListener);</b></span>
 * concurrentQ = builder.build(callback);
 * ...
 * ...
 * concurrentQ.add(item); // where item is one of the instances of ITEM
 * concurrentQ.add(item);
 * concurrentQ.add(item);
 * 
 * </pre>
 * 
 * <hr>
 * <p>
 * <u>Put Items and Handle Results When All Items Have Been Processed:</u>
 * <pre>{@literal
 * QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>() {
 *     public RESULT process(ITEM item, TaskMonitor monitor) {
 *         // do work here...
 *     }
 * };}
 *
 * {@literal ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>();}
 * builder.setThreadPoolName("Thread Pool Name");
 * <span style="color:blue"><b>builder.setCollectResults(true);</b></span>
 * concurrentQ = builder.getQueue(callback);
 * ...
 * ...
 * concurrentQ.add(item); // where item is one of the instances of ITEM
 * concurrentQ.add(item);
 * concurrentQ.add(item);
 * ...
 * 
 * <span style="color:blue"><b>{@literal List<QResult<I, R>> results = concurrentQ.waitForResults();}</b></span>{@literal
 * // process the results...
 * 
 * }</pre>
 * <hr>
 * <p>
 * <u>Put Items, <b>Blocking While Full</b>, and Handle Results in Any Order as They Available:</u>
 * <pre>
 * {@literal QCallback<ITEM, RESULT> callback = new AbstractQCallback<ITEM, RESULT>()} {
 *     public RESULT process(ITEM item, TaskMonitor monitor) {
 *         // do work here...
 *     }
 * };
 *
 * {@literal QItemListener<ITEM, RESULT> itemListener = new QItemListener<ITEM, RESULT>()} {
 *     {@literal public void itemProcessed(QResult<ITEM, RESULT> result)} {
 *         RESULT result = result.getResult();
 *             // work on my result...
 *         }
 * };
 * 
 * {@literal ConcurrentQBuilder<ITEM, RESULT> builder = new ConcurrentQBuilder<ITEM, RESULT>()};
 * builder.setThreadPoolName("Thread Pool Name");
 * <span style="color:blue"><b>builder.setQueue(new LinkedBlockingQueue(100));</b></span>
 * concurrentQ = builder.getQueue(callback);
 * ...
 * ...
 * {@literal Iterator<ITEM> iterator = <get an iterator for 1000s of items somewhere>}
 * <span style="color:blue"><b>{@code concurrentQ.offer(iterator); // this call will block when the queue fills up (100 items or more)}</b></span>
 * 
 * </pre>
 * <hr>
 * 
 * @param <I> The type of the items to be processed.
 * @param <R> The type of objects resulting from processing an item; if you don't care about the
 *            return value, then make this value whatever you want, like <code>Object</code> or the
 *            same value as {@code I} and return null from {@link QCallback#process(Object, TaskMonitor)}.
 */
public class ConcurrentQ<I, R> {

	private final Queue<I> queue;
	private final GThreadPool threadPool;

	private final QCallback<I, R> callback;
	private QItemListener<I, R> itemListener;
	private QProgressListener<I> progressListener;
	private Deque<QResult<I, R>> resultList = new LinkedList<>();
	private final Set<FutureTaskMonitor<I, R>> taskSet = new HashSet<>();

	private final int maxInProgress;
	private final boolean collectResults;
	private final boolean jobsReportProgress;

	private QMonitorAdapter monitorAdapter;
	private Exception unhandledException;
	private ProgressTracker tracker;

	private ReentrantLock lock = new ReentrantLock(false);

	/**
	 * Creates a ConcurrentQ that will process as many items as the given threadPool can handle
	 * at one time.
	 * 
	 * @param name The name of the thread pool that will be created by this constructor.
	 * @param callback the QWorker object that will be used to process items concurrently.
	 */
	public ConcurrentQ(String name, QCallback<I, R> callback) {
		this(callback, new LinkedList<I>(), GThreadPool.getPrivateThreadPool(name), null, false, 0,
			false);
	}

	/**
	 * Creates a ConcurrentQ that will process at most maxInProgress items at a time, regardless of
	 * how many threads are available in the GThreadPool.
	 * 
	 * @param callback the QWorker object that will be used to process items concurrently.
	 * @param queue the internal storage queue to use in this concurrent queue.
	 * @param threadPool the GThreadPool to used for providing the threads for concurrent processing.
	 * @param listener An optional QItemListener that will be called back with results when the
	 *                item has been processed.
	 * @param collectResults specifies if this queue should collect the results as items are processed
	 *                 so they can be returned in a waitForResults() call.
	 * @param maxInProgress specifies the maximum number of items that can be process at a time.
	 *                 If this is set to 0, then this queue will attempt to execute as many
	 *                 items at a time as there are threads in the given threadPool.  Setting
	 *                 this parameter to 1 will have the effect of guaranteeing that
	 *                 all times are processed one at a time in the order they were submitted.
	 *                 Any other positive value will run that many items concurrently,
	 *                 up to the number of available threads.
	 * @param jobsReportProgress  true signals that jobs wish to report progress via their task
	 *                 monitor.  The default is false, which triggers this queue to report an
	 *                 overall progress for each job that is processed.  False is a good default
	 *                 for clients that have a finite number of jobs to be done.
	 */
	public ConcurrentQ(QCallback<I, R> callback, Queue<I> queue, GThreadPool threadPool,
			QItemListener<I, R> listener, boolean collectResults, int maxInProgress,
			boolean jobsReportProgress) {
		this.callback = callback;
		this.queue = queue;
		this.threadPool = threadPool;
		this.itemListener = listener;
		this.collectResults = collectResults;
		this.jobsReportProgress = jobsReportProgress;
		this.maxInProgress = maxInProgress > 0 ? maxInProgress : threadPool.getMaxThreadCount();
		this.tracker = new ProgressTracker(lock);
	}

	/**
	 * Adds a progress listener for this queue.  All the progress and messages reported by a
	 * QWorker will be routed to these listener.
	 * 
	 * @param listener the listener for receiving progress and message notifications.
	 */
	public synchronized void addProgressListener(QProgressListener<I> listener) {
		if (progressListener == null) {
			progressListener = listener;
		}
		else {
			progressListener = new ChainedProgressListener<>(progressListener, listener);
		}
	}

	/**
	 * Removes a progress listener from this queue.  All the progress and messages reported by a
	 * QWorker will be routed to this listener.
	 * @param listener the listener for receiving progress and message notifications.
	 */
	public synchronized void removeProgressListener(QProgressListener<I> listener) {
		if (progressListener == listener) {
			progressListener = null;
		}
		else if (progressListener instanceof ChainedProgressListener) {
			progressListener =
				((ChainedProgressListener<I>) progressListener).removeListener(listener);
		}
	}

	/**
	 * Sets the monitor to use with this queue.
	 * 
	 * @param monitor the monitor to attache to this queue
	 * @param cancelClearsAllItems if true, cancelling the monitor will cancel all items currently
	 * 								being processed by a thread and clear the scheduled
	 * 								items that haven't yet run.
	 * 								If false, only the items currently being processed will be cancelled.
	 */
	public void setMonitor(TaskMonitor monitor, boolean cancelClearsAllItems) {
		if (monitorAdapter != null) {
			monitorAdapter.dispose();
		}
		if (monitor != null) {
			monitorAdapter = new QMonitorAdapter(monitor, cancelClearsAllItems);
		}
	}

	/**
	 * Adds the list of items to this queue for concurrent processing.
	 * @param items the items to be scheduled for concurrent processing
	 */
	public void add(Collection<I> items) {
		lock.lock();
		try {
			queue.addAll(items);
			tracker.itemsAdded(items.size());
			fillOpenProcessingSlots();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Adds the items of the given iterator to this queue for concurrent processing.
	 * @param iterator an iterator from which the items to be scheduled for concurrent processing
	 * 	      will be taken.
	 */
	public void add(Iterator<I> iterator) {
		lock.lock();
		try {
			while (iterator.hasNext()) {
				queue.add(iterator.next());
				tracker.itemsAdded(1);
				fillOpenProcessingSlots();
			}
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Allows clients to use a bounded queue (such as a {@link LinkedBlockingQueue} to control
	 * how many items get placed into this queue at one time.  Calling the <code>add</code> methods
	 * will place all items into the queue, which for a large number of items, can consume a
	 * large amount of memory.  This method will block once the queue at maximum capacity,
	 * continuing to add new items as existing items on the queue are processed.
	 * <p>
	 * To enable blocking on the queue when it is full, construct this <code>ConcurrentQ</code>
	 * with an instance of {@link BlockingQueue}.
	 * 
	 * @param iterator An iterator from which items will be taken.
	 * @throws InterruptedException if this queue is interrupted while waiting to add more items
	 */
	public void offer(Iterator<I> iterator) throws InterruptedException {
		lock.lockInterruptibly();
		try {

			while (iterator.hasNext()) {
				I next = iterator.next();

				if (!queue.offer(next)) {
					// must be full...wait until space is available
					tracker.waitForNext();
					queue.offer(next);
				}

				tracker.itemsAdded(1);
				fillOpenProcessingSlots();
			}
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Adds the item to this queue for concurrent processing.
	 * @param item the item to be scheduled for concurrent processing.
	 */
	public void add(I item) {
		lock.lock();
		try {
			queue.add(item);
			tracker.itemsAdded(1);
			fillOpenProcessingSlots();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Returns true if this queue has no items waiting to be processed or currently being processed.
	 * @return true if this queue has no items waiting to be processed or currently being processed.
	 */
	public boolean isEmpty() {
		return tracker.isDone();
	}

	/**
	 * Waits until all scheduled items have been completed or cancelled and returns a list of
	 * QResults if this queue has been told to collect results.
	 * <P>
	 * You can still call this method to wait for items to be processed, even if you did not
	 * specify to collect results.  In that case, the list returned will be empty.
	 * 
	 * @return the list of QResult objects that have all the results of the completed jobs.
	 * @throws InterruptedException if this call was interrupted--Note:  this interruption only
	 *             happens if the calling thread cannot acquire the lock.  If the thread is
	 *             interrupted while waiting for results, then it will try again.
	 */
	public Collection<QResult<I, R>> waitForResults() throws InterruptedException {
		lock.lockInterruptibly();
		try {
			tracker.waitUntilDone();
			Collection<QResult<I, R>> returnValue = resultList;
			resultList = new LinkedList<>();
			return returnValue;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Wait until at least one result is available and then return the first result.
	 * 
	 * @return the first available result
	 * @throws InterruptedException if interrupted while waiting for a result
	 * @throws IllegalStateException if this queue has been set to not collect results
	 *         (see the constructor).
	 */
	public QResult<I, R> waitForNextResult() throws InterruptedException {
		if (!collectResults) {
			throw new IllegalStateException(
				"Can't wait for next result when not collecting results");
		}
		lock.lockInterruptibly();
		try {
			if (resultList.isEmpty()) {
				if (isEmpty()) {
					return null;
				}

				tracker.waitForNext();
			}
			return resultList.pop();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Waits until all items have been processed <b>OR</b> an Exception happens during the
	 * processing of <b>ANY item</b>.
	 * <p>
	 * <b><u>Note:</u></b>
	 * If an exception does occur then the remaining items in the
	 * queue will be cleared and all current items will be cancelled.
	 * <p>
	 * If you wish for processing to continue for remaining items when any item encounters an
	 * exception, then you should instead use {@link #waitForResults()}.  That method will return
	 * all results, both with and without exceptions, which you can then process, including
	 * checking for exceptions.  Note that to use {@link #waitForResults()} to examine exceptions,
	 * you must have created this queue with <code>collectResults</code> as true.
	 * 
	 * @throws InterruptedException if interrupted while waiting for a result
	 * @throws Exception any exception encountered while processing an item (this will cancel all
	 *         items in the queue).
	 */
	public void waitUntilDone() throws InterruptedException, Exception {
		lock.lockInterruptibly();
		try {
			checkException();
			while (!isEmpty()) {
				tracker.waitForNext();
				checkException();
			}
		}
		finally {
			lock.unlock();
		}
	}

	private void checkException() throws Exception {
		if (unhandledException != null) {
			cancelAllTasks(true);
			throw unhandledException;
		}
	}

	/**
	 * Waits up to the specified time for scheduled jobs to complete.  The results of all completed
	 * jobs will be returned if this queue has been told to collect results.  At the time that this
	 * returns, there may still be work to process.  The returned list will contain as much work
	 * as has been processed when the wait has finished.  Repeated calls to this method will not
	 * return results from previous waits.
	 * <P>
	 * You can still call this method to wait for items to be processed, even if you did not
	 * specify to collect results.  In that case, the list returned will be empty.
	 * 
	 * @param timeout the timeout
	 * @param unit the timeout unit
	 * @return the list of QResult objects that have all the results of the completed jobs.
	 * @throws InterruptedException if this call was interrupted.
	 */
	public Collection<QResult<I, R>> waitForResults(long timeout, TimeUnit unit)
			throws InterruptedException {
		lock.lockInterruptibly();
		try {
			tracker.waitUntilDone(timeout, unit);

			Collection<QResult<I, R>> returnValue = resultList;
			resultList = new LinkedList<>();
			return returnValue;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Cancels the processing of currently scheduled items in this queue.  Any items that haven't
	 * yet been scheduled on the threadPool are returned immediately from this call.  Items that
	 * are currently being processed will be cancelled and those results will be available on the
	 * next waitForResults() call and also if there is a QItemListener, it will be called with
	 * the QResult.  There is no guarantee that scheduled tasks will terminate any time soon.  If
	 * they check the isCancelled() state of their QMonitor, it will be true.  Setting the
	 * interruptRunningTasks to true, will result in a thread interrupt to any currently running
	 * task which might be useful if the task perform waiting operations like I/O.
	 * 
	 * @param interruptRunningTasks if true, an attempt will be made to interrupt any currently
	 * processing thread.
	 * @return a list of all items that have not yet been queued to the threadPool.
	 */
	public List<I> cancelAllTasks(boolean interruptRunningTasks) {
		List<FutureTaskMonitor<I, R>> tasksToBeCancelled = new ArrayList<>();
		List<I> nonStartedItems;
		lock.lock();
		try {
			nonStartedItems = removeUnscheduledJobs();
			tasksToBeCancelled.addAll(taskSet);
		}
		finally {
			lock.unlock();
		}
		for (FutureTaskMonitor<I, R> task : tasksToBeCancelled) {
			task.cancel(interruptRunningTasks);
		}
		return nonStartedItems;
	}

	public List<I> removeUnscheduledJobs() {
		List<I> nonStartedItems = new ArrayList<>();
		lock.lock();
		try {
			tracker.neverStartedItemsRemoved(queue.size());
			nonStartedItems.addAll(queue);
			queue.clear();
		}
		finally {
			lock.unlock();
		}
		return nonStartedItems;
	}

	public void cancelScheduledJobs() {
		List<FutureTaskMonitor<I, R>> tasksToBeCancelled = new ArrayList<>();
		lock.lock();
		try {
			tasksToBeCancelled.addAll(taskSet);
		}
		finally {
			lock.unlock();
		}
		for (FutureTaskMonitor<I, R> task : tasksToBeCancelled) {
			task.cancel(true);
		}

	}

	/**
	 * Cancels all running tasks and disposes of the internal thread pool if it is a private
	 * pool.
	 */
	public void dispose() {
		cancelAllTasks(true);
		if (threadPool.isPrivate()) {
			threadPool.shutdownNow();
		}
	}

	public boolean waitUntilDone(long timeout, TimeUnit unit) throws InterruptedException {
		lock.lockInterruptibly();
		try {
			tracker.waitUntilDone(timeout, unit);
			return tracker.isDone();
		}
		finally {
			lock.unlock();
		}
	}

	// This method adds jobs to the thread pool up to the maximum allowed at a time.
	private void fillOpenProcessingSlots() {
		while (!queue.isEmpty() && getInProgressCount() < maxInProgress) {
			I item = queue.remove();
			tracker.itemStarted();
			CallbackCallable qCall = new CallbackCallable(item);
			FutureTaskMonitor<I, R> task =
				new FutureTaskMonitor<>(this, qCall, item, tracker.getNextID());
			qCall.setFutureTask(task);
			taskSet.add(task);
			notifyTaskStarted(task);
			threadPool.submit(task);
		}
	}

	private void notifyTaskStarted(FutureTaskMonitor<I, R> task) {
		QProgressListener<I> listener = progressListener;
		if (listener == null) {
			return;
		}

		lock.unlock();
		try {
			listener.taskStarted(task.getID(), task.getItem());
		}
		finally {
			lock.lock();
		}
	}

	private long getInProgressCount() {
		return tracker.getItemsInProgressCount();
	}

	void itemProcessed(FutureTaskMonitor<I, R> task, QResult<I, R> result) {
		if (itemListener != null) {
			itemListener.itemProcessed(result);
		}
		lock.lock();
		try {
			taskSet.remove(task);
			if (collectResults) {
				resultList.add(result);
			}
			tracker.inProgressItemCompletedOrCancelled();
			fillOpenProcessingSlots();

			if (result.hasError() && unhandledException == null) {
				unhandledException = result.getError();
			}
		}
		finally {
			lock.unlock();
		}

		QProgressListener<I> listener = progressListener;
		if (listener != null) {
			listener.taskEnded(task.getID(), task.getItem(), tracker.getTotalItemCount(),
				tracker.getCompletedItemCount());
		}
	}

	void progressChanged(long id, I item, long currentProgress) {
		QProgressListener<I> listener = progressListener;
		if (listener != null) {
			listener.progressChanged(id, item, currentProgress);
		}
	}

	void maxProgressChanged(long id, I item, long maxProgress) {
		QProgressListener<I> listener = progressListener;
		if (listener != null) {
			listener.maxProgressChanged(id, item, maxProgress);
		}
	}

	void progressModeChanged(long id, I item, boolean indeterminate) {
		QProgressListener<I> listener = progressListener;
		if (listener != null) {
			listener.progressModeChanged(id, item, indeterminate);
		}
	}

	void progressMessageChanged(long id, I item, String message) {
		QProgressListener<I> listener = progressListener;
		if (listener != null) {
			listener.progressMessageChanged(id, item, message);
		}
	}

	private class CallbackCallable implements Callable<R> {

		private I item;
		private FutureTaskMonitor<I, R> future;

		CallbackCallable(I item) {
			this.item = item;
		}

		@Override
		public R call() throws Exception {
			return callback.process(item, future);
		}

		void setFutureTask(FutureTaskMonitor<I, R> future) {
			this.future = future;
		}
	}

	private static class ChainedProgressListener<I> implements QProgressListener<I> {
		private volatile QProgressListener<I> listener1;
		private volatile QProgressListener<I> listener2;

		ChainedProgressListener(QProgressListener<I> listener1, QProgressListener<I> listener2) {
			this.listener1 = listener1;
			this.listener2 = listener2;
		}

		QProgressListener<I> removeListener(QProgressListener<I> listener) {
			if (listener1 == listener) {
				return listener2;
			}
			else if (listener2 == listener) {
				return listener1;
			}

			if (listener1 instanceof ChainedProgressListener) {
				listener1 = ((ChainedProgressListener<I>) listener1).removeListener(listener);
			}
			if (listener2 instanceof ChainedProgressListener) {
				listener2 = ((ChainedProgressListener<I>) listener2).removeListener(listener);
			}
			return this;
		}

		@Override
		public void progressChanged(long id, I Item, long currentProgress) {
			listener1.progressChanged(id, Item, currentProgress);
			listener2.progressChanged(id, Item, currentProgress);
		}

		@Override
		public void taskStarted(long id, I Item) {
			listener1.taskStarted(id, Item);
			listener2.taskStarted(id, Item);
		}

		@Override
		public void taskEnded(long id, I Item, long totalCount, long completedCount) {
			listener1.taskEnded(id, Item, totalCount, completedCount);
			listener2.taskEnded(id, Item, totalCount, completedCount);
		}

		@Override
		public void progressModeChanged(long id, I item, boolean indeterminate) {
			listener1.progressModeChanged(id, item, indeterminate);
			listener2.progressModeChanged(id, item, indeterminate);
		}

		@Override
		public void progressMessageChanged(long id, I item, String message) {
			listener1.progressMessageChanged(id, item, message);
			listener2.progressMessageChanged(id, item, message);
		}

		@Override
		public void maxProgressChanged(long id, I item, long maxProgress) {
			listener1.maxProgressChanged(id, item, maxProgress);
			listener2.maxProgressChanged(id, item, maxProgress);
		}

	}

	/**
	 * Simple connector for traditional TaskMonitor and a task from the ConcurrentQ.  This adapter
	 * adds a cancel listener to the TaskMonitor and when cancelled is called on the monitor,
	 * it cancels the currently running (scheduled on the thread pool) and leaves the waiting
	 * tasks alone.  It also implements a QProgressListener and adds itself to the concurrentQ so
	 * that it gets progress events and messages and sets them on the task monitor.
	 */
	private class QMonitorAdapter implements QProgressListener<I>, CancelledListener {

		private TaskMonitor monitor;
		public final boolean cancelClearsAllJobs;

		QMonitorAdapter(TaskMonitor monitor, boolean cancelClearsAll) {
			this.monitor = monitor;
			cancelClearsAllJobs = cancelClearsAll;
			addProgressListener(this);
			monitor.addCancelledListener(this);
		}

		@Override
		public void cancelled() {
			if (cancelClearsAllJobs) {
				cancelAllTasks(true);
			}
			else {
				cancelScheduledJobs();
				monitor.clearCanceled();
			}
		}

		@Override
		public void progressChanged(long id, I Item, long currentProgress) {
			if (jobsReportProgress) {
				monitor.setProgress(currentProgress);
			}
		}

		@Override
		public void progressModeChanged(long id, I item, boolean indeterminate) {
			if (jobsReportProgress) {
				monitor.setIndeterminate(indeterminate);
			}
		}

		@Override
		public void progressMessageChanged(long id, I item, String message) {
			monitor.setMessage(message);
		}

		@Override
		public void maxProgressChanged(long id, I item, long maxProgress) {
			if (jobsReportProgress) {
				monitor.setMaximum(maxProgress);
			}
		}

		@Override
		public void taskStarted(long id, I Item) {
			// do nothing
		}

		@Override
		public void taskEnded(long id, I Item, long total, long progress) {
			if (!jobsReportProgress) {
				//
				// This code works in 2 ways.  The default case is that clients place items on
				// the queue.  As the amount of work grows, so too does the max progress value.
				// This obviates the need for clients to manage progress.  (The downside to this
				// is that the progress may keep getting pushed back as it approaches the
				// current maximum value.)  The second case is where the client has specified a
				// true maximum value.  In that case, this code will not change the maximum
				// (assuming that the client does not put more items into the queue than they
				// specified).
				//
				if (total > monitor.getMaximum()) {
					monitor.setMaximum(total);
				}
				monitor.setProgress(progress);
			}
		}

		public void dispose() {
			removeProgressListener(this);
			monitor.removeCancelledListener(this);
			monitor = TaskMonitor.DUMMY;
		}
	}

}
