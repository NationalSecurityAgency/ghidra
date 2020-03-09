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
package ghidra.app.util;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import generic.concurrent.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utility.function.Dummy;

/**
 * A class to perform some of the boilerplate setup of the {@link ConcurrentQ} that is shared
 * amongst clients that perform decompilation in parallel.
 * 
 * <p>This class can be used in a blocking or non-blocking fashion.  
 * 
 * <ul>
 * 		<li>For blocking usage, call
 * 		one of the <u>{@code add}</u> methods to put items in the queue and then call 
 * 		{@link #waitForResults()}.</li>  
 * 		<li>For non-blocking usage, simply call 
 * 		{@link #process(Iterator, Consumer)}, passing the consumer of the results.</li>
 * </ol>
 * <p>
 *
 * @param <I> The input data needed by the supplied {@link QCallback}
 * @param <R> The result data (can be the same as {@code I} if there is no result) returned
 *            by the {@link QCallback#process(Object, TaskMonitor)} method.
 */
public class DecompilerConcurrentQ<I, R> {

	private ConcurrentQ<I, R> queue;
	private Consumer<R> resultConsumer = Dummy.consumer();

	public DecompilerConcurrentQ(QCallback<I, R> callback, TaskMonitor monitor) {
		this(callback, AutoAnalysisManager.getSharedAnalsysThreadPool(), monitor);
	}

	public DecompilerConcurrentQ(QCallback<I, R> callback, String threadPoolName,
			TaskMonitor monitor) {
		this(callback, GThreadPool.getSharedThreadPool(threadPoolName), monitor);
	}

	private DecompilerConcurrentQ(QCallback<I, R> callback, GThreadPool pool, TaskMonitor monitor) {
		// @formatter:off
		queue = new ConcurrentQBuilder<I, R>()
			.setCollectResults(true)
			.setThreadPool(pool)
			.setMonitor(monitor)
			.setListener(new InternalResultListener())
			.build(callback);		
		// @formatter:on
	}

	public void addAll(Collection<I> collection) {
		queue.add(collection);
	}

	public void addAll(Iterator<I> iterator) {
		queue.add(iterator);
	}

	public void add(I i) {
		queue.add(i);
	}

	/**
	 * Adds all items to the queue for processing.  The results will be passed to the given consumer
	 * as they are produced.
	 * 
	 * @param functions the functions to process
	 * @param consumer the results consumer
	 */
	public void process(Iterator<I> functions, Consumer<R> consumer) {
		this.resultConsumer = Objects.requireNonNull(consumer);
		addAll(functions);
	}

	/**
	 * Waits for all results to be delivered.  The client is responsible for processing the
	 * results and handling any exceptions that may have occurred.
	 * 
	 * @return all results
	 * @throws InterruptedException if interrupted while waiting
	 */
	public Collection<QResult<I, R>> waitForResults() throws InterruptedException {
		try {
			return queue.waitForResults();
		}
		finally {
			queue.dispose();
		}
	}

	/**
	 * Waits for all work to finish. Any exception encountered will trigger all processing to 
	 * stop.  If you wish for the work to continue despite exceptions, then use 
	 * {@link #waitForResults()}.
	 * 
	 * @throws InterruptedException if interrupted while waiting
	 * @throws Exception any exception that is encountered while processing items.
	 */
	public void waitUntilDone() throws InterruptedException, Exception {
		try {
			queue.waitUntilDone();
		}
		finally {
			queue.dispose();
		}
	}

	public void dispose() {
		queue.dispose();
	}

	/**
	 * Calls dispose on the queue being processed.  Further, the call will block for up to 
	 * <tt>timeoutSeconds</tt> while waiting for the queue to finish processing. 
	 * 
	 * @param timeoutSeconds the number of seconds to wait for the disposed queue to finish
	 *        processing
	 */
	public void dispose(long timeoutSeconds) {
		queue.dispose();

		boolean finished = false;
		try {
			finished = queue.waitUntilDone(timeoutSeconds, TimeUnit.SECONDS);
		}
		catch (InterruptedException e) {
			// we tried!
		}

		if (!finished) {
			Msg.debug(this,
				"Unable to shutdown all tasks in " + timeoutSeconds + " " + TimeUnit.SECONDS);
		}
	}

	private class InternalResultListener implements QItemListener<I, R> {
		@Override
		public void itemProcessed(QResult<I, R> result) {
			try {
				R r = result.getResult();
				if (r != null) {
					resultConsumer.accept(r);
				}
			}
			catch (Throwable t) {
				// This code is an asynchronous callback.  Handle the exception the same way as 
				// the waitXyz() method do, which is to shutdown the queue.
				Msg.error(this, "Unexpected exception getting Decompiler result", t);
				queue.dispose();
			}

		}
	}
}
