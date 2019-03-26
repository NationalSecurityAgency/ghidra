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

import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

import generic.concurrent.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A class to perform some of the boilerplate setup of the {@link ConcurrentQ} that is shared
 * amongst clients that perform decompilation in parallel.
 *
 * @param <I> The input data needed by the supplied {@link QCallback}
 * @param <R> The result data (can be the same as {@link I} if there is no result) returned
 *            by the {@link QCallback#process(Object, TaskMonitor)} method.
 */
public class DecompilerConcurrentQ<I, R> {

	private ConcurrentQ<I, R> queue;

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
	 * Waits for all results to be delivered.  The client is responsible for processing the
	 * results and handling any exceptions that may have occurred.
	 * 
	 * @return all results
	 * @throws InterruptedException if interrupted while waiting
	 */
	public Collection<QResult<I, R>> waitForResults() throws InterruptedException {
		Collection<QResult<I, R>> results = null;
		try {
			results = queue.waitForResults();
		}
		finally {
			queue.dispose();
		}

		return results;
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
		queue.waitUntilDone();
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
}
