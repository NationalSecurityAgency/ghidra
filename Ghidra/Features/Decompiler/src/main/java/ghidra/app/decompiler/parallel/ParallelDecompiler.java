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
package ghidra.app.decompiler.parallel;

import java.util.*;
import java.util.function.Consumer;

import generic.concurrent.*;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class ParallelDecompiler {

	static final String THREAD_POOL_NAME = "Parallel Decompiler";
	static final String DECOMPILER_PROCESSES_PROPERTY = "ghidra.parallel.decompiler.processes";
	static final String DECOMPILER_PROCESSES_ENV = "GHIDRA_PARALLEL_DECOMPILER_PROCESSES";
	static final int DEFAULT_DECOMPILER_PROCESSES = 27;

	/**
	 * Decompile the given functions using multiple decompilers
	 *
	 * @param callback the callback to be called for each item that is processed
	 * @param program the program
	 * @param addresses the addresses restricting which functions to decompile
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback, Program program,
			AddressSetView addresses, TaskMonitor monitor) throws InterruptedException, Exception {

		int functionCount = program.getFunctionManager().getFunctionCount();
		Listing listing = program.getListing();
		FunctionIterator iterator = listing.getFunctions(addresses, true);

		List<R> results = doDecompileFunctions(callback, iterator, functionCount, monitor);
		return results;
	}

	/**
	 * Decompile the given functions using a bounded number of worker threads/decompiler processes.
	 *
	 * @param callback the callback to be called for each item that is processed
	 * @param program the program
	 * @param addresses the addresses restricting which functions to decompile
	 * @param maxDecompilerProcesses the maximum number of concurrent decompiler workers
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback, Program program,
			AddressSetView addresses, int maxDecompilerProcesses, TaskMonitor monitor)
			throws InterruptedException, Exception {

		int functionCount = program.getFunctionManager().getFunctionCount();
		Listing listing = program.getListing();
		FunctionIterator iterator = listing.getFunctions(addresses, true);

		List<R> results =
			doDecompileFunctions(callback, iterator, functionCount, maxDecompilerProcesses, monitor);
		return results;
	}

	/**
	 * Decompile the given functions using multiple decompilers
	 *
	 * @param callback the callback to be called for each item that is processed
	 * @param functions the functions to decompile
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback,
			Collection<Function> functions, TaskMonitor monitor)
			throws InterruptedException, Exception {

		List<R> results =
			doDecompileFunctions(callback, functions.iterator(), functions.size(), monitor);
		return results;
	}

	/**
	 * Decompile the given functions using a bounded number of worker threads/decompiler processes.
	 *
	 * @param callback the callback to be called for each item that is processed
	 * @param functions the functions to decompile
	 * @param maxDecompilerProcesses the maximum number of concurrent decompiler workers
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback,
			Collection<Function> functions, int maxDecompilerProcesses, TaskMonitor monitor)
			throws InterruptedException, Exception {

		List<R> results = doDecompileFunctions(callback, functions.iterator(), functions.size(),
			maxDecompilerProcesses, monitor);
		return results;
	}

	/**
	 * Decompile the given functions using multiple decompilers.
	 *
	 * <p>Results will be passed to the given consumer as they are produced.  Calling this
	 * method allows you to handle results as they are discovered.
	 *
	 * <p><strong>This method will wait for all processing before returning.</strong>
	 *
	 * @param callback the callback to be called for each that is processed
	 * @param program the program
	 * @param functions the functions to decompile
	 * @param resultsConsumer the consumer to which results will be passed
	 * @param monitor the task monitor
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> void decompileFunctions(QCallback<Function, R> callback, Program program,
			Iterator<Function> functions, Consumer<R> resultsConsumer, TaskMonitor monitor)
			throws InterruptedException, Exception {

		decompileFunctions(callback, program, functions, resultsConsumer,
			getDefaultDecompilerProcessCount(), monitor);
	}

	/**
	 * Decompile the given functions using a bounded number of worker threads/decompiler processes.
	 * Results will be passed to the given consumer as they are produced.
	 *
	 * @param callback the callback to be called for each that is processed
	 * @param program the program
	 * @param functions the functions to decompile
	 * @param resultsConsumer the consumer to which results will be passed
	 * @param maxDecompilerProcesses the maximum number of concurrent decompiler workers
	 * @param monitor the task monitor
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> void decompileFunctions(QCallback<Function, R> callback, Program program,
			Iterator<Function> functions, Consumer<R> resultsConsumer, int maxDecompilerProcesses,
			TaskMonitor monitor) throws InterruptedException, Exception {

		int max = program.getFunctionManager().getFunctionCount();
		boolean collectResults = false; // the client will process results as they arrive
		GThreadPool threadPool = createBoundedThreadPool(maxDecompilerProcesses);
		DecompilerConcurrentQ<Function, R> queue =
			new DecompilerConcurrentQ<>(callback, threadPool, collectResults, monitor);

		monitor.initialize(max);
		try {
			queue.process(functions, resultsConsumer);
			queue.waitUntilDone();
		}
		finally {
			threadPool.shutdownNow();
		}
	}

	private static <R> List<R> doDecompileFunctions(QCallback<Function, R> callback,
			Iterator<Function> functions, int count, TaskMonitor monitor)
			throws InterruptedException, Exception {

		return doDecompileFunctions(callback, functions, count, getDefaultDecompilerProcessCount(),
			monitor);
	}

	private static <R> List<R> doDecompileFunctions(QCallback<Function, R> callback,
			Iterator<Function> functions, int count, int maxDecompilerProcesses, TaskMonitor monitor)
			throws InterruptedException, Exception {

		GThreadPool threadPool = createBoundedThreadPool(maxDecompilerProcesses);
		DecompilerConcurrentQ<Function, R> queue =
			new DecompilerConcurrentQ<>(callback, threadPool, true, monitor);
		return doDecompileFunctions(queue, functions, count, monitor, threadPool);
	}

	private static <R> List<R> doDecompileFunctions(DecompilerConcurrentQ<Function, R> queue,
			Iterator<Function> functions, int count, TaskMonitor monitor, GThreadPool privateThreadPool)
			throws InterruptedException, Exception {

		monitor.initialize(count);

		queue.addAll(functions);

		Collection<QResult<Function, R>> qResults = null;
		try {
			qResults = queue.waitForResults();
		}
		finally {
			queue.dispose();
			if (privateThreadPool != null) {
				privateThreadPool.shutdownNow();
			}
		}

		List<R> results = new ArrayList<>();
		for (QResult<Function, R> qResult : qResults) {
			results.add(qResult.getResult());
		}

		return results;
	}

	static GThreadPool createBoundedThreadPool(int maxDecompilerProcesses) {
		if (maxDecompilerProcesses < 1) {
			throw new IllegalArgumentException("maxDecompilerProcesses must be at least 1");
		}

		GThreadPool threadPool = GThreadPool.getPrivateThreadPool(THREAD_POOL_NAME);
		threadPool.setMinThreadCount(0);
		threadPool.setMaxThreadCount(maxDecompilerProcesses);
		return threadPool;
	}

	static int getDefaultDecompilerProcessCount() {
		String configured = System.getProperty(DECOMPILER_PROCESSES_PROPERTY);
		if (configured == null || configured.isBlank()) {
			configured = System.getenv(DECOMPILER_PROCESSES_ENV);
		}
		if (configured == null || configured.isBlank()) {
			return DEFAULT_DECOMPILER_PROCESSES;
		}
		try {
			int value = Integer.parseInt(configured.trim());
			return Math.max(value, 1);
		}
		catch (NumberFormatException e) {
			return DEFAULT_DECOMPILER_PROCESSES;
		}
	}

	/**
	 * Creates an object that can be used to perform decompilation of a limited number of
	 * functions at a time, as opposed to working over an entire range of functions at once.
	 * {@link #decompileFunctions(QCallback, Program, AddressSetView, TaskMonitor)} will create
	 * and tear down concurrent data structures on each use, making repeated calls less efficient.
	 * You would use this method when you wish to perform periodic work as results are returned
	 * <b>and when using the callback mechanism is not sufficient</b> such as when ordering of
	 * results is required.
	 *
	 * @param callback the callback required to perform work.
	 * @param monitor the monitor used to report progress and to cancel
	 * @return the parallel decompiler used for decompiling.
	 */
	public static <R> ChunkingParallelDecompiler<R> createChunkingParallelDecompiler(
			QCallback<Function, R> callback, TaskMonitor monitor) {
		return new ChunkingParallelDecompiler<>(callback, getDefaultDecompilerProcessCount(), monitor);
	}

	public static <R> ChunkingParallelDecompiler<R> createChunkingParallelDecompiler(
			QCallback<Function, R> callback, int maxDecompilerProcesses, TaskMonitor monitor) {
		return new ChunkingParallelDecompiler<>(callback, maxDecompilerProcesses, monitor);
	}

	private ParallelDecompiler() {
		// only use statically
	}
}
