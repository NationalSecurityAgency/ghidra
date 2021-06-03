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

import generic.concurrent.QCallback;
import generic.concurrent.QResult;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class ParallelDecompiler {

	static final String THREAD_POOL_NAME = "Parallel Decompiler";

	/**
	 * Decompile the given functions using multiple decompilers
	 * 
	 * @param callback the callback to be called for each that is processed
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
	 * Decompile the given functions using multiple decompilers
	 * 
	 * @param callback the callback to be called for each that is processed
	 * @param functions the functions to decompile
	 * @param monitor the task monitor
	 * @return the list of client results
	 * @throws InterruptedException if interrupted
	 * @throws Exception if any other exception occurs
	 */
	public static <R> List<R> decompileFunctions(QCallback<Function, R> callback,
			Collection<Function> functions,
			TaskMonitor monitor)
			throws InterruptedException, Exception {

		List<R> results =
			doDecompileFunctions(callback, functions.iterator(), functions.size(),
				monitor);
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
	public static <R> void decompileFunctions(QCallback<Function, R> callback,
			Program program,
			Iterator<Function> functions, Consumer<R> resultsConsumer,
			TaskMonitor monitor)
			throws InterruptedException, Exception {

		int max = program.getFunctionManager().getFunctionCount();
		DecompilerConcurrentQ<Function, R> queue =
			new DecompilerConcurrentQ<>(callback, THREAD_POOL_NAME, monitor);
		monitor.initialize(max);
		queue.process(functions, resultsConsumer);
		queue.waitUntilDone();
	}

	private static <R> List<R> doDecompileFunctions(QCallback<Function, R> callback,
			Iterator<Function> functions, int count, TaskMonitor monitor)
			throws InterruptedException, Exception {

		DecompilerConcurrentQ<Function, R> queue =
			new DecompilerConcurrentQ<>(callback, THREAD_POOL_NAME, monitor);

		monitor.initialize(count);

		queue.addAll(functions);

		Collection<QResult<Function, R>> qResults = null;
		try {
			qResults = queue.waitForResults();
		}
		finally {
			queue.dispose();
		}

		List<R> results = new ArrayList<>();
		for (QResult<Function, R> qResult : qResults) {
			results.add(qResult.getResult());
		}

		return results;
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
		return new ChunkingParallelDecompiler<>(callback, monitor);
	}

	private ParallelDecompiler() {
		// only use statically
	}
}
