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
package ghidra.features.bsim.query;

import java.util.Iterator;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Run decompilation across multiple functions in a single program, distributing the task across
 * a specific number of threads
 *
 */
public class ParallelDecompileTask {
	private Program program;
	private TaskMonitor taskMonitor = TaskMonitor.DUMMY;
	private DecompileFunctionTask ftask_template; // Template of the worker task

	// save for shutting down abnormally
	private DecompilerConcurrentQ<Function, Function> queue;

	public ParallelDecompileTask(Program prog, TaskMonitor mon, DecompileFunctionTask ftask) {
		program = prog;
		if (mon != null)
			taskMonitor = mon;
		ftask_template = ftask;

		ftask_template.initializeGlobal(program);
	}

	public void decompile(Iterator<Function> iter, int functionCount) throws DecompileException {
		try {
			doDecompile(iter, functionCount);
		}
		catch (InterruptedException e) {
			Msg.error(this, "Problem with decompiler worker thread", e);
			throw new DecompileException("interrupted", e.getMessage());
		}
		catch (Exception t) {
			Msg.error(this, "Problem with decompiler worker thread", t);
			DecompileException decompileException =
				new DecompileException("execution", t.getMessage());
			decompileException.initCause(t);
			throw decompileException;
		}
	}

	private void doDecompile(Iterator<Function> iter, int functionCount)
			throws InterruptedException, Exception {
		taskMonitor.setMessage("Analyzing functions...");
		taskMonitor.initialize(functionCount);

		CachingPool<DecompileFunctionTask> decompilerPool =
			new CachingPool<DecompileFunctionTask>(new DecompilerTaskFactory(ftask_template));
		QCallback<Function, Function> callback = new ParallelDecompilerCallback(decompilerPool);

		queue = new DecompilerConcurrentQ<Function, Function>(callback, taskMonitor);

		queue.addAll(iter);
		try {
			queue.waitUntilDone();
		}
		finally {
			queue.dispose();
			decompilerPool.dispose();
		}
	}

	void shutdown() {
		if (queue == null) {
			return;
		}

		//     Wait, at least a bit, for the tasks to drop out of their work (we could be
		//     getting called from a tool shutdown event, which means we don't want to block
		//     indefinitely, or even too long.

		// for now use 5 seconds, which seems long when closing a tool, but the user did
		// decide to exit without cancelling the task first, so it is reasonable to expect 
		// some delay
		queue.dispose(5);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class ParallelDecompilerCallback implements QCallback<Function, Function> {

		private CachingPool<DecompileFunctionTask> pool;

		ParallelDecompilerCallback(CachingPool<DecompileFunctionTask> decompilerPool) {
			this.pool = decompilerPool;
		}

		@Override
		public Function process(Function func, TaskMonitor monitor) throws Exception {
			monitor.setMessage("Decompiling " + func.getName());

			DecompileFunctionTask task = pool.get();
			try {
				task.decompile(func, monitor);
			}
			finally {
				pool.release(task);
			}

			return null; // we don't use results in the parallel implementation
		}
	}

	private class DecompilerTaskFactory extends CountingBasicFactory<DecompileFunctionTask> {
		private DecompileFunctionTask taskFactory;

		DecompilerTaskFactory(DecompileFunctionTask taskFactory) {
			this.taskFactory = taskFactory;
		}

		@Override
		public DecompileFunctionTask doCreate(int itemNumber) throws DecompileException {
			int zeroBasedNumber = itemNumber - 1;
			return taskFactory.clone(zeroBasedNumber);
		}

		@Override
		public void doDispose(DecompileFunctionTask task) {
			task.shutdown();
		}
	}
}
