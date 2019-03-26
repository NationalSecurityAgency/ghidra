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

import java.io.IOException;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of {@link QCallback} that performs the management of the 
 * {@link DecompInterface} instances using a Pool.
 * 
 * <P>Clients will get a chance to configure each newly created decompiler via the passed-in
 * {@link DecompileConfigurer}.
 * 
 * <P>Clients must implement {@link #process(DecompileResults, TaskMonitor)}, which will be
 * called for each function that is decompiled.
 *
 * @param <R> the return type
 */
public abstract class DecompilerCallback<R> implements QCallback<Function, R> {

	private CachingPool<DecompInterface> pool;
	private int timeout = 60;

	public DecompilerCallback(Program program, DecompileConfigurer configurer) {
		this.pool = new CachingPool<>(new DecompilerFactory(program, configurer));
	}

	/**
	 * This is called when a function is decompiled.
	 * 
	 * @param results the decompiled results
	 * @param monitor the task monitor
	 * @return the client result
	 * @throws Exception if there is any issue processing the given results
	 */
	public abstract R process(DecompileResults results, TaskMonitor monitor) throws Exception;

	@Override
	public R process(Function f, TaskMonitor monitor) throws Exception {

		if (monitor.isCancelled()) {
			return null;
		}

		DecompInterface decompiler = null;
		DecompileResults decompileResults;
		try {
			decompiler = pool.get();
			monitor.setMessage("Decompiling " + f.getName());
			decompileResults = decompiler.decompileFunction(f, timeout, monitor);
		}
		finally {
			if (decompiler != null) {
				pool.release(decompiler);
			}
		}

		R r = process(decompileResults, monitor);
		return r;

	}

	/**
	 * Sets the timeout for each decompile
	 * 
	 * @param timeoutSecs the timeout in seconds
	 */
	public void setTimeout(int timeoutSecs) {
		this.timeout = timeoutSecs;
	}

	/**
	 * Call this when all work is done so that the pooled decompilers can be disposed
	 */
	public void dispose() {
		pool.dispose();
	}

	private static class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		private Program program;
		private DecompileConfigurer configurer;

		DecompilerFactory(Program program, DecompileConfigurer configurer) {
			this.program = program;
			this.configurer = configurer;
		}

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {

			DecompInterface decompiler = new DecompInterface();

			configurer.configure(decompiler);
			decompiler.openProgram(program);

			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}
}
