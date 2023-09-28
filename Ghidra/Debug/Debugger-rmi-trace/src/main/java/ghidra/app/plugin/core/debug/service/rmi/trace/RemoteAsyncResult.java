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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import java.util.concurrent.*;

import ghidra.trace.model.target.TraceObject;
import ghidra.util.Swing;

/**
 * The future result of invoking a {@link RemoteMethod}.
 * 
 * <p>
 * While this can technically result in an object, returning values from remote methods is highly
 * discouraged. This has led to several issues in the past, including duplication of information
 * (and a lot of it) over the connection. Instead, most methods should just update the trace
 * database, and the client can retrieve the relevant information from it. One exception might be
 * the {@code execute} method. This is typically for executing a CLI command with captured output.
 * There is generally no place for such output to go into the trace, and the use cases for such a
 * method to return the output are compelling. For other cases, perhaps the most you can do is
 * return a {@link TraceObject}, so that a client can quickly associate the trace changes with the
 * method. Otherwise, please return null/void/None for all methods.
 * 
 * <b>NOTE:</b> To avoid the mistake of blocking the Swing thread on an asynchronous result, the
 * {@link #get()} methods have been overridden to check for the Swing thread. If invoked on the
 * Swing thread with a timeout greater than 1 second, an assertion error will be thrown. Please use
 * a non-swing thread, e.g., a task thread or script thread, to wait for results, or chain
 * callbacks.
 */
public class RemoteAsyncResult extends CompletableFuture<Object> {
	final ValueDecoder decoder;

	public RemoteAsyncResult() {
		this.decoder = ValueDecoder.DEFAULT;
	}

	public RemoteAsyncResult(OpenTrace open) {
		this.decoder = open;
	}

	@Override
	public Object get() throws InterruptedException, ExecutionException {
		if (Swing.isSwingThread()) {
			throw new AssertionError("Refusing indefinite wait on Swing thread");
		}
		return super.get();
	}

	@Override
	public Object get(long timeout, TimeUnit unit)
			throws InterruptedException, ExecutionException, TimeoutException {
		if (Swing.isSwingThread() && unit.toSeconds(timeout) > 1) {
			throw new AssertionError("Refusing a timeout > 1 second on Swing thread");
		}
		return super.get(timeout, unit);
	}
}
