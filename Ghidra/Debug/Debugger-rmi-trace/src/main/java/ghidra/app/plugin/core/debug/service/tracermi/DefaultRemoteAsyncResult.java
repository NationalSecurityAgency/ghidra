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
package ghidra.app.plugin.core.debug.service.tracermi;

import java.util.concurrent.*;

import ghidra.debug.api.tracermi.RemoteAsyncResult;
import ghidra.util.Swing;

public class DefaultRemoteAsyncResult extends CompletableFuture<Object>
		implements RemoteAsyncResult {
	final ValueDecoder decoder;

	public DefaultRemoteAsyncResult() {
		this.decoder = ValueDecoder.DEFAULT;
	}

	public DefaultRemoteAsyncResult(OpenTrace open) {
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
