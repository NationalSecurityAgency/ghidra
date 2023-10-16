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
package ghidra.debug.api.tracermi;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.TimeoutException;

import ghidra.trace.model.Trace;

public interface TraceRmiConnection extends AutoCloseable {
	SocketAddress getRemoteAddress();

	RemoteMethodRegistry getMethods();

	Trace waitForTrace(long timeoutMillis) throws TimeoutException;

	long getLastSnapshot(Trace trace);

	@Override
	void close() throws IOException;

	boolean isClosed();

	void waitClosed();
}
