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
package ghidra.comm.service;

import java.io.IOException;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.CompletableFuture;

public abstract class AbstractAsyncClientHandler<S extends AbstractAsyncServer<S, H>, H extends AbstractAsyncClientHandler<S, H>> {
	protected final S server;
	protected final AsynchronousSocketChannel sock;

	public AbstractAsyncClientHandler(S server, AsynchronousSocketChannel sock) {
		this.server = server;
		this.sock = sock;
	}

	/**
	 * Close the client connection
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	protected void close() throws IOException {
		sock.close();
	}

	/**
	 * Start the request processing loop
	 * 
	 * The loop executes until the client connection is lost, at which point the future must be
	 * completed. The server will automatically remove the handler when the future completes.
	 * 
	 * @return a future which completes when the processing loop terminates
	 */
	protected abstract CompletableFuture<Void> launchAsync();
}
