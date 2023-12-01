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

import java.io.IOException;
import java.net.*;

import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiServiceListener.ConnectMode;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public abstract class AbstractTraceRmiListener {
	protected final TraceRmiPlugin plugin;
	protected final SocketAddress address;

	protected ServerSocket socket;

	public AbstractTraceRmiListener(TraceRmiPlugin plugin, SocketAddress address) {
		this.plugin = plugin;
		this.address = address;
	}

	protected abstract void bind() throws IOException;

	public void start() throws IOException {
		socket = new ServerSocket();
		bind();
		startServiceLoop();
	}

	protected abstract void startServiceLoop();

	public void setTimeout(int millis) throws SocketException {
		socket.setSoTimeout(millis);
	}

	protected abstract ConnectMode getConnectMode();

	/**
	 * Accept a connection and handle its requests.
	 * 
	 * <p>
	 * This launches a new thread to handle the requests. The thread remains alive until the socket
	 * is closed by either side.
	 * 
	 * @return the handler
	 * @throws IOException on error
	 * @throws CancelledException if the accept is cancelled
	 */
	@SuppressWarnings("resource")
	protected TraceRmiHandler doAccept(TraceRmiAcceptor acceptor) throws IOException {
		Socket client = socket.accept();
		TraceRmiHandler handler = new TraceRmiHandler(plugin, client);
		handler.start();
		plugin.listeners.invoke().connected(handler, getConnectMode(), acceptor);
		return handler;
	}

	public void close() {
		try {
			socket.close();
		}
		catch (IOException e) {
			Msg.error("Error closing TraceRmi service", e);
		}
	}

	public SocketAddress getAddress() {
		return socket.getLocalSocketAddress();
	}
}
