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

import java.io.IOException;
import java.net.*;

import ghidra.util.Msg;

public class TraceRmiServer {
	protected final TraceRmiPlugin plugin;
	protected final SocketAddress address;

	protected ServerSocket socket;

	public TraceRmiServer(TraceRmiPlugin plugin, SocketAddress address) {
		this.plugin = plugin;
		this.address = address;
	}

	protected void bind() throws IOException {
		socket.bind(address);
	}

	public void start() throws IOException {
		socket = new ServerSocket();
		bind();
		new Thread(this::serviceLoop, "trace-rmi server " + socket.getLocalSocketAddress()).start();
	}

	public void setTimeout(int millis) throws SocketException {
		socket.setSoTimeout(millis);
	}

	/**
	 * Accept a connection and handle its requests.
	 * 
	 * <p>
	 * This launches a new thread to handle the requests. The thread remains alive until the socket
	 * is closed by either side.
	 * 
	 * @return the handler
	 * @throws IOException on error
	 */
	@SuppressWarnings("resource")
	protected TraceRmiHandler accept() throws IOException {
		Socket client = socket.accept();
		TraceRmiHandler handler = new TraceRmiHandler(plugin, client);
		handler.start();
		return handler;
	}

	protected void serviceLoop() {
		try {
			accept();
		}
		catch (IOException e) {
			if (socket.isClosed()) {
				return;
			}
			Msg.error("Error accepting TraceRmi client", e);
			return;
		}
		finally {
			try {
				socket.close();
			}
			catch (IOException e) {
				Msg.error("Error closing TraceRmi service", e);
			}
		}
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
