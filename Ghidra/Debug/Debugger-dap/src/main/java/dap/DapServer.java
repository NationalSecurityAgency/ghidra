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
package dap;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;

import org.eclipse.lsp4j.debug.services.IDebugProtocolClient;
import org.eclipse.lsp4j.jsonrpc.Launcher;
import org.eclipse.lsp4j.jsonrpc.debug.DebugLauncher;

import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.util.Msg;

public class DapServer implements Runnable {

	private DapPlugin plugin;
	private DapDebugAdapter adapter;
	private InetAddress address;
	private int port;

	private ServerSocket server;
	private Thread listenerThread;
	private ExecutorService sessionThreadPool = Executors.newCachedThreadPool();
	private volatile boolean running = false;

	public DapServer(DapPlugin plugin, DapDebugAdapter adapter) {
		this.plugin = plugin;
		this.adapter = adapter;
		this.address = plugin.getInetAddress();
		this.port = plugin.getPort();
	}

	public void startServer() {
		if (running) {
			return;
		}
		try {
			if (server != null && !server.isClosed()) {
				server.close();
			}
			server = new ServerSocket(port, 50, address);
			this.running = true;

			this.listenerThread = new Thread(this, "DAP-Server-Listener");
			this.listenerThread.start();
		}
		catch (IOException e) {
			throw new RuntimeException("Could not start server" + e.getMessage());
		}
	}

	public void stopServer() {
		if (!running) {
			return;
		}
		running = false;

		if (server != null) {
			try {
				if (!server.isClosed()) {
					server.close();
				}
			}
			catch (IOException e) {
				Msg.warn(this, "Error closing server socket: " + e.getMessage());
			}
			server = null;
		}

		if (listenerThread != null) {
			listenerThread.interrupt();
			listenerThread = null;
		}

		if (sessionThreadPool != null) {
			sessionThreadPool.shutdownNow();
			try {
				if (!sessionThreadPool.awaitTermination(2, TimeUnit.SECONDS)) {
					Msg.warn(this, "Session thread pool did not terminate cleanly.");
				}
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			sessionThreadPool = null;
		}
	}

	@Override
	public void run() {
		ServerSocket localServer = this.server;
		while (running && localServer != null && !localServer.isClosed()) {
			try {
				Socket clientSocket = localServer.accept();
				if (running && sessionThreadPool != null) {
					sessionThreadPool.submit(() -> handleClientSession(clientSocket));
				}
				else {
					clientSocket.close(); // Safeguard against trailing boundary race connections
				}
			}
			catch (IOException e) {
				if (running) {
					Msg.error(this, "Error accepting connection: " + e.getMessage());
				}
			}
		}
	}

	private void handleClientSession(Socket socket) {
		try (Socket s = socket;
				InputStream in = s.getInputStream();
				OutputStream out = s.getOutputStream()) {

			Launcher<IDebugProtocolClient> launcher = DebugLauncher.createLauncher(
				adapter,
				IDebugProtocolClient.class,
				in,
				out);
			IDebugProtocolClient client = launcher.getRemoteProxy();

			adapter.setClient(client);
			plugin.setClient(client);
			launcher.startListening().get();

		}
		catch (Exception e) {
			Msg.error(this, "Session error: " + e.getMessage());
		}
	}

	public DapDebugAdapter getAdapter() {
		return adapter;
	}

	public void updateAdapter(DebuggerCoordinates debuggerCoordinates) {
		adapter.setCoordinates(debuggerCoordinates);
	}

}
