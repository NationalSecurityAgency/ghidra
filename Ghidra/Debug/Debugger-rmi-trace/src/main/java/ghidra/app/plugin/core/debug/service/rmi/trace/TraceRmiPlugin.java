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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.TraceRmiService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Connect to back-end debuggers via Trace RMI",
	description = """
			Provides an alternative for connecting to back-end debuggers. The DebuggerModel has
			become a bit onerous to implement. Despite its apparent flexibility, the recorder at
			the front-end imposes many restrictions, and getting it to work turns into a lot of
			guess work and frustration. Trace RMI should offer a more direct means of recording a
			trace from a back-end.
			""",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesProvided = {
		TraceRmiService.class,
	})
public class TraceRmiPlugin extends Plugin implements TraceRmiService {
	private static final int DEFAULT_PORT = 15432;
	private final TaskMonitor monitor = new ConsoleTaskMonitor();

	private SocketAddress serverAddress = new InetSocketAddress("0.0.0.0", DEFAULT_PORT);
	private TraceRmiServer server;

	public TraceRmiPlugin(PluginTool tool) {
		super(tool);
	}

	public TaskMonitor getTaskMonitor() {
		// TODO: Create one in the Debug Console?
		return monitor;
	}

	@Override
	public SocketAddress getServerAddress() {
		if (server != null) {
			// In case serverAddress is ephemeral, get its actual address
			return server.getAddress();
		}
		return serverAddress;
	}

	@Override
	public void setServerAddress(SocketAddress serverAddress) {
		if (server != null) {
			throw new IllegalStateException("Cannot change server address while it is started");
		}
		this.serverAddress = serverAddress;
	}

	@Override
	public void startServer() throws IOException {
		if (server != null) {
			throw new IllegalStateException("Server is already started");
		}
		server = new TraceRmiServer(this, serverAddress);
		server.start();
	}

	@Override
	public void stopServer() {
		if (server != null) {
			server.close();
		}
		server = null;
	}

	@Override
	public boolean isServerStarted() {
		return server != null;
	}

	@Override
	@SuppressWarnings("resource")
	public TraceRmiHandler connect(SocketAddress address) throws IOException {
		Socket socket = new Socket();
		socket.connect(address);
		return new TraceRmiHandler(this, socket);
	}

	@Override
	public TraceRmiAcceptor acceptOne(SocketAddress address) throws IOException {
		TraceRmiAcceptor acceptor = new TraceRmiAcceptor(this, address);
		acceptor.start();
		return acceptor;
	}
}
