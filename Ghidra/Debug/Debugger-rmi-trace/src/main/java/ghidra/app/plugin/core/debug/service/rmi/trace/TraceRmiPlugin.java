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
import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.TraceRmiService;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Swing;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "Connect to back-end debuggers via Trace RMI",
	description = """
			Provides a means for connecting to back-end debuggers.
			NOTE this is an alternative to the DebuggerModel and is meant to replace it.
			""",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTargetService.class,
	},
	servicesProvided = {
		TraceRmiService.class,
	})
public class TraceRmiPlugin extends Plugin implements TraceRmiService {
	private static final int DEFAULT_PORT = 15432;

	@AutoServiceConsumed
	private DebuggerTargetService targetService;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	private final TaskMonitor monitor = new ConsoleTaskMonitor();

	private SocketAddress serverAddress = new InetSocketAddress("0.0.0.0", DEFAULT_PORT);
	private TraceRmiServer server;

	private final Set<TraceRmiHandler> handlers = new LinkedHashSet<>();

	public TraceRmiPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
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
		TraceRmiHandler handler = new TraceRmiHandler(this, socket);
		handler.start();
		return handler;
	}

	@Override
	public DefaultTraceRmiAcceptor acceptOne(SocketAddress address) throws IOException {
		DefaultTraceRmiAcceptor acceptor = new DefaultTraceRmiAcceptor(this, address);
		acceptor.start();
		return acceptor;
	}

	void addHandler(TraceRmiHandler handler) {
		handlers.add(handler);
	}

	void removeHandler(TraceRmiHandler handler) {
		handlers.remove(handler);
	}

	@Override
	public Collection<TraceRmiConnection> getAllConnections() {
		return List.copyOf(handlers);
	}

	void publishTarget(TraceRmiTarget target) {
		Swing.runIfSwingOrRunLater(() -> {
			targetService.publishTarget(target);
		});
	}

	void withdrawTarget(TraceRmiTarget target) {
		Swing.runIfSwingOrRunLater(() -> {
			targetService.withdrawTarget(target);
		});
	}
}
