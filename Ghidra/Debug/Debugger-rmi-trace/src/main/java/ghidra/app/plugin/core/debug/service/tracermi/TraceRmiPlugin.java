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
import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.*;
import ghidra.debug.api.progress.CloseableTaskMonitor;
import ghidra.debug.api.tracermi.*;
import ghidra.debug.api.tracermi.TraceRmiServiceListener.ConnectMode;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.task.ConsoleTaskMonitor;

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
		InternalTraceRmiService.class,
	})
public class TraceRmiPlugin extends Plugin implements InternalTraceRmiService {
	private static final int DEFAULT_PORT = 15432;

	static class FallbackTaskMonitor extends ConsoleTaskMonitor implements CloseableTaskMonitor {
		@Override
		public void close() {
			// Nothing
		}

		@Override
		public void reportError(Throwable e) {
			Msg.error(e.getMessage(), e);
		}
	}

	@AutoServiceConsumed
	private DebuggerTargetService targetService;
	@AutoServiceConsumed
	private ProgressService progressService;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	private SocketAddress serverAddress = new InetSocketAddress("0.0.0.0", DEFAULT_PORT);
	private TraceRmiServer server;

	private final Set<TraceRmiHandler> handlers = new LinkedHashSet<>();
	private final Set<DefaultTraceRmiAcceptor> acceptors = new LinkedHashSet<>();

	final ListenerSet<TraceRmiServiceListener> listeners =
		new ListenerSet<>(TraceRmiServiceListener.class, true);

	private final CloseableTaskMonitor fallbackMonitor = new FallbackTaskMonitor();

	public TraceRmiPlugin(PluginTool tool) {
		super(tool);
		autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	protected CloseableTaskMonitor createMonitor() {
		if (progressService == null) {
			return fallbackMonitor;
		}
		return progressService.publishTask();
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
		listeners.invoke().serverStarted(server.getAddress());
	}

	@Override
	public void stopServer() {
		if (server != null) {
			server.close();
			server = null;
			listeners.invoke().serverStopped();
		}
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
		listeners.invoke().connected(handler, ConnectMode.CONNECT, null);
		return handler;
	}

	@Override
	public DefaultTraceRmiAcceptor acceptOne(SocketAddress address) throws IOException {
		DefaultTraceRmiAcceptor acceptor = new DefaultTraceRmiAcceptor(this, address);
		acceptor.start();
		listeners.invoke().waitingAccept(acceptor);
		return acceptor;
	}

	void addHandler(TraceRmiHandler handler) {
		synchronized (handlers) {
			handlers.add(handler);
		}
	}

	void removeHandler(TraceRmiHandler handler) {
		synchronized (handlers) {
			handlers.remove(handler);
		}
	}

	@Override
	public Collection<TraceRmiConnection> getAllConnections() {
		synchronized (handlers) {
			return List.copyOf(handlers);
		}
	}

	void addAcceptor(DefaultTraceRmiAcceptor acceptor) {
		synchronized (acceptors) {
			acceptors.add(acceptor);
		}
	}

	void removeAcceptor(DefaultTraceRmiAcceptor acceptor) {
		synchronized (acceptors) {
			acceptors.remove(acceptor);
		}
	}

	@Override
	public Collection<TraceRmiAcceptor> getAllAcceptors() {
		synchronized (acceptors) {
			return List.copyOf(acceptors);
		}
	}

	void publishTarget(TraceRmiHandler handler, TraceRmiTarget target) {
		Swing.runIfSwingOrRunLater(() -> {
			targetService.publishTarget(target);
			listeners.invoke().targetPublished(handler, target);
		});
	}

	void withdrawTarget(TraceRmiTarget target) {
		Swing.runIfSwingOrRunLater(() -> {
			targetService.withdrawTarget(target);
		});
	}

	@Override
	public void addTraceServiceListener(TraceRmiServiceListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeTraceServiceListener(TraceRmiServiceListener listener) {
		listeners.remove(listener);
	}
}
