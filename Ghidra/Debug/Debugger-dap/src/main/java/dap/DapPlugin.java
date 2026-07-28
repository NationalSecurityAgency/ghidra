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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import org.eclipse.lsp4j.debug.*;
import org.eclipse.lsp4j.debug.Module;
import org.eclipse.lsp4j.debug.services.IDebugProtocolClient;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceProcess;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceEvents;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "DapDebuggerSupport",
	description = "Plugin implements server-side DAP access to the debugger",
	eventsConsumed = {
		ProgramActivatedPluginEvent.class, ProgramClosedPluginEvent.class,
		TraceActivatedPluginEvent.class, TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class
	})
//@formatter:on

public class DapPlugin extends ProgramPlugin {

	public final static String HELP_LOCATION = "dap";
	private static final String OPTIONS_TITLE = "DAP Server";

	private DapServer server;
	private final Map<Trace, ListenerForChanges> listeners = new HashMap<>();
	private IDebugProtocolClient client;

	public DapPlugin(PluginTool tool) {
		super(tool);
		createActions();
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.registerOption("Port", OptionType.INT_TYPE, 54321, null, "Port to connect to");
		opt.registerOption("IP address", OptionType.STRING_TYPE,
			InetAddress.getLoopbackAddress().getHostAddress(), null,
			"IP address to connect to");
	}

	private void createActions() {

		new ActionBuilder("Start DAP Server", getName())
				.menuPath("Debugger", "DAP", "Start server")
				.helpLocation(new HelpLocation(getName(),HELP_LOCATION))
				.enabledWhen(_ -> currentProgram != null)
				.onAction(_ -> doStartServer())
				.buildAndInstall(tool);


		new ActionBuilder("Stop DAP Server", getName())
				.menuPath("Debugger", "DAP", "Stop server")
				.helpLocation(new HelpLocation(getName(), HELP_LOCATION))
				.enabledWhen(_ -> currentProgram != null)
				.onAction(_ -> doStopServer())
				.buildAndInstall(tool);
	}

	private void doStartServer() {
		DapDebugAdapter adapter = new DapDebugAdapter(DapPlugin.this, tool);
		server = new DapServer(DapPlugin.this, adapter);
		server.startServer();
	}

	private void doStopServer() {
		if (server != null) {
			server.stopServer();
			server = null;
		}

		var traceIterator = listeners.keySet().iterator();
		while (traceIterator.hasNext()) {
			Trace trace = traceIterator.next();
			ListenerForChanges listener = listeners.get(trace);
			if (listener != null) {
				trace.removeListener(listener);
			}
			traceIterator.remove();
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof ProgramClosedPluginEvent closedProgEvent) {
			Program program = closedProgEvent.getProgram();
			if (currentProgram != null && currentProgram.equals(program)) {
				currentProgram = null;
			}
			return;
		}

		if (event instanceof ProgramActivatedPluginEvent activeProgEvent) {
			currentProgram = activeProgEvent.getActiveProgram();
			if (currentProgram != null) {
				SpecExtension.registerOptions(currentProgram);
			}
			return;
		}

		if (event instanceof TraceClosedPluginEvent closedEvent) {
			removeListener(closedEvent.getTrace());
			return;
		}

		if (event instanceof TraceActivatedPluginEvent activeTraceEvent) {
			if (server == null) {
				return;
			}
			server.updateAdapter(activeTraceEvent.getActiveCoordinates());
			return;
		}

	}

	void addListener(Trace trace) {
		if (trace == null || listeners.containsKey(trace)) {
			return;
		}

		ListenerForChanges listener = new ListenerForChanges(trace);
		trace.addListener(listener);
		listeners.put(trace, listener);
	}

	void removeListener(Trace trace) {
		if (trace == null) {
			return;
		}
		ListenerForChanges listener = listeners.remove(trace);
		if (listener != null) {
			trace.removeListener(listener);
		}
	}

	protected class ListenerForChanges extends TraceDomainObjectListener {

		private final Trace trace;
		private DebuggerTraceManagerService manager;

		public ListenerForChanges(Trace trace) {
			this.trace = trace;
			this.manager = tool.getService(DebuggerTraceManagerService.class);
			listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);
			listenForUntyped(DomainObjectEvent.CLOSED, this::objectClosed);
			listenFor(TraceEvents.VALUE_CREATED, this::valueModified);
			listenFor(TraceEvents.VALUE_DELETED, this::valueModified);
			listenFor(TraceEvents.VALUE_LIFESPAN_CHANGED, this::valueModified);
			listenFor(TraceEvents.THREAD_ADDED, this::threadChanged);
			listenFor(TraceEvents.THREAD_DELETED, this::threadChanged);
			listenFor(TraceEvents.THREAD_LIFESPAN_CHANGED, this::threadChanged);
			listenFor(TraceEvents.BREAKPOINT_ADDED, this::breakpointChanged);
			listenFor(TraceEvents.BREAKPOINT_CHANGED, this::breakpointChanged);
			listenFor(TraceEvents.BREAKPOINT_DELETED, this::breakpointChanged);
			listenFor(TraceEvents.BREAKPOINT_LIFESPAN_CHANGED, this::breakpointChanged);
			listenFor(TraceEvents.MODULE_ADDED, this::moduleAdded);
			listenFor(TraceEvents.MODULE_CHANGED, this::moduleChanged);
			listenFor(TraceEvents.MODULE_DELETED, this::moduleDeleted);
			listenFor(TraceEvents.MODULE_LIFESPAN_CHANGED, this::moduleChanged);
			listenFor(TraceEvents.BYTES_CHANGED, this::bytesChanged);
			listenFor(TraceEvents.PLATFORM_DELETED, this::objectClosed);
		}

		private void objectRestored(DomainObjectChangeRecord record) {
			contextChanged();
		}

		private void objectClosed(DomainObjectChangeRecord record) {
			ExitedEventArguments args = new ExitedEventArguments();
			TraceProcess process = server.getAdapter().getProcess();

			var exitAttr = process.getObject().getAttribute(manager.getCurrentSnap(), "Exit Code");
			if (exitAttr != null && exitAttr.getValue() != null) {
				Long rc = (Long) exitAttr.getValue();
				args.setExitCode(rc.intValue());
			}
			else {
				args.setExitCode(-1);
			}
			client.exited(args);
		}
		
		protected void valueModified(TraceObjectValue value) {
			contextChanged();
		}

		private void threadChanged(TraceThread thread) {
			contextChanged();
		}

		private void breakpointChanged(TraceBreakpointLocation location) {
			contextChanged();
		}

		private void moduleAdded(TraceModule module) {
			moduleUpdated(module, ModuleEventArgumentsReason.NEW);
		}

		private void moduleDeleted(TraceModule module) {
			moduleUpdated(module, ModuleEventArgumentsReason.REMOVED);
		}

		private void moduleChanged(TraceModule module) {
			moduleUpdated(module, ModuleEventArgumentsReason.CHANGED);
		}

		private void bytesChanged(AddressSpace space, TraceAddressSnapRange range) {
			MemoryEventArguments args = new MemoryEventArguments();
			AddressRange addrRange = range.getRange();
			String ref = addrRange.getMinAddress().toString(false);
			args.setCount((int) addrRange.getLength());
			args.setOffset(0);
			args.setMemoryReference(ref);
			client.memory(args);
		}

		private void contextChanged() {
			if (client == null) {
				return;
			}
			DebuggerCoordinates coordinates = manager.getCurrentFor(trace);
			Target target = coordinates.getTarget();
			long currentSnap = manager.getCurrentSnap();

			for (TraceThread t : trace.getThreadManager().getLiveThreads(currentSnap)) {
				int tid = server.getAdapter().getThreadId(t);
				TraceExecutionState state = target.getThreadExecutionState(t);
				switch (state) {
					case STOPPED -> {
						StoppedEventArguments args = new StoppedEventArguments();
						args.setThreadId(tid);
						TraceSnapshot snapshot =
							trace.getTimeManager().getSnapshot(currentSnap, false);
						args.setDescription(
							snapshot == null ? "STOPPED" : snapshot.getDescription());
						args.setReason(ThreadEventArgumentsReason.STARTED);
						client.stopped(args);
					}
					case RUNNING -> {
						ContinuedEventArguments args = new ContinuedEventArguments();
						args.setThreadId(tid);
						client.continued(args);
					}
					case ALIVE, INACTIVE -> {
						ThreadEventArguments args = new ThreadEventArguments();
						args.setThreadId(tid);
						args.setReason(ThreadEventArgumentsReason.STARTED);
						client.thread(args);
					}
					case TERMINATED -> {
						ThreadEventArguments args = new ThreadEventArguments();
						args.setThreadId(tid);
						args.setReason(ThreadEventArgumentsReason.EXITED);
						client.thread(args);
					}
				}
			}

			// NOTE: Yes, this is a lot of probably-mostly-extranous work, but...
			//  right now, the alternatives seem grim.
			List<Breakpoint> breakpointList = server.getAdapter().getBreakpointList();
			for (Breakpoint bpt : breakpointList) {
				BreakpointEventArguments args = new BreakpointEventArguments();
				args.setBreakpoint(bpt);
				client.breakpoint(args);
			}

			for (TraceModule mod : trace.getModuleManager()
					.getLoadedModules(manager.getCurrentSnap())) {
				moduleUpdated(mod, ModuleEventArgumentsReason.CHANGED);
			}
		}

		private void moduleUpdated(TraceModule module, ModuleEventArgumentsReason reason) {
			ModuleEventArguments args = new ModuleEventArguments();
			Module rmod = new Module();
			long currentSnap = manager.getCurrentSnap();

			rmod.setId((int) module.getObject().getKey());
			rmod.setName(module.getName(currentSnap));

			var range = module.getRange(currentSnap);
			rmod.setAddressRange(range != null ? range.toString() : "Unknown");

			args.setModule(rmod);
			args.setReason(reason);
			client.module(args);
		}

	}

	public void setClient(IDebugProtocolClient client) {
		this.client = client;
		DebuggerTraceManagerService manager =
			tool.getService(DebuggerTraceManagerService.class);
		if (manager != null) {
			Trace currentTrace = manager.getCurrentTrace();
			if (currentTrace != null) {
				addListener(currentTrace);
			}
		}
	}

	public IDebugProtocolClient getClient() {
		return this.client;
	}

	public Integer getPort() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		return opt.getInt("Port", 54321);
	}

	public InetAddress getInetAddress() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		String addr =
			opt.getString("IP address", InetAddress.getLoopbackAddress().getHostAddress());
		if (addr == null || addr.isEmpty() || addr.equals("localhost")) {
			return InetAddress.getLoopbackAddress();
		}
		try {
			return InetAddress.getByName(addr);
		}
		catch (UnknownHostException e) {
			return InetAddress.getLoopbackAddress();
		}
	}

}
