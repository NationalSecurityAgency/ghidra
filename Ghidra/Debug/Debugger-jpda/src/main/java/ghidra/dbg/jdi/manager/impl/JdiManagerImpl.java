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
package ghidra.dbg.jdi.manager.impl;

import static ghidra.lifecycle.Unfinished.*;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

import org.apache.commons.lang3.tuple.Pair;

import com.sun.jdi.*;
import com.sun.jdi.connect.*;

import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.manager.JdiCause.Causes;
import ghidra.util.datastruct.ListenerSet;

public class JdiManagerImpl implements JdiManager {

	public DebugStatus status;

	private VirtualMachineManager virtualMachineManager;
	private final Map<String, VirtualMachine> vms = new LinkedHashMap<>();
	private VirtualMachine curVM = null;
	private final Map<String, VirtualMachine> unmodifiableVMs = Collections.unmodifiableMap(vms);

	protected final ListenerSet<JdiTargetOutputListener> listenersTargetOutput =
		new ListenerSet<>(JdiTargetOutputListener.class);
	protected final ListenerSet<JdiConsoleOutputListener> listenersConsoleOutput =
		new ListenerSet<>(JdiConsoleOutputListener.class);
	protected final ExecutorService eventThread = Executors.newSingleThreadExecutor();

	protected JdiEventHandler globalEventHandler = new JdiEventHandler();
	protected Map<VirtualMachine, JdiEventHandler> eventHandlers = new HashMap<>();
	protected Map<VirtualMachine, Connector> connectors = new HashMap<>();

	/**
	 * Instantiate a new manager
	 */
	public JdiManagerImpl() {
		virtualMachineManager = Bootstrap.virtualMachineManager();
	}

	public VirtualMachine connectVM(Connector cx, Map<String, Connector.Argument> arguments)
			throws Exception {
		if (cx instanceof LaunchingConnector) {
			LaunchingConnector lcx = (LaunchingConnector) cx;
			return lcx.launch(arguments);
		}
		if (cx instanceof AttachingConnector) {
			AttachingConnector acx = (AttachingConnector) cx;
			return acx.attach(arguments);
		}
		if (cx instanceof ListeningConnector) {
			ListeningConnector lcx = (ListeningConnector) cx;
			return lcx.accept(arguments);
		}
		throw new Exception("Unknown connector type");
	}

	@Override
	public void terminate() {
		/**
		 * NB: can use manager.connectedVMs, because technically, other things could be using the
		 * JDI outside of this manager.
		 */
		for (VirtualMachine vm : vms.values()) {
			// TODO: Force exit those we launched?
			try {
				vm.dispose();
			}
			catch (VMDisconnectedException e) {
				// I guess we're good!
			}
		}
	}

	@Override
	public void addStateListener(VirtualMachine vm, JdiStateListener listener) {
		if (vm != null) {
			JdiEventHandler eventHandler = eventHandlers.get(vm);
			if (eventHandler != null) {
				eventHandler.addStateListener(listener);
			}
		}
		else {
			globalEventHandler.addStateListener(listener);
		}
	}

	@Override
	public void removeStateListener(VirtualMachine vm, JdiStateListener listener) {
		if (vm != null) {
			eventHandlers.get(vm).removeStateListener(listener);
		}
		else {
			globalEventHandler.removeStateListener(listener);
		}
	}

	@Override
	public void addEventsListener(VirtualMachine vm, JdiEventsListener listener) {
		if (vm != null) {
			eventHandlers.get(vm).addEventsListener(listener);
		}
		else {
			globalEventHandler.addEventsListener(listener);
		}
	}

	@Override
	public void removeEventsListener(VirtualMachine vm, JdiEventsListener listener) {
		if (vm != null) {
			eventHandlers.get(vm).removeEventsListener(listener);
		}
		else {
			globalEventHandler.removeEventsListener(listener);
		}
	}

	@Override
	public void addTargetOutputListener(JdiTargetOutputListener listener) {
		listenersTargetOutput.add(listener);
	}

	@Override
	public void removeTargetOutputListener(JdiTargetOutputListener listener) {
		listenersTargetOutput.remove(listener);
	}

	@Override
	public void addConsoleOutputListener(JdiConsoleOutputListener listener) {
		listenersConsoleOutput.add(listener);
	}

	@Override
	public void removeConsoleOutputListener(JdiConsoleOutputListener listener) {
		listenersConsoleOutput.remove(listener);
	}

	@Override
	public VirtualMachine getVM(String id) {
		return vms.get(id);
	}

	@Override
	public Map<String, VirtualMachine> getKnownVMs() {
		return unmodifiableVMs;
	}

	@Override
	public void sendInterruptNow() throws IOException {
		for (VirtualMachine vm : vms.values()) {
			for (ThreadReference thread : vm.allThreads()) {
				thread.interrupt();
			}
		}
	}

	@Override
	public CompletableFuture<VirtualMachine> addVM(Connector cx, List<String> args) {
		Map<String, Connector.Argument> arguments = cx.defaultArguments();
		if (cx instanceof LaunchingConnector) {
			if (arguments.containsKey("command")) {
				arguments.get("command").setValue(args.get(0));
			}
			else {
				arguments.get("main").setValue(args.get(0));
			}
		}
		if (cx instanceof AttachingConnector) {
			if (arguments.containsKey("pid")) {
				arguments.get("pid").setValue("" + Integer.decode(args.get(0)));
			}
			else {
				if (args.size() == 2) {
					arguments.get("hostname").setValue(args.get(0));
					arguments.get("port").setValue(args.get(1));
				}
				else {
					arguments.get("port").setValue(args.get(0));
				}
			}
		}
		if (cx instanceof ListeningConnector) {
			arguments.get("port").setValue("0");
			arguments.get("localAddress").setValue("localhost");
		}
		return addVM(cx, arguments);
	}

	@Override
	public CompletableFuture<VirtualMachine> addVM(Connector cx,
			Map<String, Connector.Argument> args) {
		// TODO: Since this is making a blocking-on-the-network call, it should be supplyAsync
		try {
			curVM = connectVM(cx, args);
			JdiEventHandler eventHandler = new JdiEventHandler(curVM, globalEventHandler);
			eventHandler.start();
			eventHandler.setState(ThreadReference.THREAD_STATUS_NOT_STARTED, Causes.UNCLAIMED);
			eventHandlers.put(curVM, eventHandler);
			vms.put(curVM.name(), curVM);
			connectors.put(curVM, cx);
		}
		catch (VMDisconnectedException e) {
			System.out.println("Virtual Machine is disconnected.");
			return CompletableFuture.failedFuture(e);
		}
		catch (Exception e) {
			return CompletableFuture.failedFuture(e);
		}
		return CompletableFuture.completedFuture(curVM);
	}

	@Override
	public CompletableFuture<Void> removeVM(VirtualMachine vm) {
		if (curVM == vm) {
			curVM = null;
		}
		vms.remove(vm.name());
		connectors.remove(vm);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		return TODO();
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return TODO();
	}

	@Override
	public CompletableFuture<Map<String, VirtualMachine>> listVMs() {
		return CompletableFuture.completedFuture(vms);
	}

	@Override
	@Deprecated(forRemoval = true)
	public CompletableFuture<List<Pair<Integer, String>>> listAvailableProcesses() {
		List<Pair<Integer, String>> processes = new ArrayList<>();
		return CompletableFuture.completedFuture(processes);
	}

	@Override
	public VirtualMachineManager getVirtualMachineManager() {
		return virtualMachineManager;
	}

	public Connector getConnector(VirtualMachine vm) {
		return connectors.get(vm);
	}

	@Override
	public JdiEventHandler getEventHandler(VirtualMachine vm) {
		return eventHandlers.get(vm);
	}

}
