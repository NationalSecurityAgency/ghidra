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

import static ghidra.lifecycle.Unfinished.TODO;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import org.apache.commons.lang3.tuple.Pair;

import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.event.Event;

import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.manager.JdiCause.Causes;
import ghidra.dbg.jdi.rmi.jpda.JdiArguments;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class JdiManagerImpl implements JdiManager {

	private VirtualMachineManager virtualMachineManager;
	private final Map<String, VirtualMachine> vms = new LinkedHashMap<>();
	private VirtualMachine curVM = null;
	private ThreadReference curThread = null;
	private StackFrame curFrame = null;
	private Location curLocation = null;
	private Event curEvent = null;

	private final Map<String, VirtualMachine> unmodifiableVMs = Collections.unmodifiableMap(vms);

	protected final ListenerSet<JdiTargetOutputListener> listenersTargetOutput =
		new ListenerSet<>(JdiTargetOutputListener.class, true);
	protected final ListenerSet<JdiConsoleOutputListener> listenersConsoleOutput =
		new ListenerSet<>(JdiConsoleOutputListener.class, true);
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

	private static void pumpStream(InputStream in, OutputStream out) {
		try {
			in.transferTo(out);
		}
		catch (IOException e) {
			// We're done!
		}
	}

	public VirtualMachine connectVM(Connector cx, Map<String, Connector.Argument> arguments)
			throws Exception {
		if (cx instanceof LaunchingConnector lcx) {
			VirtualMachine vm = lcx.launch(arguments);
			new Thread(() -> pumpStream(vm.process().getErrorStream(), System.err)).start();
			new Thread(() -> pumpStream(vm.process().getInputStream(), System.out)).start();
			return vm;
		}
		if (cx instanceof AttachingConnector acx) {
			return acx.attach(arguments);
		}
		if (cx instanceof ListeningConnector lcx) {
			return lcx.accept(arguments);
		}
		throw new Exception("Unknown connector type");
	}

	public VirtualMachine createVM(Map<String, String> env) {
		JdiArguments args = new JdiArguments(env);
		Connector cx = args.getConnector(virtualMachineManager);
		Map<String, Connector.Argument> defaultArguments = cx.defaultArguments();
		args.putArguments(defaultArguments);
		return addVM(cx, defaultArguments);
	}

	@Override
	public void terminate() {
		/**
		 * NB: can't use manager.connectedVMs, because technically, other things could be using the
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
	public VirtualMachine addVM(Connector cx, List<String> args) {
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
	public VirtualMachine addVM(Connector cx, Map<String, Connector.Argument> args) {
		try {
			setCurrentVM(connectVM(cx, args));
			JdiEventHandler eventHandler = new JdiEventHandler(getCurrentVM(), globalEventHandler);
			eventHandler.start();
			eventHandler.setState(ThreadReference.THREAD_STATUS_NOT_STARTED, Causes.UNCLAIMED);
			eventHandlers.put(getCurrentVM(), eventHandler);
			vms.put(getCurrentVM().name(), getCurrentVM());
			connectors.put(getCurrentVM(), cx);
		}
		catch (VMDisconnectedException e) {
			Msg.error(this, "Virtual Machine is disconnected.");
			return null;
		}
		catch (Exception e) {
			Msg.error(this, "Could not connect Virtual Machine", e);
			return null;
		}
		return getCurrentVM();
	}

	public void addVM(VirtualMachine vm) {
		JdiEventHandler eventHandler = new JdiEventHandler(vm, globalEventHandler);
		eventHandler.start();
		eventHandler.setState(ThreadReference.THREAD_STATUS_NOT_STARTED, Causes.UNCLAIMED);
		eventHandlers.put(getCurrentVM(), eventHandler);
		vms.put(getCurrentVM().name(), getCurrentVM());
	}

	@Override
	public CompletableFuture<Void> removeVM(VirtualMachine vm) {
		if (getCurrentVM() == vm) {
			setCurrentVM(null);
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

	public VirtualMachine getCurrentVM() {
		return curVM;
	}

	public void setCurrentVM(VirtualMachine vm) {
		this.curVM = vm;
		if (!vms.containsValue(vm)) {
			addVM(vm);
		}
	}

	public ThreadReference getCurrentThread() {
		if (curThread == null) {
			List<ThreadReference> threads = curVM.allThreads();
			curThread = threads.getFirst();
		}
		return curThread;
	}

	public void setCurrentThread(ThreadReference thread) {
		this.curThread = thread;
	}

	public StackFrame getCurrentFrame() {
		return curFrame;
	}

	public void setCurrentFrame(StackFrame frame) {
		this.curFrame = frame;
	}

	public void setCurrentLocation(Location location) {
		this.curLocation = location;
	}

	public Location getCurrentLocation() {
		return curLocation;
	}

	public void setCurrentEvent(Event event) {
		this.curEvent = event;
	}

	public Event getCurrentEvent() {
		return curEvent;
	}
}
