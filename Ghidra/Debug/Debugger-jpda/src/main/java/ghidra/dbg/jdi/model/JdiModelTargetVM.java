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
package ghidra.dbg.jdi.model;

import java.lang.ProcessHandle.Info;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.PathSearchingVirtualMachine;
import com.sun.jdi.VirtualMachine;
import com.sun.jdi.connect.Connector;
import com.sun.jdi.connect.Connector.Argument;
import com.sun.jdi.event.*;
import com.sun.jdi.request.*;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;
import ghidra.dbg.jdi.model.iface1.*;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;
import ghidra.lifecycle.Internal;

/**
 * 
 * <p>
 * TODO: Implementing {@link TargetLauncher} here doesn't seem right. While it's convenient from a
 * UI perspective, it doesn't make sense semantically.
 */
@TargetObjectSchemaInfo(name = "VM", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Attributes", type = JdiModelTargetAttributesContainer.class),
		@TargetAttributeType(name = "Breakpoints", type = JdiModelTargetBreakpointContainer.class, fixed = true),
		@TargetAttributeType(name = "Classes", type = JdiModelTargetClassContainer.class, fixed = true),
		@TargetAttributeType(name = "Modules", type = JdiModelTargetModuleContainer.class, fixed = true),
		@TargetAttributeType(name = "Threads", type = JdiModelTargetThreadContainer.class, required = true, fixed = true),
		@TargetAttributeType(name = "ThreadGroups", type = JdiModelTargetThreadGroupContainer.class, fixed = true),
		@TargetAttributeType(type = Object.class) }, canonicalContainer = true)
public class JdiModelTargetVM extends JdiModelTargetObjectImpl implements //
		TargetProcess, //
		TargetAggregate, //
		JdiModelTargetEnvironment, //
		JdiModelTargetAccessConditioned, //
		JdiModelTargetExecutionStateful, //
		JdiModelTargetLauncher, //
		JdiModelTargetDeletable, //
		JdiModelTargetKillable, //
		JdiModelTargetResumable, //
		JdiModelTargetInterruptible, //
		JdiEventsListenerAdapter, //
		JdiModelSelectableObject {

	public static final String ID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "id";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	protected final VirtualMachine vm;
	protected boolean trackMonitor = false;

	private Map<String, JdiModelTargetObject> objectMap;
	private Map<Object, String> object2key;

	protected final JdiModelTargetThreadContainer threads;
	protected JdiModelTargetThreadGroupContainer threadGroups;
	protected JdiModelTargetModuleContainer modules;
	protected JdiModelTargetClassContainer classes;
	protected final JdiModelTargetProcess process;
	protected JdiModelTargetBreakpointContainer breakpoints;
	protected JdiModelTargetAttributesContainer addedAttributes;

	private final EventRequestManager eventManager;
	private final ThreadStartRequest threadStartRequest;
	private final ThreadDeathRequest threadStopRequest;
	private final MonitorWaitRequest monitorWaitRequest;
	private final MonitorWaitedRequest monitorWaitedRequest;
	private final MonitorContendedEnterRequest monitorEnterRequest;
	private final MonitorContendedEnteredRequest monitorEnteredRequest;

	public JdiModelTargetVM(JdiModelTargetVMContainer vms, VirtualMachine vm, boolean isElement) {
		super(vms, vm.name(), vm, isElement);
		vms.vmsById.put(vm.name(), this);
		this.vm = vm;
		this.eventManager = vm.eventRequestManager();

		threadStartRequest = eventManager.createThreadStartRequest();
		threadStopRequest = eventManager.createThreadDeathRequest();
		if (vm.canRequestMonitorEvents() && trackMonitor) {
			monitorWaitRequest = eventManager.createMonitorWaitRequest();
			monitorWaitedRequest = eventManager.createMonitorWaitedRequest();
			monitorEnterRequest = eventManager.createMonitorContendedEnterRequest();
			monitorEnteredRequest = eventManager.createMonitorContendedEnteredRequest();
		}
		else {
			trackMonitor = false;
			monitorWaitRequest = null;
			monitorWaitedRequest = null;
			monitorEnterRequest = null;
			monitorEnteredRequest = null;
		}

		threadStartRequest.enable();
		threadStopRequest.enable();
		if (vm.canRequestMonitorEvents() && trackMonitor) {
			monitorWaitRequest.enable();
			monitorWaitedRequest.enable();
			monitorEnterRequest.enable();
			monitorEnteredRequest.enable();
		}

		Process proc = vm.process();
		if (proc != null) {
			this.process = new JdiModelTargetProcess(this, proc, false);
		}
		else {
			this.process = null;
		}
		this.threads = new JdiModelTargetThreadContainer(this, "Threads", vm.allThreads());

		changeAttributes(List.of(), List.of( //
			threads //
		), Map.of( //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
			ACCESSIBLE_ATTRIBUTE_NAME, isAccessible(), //
			DISPLAY_ATTRIBUTE_NAME, updateDisplay(), //
			ARCH_ATTRIBUTE_NAME, vm.name(), //
			DEBUGGER_ATTRIBUTE_NAME, vm.description(), //
			OS_ATTRIBUTE_NAME, "JRE " + vm.version(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetCmdLineLauncher.PARAMETERS //
		), "Initialized");

		if (process != null) {
			changeAttributes(List.of(), List.of( //
				process //
			), Map.of(), "Initialized");
		}

	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("version", vm.version());
		attrs.put("description", vm.description());
		attrs.put("canAddMethods", Boolean.valueOf(vm.canAddMethod()));
		attrs.put("canBeModified", Boolean.valueOf(vm.canBeModified()));
		attrs.put("canForceEarlyReturn", Boolean.valueOf(vm.canForceEarlyReturn()));
		attrs.put("canGetBytecodes", Boolean.valueOf(vm.canGetBytecodes()));
		attrs.put("canGetClassFileVersion", Boolean.valueOf(vm.canGetClassFileVersion()));
		attrs.put("canGetConstantPool", Boolean.valueOf(vm.canGetConstantPool()));
		attrs.put("canGetCurrentContendedMonitor",
			Boolean.valueOf(vm.canGetCurrentContendedMonitor()));
		attrs.put("canGetInstanceInfo", Boolean.valueOf(vm.canGetInstanceInfo()));
		attrs.put("canGetMethodReturnValues", Boolean.valueOf(vm.canGetMethodReturnValues()));
		attrs.put("canGetModuleInfo", Boolean.valueOf(vm.canGetModuleInfo()));
		attrs.put("canGetMonitorFrameInfo", Boolean.valueOf(vm.canGetMonitorFrameInfo()));
		attrs.put("canGetMonitorInfo", Boolean.valueOf(vm.canGetMonitorInfo()));
		attrs.put("canGetOwnedMonitorInfo", Boolean.valueOf(vm.canGetOwnedMonitorInfo()));
		attrs.put("canGetSourceDebugExtension", Boolean.valueOf(vm.canGetSourceDebugExtension()));
		attrs.put("canGetSyntheticAttribute", Boolean.valueOf(vm.canGetSyntheticAttribute()));
		attrs.put("canPopFrames", Boolean.valueOf(vm.canPopFrames()));
		attrs.put("canRedefineClasses", Boolean.valueOf(vm.canRedefineClasses()));
		attrs.put("canRequestMonitorEvents", Boolean.valueOf(vm.canRequestMonitorEvents()));
		attrs.put("canRequestVMDeathEvent", Boolean.valueOf(vm.canRequestVMDeathEvent()));
		attrs.put("canUnrestrictedlyRedefineClasses",
			Boolean.valueOf(vm.canUnrestrictedlyRedefineClasses()));
		attrs.put("canUseInstanceFilters", Boolean.valueOf(vm.canUseInstanceFilters()));
		attrs.put("canUseSourceNameFilters", Boolean.valueOf(vm.canUseSourceNameFilters()));
		attrs.put("canWatchFieldAccess", Boolean.valueOf(vm.canWatchFieldAccess()));
		attrs.put("canWatchFieldModification", Boolean.valueOf(vm.canWatchFieldModification()));
		if (vm instanceof PathSearchingVirtualMachine) {
			PathSearchingVirtualMachine psvm = (PathSearchingVirtualMachine) vm;
			attrs.put("classPath", psvm.classPath());
			attrs.put("baseDirectory", psvm.baseDirectory());
			attrs.put("baseDirectory", psvm.baseDirectory());
		}
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		this.threadGroups = new JdiModelTargetThreadGroupContainer(this);
		this.modules = new JdiModelTargetModuleContainer(this);
		this.classes = new JdiModelTargetClassContainer(this);
		this.breakpoints = new JdiModelTargetBreakpointContainer(this);

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			modules, //
			threadGroups, //
			classes, //
			breakpoints, //
			addedAttributes //
		), Map.of(), "Initialized");

		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		JdiManagerImpl manager = (JdiManagerImpl) impl.getManager();
		Connector cx = manager.getConnector(vm);
		Map<String, Argument> defaultArguments = cx.defaultArguments();
		Map<String, Argument> jdiArgs = JdiModelTargetLauncher.getArguments(defaultArguments,
			JdiModelTargetLauncher.getParameters(defaultArguments), args);
		return getManager().addVM(cx, jdiArgs).thenApply(__ -> null);
	}

	@Override
	public TargetParameterMap getParameters() {
		JdiManagerImpl manager = (JdiManagerImpl) impl.getManager();
		Connector cx = manager.getConnector(vm);
		Map<String, Argument> defaultArguments = cx.defaultArguments();
		return TargetParameterMap.copyOf(JdiModelTargetLauncher.getParameters(defaultArguments));
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		vm.suspend();
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> resume() {
		vmStateChanged(TargetExecutionState.RUNNING, JdiReason.Reasons.RESUMED);
		invalidateMemoryAndRegisterCaches();
		vm.resume();
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> kill() {
		vm.exit(0);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> delete() {
		vm.dispose();
		return CompletableFuture.completedFuture(null);
	}

	public CompletableFuture<Void> started(String id) {
		AsyncFence fence = new AsyncFence();
		return fence.ready().thenAccept(__ -> {
			if (id != null) {
				changeAttributes(List.of(), List.of(), Map.of( //
					STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
					ID_ATTRIBUTE_NAME, id, //
					DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
				), "Started");
			}
			else {
				changeAttributes(List.of(), List.of(), Map.of( //
					STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
					DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
				), "Started");
			}
			vmSelected(vm, JdiCause.Causes.UNCLAIMED);
		});
	}

	protected void exited(VirtualMachine vm2) {
		if (vm2 != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, vm2, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
			), "Exited");
		}
		else {
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
			), "Exited");
		}
	}

	@Override
	public void vmSelected(VirtualMachine eventVM, JdiCause cause) {
		if (eventVM.equals(vm)) {
			((JdiModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	public void vmStateChanged(TargetExecutionState targetState, JdiReason reason) {
		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState //
		), reason.desc());
	}

	@Override
	public void monitorContendedEntered(MonitorContendedEnteredEvent evt, JdiCause cause) {
		System.err.println(this + ":" + evt);
	}

	@Override
	public void monitorContendedEnter(MonitorContendedEnterEvent evt, JdiCause cause) {
		System.err.println(this + ":" + evt);
	}

	@Override
	public void monitorWaited(MonitorWaitedEvent evt, JdiCause cause) {
		System.err.println(this + ":" + evt);
	}

	@Override
	public void monitorWait(MonitorWaitEvent evt, JdiCause cause) {
		System.err.println(this + ":" + evt);
	}

	protected void updateDisplayAttribute() {
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
		), "Display changed");
	}

	protected String updateDisplay() {
		if (vm.process() == null) {
			return vm.toString();
		}
		String name = "VM(" + JdiModelTargetProcess.getUniqueId(vm.process()) + ") ";
		Info info = vm.process().info();
		Optional<String[]> arguments = info.arguments();
		if (!arguments.isEmpty()) {
			String[] args = arguments.get();
			for (String arg : args) {
				if (!arg.startsWith("-")) {
					String[] split = arg.split("/");
					name += split.length == 0 ? arg : split[split.length - 1];
				}
			}
		}
		return String.format("%s", name);
	}

	@Override
	public String getDisplay() {
		return vm == null ? super.getDisplay() : updateDisplay();
	}

	protected void invalidateMemoryAndRegisterCaches() {
		///memory.invalidateMemoryCaches();
	}

	protected void updateMemory() {
		// This is a little ew. Wish I didn't have to list regions every STOP
		/*
		memory.update().exceptionally(ex -> {
			Msg.error(this, "Could not update process memory mappings", ex);
			return null;
		});
		*/
	}

	@Override
	@Internal
	public CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
	}

	public JdiModelTargetClassContainer getClasses() {
		return classes;
	}

	@Override
	public void refreshInternal() {
		// TODO Auto-generated method stub

	}

	// OBJECT MAP METHODS

	public synchronized JdiModelTargetObject getTargetObject(String key) {
		return objectMap.get(key);
	}

	@Override
	public synchronized JdiModelTargetObject getTargetObject(Object obj) {
		return objectMap.get(object2key.get(obj));
	}

	public synchronized void setTargetObject(String id, Object key, JdiModelTargetObject object) {
		if (objectMap == null) {
			objectMap = new HashMap<>();
			object2key = new HashMap<>();
		}
		if (objectMap.containsKey(id) && key != null) {
			if (!(object instanceof JdiModelTargetValue) &&
				!(object instanceof JdiModelTargetLocation) &&
				!(object instanceof JdiModelTargetRegister) &&
				!(object instanceof JdiModelTargetStackFrame)) {
				// new RuntimeException(this+":"+key);
				System.err.println("setTargetObject: " + key);
			}
		}
		if (key != null) {
			object2key.put(key, id);
		}
		objectMap.put(id, object);
	}

	@Override
	public boolean isAccessible() {
		for (JdiModelTargetThread thread : threads.threadsById.values()) {
			if (thread.isAccessible()) {
				return true;
			}
		}
		return false;
	}

}
