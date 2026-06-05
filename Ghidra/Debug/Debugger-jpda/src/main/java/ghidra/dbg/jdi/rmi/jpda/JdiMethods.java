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
package ghidra.dbg.jdi.rmi.jpda;

import static ghidra.dbg.jdi.rmi.jpda.JdiConnector.*;

import java.io.IOException;
import java.util.*;

import com.sun.jdi.*;
import com.sun.jdi.request.*;

import ghidra.app.plugin.core.debug.client.tracermi.*;
import ghidra.app.plugin.core.debug.client.tracermi.RmiMethodRegistry.TraceRmiMethod;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.rmi.trace.TraceRmi.MemoryState;
import ghidra.trace.model.target.iface.TraceMethod.Param;
import ghidra.util.Msg;

public class JdiMethods implements RmiMethods {

	private JdiConnector connector;
	private JdiCommands cmds;

	public JdiMethods(JdiConnector connector, JdiCommands cmds) {
		this.connector = connector;
		this.cmds = cmds;
		registerMethods();
	}

	public void registerMethods() {
		Class<?> cls = this.getClass();
		for (java.lang.reflect.Method m : cls.getMethods()) {
			TraceRmiMethod annot = m.getAnnotation(TraceRmiMethod.class);
			if (annot != null) {
				connector.registerRemoteMethod(this, m, m.getName());
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh VM")
	public void refresh_vm(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshVM")) {
			String path = obj.getPath();
			VirtualMachine vm = (VirtualMachine) getObjectFromPath(path);
			cmds.putVMDetails(path, vm);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh process")
	public void refresh_process(
			@Param(schema = "ProcessRef", name = "process") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshProcess")) {
			String path = obj.getPath();
			Process proc = (Process) getObjectFromPath(path);
			cmds.putProcessDetails(path, proc);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh thread groups")
	public void refresh_thread_groups(
			@Param(
				schema = "ThreadGroupReferenceContainer",
				name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreadGroups")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof VirtualMachine vm) {
				cmds.putThreadGroupContainer(ppath, vm.topLevelThreadGroups());
			}
			if (parent instanceof ThreadGroupReference group) {
				cmds.putThreadGroupContainer(ppath, group.threadGroups());
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh thread group")
	public void refresh_thread_group_proxy(
			@Param(schema = "ThreadGroupReferenceProxy", name = "proxy") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreadGroup")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ThreadGroupReference group) {
				cmds.putThreadGroupReference(path, group.parent());
			}
			if (parent instanceof ThreadReference ref) {
				cmds.putThreadGroupReference(path, ref.threadGroup());
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh thread group")
	public void refresh_thread_group(
			@Param(schema = "ThreadGroupReference", name = "group") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreadGroup")) {
			String path = obj.getPath();
			ThreadGroupReference ref = (ThreadGroupReference) getObjectFromPath(path);
			cmds.putThreadGroupReferenceDetails(path, ref);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh threads")
	public void refresh_threads(
			@Param(schema = "ThreadContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreads")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			VirtualMachine vm = (VirtualMachine) getObjectFromPath(ppath);
			cmds.putThreadContainer(ppath, vm.allThreads(), false);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh threads")
	public void refresh_threadrefs(
			@Param(schema = "ThreadReferenceContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreads")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ThreadGroupReference group && path.endsWith(".Threads")) {
				cmds.putThreadContainer(ppath, group.threads(), true);
			}
			if (parent instanceof ObjectReference ref && !path.endsWith(".Threads")) {
				try {
					cmds.putThreadContainer(ppath, ref.waitingThreads(), true);
				}
				catch (IncompatibleThreadStateException e) {
					// IGNORE
				}
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh thread")
	public void refresh_thread(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThread")) {
			String path = obj.getPath();
			ThreadReference ref = (ThreadReference) getObjectFromPath(path);
			cmds.putThreadReferenceDetails(path, ref);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh stack")
	public void refresh_stack(@Param(schema = "Stack", name = "stack") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshStack")) {
			cmds.ghidraTracePutFrames();
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh registers")
	public void refresh_registers(
			@Param(schema = "RegisterContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshRegisters")) {
			cmds.ghidraTracePutFrames();
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh modules")
	public void refresh_modules(
			@Param(schema = "ModuleReferenceContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshModules")) {
			cmds.putModuleReferenceContainer();
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh module")
	public void refresh_module(
			@Param(schema = "ModuleReference", name = "module") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshModule")) {
			String path = obj.getPath();
			ModuleReference ref = (ModuleReference) getObjectFromPath(path);
			cmds.putModuleReferenceDetails(path, ref);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh monitor info")
	public void refresh_monitors(
			@Param(schema = "MonitorInfoContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMonitorInfo")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			ThreadReference ref = (ThreadReference) getObjectFromPath(ppath);
			cmds.putMonitorInfoContainer(path, ref.ownedMonitorsAndFrames());
		}
		catch (IncompatibleThreadStateException e) {
			// IGNORE
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh monitor info")
	public void refresh_monitor_info(
			@Param(schema = "MonitorInfo", name = "monitor_info") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMonitorInfo")) {
			String path = obj.getPath();
			MonitorInfo mi = (MonitorInfo) getObjectFromPath(path);
			cmds.putMonitorInfoDetails(path, mi);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh fields")
	public void refresh_canonical_fields(
			@Param(schema = "CanonicalFieldContainer", name = "container") RmiTraceObject obj) {
		refresh_fields(obj);
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh fields")
	public void refresh_fields(
			@Param(schema = "FieldContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshFields")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ReferenceType refType) {
				cmds.putFieldContainer(path, refType);
			}
			else if (parent instanceof ObjectReference ref) {
				cmds.putVariableContainer(path, ref);
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh objects")
	public void refresh_objects(
			@Param(schema = "ObjectReferenceContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshObjects")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ReferenceType refType) {
				cmds.putObjectContainer(path, refType.instances(cmds.MAX_REFS));
			}
			if (parent instanceof ThreadReference thread) {
				try {
					if (path.endsWith("OwnedMonitors")) {
						cmds.putObjectContainer(path, thread.ownedMonitors());
					}
				}
				catch (IncompatibleThreadStateException e) {
					// IGNORE
				}
			}
			if (parent instanceof ObjectReference ref && path.endsWith("ReferringObjects")) {
				cmds.putObjectContainer(path, ref.referringObjects(cmds.MAX_REFS));
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh object")
	public void refresh_object_proxy(
			@Param(schema = "ObjectReferenceProxy", name = "proxy") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshObject")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ThreadReference thread &&
				path.endsWith("CurrentContendedMonitor")) {
				try {
					cmds.putObjectReference(path, thread.currentContendedMonitor());
				}
				catch (IncompatibleThreadStateException e) {
					// IGNORE
				}
			}
			if (parent instanceof StackFrame frame) {
				cmds.putObjectReference(path, frame.thisObject());
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh object")
	public void refresh_object(
			@Param(schema = "ObjectReference", name = "object") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshInstance")) {
			String path = obj.getPath();
			ObjectReference method = (ObjectReference) getObjectFromPath(path);
			cmds.putObjectReferenceDetails(path, method);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh methods")
	public void refresh_canonical_methods(
			@Param(schema = "CanonicalMethodContainer", name = "container") RmiTraceObject obj) {
		refresh_methods(obj);
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh methods")
	public void refresh_methods(
			@Param(schema = "MethodContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMethods")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			ReferenceType refType = (ReferenceType) getObjectFromPath(ppath);
			cmds.putMethodContainer(path, refType);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh method")
	public void refresh_method(@Param(schema = "Method", name = "method") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMethod")) {
			String path = obj.getPath();
			Method method = (Method) getObjectFromPath(path);
			cmds.putMethodDetails(path, method, false);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh arguments")
	public void refresh_arguments(
			@Param(schema = "ArgumentContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshArguments")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Method method = (Method) getObjectFromPath(ppath);
			cmds.putMethodTypeContainer(path, method);
		}
	}

	@TraceRmiMethod(display = "Load class")
	public boolean find_canonical_class(
			@Param(
				schema = "CanonicalReferenceTypeContainer",
				description = "Container",
				display = "Container",
				name = "container") RmiTraceObject obj,
			@Param(
				description = "Class to open",
				display = "Class",
				name = "find") String targetClass) {
		return find_class(obj, targetClass);
	}

	@TraceRmiMethod(display = "Load class")
	public boolean find_class(
			@Param(
				schema = "ReferenceTypeContainer",
				description = "Container",
				display = "Container",
				name = "container") RmiTraceObject obj,
			@Param(
				description = "Class to open",
				display = "Class",
				name = "find") String targetClass) {
		try (RmiTransaction tx = cmds.state.trace.openTx("FindClass")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof VirtualMachine vm) {
				return cmds.loadReferenceType(path, vm.allClasses(), targetClass);
			}
			return false;
		}
	}

	/**
	 * NB. Did not assign action="refresh" because this method is expensive. Assigning that action
	 * name will cause the UI to do it upon expanding the node, which we <em>do not</em> want.
	 */
	@TraceRmiMethod(display = "Refresh memory")
	public void refresh_memory(@Param(schema = "Memory", name = "memory") RmiTraceObject obj) {
		refresh_reference_types(obj);
	}

	@TraceRmiMethod(display = "Refresh reference types")
	public void refresh_canonical_reference_types(
			@Param(
				schema = "CanonicalReferenceTypeContainer",
				name = "container") RmiTraceObject obj) {
		refresh_reference_types(obj);
	}

	/**
	 * NB. Did not assign action="refresh" because this method is expensive. Assigning that action
	 * name will cause the UI to do it upon expanding the node, which we <em>do not</em> want.
	 */
	@TraceRmiMethod(display = "Refresh reference types")
	public void refresh_reference_types(
			@Param(schema = "ReferenceTypeContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshReferenceTypes")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof VirtualMachine vm) {
				cmds.putReferenceTypeContainer(path, vm.allClasses());
			}
			if (parent instanceof ClassLoaderReference ref) {
				if (path.endsWith("DefinedClasses")) {
					cmds.putReferenceTypeContainer(path, ref.definedClasses());
				}
				if (path.endsWith("VisibleClasses")) {
					cmds.putReferenceTypeContainer(path, ref.visibleClasses());
				}
			}
			if (parent instanceof ClassType ct) {
				if (path.endsWith("AllInterfaces")) {
					cmds.putInterfaceTypes(path, ct.allInterfaces());
				}
				if (path.endsWith("Interfaces")) {
					cmds.putInterfaceTypes(path, ct.interfaces());
				}
				if (path.endsWith("SubClasses")) {
					cmds.putClassTypes(path, ct.subclasses());
				}
			}
			if (parent instanceof InterfaceType it) {
				if (path.endsWith("Implementors")) {
					cmds.putClassTypes(path, it.implementors());
				}
				if (path.endsWith("SubInterfaces")) {
					cmds.putInterfaceTypes(path, it.subinterfaces());
				}
				if (path.endsWith("SuperInterfaces")) {
					cmds.putInterfaceTypes(path, it.superinterfaces());
				}
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh reference type")
	public void refresh_reference_type_proxy(
			@Param(schema = "ReferenceTypeProxy", name = "proxy") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshReferenceType")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ObjectReference ref) {
				cmds.putReferenceType(path, ref.referenceType(), false);
			}
			if (parent instanceof ClassObjectReference ref && path.endsWith("ReflectedType")) {
				cmds.putReferenceType(path, ref.reflectedType(), false);
			}
			if (parent instanceof ClassType ct) {
				cmds.putReferenceType(path, ct.superclass(), false);
			}
			if (parent instanceof Method method) {
				cmds.putReferenceType(path, method.declaringType(), false);
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh reference type")
	public void refresh_canonical_reference_type(
			@Param(schema = "CanonicalReferenceType", name = "container") RmiTraceObject obj) {
		refresh_reference_type(obj);
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh reference type")
	public void refresh_reference_type(
			@Param(schema = "ReferenceType", name = "reference_type") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshReferenceType")) {
			String path = obj.getPath();
			ReferenceType refType = (ReferenceType) getObjectFromPath(path);
			cmds.putReferenceType(path, refType, false);
		}
	}

	@TraceRmiMethod(display = "Load reference type")
	public void load_reftype(
			@Param(schema = "ReferenceType", name = "reference_type") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshReferenceType")) {
			VirtualMachine vm = connector.getJdi().getCurrentVM();
			String path = obj.getPath();
			String mempath = cmds.getPath(vm) + ".Classes";
			ReferenceType refType = (ReferenceType) getObjectFromPath(path);
			cmds.putReferenceType(mempath, refType, true);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh variables")
	public void refresh_canonical_variables(
			@Param(schema = "CanonicalVariableContainer", name = "container") RmiTraceObject obj) {
		refresh_variables(obj);
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh variables")
	public void refresh_variables(
			@Param(schema = "VariableContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshVariables")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			try {
				if (parent instanceof Method method) {
					if (path.endsWith("Arguments")) {
						cmds.putLocalVariableContainer(path, method.arguments());
					}
					if (path.endsWith("Variables")) {
						cmds.putLocalVariableContainer(path, method.variables());
					}
				}
				if (parent instanceof StackFrame frame) {
					Map<LocalVariable, Value> map = frame.getValues(frame.visibleVariables());
					cmds.putLocalVariableContainer(path, map);
				}
			}
			catch (AbsentInformationException e) {
				// IGNORE
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh variable")
	public void refresh_variable(
			@Param(schema = "Variable", name = "variable") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshVariable")) {
			String path = obj.getPath();
			Object object = getObjectFromPath(path);
			if (object instanceof LocalVariable var) {
				cmds.putLocalVariableDetails(path, var);
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh locations")
	public void refresh_locations(
			@Param(schema = "LocationContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocations")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof Method) {
				Method method = (Method) parent;
				cmds.putLocationContainer(path, method);
			}
			if (parent instanceof ReferenceType) {
				ReferenceType ref = (ReferenceType) parent;
				cmds.putLocationContainer(path, ref);
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh location")
	public void refresh_location(
			@Param(schema = "Location", name = "location") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			Location loc = (Location) getObjectFromPath(path);
			cmds.putLocationDetails(path, loc);
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh breakpoints")
	public void refresh_breakpoints(
			@Param(schema = "BreakpointContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshBreakpoints")) {
			cmds.putBreakpoints();
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh events")
	public void refresh_events(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshEvents")) {
			cmds.putEvents();
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh values")
	public void refresh_values(
			@Param(schema = "ValueContainer", name = "container") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshValues")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ArrayReference arr) {
				cmds.putValueContainer(path, arr.getValues());
			}
		}
	}

	@TraceRmiMethod(action = "refresh", display = "Refresh value")
	public void refresh_value(@Param(schema = "Value", name = "value") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			Value val = (Value) getObjectFromPath(path);
			cmds.putValueDetailsByType(path, val);
		}
	}

	@TraceRmiMethod(display = "Set value")
	public void set_value_lvar(
			@Param(
				schema = "Variable",
				description = "Variable",
				display = "Variable",
				name = "variable") RmiTraceObject obj,
			@Param(
				description = "Value",
				display = "Value",
				name = "value") String value) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			LocalVariable lvar = (LocalVariable) getObjectFromPath(path);
			cmds.modifyValue(lvar, value);
		}
	}

	@TraceRmiMethod(display = "Set value")
	public void set_value_field(
			@Param(
				schema = "Field",
				description = "Field",
				display = "Field",
				name = "field") RmiTraceObject obj,
			@Param(
				description = "Value",
				display = "Value",
				name = "value") String value) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			Field field = (Field) getObjectFromPath(path);
			cmds.modifyValue(field, value);
		}
	}

	@TraceRmiMethod(action = "activate", display = "Activate")
	public void activate(@Param(schema = "OBJECT", name = "object") RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("Activate")) {
			String path = obj.getPath();
			cmds.activate(path);
		}
	}

	@TraceRmiMethod(action = "kill", display = "Terminate")
	public void kill(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = (VirtualMachine) getObjectFromPath(obj.getPath());
		vm.exit(143);
		try {
			connector.getJdi().sendInterruptNow();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	@TraceRmiMethod(action = "resume", display = "Resume")
	public void resume_vm(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = (VirtualMachine) getObjectFromPath(obj.getPath());
		vm.resume();
		connector.getHooks().setState(vm);
	}

	@TraceRmiMethod(action = "resume", display = "Resume")
	public void resume_thread(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		thread.resume();
		connector.getHooks().setState(thread.virtualMachine());
	}

	@TraceRmiMethod(action = "interrupt", display = "Suspend")
	public void suspend_vm(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = (VirtualMachine) getObjectFromPath(obj.getPath());
		vm.suspend();
		connector.getHooks().setState(vm);
	}

	@TraceRmiMethod(action = "interrupt", display = "Suspend")
	public void suspend_thread(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		thread.suspend();
		connector.getHooks().setState(thread.virtualMachine());
	}

	/**
	 * NB: For the VirtualMachine, the step methods add requests for break-on-step for all threads.
	 * These requests will remain pending until the VM is resumed.
	 */
	@TraceRmiMethod(action = "step_into", display = "Step into")
	public void step_vm_into(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		List<ThreadReference> threads = getThreadsFromValue(obj);
		for (ThreadReference thread : threads) {
			try {
				StepRequest stepReq = vm.eventRequestManager()
						.createStepRequest(thread, StepRequest.STEP_MIN,
							StepRequest.STEP_INTO);
				stepReq.enable();
			}
			catch (DuplicateRequestException dre) {
				// IGNORE
			}
		}
		vm.resume();
	}

	@TraceRmiMethod(action = "step_over", display = "Step over")
	public void step_vm_over(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		List<ThreadReference> threads = getThreadsFromValue(obj);
		for (ThreadReference thread : threads) {
			try {
				StepRequest stepReq = vm.eventRequestManager()
						.createStepRequest(thread, StepRequest.STEP_MIN,
							StepRequest.STEP_OVER);
				stepReq.enable();
			}
			catch (DuplicateRequestException dre) {
				// IGNORE
			}
		}
		vm.resume();
	}

	@TraceRmiMethod(action = "step_out", display = "Step out")
	public void step_vm_out(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		List<ThreadReference> threads = getThreadsFromValue(obj);
		for (ThreadReference thread : threads) {
			try {
				StepRequest stepReq = vm.eventRequestManager()
						.createStepRequest(thread, StepRequest.STEP_MIN,
							StepRequest.STEP_OUT);
				stepReq.enable();
			}
			catch (DuplicateRequestException dre) {
				// IGNORE
			}
		}
		vm.resume();
	}

	@TraceRmiMethod(action = "step_into", display = "Step into")
	public void step_into(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_MIN,
					StepRequest.STEP_INTO);
		stepReq.enable();
		vm.resume();
	}

	@TraceRmiMethod(action = "step_over", display = "Step over")
	public void step_over(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_MIN,
					StepRequest.STEP_OVER);
		stepReq.enable();
		vm.resume();
	}

	@TraceRmiMethod(action = "step_out", display = "Step out")
	public void step_out(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_MIN,
					StepRequest.STEP_OUT);
		stepReq.enable();
		vm.resume();
	}

	@TraceRmiMethod(display = "Thread Interrupt")
	public void thread_interrupt(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		Object object = getObjectFromPath(obj.getPath());
		if (object instanceof ThreadReference thread) {
			thread.interrupt();
			connector.getHooks().setState(thread.virtualMachine());
		}
	}

	@TraceRmiMethod(action = "step_ext", display = "Pop stack")
	public void pop_stack(@Param(schema = "StackFrame", name = "frame") RmiTraceObject obj) {
		StackFrame frame = (StackFrame) getObjectFromPath(obj.getPath());
		ThreadReference thread = frame.thread();
		try {
			thread.popFrames(frame);
		}
		catch (IncompatibleThreadStateException e) {
			Msg.out("Incompatible thread state for pop");
		}
	}

	@TraceRmiMethod(display = "Break on execute")
	public void break_location(@Param(schema = "Location", name = "location") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Location loc) {
			BreakpointRequest brkReq = vm.eventRequestManager()
					.createBreakpointRequest(loc);
			brkReq.enable();
			cmds.putBreakpoints();
		}
	}

	@TraceRmiMethod(display = "Break on access")
	public void break_access(@Param(schema = "Field", name = "field") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Field field) {
			AccessWatchpointRequest brkReq = vm.eventRequestManager()
					.createAccessWatchpointRequest(field);
			brkReq.enable();
			cmds.putBreakpoints();
		}
	}

	@TraceRmiMethod(display = "Break on modify")
	public void break_modify(@Param(schema = "Field", name = "field") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Field field) {
			ModificationWatchpointRequest brkReq = vm.eventRequestManager()
					.createModificationWatchpointRequest(field);
			brkReq.enable();
			cmds.putBreakpoints();
		}
	}

	@TraceRmiMethod(display = "Break on exception")
	public void break_exception(
			@Param(
				schema = "ReferenceType",
				description = "Reference Type (Class)",
				display = "Type",
				name = "reference_type") RmiTraceObject obj,
			@Param(
				description = "Caught exceptions will be notified",
				display = "NotifyCaught",
				name = "notify_caught") boolean notifyCaught,
			@Param(
				description = "Uncaught exceptions will be notified",
				display = "NotifyUncaught",
				name = "notify_uncaught") boolean notifyUncaught) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			ExceptionRequest excReq = vm.eventRequestManager()
					.createExceptionRequest(reftype, notifyCaught, notifyUncaught);
			excReq.enable();
			cmds.putEvents();
		}
	}

	private void break_started(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ThreadStartRequest brkReq = vm.eventRequestManager()
				.createThreadStartRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on thread start")
	public void break_started_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_started(obj);
	}

	@TraceRmiMethod(display = "Break on thread start")
	public void break_started_thread(
			@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_started(obj);
	}

	private void break_death(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ThreadDeathRequest brkReq = vm.eventRequestManager()
				.createThreadDeathRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on thread exit")
	public void break_death_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_death(obj);
	}

	@TraceRmiMethod(display = "Break on thread exit")
	public void break_death_thread(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_death(obj);
	}

	@TraceRmiMethod(display = "Break on VM death")
	public void break_vm_death(@Param(schema = "VirtualMachine", name = "vm") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		VMDeathRequest brkReq = vm.eventRequestManager()
				.createVMDeathRequest();
		brkReq.enable();
		cmds.putEvents();
	}

	private void break_enter(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MethodEntryRequest brkReq = vm.eventRequestManager()
				.createMethodEntryRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		if (ctxt instanceof ObjectReference ref) {
			brkReq.putProperty("Instance", ref);
			brkReq.addInstanceFilter(ref);
		}
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on method enter")
	public void break_enter_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_enter(obj);
	}

	@TraceRmiMethod(display = "Break on method enter")
	public void break_enter_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_enter(obj);
	}

	@TraceRmiMethod(display = "Break on method enter")
	public void break_enter_instance(
			@Param(schema = "ObjectReference", name = "instance") RmiTraceObject obj) {
		break_enter(obj);
	}

	@TraceRmiMethod(display = "Break on method enter")
	public void break_enter_thread(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_enter(obj);
	}

	private void break_exit(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MethodExitRequest brkReq = vm.eventRequestManager()
				.createMethodExitRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		if (ctxt instanceof ObjectReference ref) {
			brkReq.putProperty("Instance", ref);
			brkReq.addInstanceFilter(ref);
		}
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on method exit")
	public void break_exit_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_exit(obj);
	}

	@TraceRmiMethod(display = "Break on method exit")
	public void break_exit_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_exit(obj);
	}

	@TraceRmiMethod(display = "Break on method exit")
	public void break_exit_instance(
			@Param(schema = "ObjectReference", name = "instance") RmiTraceObject obj) {
		break_exit(obj);
	}

	@TraceRmiMethod(display = "Break on method exit")
	public void break_exit_thread(@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_exit(obj);
	}

	private void break_load(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ClassPrepareRequest brkReq = vm.eventRequestManager()
				.createClassPrepareRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on class load")
	public void break_load_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_load(obj);
	}

	@TraceRmiMethod(display = "Break on class load")
	public void break_load_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_load(obj);
	}

	private void break_unload(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ClassUnloadRequest brkReq = vm.eventRequestManager()
				.createClassUnloadRequest();
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on class unload")
	public void break_unload_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_unload(obj);
	}

	private void break_mon_enter_contention(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MonitorContendedEnterRequest brkReq = vm.eventRequestManager()
				.createMonitorContendedEnterRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		if (ctxt instanceof ObjectReference ref) {
			brkReq.putProperty("Instance", ref);
			brkReq.addInstanceFilter(ref);
		}
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on monitor contended enter")
	public void break_mon_enter_contention_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	@TraceRmiMethod(display = "Break on monitor contended enter")
	public void break_mon_enter_contention_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	@TraceRmiMethod(display = "Break on monitor contended enter")
	public void break_mon_enter_contention_instance(
			@Param(schema = "ObjectReference", name = "instance") RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	@TraceRmiMethod(display = "Break on monitor contended enter")
	public void break_mon_enter_contention_thread(
			@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	private void break_mon_entered_contention(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MonitorContendedEnteredRequest brkReq = vm.eventRequestManager()
				.createMonitorContendedEnteredRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		if (ctxt instanceof ObjectReference ref) {
			brkReq.putProperty("Instance", ref);
			brkReq.addInstanceFilter(ref);
		}
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on monitor contented entered")
	public void break_mon_entered_contention_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	@TraceRmiMethod(display = "Break on monitor contented entered")
	public void break_mon_entered_contention_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	@TraceRmiMethod(display = "Break on monitor contented entered")
	public void break_mon_entered_contention_instance(
			@Param(schema = "ObjectReference", name = "instance") RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	@TraceRmiMethod(display = "Break on monitor contented entered")
	public void break_mon_entered_contention_thread(
			@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	private void break_mon_wait(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MonitorWaitRequest brkReq = vm.eventRequestManager()
				.createMonitorWaitRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		if (ctxt instanceof ObjectReference ref) {
			brkReq.putProperty("Instance", ref);
			brkReq.addInstanceFilter(ref);
		}
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on monitor wait")
	public void break_mon_wait_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	@TraceRmiMethod(display = "Break on monitor wait")
	public void break_mon_wait_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	@TraceRmiMethod(display = "Break on monitor wait")
	public void break_mon_wait_instance(
			@Param(schema = "ObjectReference", name = "instance") RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	@TraceRmiMethod(display = "Break on monitor wait")
	public void break_mon_wait_thread(
			@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	private void break_mon_waited(RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MonitorWaitedRequest brkReq = vm.eventRequestManager()
				.createMonitorWaitedRequest();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			brkReq.putProperty("Class", reftype);
			brkReq.addClassFilter(reftype);
		}
		if (ctxt instanceof ObjectReference ref) {
			brkReq.putProperty("Instance", ref);
			brkReq.addInstanceFilter(ref);
		}
		if (ctxt instanceof ThreadReference ref) {
			brkReq.putProperty("Thread", ref);
			brkReq.addThreadFilter(ref);
		}
		brkReq.enable();
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Break on monitor waited")
	public void break_mon_waited_container(
			@Param(schema = "EventContainer", name = "container") RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@TraceRmiMethod(display = "Break on monitor waited")
	public void break_mon_waited_reftype(
			@Param(schema = "ReferenceType", name = "class") RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@TraceRmiMethod(display = "Break on monitor waited")
	public void break_mon_waited_instance(
			@Param(schema = "ObjectReference", name = "instance") RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@TraceRmiMethod(display = "Break on monitor waited")
	public void break_mon_waited_thread(
			@Param(schema = "Thread", name = "thread") RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@TraceRmiMethod(display = "Add count filter")
	public void add_count_filter(
			@Param(
				schema = "Event",
				description = "Event",
				display = "Event",
				name = "event") RmiTraceObject obj,
			@Param(
				description = "Count",
				display = "MaxCount",
				name = "count") int count) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof EventRequest req) {
			req.disable();
			req.addCountFilter(count);
			cmds.setValue(obj.getPath(), "Count", count);
			req.enable();
			cmds.putEvents();
		}
	}

	@TraceRmiMethod(display = "Set class filter")
	public void set_class_filter(
			@Param(
				schema = "Event",
				description = "Event",
				display = "Event",
				name = "event") RmiTraceObject obj,
			@Param(
				description = "Filter Pattern",
				display = "Filter",
				name = "filter") String filter,
			@Param(
				description = "Exclude",
				display = "Exclude",
				name = "exclude") boolean exclude) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof MethodEntryRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof MethodExitRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof ClassPrepareRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof ClassUnloadRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorContendedEnterRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorContendedEnteredRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorWaitRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorWaitedRequest req) {
			req.disable();
			if (exclude) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_EXCLUDE, filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), ATTR_INCLUDE, filter);
			}
			req.enable();
		}
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Set source filter")
	public void set_source_filter(
			@Param(
				schema = "Event",
				description = "Event",
				display = "Event",
				name = "event") RmiTraceObject obj,
			@Param(
				description = "Source Name Pattern",
				display = "SourceName",
				name = "source_name") String srcname) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ClassPrepareRequest req) {
			req.disable();
			req.addSourceNameFilter(srcname);
			cmds.setValue(obj.getPath(), "SourceMatches", srcname);
			req.enable();
		}
		cmds.putEvents();
	}

	@TraceRmiMethod(display = "Set platform filter")
	public void set_platform_filter(@Param(schema = "Event", name = "event") RmiTraceObject obj) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ThreadStartRequest req) {
			req.disable();
			req.addPlatformThreadsOnlyFilter();
			cmds.setValue(obj.getPath(), ATTR_PLATFORM_ONLY, true);
			req.enable();
		}
		if (ctxt instanceof ThreadDeathRequest req) {
			req.disable();
			req.addPlatformThreadsOnlyFilter();
			cmds.setValue(obj.getPath(), ATTR_PLATFORM_ONLY, true);
			req.enable();
		}
		cmds.putEvents();
	}

	@TraceRmiMethod(action = "toggle", display = "Toggle breakpoint")
	public void toggle_breakpoint(
			@Param(schema = "BreakpointSpec", name = "breakpoint") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Field field) {
			ModificationWatchpointRequest brkReq = vm.eventRequestManager()
					.createModificationWatchpointRequest(field);
			brkReq.enable();
		}
		if (ctxt instanceof EventRequest req) {
			if (req.isEnabled()) {
				req.disable();
			}
			else {
				req.enable();
			}
		}
		cmds.putBreakpoints();
	}

	@TraceRmiMethod(action = "delete", display = "Delete breakpoint")
	public void delete_breakpoint(
			@Param(schema = "BreakpointSpec", name = "breakpoint") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof EventRequest req) {
			vm.eventRequestManager().deleteEventRequest(req);
		}
		cmds.putBreakpoints();
	}

	@TraceRmiMethod(action = "toggle", display = "Toggle event")
	public void toggle_event(@Param(schema = "Event", name = "event") RmiTraceObject obj) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof EventRequest req) {
			if (req.isEnabled()) {
				req.disable();
			}
			else {
				req.enable();
			}
			cmds.putEvents();
		}
	}

	@TraceRmiMethod(action = "delete", display = "Delete Event")
	public void delete_event(@Param(schema = "Event", name = "event") RmiTraceObject obj) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof EventRequest req) {
			vm.eventRequestManager().deleteEventRequest(req);
		}
		cmds.putEvents();
	}

	@TraceRmiMethod(action = "toggle", display = "Toggle scope")
	public void toggle_scope_canonical_methods(
			@Param(schema = "CanonicalMethodContainer", name = "container") RmiTraceObject obj) {
		toggle_scope_methods(obj);
	}

	@TraceRmiMethod(action = "toggle", display = "Toggle scope")
	public void toggle_scope_methods(
			@Param(schema = "MethodContainer", name = "container") RmiTraceObject obj) {
		String ppath = cmds.getParentPath(obj.getPath());
		Object parent = getObjectFromPath(ppath);
		connector.toggleScope(parent);
		refresh_methods(obj);
	}

	@TraceRmiMethod(action = "toggle", display = "Toggle scope")
	public void toggle_scope_canonical_fields(
			@Param(schema = "CanonicalFieldContainer", name = "container") RmiTraceObject obj) {
		toggle_scope_fields(obj);
	}

	@TraceRmiMethod(action = "toggle", display = "Toggle scope")
	public void toggle_scope_fields(
			@Param(schema = "FieldContainer", name = "container") RmiTraceObject obj) {
		String ppath = cmds.getParentPath(obj.getPath());
		Object parent = getObjectFromPath(ppath);
		connector.toggleScope(parent);
		if (obj.getPath().endsWith("Fields")) {
			refresh_fields(obj);
		}
		if (obj.getPath().endsWith("Variables")) {
			refresh_fields(obj);
		}
	}

	@TraceRmiMethod(action = "read_mem", display = "Read Memory")
	public long read_mem(
			@Param(
				schema = "VirtualMachine",
				description = "VirtualMachine",
				display = "VirtualMachine",
				name = "vm") RmiTraceObject obj,
			@Param(
				description = "Range",
				display = "Range",
				name = "range") AddressRange range) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		MemoryMapper mapper = cmds.state.trace.memoryMapper;
		Address start = mapper.mapBack(range.getMinAddress());
		try (RmiTransaction tx = cmds.state.trace.openTx("ReadMemory")) {
			cmds.putMem(start, range.getLength(), true);
			cmds.putMemState(start, range.getLength(), MemoryState.MS_KNOWN, true);
		}
		catch (Exception e) {
			cmds.putMemState(start, range.getLength(), MemoryState.MS_ERROR, true);
		}
		return range.getLength();
	}

	@TraceRmiMethod(display = "Invoke method (no args)")
	public void execute_on_instance(
			@Param(
				schema = "ObjectReference",
				description = "Object Reference",
				display = "Object",
				name = "object") RmiTraceObject obj,
			@Param(
				description = "Thread Name",
				display = "ThreadName",
				name = "thread_name") String threadName,
			@Param(
				description = "Method Name",
				display = "MethodName",
				name = "method_name") String methodName) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ObjectReference ref = (ObjectReference) getObjectFromPath(obj.getPath());
		List<Method> methods = ref.referenceType().methodsByName(methodName);
		if (methods.size() > 1) {
			Msg.warn(this, "Method " + methodName + " is not unique - using first variant");
		}
		for (ThreadReference thread : vm.allThreads()) {
			if (thread.name().equals(threadName)) {
				cmds.execute(ref, thread, methods.get(0), new ArrayList<Value>(), 0);
			}
		}
	}

	@TraceRmiMethod(display = "Invoke static method (no args)")
	public void execute_on_class(
			@Param(
				schema = "ReferenceType",
				description = "Class",
				display = "Class",
				name = "class") RmiTraceObject obj,
			@Param(
				description = "Thread Name",
				display = "ThreadName",
				name = "thread_name") String threadName,
			@Param(
				description = "Method Name",
				display = "MethodName",
				name = "method_name") String methodName) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		ReferenceType reftype = (ReferenceType) getObjectFromPath(obj.getPath());
		if (reftype instanceof ClassType cls) {
			List<Method> methods = cls.methodsByName(methodName);
			if (methods.size() > 1) {
				Msg.warn(this, "Method " + methodName + " is not unique - using first variant");
			}
			if (!methods.get(0).isStatic()) {
				Msg.error(this, "Method " + methodName + " is not static");
				return;
			}
			for (ThreadReference thread : vm.allThreads()) {
				if (thread.name().equals(threadName)) {
					cmds.execute(cls, thread, methods.get(0), new ArrayList<Value>(), 0);
				}
			}
		}
	}

	@TraceRmiMethod(display = "Invoke method (no args)")
	public void execute_method(
			@Param(
				schema = "Method",
				description = "Method",
				display = "Method",
				name = "method") RmiTraceObject obj,
			@Param(
				description = "Instance Pattern",
				display = "InstancePattern",
				name = "instance_pattern") String instancePattern,
			@Param(
				description = "Thread Name",
				display = "ThreadName",
				name = "thread_name") String threadName) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		String path = obj.getPath();
		Method method = (Method) getObjectFromPath(path);
		ReferenceType declaringType = method.declaringType();
		List<ObjectReference> instances = declaringType.instances(0);
		for (ObjectReference ref : instances) {
			if (ref.toString().contains(instancePattern)) {
				for (ThreadReference thread : vm.allThreads()) {
					if (thread.name().equals(threadName)) {
						cmds.execute(ref, thread, method, new ArrayList<Value>(), 0);
					}
				}
			}
		}
	}

	@TraceRmiMethod(display = "Invoke static method (no args)")
	public void execute_static_method(
			@Param(
				schema = "Method",
				description = "Method",
				display = "Method",
				name = "method") RmiTraceObject obj,
			@Param(
				description = "Thread Name",
				display = "ThreadName",
				name = "thread_name") String threadName) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		String path = obj.getPath();
		Method method = (Method) getObjectFromPath(path);
		if (!method.isStatic()) {
			Msg.error(this, "Method " + method.name() + " is not static");
			return;
		}
		ReferenceType reftype = method.declaringType();
		if (reftype instanceof ClassType ct) {
			for (ThreadReference thread : vm.allThreads()) {
				if (thread.name().equals(threadName)) {
					cmds.execute(ct, thread, method, new ArrayList<Value>(), 0);
				}
			}
		}
	}

	private List<ThreadReference> getThreadsFromValue(RmiTraceObject obj) {
		Object object = getObjectFromPath(obj.getPath());
		if (object instanceof VirtualMachine vm) {
			return vm.allThreads();
		}
		List<ThreadReference> threads = new ArrayList<>();
		if (object instanceof ThreadReference thread) {
			threads.add(thread);
		}
		else {
			threads.add(connector.getJdi().getCurrentThread());
		}
		return threads;
	}

	private Object getObjectFromPath(String path) {
		return connector.objForPath(path);
	}

}
