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

import java.io.IOException;
import java.util.*;

import com.sun.jdi.*;
import com.sun.jdi.request.*;

import ghidra.app.plugin.core.debug.client.tracermi.*;
import ghidra.dbg.target.TargetMethod;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.rmi.trace.TraceRmi.MemoryState;
import ghidra.util.Msg;

public class TraceJdiMethods implements RmiMethods {

	private TraceJdiManager manager;
	private TraceJdiCommands cmds;

	public TraceJdiMethods(TraceJdiManager manager) {
		this.manager = manager;
		this.cmds = manager.getCommands();
		registerMethods();
	}

	public void registerMethods() {
		Class<?> cls = this.getClass();
		for (java.lang.reflect.Method m : cls.getMethods()) {
			RmiMethodRegistry.TraceMethod annot =
				m.getAnnotation(RmiMethodRegistry.TraceMethod.class);
			if (annot != null) {
				manager.registerRemoteMethod(this, m, m.getName());
			}
		}
	}

//	public void execute(String cmd) {
//			
//	}

//	public void refresh_available(Object obj) {
//		
//	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh VM",
		schema = "VirtualMachine")
	public void refresh_vm(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshVM")) {
			String path = obj.getPath();
			VirtualMachine vm = (VirtualMachine) getObjectFromPath(path);
			cmds.putVMDetails(path, vm);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh process",
		schema = "ProcessRef")
	public void refresh_process(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshProcess")) {
			String path = obj.getPath();
			Process proc = (Process) getObjectFromPath(path);
			cmds.putProcessDetails(path, proc);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh thread groups",
		schema = "ThreadGroupReferenceContainer")
	public void refresh_thread_groups(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh thread group",
		schema = "ThreadGroupReferenceProxy")
	public void refresh_thread_group_proxy(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh thread group",
		schema = "ThreadGroupReference")
	public void refresh_thread_group(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreadGroup")) {
			String path = obj.getPath();
			ThreadGroupReference ref = (ThreadGroupReference) getObjectFromPath(path);
			cmds.putThreadGroupReferenceDetails(path, ref);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh threads",
		schema = "ThreadContainer")
	public void refresh_threads(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThreads")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			VirtualMachine vm = (VirtualMachine) getObjectFromPath(ppath);
			cmds.putThreadContainer(ppath, vm.allThreads(), false);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh threads",
		schema = "ThreadReferenceContainer")
	public void refresh_threadrefs(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh Thread",
		schema = "Thread")
	public void refresh_thread(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshThread")) {
			String path = obj.getPath();
			ThreadReference ref = (ThreadReference) getObjectFromPath(path);
			cmds.putThreadReferenceDetails(path, ref);
		}
	}

	@RmiMethodRegistry.TraceMethod(action = "refresh", display = "Refresh Stack", schema = "Stack")
	public void refresh_stack(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshStack")) {
			cmds.ghidraTracePutFrames();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh registers",
		schema = "RegisterContainer")
	public void refresh_registers(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshRegisters")) {
			cmds.ghidraTracePutFrames();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh modules",
		schema = "ModuleReferenceContainer")
	public void refresh_modules(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshModules")) {
			cmds.putModuleReferenceContainer();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh module",
		schema = "ModuleReference")
	public void refresh_module(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshModule")) {
			String path = obj.getPath();
			ModuleReference ref = (ModuleReference) getObjectFromPath(path);
			cmds.putModuleReferenceDetails(path, ref);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh monitor info",
		schema = "MonitorInfoContainer")
	public void refresh_monitors(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh monitor info",
		schema = "MonitorInfo")
	public void refresh_monitor_info(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMonitorInfo")) {
			String path = obj.getPath();
			MonitorInfo mi = (MonitorInfo) getObjectFromPath(path);
			cmds.putMonitorInfoDetails(path, mi);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh fields",
		schema = "FieldContainer")
	public void refresh_fields(RmiTraceObject obj) {
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

//	@RmiMethodRegistry.method(action = "refresh", display = "Refresh Field", schema = "Field")
//	public void refresh_field(RmiTraceObject obj) {
//		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshField")) {
//			String path = obj.getPath();
//			Field field = (Field) getObjectFromPath(path);
//			cmds.putFieldDetails(path, field);
//		}
//	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh objects",
		schema = "ObjectReferenceContainer")
	public void refresh_objects(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh object",
		schema = "ObjectReferenceProxy")
	public void refresh_object_proxy(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh object",
		schema = "ObjectReference")
	public void refresh_object(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshInstance")) {
			String path = obj.getPath();
			ObjectReference method = (ObjectReference) getObjectFromPath(path);
			cmds.putObjectReferenceDetails(path, method);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh methods",
		schema = "MethodContainer")
	public void refresh_methods(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMethods")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			ReferenceType refType = (ReferenceType) getObjectFromPath(ppath);
			cmds.putMethodContainer(path, refType);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh method",
		schema = "Method")
	public void refresh_method(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshMethod")) {
			String path = obj.getPath();
			Method method = (Method) getObjectFromPath(path);
			cmds.putMethodDetails(path, method, false);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh arguments",
		schema = "ArgumentContainer")
	public void refresh_arguments(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshArguments")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Method method = (Method) getObjectFromPath(ppath);
			cmds.putMethodTypeContainer(path, method);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "load_class",
		display = "Load class",
		schema = "ReferenceTypeContainer")
	public void find_class(RmiTraceObject obj,
			@TargetMethod.Param(
				description = "Class to open",
				display = "Class",
				name = "find") String targetClass) {
		try (RmiTransaction tx = cmds.state.trace.openTx("FindClass")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof VirtualMachine vm) {
				cmds.loadReferenceType(path, vm.allClasses(), targetClass);
			}
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh_memory",
		display = "Refresh memory",
		schema = "Memory")
	public void refresh_memory(RmiTraceObject obj) {
		refresh_reference_types(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh_types",
		display = "Refresh reference types",
		schema = "ReferenceTypeContainer")
	public void refresh_reference_types(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh reference type",
		schema = "ReferenceTypeProxy")
	public void refresh_reference_type_proxy(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh reference type",
		schema = "ReferenceType")
	public void refresh_reference_type(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshReferenceType")) {
			String path = obj.getPath();
			ReferenceType refType = (ReferenceType) getObjectFromPath(path);
			cmds.putReferenceType(path, refType, false);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "load",
		display = "Load reference",
		schema = "ReferenceType")
	public void load_reftype(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshReferenceType")) {
			VirtualMachine vm = manager.getJdi().getCurrentVM();
			String path = obj.getPath();
			String mempath = cmds.getPath(vm) + ".Classes";
			ReferenceType refType = (ReferenceType) getObjectFromPath(path);
			cmds.putReferenceType(mempath, refType, true);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh variables",
		schema = "VariableContainer")
	public void refresh_variables(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh variable",
		schema = "Variable")
	public void refresh_variable(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshVariable")) {
			String path = obj.getPath();
			Object object = getObjectFromPath(path);
			if (object instanceof LocalVariable var) {
				cmds.putLocalVariableDetails(path, var);
			}
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh locations",
		schema = "LocationContainer")
	public void refresh_locations(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh location",
		schema = "Location")
	public void refresh_location(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			Location loc = (Location) getObjectFromPath(path);
			cmds.putLocationDetails(path, loc);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh breakpoints",
		schema = "BreakpointContainer")
	public void refresh_breakpoints(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshBreakpoints")) {
			cmds.putBreakpoints();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh events",
		schema = "EventContainer")
	public void refresh_events(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshEvents")) {
			cmds.putEvents();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh values",
		schema = "ValueContainer")
	public void refresh_values(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshValues")) {
			String path = obj.getPath();
			String ppath = cmds.getParentPath(path);
			Object parent = getObjectFromPath(ppath);
			if (parent instanceof ArrayReference arr) {
				cmds.putValueContainer(path, arr.getValues());
			}
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "refresh",
		display = "Refresh value",
		schema = "Value")
	public void refresh_value(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			Value val = (Value) getObjectFromPath(path);
			cmds.putValueDetailsByType(path, val);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "set",
		display = "Set value",
		schema = "Variable")
	public void set_value_lvar(RmiTraceObject obj, String value) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			LocalVariable lvar = (LocalVariable) getObjectFromPath(path);
			cmds.modifyValue(lvar, value);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "set",
		display = "Set value",
		schema = "Field")
	public void set_value_field(RmiTraceObject obj, String value) {
		try (RmiTransaction tx = cmds.state.trace.openTx("RefreshLocation")) {
			String path = obj.getPath();
			Field field = (Field) getObjectFromPath(path);
			cmds.modifyValue(field, value);
		}
	}

	@RmiMethodRegistry.TraceMethod(action = "activate", display = "Activate", schema = "ANY")
	public void activate(RmiTraceObject obj) {
		try (RmiTransaction tx = cmds.state.trace.openTx("Activate")) {
			String path = obj.getPath();
			cmds.activate(path);
		}
	}

	@RmiMethodRegistry.TraceMethod(action = "kill", display = "Kill", schema = "VirtualMachine")
	public void kill(RmiTraceObject obj) {
		try {
			manager.getJdi().sendInterruptNow();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	@RmiMethodRegistry.TraceMethod(action = "resume", display = "Resume", schema = "VirtualMachine")
	public void resume_vm(RmiTraceObject obj) {
		VirtualMachine vm = (VirtualMachine) getObjectFromPath(obj.getPath());
		vm.resume();
		manager.getHooks().setState(vm);
	}

	@RmiMethodRegistry.TraceMethod(action = "resume", display = "Resume", schema = "Thread")
	public void resume(RmiTraceObject obj) {
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		thread.resume();
		manager.getHooks().setState(thread.virtualMachine());
	}

	@RmiMethodRegistry.TraceMethod(
		action = "suspend",
		display = "Suspend",
		schema = "VirtualMachine")
	public void suspend(RmiTraceObject obj) {
		Object object = getObjectFromPath(obj.getPath());
		if (object instanceof ThreadReference thread) {
			thread.suspend();
			manager.getHooks().setState(thread.virtualMachine());
		}
		else {
			VirtualMachine vm = manager.getJdi().getCurrentVM();
			vm.suspend();
			manager.getHooks().setState(vm);
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "interrupt",
		display = "Interrupt",
		schema = "VirtualMachine")
	public void interrupt(RmiTraceObject obj) {
		suspend(obj);
	}

	// NB: For the VirtualMachine, the step methods add requests for break-on-step for all threads.
	//  These requests will remain pending until the VM is resumed.
	@RmiMethodRegistry.TraceMethod(
		action = "step_into",
		display = "Step into",
		schema = "VirtualMachine")
	public void step_vm_into(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "step_over",
		display = "Step over",
		schema = "VirtualMachine")
	public void step_vm_over(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "step_out",
		display = "Step out",
		schema = "VirtualMachine")
	public void step_vm_out(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(action = "step_into", display = "Step into", schema = "Thread")
	public void step_into(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_MIN,
					StepRequest.STEP_INTO);
		stepReq.enable();
		vm.resume();
	}

	@RmiMethodRegistry.TraceMethod(action = "step_over", display = "Step over", schema = "Thread")
	public void step_over(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_OVER,
					StepRequest.STEP_INTO);
		stepReq.enable();
		vm.resume();
	}

	@RmiMethodRegistry.TraceMethod(action = "step_out", display = "Step out", schema = "Thread")
	public void step_out(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		ThreadReference thread = (ThreadReference) getObjectFromPath(obj.getPath());
		StepRequest stepReq = vm.eventRequestManager()
				.createStepRequest(thread, StepRequest.STEP_OUT,
					StepRequest.STEP_INTO);
		stepReq.enable();
		vm.resume();
	}

//	public void step_advance(Object obj) {}
//  public void step_return(Object obj) {}

	@RmiMethodRegistry.TraceMethod(
		action = "thread_interrupt",
		display = "Thread Interrupt",
		schema = "Thread")
	public void thread_interrupt(RmiTraceObject obj) {
		Object object = getObjectFromPath(obj.getPath());
		if (object instanceof ThreadReference thread) {
			thread.interrupt();
			manager.getHooks().setState(thread.virtualMachine());
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "pop_stack",
		display = "Pop stack",
		schema = "StackFrame")
	public void pop_stack(RmiTraceObject obj) {
		StackFrame frame = (StackFrame) getObjectFromPath(obj.getPath());
		ThreadReference thread = frame.thread();
		try {
			thread.popFrames(frame);
		}
		catch (IncompatibleThreadStateException e) {
			Msg.out("Incompatible thread state for pop");
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_location",
		display = "Break on execute",
		schema = "Location")
	public void break_location(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Location loc) {
			BreakpointRequest brkReq = vm.eventRequestManager()
					.createBreakpointRequest(loc);
			brkReq.enable();
			cmds.putBreakpoints();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_field_access",
		display = "Break on access",
		schema = "Field")
	public void break_access(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Field field) {
			AccessWatchpointRequest brkReq = vm.eventRequestManager()
					.createAccessWatchpointRequest(field);
			brkReq.enable();
			cmds.putBreakpoints();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_field_modified",
		display = "Break on modify",
		schema = "Field")
	public void break_modify(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof Field field) {
			ModificationWatchpointRequest brkReq = vm.eventRequestManager()
					.createModificationWatchpointRequest(field);
			brkReq.enable();
			cmds.putBreakpoints();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_exception",
		display = "Break on exception",
		schema = "ReferenceType")
	public void break_exception(RmiTraceObject obj,
			@TargetMethod.Param(
				description = "Caught exceptions will be notified",
				display = "NotifyCaught",
				name = "notifyC") Boolean notifyCaught,
			@TargetMethod.Param(
				description = "Uncaught exceptions will be notified",
				display = "NotifyUncaught",
				name = "notifyU") Boolean notifyUncaught) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ReferenceType reftype) {
			ExceptionRequest excReq = vm.eventRequestManager()
					.createExceptionRequest(reftype, notifyCaught, notifyUncaught);
			excReq.enable();
			cmds.putEvents();
		}
	}

	private void break_started(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_started",
		display = "Break on thread start",
		schema = "EventContainer")
	public void break_started_container(RmiTraceObject obj) {
		break_started(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_started",
		display = "Break on thread start",
		schema = "Thread")
	public void break_started_thread(RmiTraceObject obj) {
		break_started(obj);
	}

	private void break_death(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_death",
		display = "Break on thread exit",
		schema = "EventContainer")
	public void break_death_container(RmiTraceObject obj) {
		break_death(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_death",
		display = "Break on thread exit",
		schema = "Thread")
	public void break_death_thread(RmiTraceObject obj) {
		break_death(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_vm_death",
		display = "Break on VM death",
		schema = "VirtualMachine")
	public void break_vm_death(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		VMDeathRequest brkReq = vm.eventRequestManager()
				.createVMDeathRequest();
		brkReq.enable();
		cmds.putEvents();
	}

	private void break_enter(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_enter",
		display = "Break on method enter",
		schema = "EventContainer")
	public void break_enter_container(RmiTraceObject obj) {
		break_enter(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_enter",
		display = "Break on method enter",
		schema = "ReferenceType")
	public void break_enter_reftype(RmiTraceObject obj) {
		break_enter(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_enter_instance",
		display = "Break on method enter",
		schema = "ObjectReference")
	public void break_enter_instance(RmiTraceObject obj) {
		break_enter(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_enter_thread",
		display = "Break on method enter",
		schema = "Thread")
	public void break_enter_thread(RmiTraceObject obj) {
		break_enter(obj);
	}

	private void break_exit(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_exit",
		display = "Break on method exit",
		schema = "EventContainer")
	public void break_exit_container(RmiTraceObject obj) {
		break_exit(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_exit",
		display = "Break on method exit",
		schema = "ReferenceType")
	public void break_exit_reftype(RmiTraceObject obj) {
		break_exit(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_exit",
		display = "Break on method exit",
		schema = "ObjectReference")
	public void break_exit_instance(RmiTraceObject obj) {
		break_exit(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_exit",
		display = "Break on method exit",
		schema = "Thread")
	public void break_exit_thread(RmiTraceObject obj) {
		break_exit(obj);
	}

	private void break_load(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_load",
		display = "Break on class load",
		schema = "EventContainer")
	public void break_load_container(RmiTraceObject obj) {
		break_load(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_load",
		display = "Break on class load",
		schema = "ReferenceType")
	public void break_load_reftype(RmiTraceObject obj) {
		break_load(obj);
	}

	private void break_unload(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		ClassUnloadRequest brkReq = vm.eventRequestManager()
				.createClassUnloadRequest();
		brkReq.enable();
		cmds.putEvents();
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_unload",
		display = "Break on class unload",
		schema = "EventContainer")
	public void break_unload_container(RmiTraceObject obj) {
		break_unload(obj);
	}

	private void break_mon_enter_contention(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_enter_contention",
		display = "Break on monitor contended enter",
		schema = "EventContainer")
	public void break_mon_enter_contention_container(RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_enter_contention",
		display = "Break on monitor contended enter",
		schema = "ReferenceType")
	public void break_mon_enter_contention_reftype(RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_enter_contention",
		display = "Break on monitor contended enter",
		schema = "ObjectReference")
	public void break_mon_enter_contention_instance(RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_enter_contention",
		display = "Break on monitor contended enter",
		schema = "Thread")
	public void break_mon_enter_contention_thread(RmiTraceObject obj) {
		break_mon_enter_contention(obj);
	}

	private void break_mon_entered_contention(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_entered_contention",
		display = "Break on monitor contented entered",
		schema = "EventContainer")
	public void break_mon_entered_contention_container(RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_entered_contention",
		display = "Break on monitor contented entered",
		schema = "ReferenceType")
	public void break_mon_entered_contention_reftype(RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_entered_contention",
		display = "Break on monitor contented entered",
		schema = "ObjectReference")
	public void break_mon_entered_contention_instance(RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_entered_contention",
		display = "Break on monitor contented entered",
		schema = "Thread")
	public void break_mon_entered_contention_thread(RmiTraceObject obj) {
		break_mon_entered_contention(obj);
	}

	private void break_mon_wait(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_wait",
		display = "Break on monitor wait",
		schema = "EventContainer")
	public void break_mon_wait_container(RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_wait",
		display = "Break on monitor wait",
		schema = "ReferenceType")
	public void break_mon_wait_reftype(RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_wait",
		display = "Break on monitor wait",
		schema = "ObjectReference")
	public void break_mon_wait_instance(RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_wait",
		display = "Break on monitor wait",
		schema = "Thread")
	public void break_mon_wait_thread(RmiTraceObject obj) {
		break_mon_wait(obj);
	}

	private void break_mon_waited(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_waited",
		display = "Break on monitor waited",
		schema = "EventContainer")
	public void break_mon_waited_container(RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_waited",
		display = "Break on monitor waited",
		schema = "ReferenceType")
	public void break_mon_waited_reftype(RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_waited",
		display = "Break on monitor waited",
		schema = "ObjectReference")
	public void break_mon_waited_instance(RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "break_mon_waited",
		display = "Break on monitor waited",
		schema = "Thread")
	public void break_mon_waited_thread(RmiTraceObject obj) {
		break_mon_waited(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "add_count_filter",
		display = "Add count filter",
		schema = "Event")
	public void add_count_filter(RmiTraceObject obj,
			@TargetMethod.Param(
				description = "Count",
				display = "MaxCount",
				name = "count") Integer count) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof EventRequest req) {
			req.disable();
			req.addCountFilter(count);
			cmds.setValue(obj.getPath(), "Count", count);
			req.enable();
			cmds.putEvents();
		}
	}

	@RmiMethodRegistry.TraceMethod(
		action = "set_class_filter",
		display = "Set class filter",
		schema = "Event")
	public void set_class_filter(RmiTraceObject obj,
			@TargetMethod.Param(
				description = "Filter Pattern",
				display = "Filter",
				name = "filter") String filter,
			@TargetMethod.Param(
				description = "Exclude",
				display = "Exclude",
				name = "exclude") String exclude) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof MethodEntryRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof MethodExitRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof ClassPrepareRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof ClassUnloadRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorContendedEnterRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorContendedEnteredRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorWaitRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		if (ctxt instanceof MonitorWaitedRequest req) {
			req.disable();
			if (exclude.equals("true")) {
				req.addClassExclusionFilter(filter);
				cmds.setValue(obj.getPath(), "Exclude", filter);
			}
			else {
				req.addClassFilter(filter);
				cmds.setValue(obj.getPath(), "Include", filter);
			}
			req.enable();
		}
		cmds.putEvents();
	}

	@RmiMethodRegistry.TraceMethod(
		action = "set_source_filter",
		display = "Set source filter",
		schema = "Event")
	public void set_source_filter(RmiTraceObject obj,
			@TargetMethod.Param(
				description = "Source Name Pattern",
				display = "SourceName",
				name = "srcname") String srcname) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ClassPrepareRequest req) {
			req.disable();
			req.addSourceNameFilter(srcname);
			cmds.setValue(obj.getPath(), "SourceMatches", srcname);
			req.enable();
		}
		cmds.putEvents();
	}

	@RmiMethodRegistry.TraceMethod(
		action = "set_platform_filter",
		display = "Set platform filter",
		schema = "Event")
	public void set_platform_filter(RmiTraceObject obj) {
		Object ctxt = getObjectFromPath(obj.getPath());
		if (ctxt instanceof ThreadStartRequest req) {
			req.disable();
			req.addPlatformThreadsOnlyFilter();
			cmds.setValue(obj.getPath(), "PlatformOnly", true);
			req.enable();
		}
		if (ctxt instanceof ThreadDeathRequest req) {
			req.disable();
			req.addPlatformThreadsOnlyFilter();
			cmds.setValue(obj.getPath(), "PlatformOnly", true);
			req.enable();
		}
		cmds.putEvents();
	}

	@RmiMethodRegistry.TraceMethod(
		action = "toggle_breakpoint",
		display = "Toggle breakpoint",
		schema = "BreakpointSpec")
	public void toggle_breakpoint(RmiTraceObject obj) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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

	@RmiMethodRegistry.TraceMethod(
		action = "toggle_event",
		display = "Toggle event",
		schema = "Event")
	public void toggle_event(RmiTraceObject obj) {
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

	@RmiMethodRegistry.TraceMethod(
		action = "toggle_scope",
		display = "Toggle scope",
		schema = "MethodContainer")
	public void toggle_scope_methods(RmiTraceObject obj) {
		String ppath = cmds.getParentPath(obj.getPath());
		Object parent = getObjectFromPath(ppath);
		manager.toggleScope(parent);
		refresh_methods(obj);
	}

	@RmiMethodRegistry.TraceMethod(
		action = "toggle_scope",
		display = "Toggle scope",
		schema = "FieldContainer")
	public void toggle_scope_fields(RmiTraceObject obj) {
		String ppath = cmds.getParentPath(obj.getPath());
		Object parent = getObjectFromPath(ppath);
		manager.toggleScope(parent);
		if (obj.getPath().endsWith("Fields")) {
			refresh_fields(obj);
		}
		if (obj.getPath().endsWith("Variables")) {
			refresh_fields(obj);
		}
	}

	@RmiMethodRegistry.TraceMethod(action = "read_mem", display = "", schema = "VirtualMachine")
	public long read_mem(RmiTraceObject obj, AddressRange range) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
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
			threads.add(manager.getJdi().getCurrentThread());
		}
		return threads;
	}

	private Object getObjectFromPath(String path) {
		return manager.objForPath(path);
	}

}
