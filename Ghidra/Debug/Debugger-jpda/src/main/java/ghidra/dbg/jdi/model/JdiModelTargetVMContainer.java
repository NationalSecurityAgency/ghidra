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

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.ThreadReference;
import com.sun.jdi.VirtualMachine;
import com.sun.jdi.event.*;

import ghidra.async.AsyncUtils;
import ghidra.dbg.jdi.manager.JdiCause;
import ghidra.dbg.jdi.manager.JdiEventsListenerAdapter;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(name = "VMContainer", elements = { //
	@TargetElementType(type = JdiModelTargetVM.class) //
}, attributes = { //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class JdiModelTargetVMContainer extends JdiModelTargetObjectImpl
		implements JdiEventsListenerAdapter {

	private JdiModelTargetRoot session;
	protected final Map<String, JdiModelTargetVM> vmsById = new WeakValueHashMap<>();

	public JdiModelTargetVMContainer(JdiModelTargetRoot session) {
		super(session, "VirtualMachines");
		this.session = session;

		impl.getManager().addEventsListener(null, this);
	}

	@Override
	public void vmStarted(VMStartEvent event, JdiCause cause) {
		VirtualMachine vm = event.virtualMachine();
		JdiModelTargetVM target = getTargetVM(vm);
		// TODO: Move PROCESS_CREATED here to restore proper order of event reporting
		// Pending some client-side changes to handle architecture selection, though.
		target.started(vm.name()).thenAccept(__ -> {
			session.getListeners().fire.event(session, null, TargetEventType.PROCESS_CREATED,
				"VM " + vm.name() + " started " + vm.process() + " pid=" + vm.name(), List.of(vm));
		}).exceptionally(ex -> {
			Msg.error(this, "Could not notify vm started", ex);
			return null;
		});

		changeElements(List.of(), List.of(target), Map.of(), "Added");
	}

	@Override
	public void vmDied(VMDeathEvent event, JdiCause cause) {
		VirtualMachine vm = event.virtualMachine();
		JdiModelTargetVM tgtVM = vmsById.get(vm.name());
		session.getListeners().fire.event(session, null, TargetEventType.PROCESS_EXITED,
			"VM " + vm.name(), List.of(tgtVM));
		tgtVM.exited(vm);
		synchronized (this) {
			vmsById.remove(vm.name());
			getManager().removeVM(vm);
		}
		changeElements(List.of(vm.name()), List.of(), Map.of(), "Removed");
	}

	protected void gatherThreads(List<? super JdiModelTargetThread> into, JdiModelTargetVM vm,
			Collection<? extends ThreadReference> from) {
		for (ThreadReference t : from) {
			JdiModelTargetThread p = vm.threads.getTargetThread(t);
			if (p != null) {
				into.add(p);
			}
		}
	}

	@Override
	public void threadStarted(ThreadStartEvent event, JdiCause cause) {
		ThreadReference thread = event.thread();
		JdiModelTargetVM vm = getTargetVM(thread.threadGroup().virtualMachine());
		if (!vmsById.containsValue(vm)) {
			Msg.info(this, event + " ignored as vm may have exited");
			return;
		}
		JdiModelTargetThread targetThread = vm.threads.threadCreated(thread);
		session.getListeners().fire.event(session, targetThread, TargetEventType.THREAD_CREATED,
			"Thread " + thread.name() + " started", List.of(targetThread));
	}

	@Override
	public void threadExited(ThreadDeathEvent event, JdiCause cause) {
		ThreadReference thread = event.thread();
		JdiModelTargetVM tgtVM = vmsById.get(thread.virtualMachine().name());
		JdiModelTargetThread targetThread = tgtVM.threads.threadsById.get(thread.name());
		session.getListeners().fire.event(session, targetThread, TargetEventType.THREAD_EXITED,
			"Thread " + thread.name() + " exited", List.of(targetThread));
		tgtVM.threads.threadExited(thread);
	}

	@Override
	public void libraryLoaded(VirtualMachine vm, String name, JdiCause cause) {
		/*
		JdiModelTargetVM vm = getTargetInferior(inf);
		JdiModelTargetModule module = vm.modules.libraryLoaded(name);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, null, TargetEventType.MODULE_LOADED,
					"Library " + name + " loaded", List.of(module));
					*/
	}

	@Override
	public void libraryUnloaded(VirtualMachine vm, String name, JdiCause cause) {
		/*
		JdiModelTargetVM vm = getTargetInferior(inf);
		JdiModelTargetModule module = vm.modules.getTargetModuleIfPresent(name);
		parent.getListeners()
				.fire(TargetEventScopeListener.class)
				.event(parent, null, TargetEventType.MODULE_UNLOADED,
					"Library " + name + " unloaded", List.of(module));
		vm.modules.libraryUnloaded(name);
		*/
	}

	private void updateUsingVMs(Map<String, VirtualMachine> byName) {
		List<JdiModelTargetVM> vms;
		synchronized (this) {
			vms = byName.values().stream().map(this::getTargetVM).collect(Collectors.toList());
		}
		setElements(vms, Map.of(), "Refreshed");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (!refresh) {
			updateUsingVMs(impl.getManager().getKnownVMs());
			return AsyncUtils.NIL;
		}
		return impl.getManager().listVMs().thenAccept(this::updateUsingVMs);
	}

	// NOTE: Does no good to override fetchElement
	// Cache should be kept in sync all the time, anyway

	public synchronized JdiModelTargetVM getTargetVM(VirtualMachine vm) {
		return vmsById.computeIfAbsent(vm.name(),
			i -> new JdiModelTargetVM(this, impl.getManager().getKnownVMs().get(i), true));
	}

	public synchronized JdiModelTargetVM getTargetVMByName(String name) {
		return vmsById.computeIfAbsent(name,
			i -> new JdiModelTargetVM(this, impl.getManager().getKnownVMs().get(i), true));
	}

	protected void invalidateMemoryAndRegisterCaches() {
		for (JdiModelTargetVM inf : vmsById.values()) {
			inf.invalidateMemoryAndRegisterCaches();
		}
	}

}
