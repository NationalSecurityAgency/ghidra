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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.*;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "InferiorContainer",
	attributes = {
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class) //
	},
	canonicalContainer = true)
public class GdbModelTargetInferiorContainer
		extends DefaultTargetObject<GdbModelTargetInferior, GdbModelTargetSession>
		implements TargetConfigurable, GdbEventsListenerAdapter {
	public static final String NAME = "Inferiors";

	protected final GdbModelImpl impl;

	public GdbModelTargetInferiorContainer(GdbModelTargetSession session) {
		super(session.impl, session, NAME, "InferiorContainer");
		this.impl = session.impl;
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 10), "Initialized");

		impl.gdb.addEventsListener(this);
	}

	@Override
	public void inferiorAdded(GdbInferior inferior, GdbCause cause) {
		GdbModelTargetInferior inf = getTargetInferior(inferior);
		changeElements(List.of(), List.of(inf), "Added");
	}

	@Override
	public void inferiorStarted(GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		inferior.inferiorStarted(inf.getPid()).exceptionally(ex -> {
			impl.reportError(this, "Could not notify inferior started", ex);
			return null;
		});
	}

	@Override
	public void inferiorExited(GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		parent.getListeners().fire.event(parent, null, TargetEventType.PROCESS_EXITED,
			"Inferior " + inf.getId() + " exited code=" + inf.getExitCode(), List.of(inferior));
		inferior.inferiorExited(inf.getExitCode());
	}

	@Override
	public void inferiorRemoved(int inferiorId, GdbCause cause) {
		synchronized (this) {
			impl.deleteModelObject(inferiorId);
		}
		changeElements(List.of(GdbModelTargetInferior.indexInferior(inferiorId)), List.of(),
			"Removed");
	}

	@Override
	public void threadCreated(GdbThread thread, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(thread.getInferior());
		GdbModelTargetThread targetThread = inferior.threads.threadCreated(thread);
		parent.getListeners().fire.event(parent, targetThread, TargetEventType.THREAD_CREATED,
			"Thread " + thread.getId() + " started", List.of(targetThread));
	}

	@Override
	public void threadExited(int threadId, GdbInferior inf, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetThread targetThread =
			inferior.threads.getCachedElements().get(GdbModelTargetThread.indexThread(threadId));
		parent.getListeners().fire.event(parent, targetThread, TargetEventType.THREAD_EXITED,
			"Thread " + threadId + " exited", List.of(targetThread));
		inferior.threads.threadExited(threadId);
	}

	@Override
	public void libraryLoaded(GdbInferior inf, String name, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetModule module = inferior.modules.libraryLoaded(name);
		parent.getListeners().fire.event(parent, null, TargetEventType.MODULE_LOADED,
			"Library " + name + " loaded", List.of(module));
	}

	@Override
	public void libraryUnloaded(GdbInferior inf, String name, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		GdbModelTargetModule module = inferior.modules.getTargetModuleIfPresent(name);
		parent.getListeners().fire.event(parent, null, TargetEventType.MODULE_UNLOADED,
			"Library " + name + " unloaded", List.of(module));
		inferior.modules.libraryUnloaded(name);
	}

	@Override
	public void memoryChanged(GdbInferior inf, long addr, int len, GdbCause cause) {
		GdbModelTargetInferior inferior = getTargetInferior(inf);
		inferior.memory.memoryChanged(addr, len);
	}

	private void updateUsingInferiors(Map<Integer, GdbInferior> byIID) {
		List<GdbModelTargetInferior> inferiors;
		synchronized (this) {
			inferiors =
				byIID.values().stream().map(this::getTargetInferior).collect(Collectors.toList());
		}
		setElements(inferiors, "Refreshed");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (!refresh) {
			updateUsingInferiors(impl.gdb.getKnownInferiors());
			return AsyncUtils.NIL;
		}
		return impl.gdb.listInferiors().thenAccept(this::updateUsingInferiors);
	}

	// NOTE: Does no good to override fetchElement
	// Cache should be kept in sync all the time, anyway

	public synchronized GdbModelTargetInferior getTargetInferior(int id) {
		TargetObject modelObject = impl.getModelObject(id);
		if (modelObject != null) {
			return (GdbModelTargetInferior) modelObject;
		}
		return new GdbModelTargetInferior(this, impl.gdb.getKnownInferiors().get(id));
	}

	public synchronized GdbModelTargetInferior getTargetInferior(GdbInferior inferior) {
		TargetObject modelObject = impl.getModelObject(inferior);
		if (modelObject != null) {
			return (GdbModelTargetInferior) modelObject;
		}
		return new GdbModelTargetInferior(this, inferior);
	}

	protected void invalidateMemoryAndRegisterCaches() {
		for (GdbInferior inf : impl.gdb.getKnownInferiors().values()) {
			GdbModelTargetInferior targetInf = (GdbModelTargetInferior) impl.getModelObject(inf);
			targetInf.invalidateMemoryAndRegisterCaches();
		}
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		return getTargetInferior(sco.getInferior()).stateChanged(sco);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (GdbModelTargetInferior child : this.getCachedElements().values()) {
						child.setBase(value);
					}
				}
				else {
					throw new DebuggerIllegalArgumentException("Base should be numeric");
				}
			default:
		}
		return AsyncUtils.NIL;
	}

}
