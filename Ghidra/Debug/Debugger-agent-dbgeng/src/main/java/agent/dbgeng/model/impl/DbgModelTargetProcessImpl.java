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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.cmd.DbgProcessSelectCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "Process", elements = { //
	@TargetElementType(type = Void.class) //
}, attributes = { //
	@TargetAttributeType(name = "Debug", type = DbgModelTargetDebugContainerImpl.class, required = true, fixed = true), //
	@TargetAttributeType(name = "Memory", type = DbgModelTargetMemoryContainerImpl.class, required = true, fixed = true), //
	@TargetAttributeType(name = "Modules", type = DbgModelTargetModuleContainerImpl.class, required = true, fixed = true), //
	@TargetAttributeType(name = "Threads", type = DbgModelTargetThreadContainerImpl.class, required = true, fixed = true), //
	@TargetAttributeType(type = Void.class) //
})
public class DbgModelTargetProcessImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetProcess {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	protected static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexProcess(DebugProcessId debugProcessId) {
		return PathUtils.makeIndex(debugProcessId.id);
	}

	protected static String indexProcess(DbgProcess process) {
		return indexProcess(process.getId());
	}

	protected static String keyProcess(DbgProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}

	protected final DbgProcess process;

	protected final DbgModelTargetDebugContainer debug;
	protected final DbgModelTargetMemoryContainer memory;
	protected final DbgModelTargetModuleContainer modules;
	protected final DbgModelTargetThreadContainer threads;
	// Note: not sure section info is available from the dbgeng
	//protected final DbgModelTargetProcessSectionContainer sections;

	public DbgModelTargetProcessImpl(DbgModelTargetProcessContainer processes, DbgProcess process) {
		super(processes.getModel(), processes, keyProcess(process), "Process");
		this.process = process;

		this.debug = new DbgModelTargetDebugContainerImpl(this);
		this.memory = new DbgModelTargetMemoryContainerImpl(this);
		this.modules = new DbgModelTargetModuleContainerImpl(this);
		//this.sections = new DbgModelTargetProcessSectionContainerImpl(this);
		this.threads = new DbgModelTargetThreadContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			debug, //
			memory, //
			modules, //
			//sections, //
			threads //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, DbgModelTargetThreadImpl.SUPPORTED_KINDS //
		), "Initialized");
		setExecutionState(TargetExecutionState.ALIVE, "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public String getDisplay() {
		if (getManager().isKernelMode()) {
			return "[kernel]";
		}
		return "[" + process.getId().id + ":0x" + Long.toHexString(process.getPid()) + "]";
	}

	@Override
	public void processSelected(DbgProcess eventProcess, DbgCause cause) {
		if (eventProcess.equals(process)) {
			AtomicReference<DbgModelTargetFocusScope<?>> scope = new AtomicReference<>();
			AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				DebugModelConventions.findSuitable(DbgModelTargetFocusScope.class, this)
						.handle(seq::next);
			}, scope).then(seq -> {
				scope.get().setFocus(this);
			}).finish();
		}
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		TargetExecutionState targetState = convertState(state);
		setExecutionState(targetState, "ThreadStateChanged");
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		return DbgModelImplUtils.launch(getModel(), process, args);
	}

	@Override
	public CompletableFuture<Void> resume() {
		return process.cont();
	}

	@Override
	public CompletableFuture<Void> kill() {
		return process.kill();
	}

	@Override
	public CompletableFuture<Void> attach(TypedTargetObjectRef<? extends TargetAttachable<?>> ref) {
		getModel().assertMine(TargetObjectRef.class, ref);
		// NOTE: Get the object and type check it myself.
		// The typed ref could have been unsafely cast
		List<String> tPath = ref.getPath();
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getModel().fetchModelObject(tPath).handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
			TargetAttachable<?> attachable =
				DebuggerObjectModel.requireIface(TargetAttachable.class, obj, tPath);
			process.reattach(attachable);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			process.attach(pid).handle(seq::nextIgnore);
		}).finish();
	}

	@Override
	public CompletableFuture<Void> detach() {
		return process.detach();
	}

	@Override
	public CompletableFuture<Void> delete() {
		return process.remove();
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		DbgThread thread = getManager().getCurrentThread();
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in dbgeng?
				return thread.console("advance");
			default:
				return thread.step(convertToDbg(kind));
		}
	}

	@Override
	public void processStarted(Long pid) {
		if (pid != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, pid, //
				DISPLAY_ATTRIBUTE_NAME, "[0x" + Long.toHexString(pid) + "]" //
			), "Started");
		}
		setExecutionState(TargetExecutionState.ALIVE, "Started");
	}

	@Override
	public void processExited(Long exitCode) {
		if (exitCode != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				EXIT_CODE_ATTRIBUTE_NAME, exitCode //
			), "Exited");
		}
		setExecutionState(TargetExecutionState.TERMINATED, "Exited");
	}

	@Override
	public void onExit() {
		super.onExit();
		DbgModelTargetProcessContainer processes = (DbgModelTargetProcessContainer) getImplParent();
		processes.processRemoved(process.getId(), DbgCause.Causes.UNCLAIMED);
	}

	@Override
	public CompletableFuture<Void> select() {
		DbgManagerImpl manager = getManager();
		return manager.execute(new DbgProcessSelectCommand(manager, process));
	}

	@Override
	public DbgModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public DbgModelTargetModuleContainer getModules() {
		return modules;
	}

	@Override
	public DbgProcess getProcess() {
		return process;
	}

	@Override
	public TargetAccessibility getAccessibility() {
		return accessibility;
	}

}
