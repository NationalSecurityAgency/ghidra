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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.GdbManager.ExecSuffix;
import ghidra.async.AsyncFence;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.error.DebuggerModelNoSuchPathException;
import ghidra.dbg.error.DebuggerModelTypeException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "Inferior",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetInferior
		extends DefaultTargetObject<TargetObject, GdbModelTargetInferiorContainer> implements //
		TargetProcess<GdbModelTargetInferior>,  //
		TargetAggregate, //
		TargetExecutionStateful<GdbModelTargetInferior>, //
		TargetAttacher<GdbModelTargetInferior>, //
		TargetDeletable<GdbModelTargetInferior>, //
		TargetDetachable<GdbModelTargetInferior>, //
		TargetKillable<GdbModelTargetInferior>, //
		TargetCmdLineLauncher<GdbModelTargetInferior>, //
		TargetResumable<GdbModelTargetInferior>, //
		TargetSteppable<GdbModelTargetInferior>, //
		GdbModelSelectableObject {

	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	protected static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexInferior(int inferiorId) {
		return PathUtils.makeIndex(inferiorId);
	}

	protected static String indexInferior(GdbInferior inferior) {
		return indexInferior(inferior.getId());
	}

	protected static String keyInferior(GdbInferior inferior) {
		return PathUtils.makeKey(indexInferior(inferior));
	}

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;
	protected String display;

	protected final GdbModelTargetEnvironment environment;
	protected final GdbModelTargetProcessMemory memory;
	protected final GdbModelTargetModuleContainer modules;
	protected final GdbModelTargetRegisterContainer registers;
	protected final GdbModelTargetThreadContainer threads;

	protected Long exitCode;

	public GdbModelTargetInferior(GdbModelTargetInferiorContainer inferiors, GdbInferior inferior) {
		super(inferiors.impl, inferiors, keyInferior(inferior), "Inferior");
		this.impl = inferiors.impl;
		this.inferior = inferior;

		this.environment = new GdbModelTargetEnvironment(this);
		this.memory = new GdbModelTargetProcessMemory(this);
		this.modules = new GdbModelTargetModuleContainer(this);
		this.registers = new GdbModelTargetRegisterContainer(this);
		this.threads = new GdbModelTargetThreadContainer(this);

		changeAttributes(List.of(), //
			List.of( //
				environment, //
				memory, //
				modules, //
				registers, //
				threads), //
			Map.of(STATE_ATTRIBUTE_NAME, TargetExecutionState.INACTIVE, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay(), //
				TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetCmdLineLauncher.PARAMETERS, //
				UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED, //
				SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
				SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, GdbModelTargetThread.SUPPORTED_KINDS), //
			"Initialized");
	}

	@TargetAttributeType(name = GdbModelTargetEnvironment.NAME, required = true, fixed = true)
	public GdbModelTargetEnvironment getEnvironment() {
		return environment;
	}

	@TargetAttributeType(name = GdbModelTargetProcessMemory.NAME, required = true, fixed = true)
	public GdbModelTargetProcessMemory getMemory() {
		return memory;
	}

	@TargetAttributeType(name = GdbModelTargetModuleContainer.NAME, required = true, fixed = true)
	public GdbModelTargetModuleContainer getModules() {
		return modules;
	}

	@TargetAttributeType(name = GdbModelTargetRegisterContainer.NAME, required = true, fixed = true)
	public GdbModelTargetRegisterContainer getRegisters() {
		return registers;
	}

	@TargetAttributeType(name = GdbModelTargetThreadContainer.NAME, required = true, fixed = true)
	public GdbModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		return GdbModelImplUtils.launch(impl, inferior, args);
	}

	@Override
	public CompletableFuture<Void> resume() {
		return inferior.cont();
	}

	protected ExecSuffix convertToGdb(TargetStepKind kind) {
		switch (kind) {
			case FINISH:
				return ExecSuffix.FINISH;
			case INTO:
				return ExecSuffix.STEP_INSTRUCTION;
			case LINE:
				return ExecSuffix.STEP;
			case OVER:
				return ExecSuffix.NEXT_INSTRUCTION;
			case OVER_LINE:
				return ExecSuffix.NEXT;
			case RETURN:
				return ExecSuffix.RETURN;
			case UNTIL:
				return ExecSuffix.UNTIL;
			case EXTENDED:
				return ExecSuffix.EXTENDED;
			default:
				throw new AssertionError();
		}
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in GDB/MI?
				// TODO: This doesn't work, since advance requires a parameter
				return inferior.console("advance");
			default:
				return inferior.step(convertToGdb(kind));
		}
	}

	@Override
	public CompletableFuture<Void> kill() {
		return inferior.kill();
	}

	@Override
	public CompletableFuture<Void> attach(TypedTargetObjectRef<? extends TargetAttachable<?>> ref) {
		impl.assertMine(TargetObjectRef.class, ref);
		// NOTE: These can change at any time. Just use the path to derive the target PID
		if (!Objects.equals(PathUtils.parent(ref.getPath()), impl.session.available.getPath())) {
			throw new DebuggerModelTypeException(
				"Target of attach must be a child of " + impl.session.available.getPath());
		}
		long pid;
		try {
			pid = Long.parseLong(ref.getIndex());
		}
		catch (IllegalArgumentException e) {
			throw new DebuggerModelNoSuchPathException("Badly-formatted PID", e);
		}
		return attach(pid);
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return inferior.attach(pid).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> detach() {
		return inferior.detach();
	}

	@Override
	public CompletableFuture<Void> delete() {
		return inferior.remove();
	}

	protected CompletableFuture<Void> inferiorStarted(Long pid) {
		AsyncFence fence = new AsyncFence();
		fence.include(modules.refresh());
		fence.include(registers.refresh());
		fence.include(environment.refresh());
		return fence.ready().thenAccept(__ -> {
			if (pid != null) {
				changeAttributes(List.of(), Map.of( //
					STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
					PID_ATTRIBUTE_NAME, pid, //
					DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
				), "Started");
			}
			else {
				changeAttributes(List.of(), Map.of( //
					STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
					DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
				), "Started");
			}
			listeners.fire(TargetExecutionStateListener.class)
					.executionStateChanged(this, TargetExecutionState.ALIVE);
		});
	}

	protected void inferiorExited(Long exitCode) {
		this.exitCode = exitCode;
		if (exitCode != null) {
			changeAttributes(List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, exitCode, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
			), "Exited");
		}
		else {
			changeAttributes(List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
			), "Exited");
		}
		listeners.fire(TargetExecutionStateListener.class)
				.executionStateChanged(this, TargetExecutionState.TERMINATED);
	}

	protected void updateDisplayAttribute() {
		changeAttributes(List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
		), "Display changed");
	}

	protected String updateDisplay() {
		if (inferior.getPid() == null) {
			return display = String.format("%d - <null>", inferior.getId());
		}
		return display = String.format("%d - %s - %s", inferior.getId(), inferior.getDescriptor(),
			inferior.getExecutable());
	}

	@Override
	public String getDisplay() {
		return display;
	}

	protected void invalidateMemoryAndRegisterCaches() {
		memory.invalidateMemoryCaches();
		threads.invalidateRegisterCaches();
	}

	protected void updateMemory() {
		// This is a little ew. Wish I didn't have to list regions every STOP
		memory.update().exceptionally(ex -> {
			Msg.error(this, "Could not update process memory mappings", ex);
			return null;
		});
	}

	@Override
	@Internal
	public CompletableFuture<Void> select() {
		return inferior.select();
	}

	@TargetAttributeType(name = EXIT_CODE_ATTRIBUTE_NAME)
	public Long getExitCode() {
		return exitCode;
	}
}
