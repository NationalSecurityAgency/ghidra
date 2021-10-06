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

import agent.gdb.manager.*;
import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.manager.reason.*;
import ghidra.async.AsyncFence;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;

@TargetObjectSchemaInfo(
	name = "Inferior",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetInferior
		extends DefaultTargetObject<TargetObject, GdbModelTargetInferiorContainer>
		implements TargetProcess, TargetAggregate, TargetExecutionStateful, TargetAttacher,
		TargetDeletable, TargetDetachable, TargetKillable, TargetLauncher, TargetResumable,
		TargetSteppable, GdbModelSelectableObject {

	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	public static final ParameterDescription<Boolean> PARAMETER_STARTI =
		ParameterDescription.create(Boolean.class, "starti", false, false,
			"Break on first instruction (use starti)",
			"true to use starti, false to use start. Requires GDB 8.1 or later.");

	public static final TargetParameterMap PARAMETERS =
		TargetMethod.makeParameters(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS, PARAMETER_STARTI);

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
	protected TargetExecutionState state;
	/**
	 * When state=INACTIVE/TERMINATED, and we're waiting on a refresh, this keep the "real" state,
	 * which is the last state actually reported by *running or *stopped.
	 */
	protected TargetExecutionState realState;

	protected final GdbModelTargetEnvironment environment;
	protected final GdbModelTargetProcessMemory memory;
	protected final GdbModelTargetModuleContainer modules;
	//protected final GdbModelTargetRegisterContainer registers;
	protected final GdbModelTargetThreadContainer threads;
	protected final GdbModelTargetBreakpointLocationContainer breakpoints;

	protected Long exitCode;
	private Integer base = 10;

	public GdbModelTargetInferior(GdbModelTargetInferiorContainer inferiors, GdbInferior inferior) {
		super(inferiors.impl, inferiors, keyInferior(inferior), "Inferior");
		this.impl = inferiors.impl;
		this.inferior = inferior;
		impl.addModelObject(inferior, this);
		impl.addModelObject(inferior.getId(), this);

		this.environment = new GdbModelTargetEnvironment(this);
		this.memory = new GdbModelTargetProcessMemory(this);
		this.modules = new GdbModelTargetModuleContainer(this);
		//this.registers = new GdbModelTargetRegisterContainer(this);
		this.threads = new GdbModelTargetThreadContainer(this);
		this.breakpoints = new GdbModelTargetBreakpointLocationContainer(this);

		this.realState =
			inferior.getPid() == null ? TargetExecutionState.INACTIVE : TargetExecutionState.ALIVE;

		changeAttributes(List.of(), //
			List.of( //
				environment, //
				memory, //
				modules, //
				//registers, //
				threads, //
				breakpoints), //
			Map.of( //
				STATE_ATTRIBUTE_NAME, state = realState, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay(), //
				TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
				SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
				SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, GdbModelTargetThread.SUPPORTED_KINDS), //
			"Initialized");
	}

	protected TargetParameterMap computeParams() {
		return TargetMethod.makeParameters(
			TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS,
			PARAMETER_STARTI);
	}

	@Override
	public TargetParameterMap getParameters() {
		return PARAMETERS;
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

	/*
	@TargetAttributeType(name = GdbModelTargetRegisterContainer.NAME, required = true, fixed = true)
	public GdbModelTargetRegisterContainer getRegisters() {
		return registers;
	}
	*/

	@TargetAttributeType(name = GdbModelTargetThreadContainer.NAME, required = true, fixed = true)
	public GdbModelTargetThreadContainer getThreads() {
		return threads;
	}

	@TargetAttributeType(
		name = GdbModelTargetBreakpointLocationContainer.NAME,
		required = true,
		fixed = true)
	public GdbModelTargetBreakpointLocationContainer getBreakpoints() {
		return breakpoints;
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		List<String> cmdLineArgs =
			CmdLineParser.tokenize(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS.get(args));
		Boolean useStarti = PARAMETER_STARTI.get(args);
		return impl.gateFuture(
			GdbModelImplUtils.launch(inferior, cmdLineArgs, useStarti, () -> {
				return environment.refreshInternal();
			}).thenApply(__ -> null));
	}

	@Override
	public CompletableFuture<Void> resume() {
		return impl.gateFuture(inferior.cont());
	}

	protected StepCmd convertToGdb(TargetStepKind kind) {
		switch (kind) {
			case FINISH:
				return StepCmd.FINISH;
			case INTO:
				return StepCmd.STEPI;
			case LINE:
				return StepCmd.STEP;
			case OVER:
				return StepCmd.NEXTI;
			case OVER_LINE:
				return StepCmd.NEXT;
			case RETURN:
				return StepCmd.RETURN;
			case UNTIL:
				return StepCmd.UNTIL;
			case EXTENDED:
				return StepCmd.EXTENDED;
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
				return model.gateFuture(inferior.console("advance", CompletesWithRunning.MUST));
			default:
				return model.gateFuture(inferior.step(convertToGdb(kind)));
		}
	}

	@Override
	public CompletableFuture<Void> kill() {
		return model.gateFuture(inferior.kill());
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		GdbModelTargetAttachable mine = impl.assertMine(GdbModelTargetAttachable.class, attachable);
		return attach(mine.pid);
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return model.gateFuture(inferior.attach(pid)).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> detach() {
		return model.gateFuture(inferior.detach());
	}

	@Override
	public CompletableFuture<Void> delete() {
		return model.gateFuture(inferior.remove());
	}

	protected CompletableFuture<Void> inferiorStarted(Long pid) {
		parent.getListeners().fire.event(parent, null, TargetEventType.PROCESS_CREATED,
			"Inferior " + inferior.getId() + " started " + inferior.getExecutable() + " pid=" + pid,
			List.of(this));
		/*System.err.println("inferiorStarted: realState = " + realState);
		changeAttributes(List.of(), Map.ofEntries(
			// This is hacky, but =inferior-started comes before ^running.
			// Is it ever not followed by ^running, except on failure?
			Map.entry(STATE_ATTRIBUTE_NAME, state = TargetExecutionState.RUNNING),
			Map.entry(PID_ATTRIBUTE_NAME, pid),
			Map.entry(DISPLAY_ATTRIBUTE_NAME, updateDisplay())),
			"Refresh on started");*/
		AsyncFence fence = new AsyncFence();
		fence.include(memory.refreshInternal()); // In case of resync
		fence.include(modules.refreshInternal());
		fence.include(threads.refreshInternal()); // In case of resync
		fence.include(environment.refreshInternal());
		fence.include(impl.gdb.listInferiors()); // HACK to update inferior.getExecutable()
		return fence.ready().thenAccept(__ -> {
			// NB. Hack also updates inferior.getPid()
			Long p = pid;
			if (p == null) {
				// Might have become null if it quickly terminates
				// Also, we should save it before waiting on the refresh
				p = inferior.getPid();
			}
			if (p == null) {
				changeAttributes(List.of(), Map.ofEntries(
					Map.entry(STATE_ATTRIBUTE_NAME, state = realState),
					Map.entry(DISPLAY_ATTRIBUTE_NAME, updateDisplay())),
					"Refresh on initial break");
			}
			else {
				if (!realState.isAlive()) {
					realState = TargetExecutionState.ALIVE;
				}
				changeAttributes(List.of(), Map.ofEntries(
					Map.entry(STATE_ATTRIBUTE_NAME, state = realState),
					Map.entry(PID_ATTRIBUTE_NAME, p),
					Map.entry(DISPLAY_ATTRIBUTE_NAME, updateDisplay())),
					"Refresh on initial break");
			}
		});
	}

	protected void inferiorExited(Long exitCode) {
		this.exitCode = exitCode;
		if (exitCode != null) {
			changeAttributes(List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, state = realState = TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, exitCode, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
			), "Exited");
		}
		else {
			changeAttributes(List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, state = realState = TargetExecutionState.TERMINATED, //
				DISPLAY_ATTRIBUTE_NAME, updateDisplay() //
			), "Exited");
		}
	}

	protected void gatherThreads(List<? super GdbModelTargetThread> into,
			Collection<? extends GdbThread> from) {
		for (GdbThread t : from) {
			GdbModelTargetThread p = threads.getTargetThread(t);
			if (p != null) {
				into.add(p);
			}
		}
	}

	protected void emitEvent(GdbStateChangeRecord sco, GdbModelTargetThread targetEventThread) {
		GdbReason reason = sco.getReason();
		if (reason instanceof GdbBreakpointHitReason) {
			GdbBreakpointHitReason bpHit = (GdbBreakpointHitReason) reason;
			List<Object> params = new ArrayList<>();
			GdbModelTargetBreakpointLocation loc = threads.breakpointHit(bpHit);
			if (loc != null) {
				// e.g. target could execute INT3, causing "trapped" for unknown bp/loc
				params.add(loc);
			}
			gatherThreads(params, sco.getAffectedThreads());
			impl.session.getListeners().fire.event(impl.session, targetEventThread,
				TargetEventType.BREAKPOINT_HIT, bpHit.desc(), params);
		}
		else if (reason instanceof GdbEndSteppingRangeReason) {
			List<Object> params = new ArrayList<>();
			gatherThreads(params, sco.getAffectedThreads());
			impl.session.getListeners().fire.event(impl.session, targetEventThread,
				TargetEventType.STEP_COMPLETED, reason.desc(), params);
		}
		else if (reason instanceof GdbSignalReceivedReason) {
			GdbSignalReceivedReason signal = (GdbSignalReceivedReason) reason;
			List<Object> params = new ArrayList<>();
			params.add(signal.getSignalName());
			gatherThreads(params, sco.getAffectedThreads());
			impl.session.getListeners().fire.event(impl.session, targetEventThread,
				TargetEventType.SIGNAL, reason.desc(), params);
		}
		else {
			List<Object> params = new ArrayList<>();
			gatherThreads(params, sco.getAffectedThreads());
			impl.session.getListeners().fire.event(impl.session, targetEventThread,
				TargetEventType.STOPPED, reason.desc(), params);
		}
	}

	protected void inferiorRunning(GdbReason reason) {
		realState = TargetExecutionState.RUNNING;
		if (!state.isAlive()) {
			return;
		}
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, state = realState //
		), reason.desc());
	}

	protected void inferiorStopped(GdbReason reason) {
		realState = TargetExecutionState.STOPPED;
		if (!state.isAlive()) {
			return;
		}
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, state = realState //
		), reason.desc());
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
		String descriptor = inferior.getDescriptor();
		String[] split = descriptor.split(" ");
		if (base == 16) {
			descriptor = split[0] + " 0x" + Long.toHexString(Long.decode(split[1]));
		}
		return display =
			String.format("%d - %s - %s", inferior.getId(), descriptor, inferior.getExecutable());
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public TargetExecutionState getExecutionState() {
		return state;
	}

	protected void invalidateMemoryAndRegisterCaches() {
		memory.invalidateMemoryCaches();
		threads.invalidateRegisterCaches();
	}

	@Override
	@Internal
	public CompletableFuture<Void> setActive() {
		return impl.gateFuture(inferior.setActive(false));
	}

	@TargetAttributeType(name = EXIT_CODE_ATTRIBUTE_NAME)
	public Long getExitCode() {
		return exitCode;
	}

	/**
	 * Handle state changes for this inferior
	 * 
	 * <p>
	 * Desired order of updates:
	 * <ol>
	 * <li>TargetEvent emitted</li>
	 * <li>Thread states/stacks updated</li>
	 * <li>Memory regions updated (Ew)</li>
	 * </ol>
	 * 
	 * <p>
	 * Note that the event thread may not belong to this inferior. When it does not, this inferior
	 * will not emit any event(). Presumably, this same method will be called on the relevant
	 * inferior, which will report the event. However, this inferior must still update its state.
	 * Without this screening:
	 * <ol>
	 * <li>The thread gets replicated into a different inferior</li>
	 * <li>The event() gets replicated on a different inferior<br>
	 * (We only need to report state changes, not event, for non-event inferiors</li>
	 * </ol>
	 * 
	 * @param sco the record of the change
	 */
	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {

		GdbModelTargetThread targetEventThread = null;
		GdbThread gdbEventThread = sco.getEventThread();
		if (gdbEventThread != null && gdbEventThread.getInferior() == inferior) {
			targetEventThread = threads.getTargetThread(gdbEventThread);
		}
		if (sco.getState() == GdbState.RUNNING) {
			inferiorRunning(sco.getReason());
			List<Object> params = new ArrayList<>();
			gatherThreads(params, sco.getAffectedThreads());
			if (targetEventThread == null && !params.isEmpty()) {
				targetEventThread =
					threads.getTargetThread(sco.getAffectedThreads().iterator().next());
			}
			if (targetEventThread != null) {
				impl.session.getListeners().fire.event(impl.session, targetEventThread,
					TargetEventType.RUNNING, "Running", params);
				invalidateMemoryAndRegisterCaches();
			}
		}
		if (sco.getState() != GdbState.STOPPED) {
			return threads.stateChanged(sco);
		}

		if (targetEventThread != null) {
			emitEvent(sco, targetEventThread);
		}

		AsyncFence fence = new AsyncFence();
		// TODO: How does GDB for Windows handle WoW64?
		// Can there be architecture changes during execution? Per thread?
		//fence.include(environment.refreshArchitecture());
		fence.include(threads.stateChanged(sco));
		inferiorStopped(sco.getReason());
		//registers.stateChanged(sco);
		fence.include(memory.stateChanged(sco));
		return fence.ready();
	}

	public void addBreakpointLocation(GdbModelTargetBreakpointLocation loc) {
		breakpoints.addBreakpointLocation(loc);
	}

	public void removeBreakpointLocation(GdbModelTargetBreakpointLocation loc) {
		breakpoints.removeBreakpointLocation(loc);
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		updateDisplayAttribute();
	}

}
