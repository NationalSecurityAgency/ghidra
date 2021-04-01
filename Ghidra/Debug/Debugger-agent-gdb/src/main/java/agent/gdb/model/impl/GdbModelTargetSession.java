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

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import agent.gdb.manager.*;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import agent.gdb.manager.reason.GdbReason;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "Session",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetSession extends DefaultTargetModelRoot
		implements TargetAccessConditioned, TargetAttacher, TargetFocusScope, TargetInterpreter,
		TargetInterruptible, TargetCmdLineLauncher, TargetEventScope, GdbConsoleOutputListener,
		GdbEventsListenerAdapter {
	protected static final String GDB_PROMPT = "(gdb)";

	protected final GdbModelImpl impl;
	protected String display = "GNU gdb (GDB)";

	protected final GdbModelTargetInferiorContainer inferiors;
	protected final GdbModelTargetAvailableContainer available;
	protected final GdbModelTargetBreakpointContainer breakpoints;

	private boolean accessible = true;
	protected AtomicInteger focusFreezeCount = new AtomicInteger();
	protected GdbModelSelectableObject focus;

	protected String debugger = "gdb"; // Used by GdbModelTargetEnvironment

	public GdbModelTargetSession(GdbModelImpl impl, TargetObjectSchema schema) {
		super(impl, "Session", schema);
		this.impl = impl;

		this.inferiors = new GdbModelTargetInferiorContainer(this);
		this.available = new GdbModelTargetAvailableContainer(this);
		this.breakpoints = new GdbModelTargetBreakpointContainer(this);

		changeAttributes(List.of(), Map.of( //
			inferiors.getName(), inferiors, //
			available.getName(), available, //
			breakpoints.getName(), breakpoints, //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			PROMPT_ATTRIBUTE_NAME, GDB_PROMPT, //
			DISPLAY_ATTRIBUTE_NAME, display, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetCmdLineLauncher.PARAMETERS, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, GdbModelTargetInferior.SUPPORTED_KINDS, //
			FOCUS_ATTRIBUTE_NAME, this // Satisfy schema. Will be set to first inferior.
		), "Initialized");
		impl.gdb.addEventsListener(this);
		impl.gdb.addConsoleOutputListener(this);

		getVersion();
	}

	@TargetAttributeType(name = GdbModelTargetInferiorContainer.NAME, required = true, fixed = true)
	public GdbModelTargetInferiorContainer getInferiors() {
		return inferiors;
	}

	@TargetAttributeType(
		name = GdbModelTargetAvailableContainer.NAME,
		required = true,
		fixed = true)
	public GdbModelTargetAvailableContainer getAvailable() {
		return available;
	}

	@TargetAttributeType(
		name = GdbModelTargetBreakpointContainer.NAME,
		required = true,
		fixed = true)
	public GdbModelTargetBreakpointContainer getBreakpoints() {
		return breakpoints;
	}

	protected void getVersion() {
		impl.gdb.waitForPrompt().thenCompose(__ -> {
			return impl.gdb.consoleCapture("show version");
		}).thenAccept(out -> {
			debugger = out;
			changeAttributes(List.of(),
				Map.of(DISPLAY_ATTRIBUTE_NAME, display = out.split("\n")[0].strip() //
			), "Version refreshed");
		}).exceptionally(e -> {
			model.reportError(this, "Could not get GDB version", e);
			debugger = "gdb";
			return null;
		});
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public void output(GdbManager.Channel gdbChannel, String out) {
		TargetConsole.Channel dbgChannel;
		switch (gdbChannel) {
			case STDOUT:
				dbgChannel = TargetConsole.Channel.STDOUT;
				break;
			case STDERR:
				dbgChannel = TargetConsole.Channel.STDERR;
				break;
			default:
				throw new AssertionError();
		}
		listeners.fire.consoleOutput(this, dbgChannel, out);
	}

	@Override
	public void inferiorSelected(GdbInferior inferior, GdbCause cause) {
		if (inferior.getKnownThreads().isEmpty()) {
			GdbModelTargetInferior inf = inferiors.getTargetInferior(inferior);
			setFocus(inf);
		}
		// Otherwise, we'll presumably get the =thread-selected event 
	}

	@Override
	public void threadSelected(GdbThread thread, GdbStackFrame frame, GdbCause cause) {
		GdbModelTargetInferior inf = inferiors.getTargetInferior(thread.getInferior());
		GdbModelTargetThread t = inf.threads.getTargetThread(thread);
		if (frame == null) {
			setFocus(t);
			return;
		}
		GdbModelTargetStackFrame f = t.stack.getTargetFrame(frame);
		setFocus(f);
	}

	public void setAccessible(boolean accessible) {
		changeAttributes(List.of(), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, this.accessible = accessible //
		), "Accessibility changed");
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		return impl.gateFuture(impl.gdb.availableInferior().thenCompose(inf -> {
			return GdbModelImplUtils.launch(impl, inf, args);
		}).thenApply(__ -> null));
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		GdbModelTargetAttachable mine = impl.assertMine(GdbModelTargetAttachable.class, attachable);
		return attach(mine.pid);
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return impl.gateFuture(impl.gdb.availableInferior().thenCompose(inf -> {
			return inf.attach(pid).thenApply(__ -> null);
		}));
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		//return impl.gdb.interrupt();
		try {
			impl.gdb.sendInterruptNow();
		}
		catch (IOException e) {
			Msg.error(this, "Could not interrupt", e);
		}
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> execute(String cmd) {
		return impl.gateFuture(impl.gdb.console(cmd).exceptionally(GdbModelImpl::translateEx));
	}

	@Override
	public CompletableFuture<String> executeCapture(String cmd) {
		return impl
				.gateFuture(impl.gdb.consoleCapture(cmd).exceptionally(GdbModelImpl::translateEx));
	}

	@Override
	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		impl.assertMine(TargetObject.class, obj);
		/**
		 * Yes, this is pointless, since I'm the root, but do it right (TM), since this may change
		 * or be used as an example for other implementations.
		 */
		if (!PathUtils.isAncestor(this.getPath(), obj.getPath())) {
			throw new DebuggerIllegalArgumentException("Can only focus a successor of the scope");
		}
		TargetObject cur = obj;
		while (cur != null) {
			if (cur instanceof GdbModelSelectableObject) {
				GdbModelSelectableObject sel = (GdbModelSelectableObject) cur;
				return sel.select();
			}
			cur = cur.getParent();
		}
		return AsyncUtils.NIL;
	}

	protected void invalidateMemoryAndRegisterCaches() {
		inferiors.invalidateMemoryAndRegisterCaches();
	}

	protected void freezeFocusUpdates() {
		focusFreezeCount.incrementAndGet();
	}

	protected void thawFocusUpdates() {
		focusFreezeCount.decrementAndGet();
	}

	protected void setFocus(GdbModelSelectableObject focus) {
		if (focusFreezeCount.get() == 0) {
			changeAttributes(List.of(), Map.of( //
				FOCUS_ATTRIBUTE_NAME, this.focus = focus //
			), "Focus changed");
		}
	}

	@Override
	public GdbModelSelectableObject getFocus() {
		return focus;
	}

	@Override
	public void inferiorStateChanged(GdbInferior inf, Collection<GdbThread> threads, GdbState state,
			GdbThread thread, GdbCause cause, GdbReason reason) {
		GdbStateChangeRecord sco =
			new GdbStateChangeRecord(inf, threads, state, thread, cause, reason);
		GdbInferior toFocus = thread == null ? impl.gdb.currentInferior() : thread.getInferior();
		freezeFocusUpdates();
		CompletableFuture<Void> infUpdates = CompletableFuture.allOf(
			breakpoints.stateChanged(sco),
			inferiors.stateChanged(sco));
		infUpdates.whenComplete((v, t) -> {
			thawFocusUpdates();
			toFocus.select();
		});
	}
}
