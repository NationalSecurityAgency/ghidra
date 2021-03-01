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

import agent.gdb.manager.*;
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
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	})
public class GdbModelTargetSession extends DefaultTargetModelRoot implements
		TargetAccessConditioned, TargetAttacher, TargetFocusScope, TargetInterpreter,
		TargetInterruptible, TargetCmdLineLauncher, TargetEventScope,
		GdbConsoleOutputListener, GdbEventsListenerAdapter {
	protected static final String GDB_PROMPT = "(gdb)";

	protected final GdbModelImpl impl;
	protected String display = "GNU gdb (GDB)";

	protected final GdbModelTargetInferiorContainer inferiors;
	protected final GdbModelTargetAvailableContainer available;
	protected final GdbModelTargetBreakpointContainer breakpoints;

	private boolean accessible = true;
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
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
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
			Msg.error(this, "Could not get GDB version", e);
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
		listeners.fire(TargetInterpreterListener.class).consoleOutput(this, dbgChannel, out);
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
		synchronized (attributes) {
			if (this.accessible == accessible) {
				return;
			}
			this.accessible = accessible;
			changeAttributes(List.of(), Map.of( //
				ACCESSIBLE_ATTRIBUTE_NAME, accessible //
			), "Accessibility changed");
		}
		listeners.fire(TargetAccessibilityListener.class).accessibilityChanged(this, accessible);
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		// TODO: Find first unused inferior?
		return impl.gdb.addInferior().thenCompose(inf -> {
			return GdbModelImplUtils.launch(impl, inf, args);
		});
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		GdbModelTargetAttachable mine =
			getModel().assertMine(GdbModelTargetAttachable.class, attachable);
		return attach(mine.pid);
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		// TODO: Find first unused inferior?
		return impl.gdb.addInferior().thenCompose(inf -> {
			return inf.attach(pid).thenApply(__ -> null);
		});
	}

	@Override
	public CompletableFuture<Void> interrupt() {
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
		return impl.gdb.console(cmd).exceptionally(GdbModelImpl::translateEx);
	}

	@Override
	public CompletableFuture<String> executeCapture(String cmd) {
		return impl.gdb.consoleCapture(cmd).exceptionally(GdbModelImpl::translateEx);
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

	protected void setFocus(GdbModelSelectableObject sel) {
		boolean doFire;
		synchronized (this) {
			doFire = !Objects.equals(this.focus, sel);
			this.focus = sel;
		}
		if (doFire) {
			changeAttributes(List.of(), Map.of( //
				FOCUS_ATTRIBUTE_NAME, focus //
			), "Focus changed");
			listeners.fire(TargetFocusScopeListener.class).focusChanged(this, sel);
		}
	}

	@Override
	public GdbModelSelectableObject getFocus() {
		return focus;
	}
}
