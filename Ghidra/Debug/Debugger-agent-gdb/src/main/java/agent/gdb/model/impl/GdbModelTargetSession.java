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
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.agent.AbstractTargetObject;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

public class GdbModelTargetSession extends DefaultTargetModelRoot implements // 
		TargetAccessConditioned<GdbModelTargetSession>,
		TargetAttacher<GdbModelTargetSession>,
		TargetFocusScope<GdbModelTargetSession>,
		TargetInterpreter<GdbModelTargetSession>,
		TargetInterruptible<GdbModelTargetSession>,
		TargetCmdLineLauncher<GdbModelTargetSession>,
		TargetEventScope<GdbModelTargetSession>,
		GdbConsoleOutputListener,
		GdbEventsListenerAdapter {
	protected static final String GDB_PROMPT = "(gdb)";

	protected final GdbModelImpl impl;
	protected String display = "GNU gdb (GDB)";

	protected final GdbModelTargetInferiorContainer inferiors;
	protected final GdbModelTargetAvailableContainer available;
	protected final GdbModelTargetBreakpointContainer breakpoints;

	private TargetAccessibility accessibility = TargetAccessibility.ACCESSIBLE;
	protected GdbModelSelectableObject focus;

	protected String debugger = "gdb"; // Used by GdbModelTargetEnvironment

	public GdbModelTargetSession(GdbModelImpl impl) {
		super(impl, "Session");
		this.impl = impl;

		this.inferiors = new GdbModelTargetInferiorContainer(this);
		this.available = new GdbModelTargetAvailableContainer(this);
		this.breakpoints = new GdbModelTargetBreakpointContainer(this);

		changeAttributes(List.of(), Map.of( //
			inferiors.getName(), inferiors, //
			available.getName(), available, //
			breakpoints.getName(), breakpoints, //
			ACCESSIBLE_ATTRIBUTE_NAME, accessibility == TargetAccessibility.ACCESSIBLE, //
			PROMPT_ATTRIBUTE_NAME, GDB_PROMPT, //
			DISPLAY_ATTRIBUTE_NAME, display, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetCmdLineLauncher.PARAMETERS, //
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
		), "Initialized");
		impl.gdb.addEventsListener(this);
		impl.gdb.addConsoleOutputListener(this);

		getVersion();
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

	public void setAccessibility(TargetAccessibility accessibility) {
		synchronized (attributes) {
			if (this.accessibility == accessibility) {
				return;
			}
			this.accessibility = accessibility;
			changeAttributes(List.of(), Map.of( //
				ACCESSIBLE_ATTRIBUTE_NAME, accessibility == TargetAccessibility.ACCESSIBLE //
			), "Accessibility changed");
		}
		listeners.fire(TargetAccessibilityListener.class).accessibilityChanged(this, accessibility);
	}

	@Override
	public TargetAccessibility getAccessibility() {
		return accessibility;
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		// TODO: Find first unused inferior?
		return impl.gdb.addInferior().thenCompose(inf -> {
			return GdbModelImplUtils.launch(impl, inf, args);
		});
	}

	@Override
	public CompletableFuture<Void> attach(TypedTargetObjectRef<? extends TargetAttachable<?>> ref) {
		getModel().assertMine(TargetObjectRef.class, ref);
		List<String> tPath = ref.getPath();
		return impl.fetchModelObject(tPath).thenCompose(obj -> {
			GdbModelTargetAttachable attachable = (GdbModelTargetAttachable) DebuggerObjectModel
					.requireIface(TargetAttachable.class, obj, tPath);
			// TODO: Find first unused inferior?
			return impl.gdb.addInferior().thenCompose(inf -> {
				return inf.attach(attachable.pid).thenApply(__ -> null);
			});
		});
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
	public CompletableFuture<Void> requestFocus(TargetObjectRef ref) {
		impl.assertMine(TargetObjectRef.class, ref);
		/**
		 * Yes, this is pointless, since I'm the root, but do it right (TM), since this may change
		 * or be used as an example for other implementations.
		 */
		if (!PathUtils.isAncestor(this.getPath(), ref.getPath())) {
			throw new DebuggerIllegalArgumentException("Can only focus a successor of the scope");
		}
		return ref.fetch().thenCompose(obj -> {
			TargetObject cur = obj;
			while (cur != null) {
				if (cur instanceof GdbModelSelectableObject) {
					GdbModelSelectableObject sel = (GdbModelSelectableObject) cur;
					return sel.select();
				}
				if (cur instanceof AbstractTargetObject) {
					AbstractTargetObject<?> def = (AbstractTargetObject<?>) cur;
					cur = def.getImplParent();
					continue;
				}
				throw new AssertionError();
			}
			return AsyncUtils.NIL;
		});
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
