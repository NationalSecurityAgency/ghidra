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

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.sun.jdi.*;
import com.sun.jdi.connect.*;
import com.sun.jdi.connect.Connector.Argument;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.agent.AbstractTargetObject;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.model.iface1.*;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

/**
 * <p>
 * TODO: It would probably be better to implement {@link TargetLauncher} on each connector, rather
 * than using "focus" (a UI concept) to decide which to use. Additionally, for each connector, we
 * can decide whether to implement {@link TargetLauncher} or {@link TargetAttacher} based on whether
 * it's a {@link LaunchingConnector} or an {@link AttachingConnector}. Granted, there are some UI
 * hiccups to work out when/if we take that approach, since
 * {@link DebugModelConventions#findSuitable(Class, TargetObject)} requires a unique answer. That
 * would mean neither attach nor launch will be enabled anywhere except on a connector....
 */
public class JdiModelTargetRoot extends DefaultTargetModelRoot implements // 
		JdiModelTargetAccessConditioned<JdiModelTargetRoot>, //
		//JdiModelTargetAttacher<JdiModelTargetRoot>, //
		JdiModelTargetFocusScope<JdiModelTargetRoot>, //
		//TargetFocusScope<JdiModelTargetRoot>, //
		//JdiModelTargetInterpreter<JdiModelTargetRoot>, //
		JdiModelTargetInterruptible<JdiModelTargetRoot>, //
		JdiModelTargetLauncher<JdiModelTargetRoot>, //
		JdiModelTargetEventScope<JdiModelTargetRoot>, //
		JdiEventsListenerAdapter {
	protected static final String JDB_PROMPT = ">";

	protected final JdiModelImpl impl;
	protected String display = "JDI";

	protected final VirtualMachineManager vmm;
	protected final JdiModelTargetVMContainer vms;
	protected final JdiModelTargetConnectorContainer connectors;
	protected JdiModelTargetAttributesContainer addedAttributes;

	private TargetAccessibility accessibility = TargetAccessibility.ACCESSIBLE;
	protected JdiModelSelectableObject focus;

	protected String debugger = "Jdi"; // Used by JdiModelTargetEnvironment

	public JdiModelTargetRoot(JdiModelImpl impl) {
		super(impl, "VirtualMachineManager");
		this.impl = impl;
		this.vmm = this.impl.getManager().getVirtualMachineManager();

		this.vms = new JdiModelTargetVMContainer(this);
		this.connectors = new JdiModelTargetConnectorContainer(this);

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			vms, //
			connectors, //
			addedAttributes //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessibility == TargetAccessibility.ACCESSIBLE, //
			DISPLAY_ATTRIBUTE_NAME, display, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetCmdLineLauncher.PARAMETERS, //
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
		), "Initialized");

		impl.getManager().addEventsListener(null, this);
		//impl.getManager().addConsoleOutputListener(this);
	}

	@Override
	public JdiModelImpl getModelImpl() {
		return impl;
	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("Major Version", vmm.majorInterfaceVersion());
		attrs.put("Minor Version", vmm.minorInterfaceVersion());
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public String getDisplay() {
		return display;
	}

	/*///
	@Override
	public void output(JdiManager.Channel JdiChannel, String out) {
		TargetInterpreter.Channel dbgChannel;
		switch (JdiChannel) {
			case STDOUT:
				dbgChannel = TargetInterpreter.Channel.STDOUT;
				break;
			case STDERR:
				dbgChannel = TargetInterpreter.Channel.STDERR;
				break;
			default:
				throw new AssertionError();
		}
		listeners.fire(TargetInterpreterListener.class).consoleOutput(this, dbgChannel, out);
	}
	*/

	@Override
	public void vmSelected(VirtualMachine vm, JdiCause cause) {
		if (vm.allThreads().isEmpty()) {
			JdiModelTargetVM targetVM = vms.getTargetVM(vm);
			setFocus(targetVM);
		}
		// Otherwise, we'll presumably get the =thread-selected event 
	}

	@Override
	public void threadSelected(ThreadReference thread, StackFrame frame, JdiCause cause) {
		JdiModelTargetVM vm = vms.getTargetVM(thread.threadGroup().virtualMachine());
		JdiModelTargetThread t = vm.threads.getTargetThread(thread);
		if (frame == null) {
			setFocus(t);
			return;
		}
		JdiModelTargetStackFrame f = t.stack.getTargetFrame(frame);
		setFocus(f);
	}

	public void setAccessibility(TargetAccessibility accessibility) {
		synchronized (attributes) {
			if (this.accessibility == accessibility) {
				return;
			}
			this.accessibility = accessibility;
			changeAttributes(List.of(), List.of(), Map.of( //
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
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		JdiManager manager = impl.getManager();
		JdiModelTargetConnector targetConnector = connectors.getDefaultConnector();
		Connector cx = (targetConnector != null) ? targetConnector.cx
				: manager.getVirtualMachineManager().defaultConnector();
		Map<String, Argument> defaultArguments = cx.defaultArguments();
		Map<String, Argument> jdiArgs = JdiModelTargetLauncher.getArguments(defaultArguments,
			JdiModelTargetLauncher.getParameters(defaultArguments), args);
		return getManager().addVM(cx, jdiArgs).thenApply(__ -> null);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * TODO: Technically, this should be done by setting
	 * {@link TargetMethod#PARAMTERS_ATTRIBUTE_NAME} whenever the default connector changes.
	 * However, that's really only needed if this is to be marshalled over GADP, and that is not the
	 * case. Listening for parameter description changes doesn't seem like a normal thing to do
	 * otherwise.
	 */
	@Override
	public TargetParameterMap getParameters() {
		JdiManager manager = impl.getManager();
		JdiModelTargetConnector targetConnector = connectors.getDefaultConnector();
		Connector cx = (targetConnector != null) ? targetConnector.cx
				: manager.getVirtualMachineManager().defaultConnector();
		Map<String, Argument> defaultArguments = cx.defaultArguments();
		return TargetParameterMap.copyOf(JdiModelTargetLauncher.getParameters(defaultArguments));
	}

	public CompletableFuture<Void> attach(long pid) {
		JdiManager manager = impl.getManager();
		JdiModelTargetConnector targetConnector =
			connectors.getTargetConnectorIfPresent("SocketAttach");
		if (targetConnector == null) {
			Msg.error(this, "No match found in connectors for SocketAttach");
		}
		else {
			Connector cx = targetConnector.cx;
			manager.addVM(cx, List.of(Long.toString(pid)));
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		try {
			impl.getManager().sendInterruptNow();
		}
		catch (IOException e) {
			Msg.error(this, "Could not interrupt", e);
		}
		return AsyncUtils.NIL;
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
				if (cur instanceof JdiModelSelectableObject) {
					JdiModelSelectableObject sel = (JdiModelSelectableObject) cur;
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
		vms.invalidateMemoryAndRegisterCaches();
	}

	@Override
	public boolean setFocus(JdiModelSelectableObject sel) {
		boolean doFire;
		synchronized (this) {
			doFire = !Objects.equals(this.focus, sel);
			this.focus = sel;
		}
		if (doFire) {
			changeAttributes(List.of(), List.of(), Map.of( //
				FOCUS_ATTRIBUTE_NAME, focus //
			), "Focus changed");
			listeners.fire(TargetFocusScopeListener.class).focusChanged(this, sel);
			return true;
		}
		return false;
	}

	@Override
	public JdiModelSelectableObject getFocus() {
		return focus;
	}

	@Override
	public Object getObject() {
		return null;
	}

	@Override
	public JdiModelTargetObject getTargetObject(Object object) {
		return null;
	}

}
