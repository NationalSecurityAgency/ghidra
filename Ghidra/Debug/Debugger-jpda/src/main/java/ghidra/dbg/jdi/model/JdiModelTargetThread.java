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

import com.sun.jdi.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.EventRequestManager;
import com.sun.jdi.request.StepRequest;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.model.iface1.*;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.schema.*;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(name = "Thread", elements = { //
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Attributes", type = JdiModelTargetAttributesContainer.class),
		@TargetAttributeType(name = "Registers", type = JdiModelTargetRegisterContainer.class, required = true, fixed = true),
		@TargetAttributeType(name = "Stack", type = JdiModelTargetStack.class, required = true, fixed = true),
		@TargetAttributeType(name = "Status", type = Integer.class),
		@TargetAttributeType(name = "UID", type = Long.class, fixed = true),
		@TargetAttributeType(type = Object.class) //
}, canonicalContainer = true)
public class JdiModelTargetThread extends JdiModelTargetObjectReference implements //
		TargetThread, //
		JdiModelTargetAccessConditioned, //
		JdiModelTargetExecutionStateful, //
		JdiModelTargetInterruptible, //
		JdiModelTargetKillable, //
		JdiModelTargetResumable, //
		JdiModelTargetSteppable, //
		// TargetSuspendable,
		JdiEventsListenerAdapter, //
		JdiModelSelectableObject {

	protected static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, //
		TargetStepKind.FINISH, //
		TargetStepKind.LINE, //
		TargetStepKind.OVER, //
		TargetStepKind.OVER_LINE, //
		TargetStepKind.RETURN, //
		TargetStepKind.UNTIL, //
		TargetStepKind.EXTENDED);

	private EventRequestManager eventManager;
	protected final ThreadReference thread;

	protected final JdiModelTargetStack stack;
	protected final JdiModelTargetRegisterContainer registers;
	protected JdiModelTargetLocation location;

	protected JdiModelTargetThreadGroupContainer threadGroup;
	protected JdiModelTargetObjectReference currentContendedMonitor;
	protected JdiModelTargetObjectReferenceContainer ownedMonitors;
	protected JdiModelTargetAttributesContainer addedAttributes;

	public JdiModelTargetThread(JdiModelTargetObject parent, ThreadReference thread,
			boolean isElement) {
		super(parent, thread.name(), thread, isElement);
		this.thread = thread;
		this.eventManager = thread.virtualMachine().eventRequestManager();

		this.stack = new JdiModelTargetStack(this);
		this.registers = new JdiModelTargetRegisterContainer(this);

		impl.getManager().addEventsListener(targetVM.vm, this);

		TargetExecutionState targetState = convertState(thread.status());
		changeAttributes(List.of(), List.of( //
			registers, //
			stack //
		), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState, //
			"Status", thread.status(), //
			ACCESSIBLE_ATTRIBUTE_NAME, thread.isSuspended(), //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			DISPLAY_ATTRIBUTE_NAME, display = getDisplay() //
		), "Initialized");

		getManager().addStateListener(thread.virtualMachine(), accessListener);
	}

	private void populateAttributes() {
		this.addedAttributes = new JdiModelTargetAttributesContainer(this, "Attributes");
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("isAtBreakpoint", thread.isAtBreakpoint());
		attrs.put("isCollected", thread.isCollected());
		attrs.put("isSuspended", thread.isSuspended());
		try {
			attrs.put("entryCount", thread.entryCount());
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		try {
			attrs.put("frameCount", thread.frameCount());
		}
		catch (IncompatibleThreadStateException e) {
			// Ignore
		}
		attrs.put("suspendCount", thread.suspendCount());
		addedAttributes.addAttributes(attrs);
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {

		populateAttributes();

		changeAttributes(List.of(), List.of( //
			addedAttributes //
		), Map.of(), "Initialized");

		if (targetVM.vm.canGetCurrentContendedMonitor()) {
			try {
				ObjectReference monitor = thread.currentContendedMonitor();
				if (monitor != null) {
					currentContendedMonitor = (JdiModelTargetObjectReference) getInstance(monitor);
					if (currentContendedMonitor != null) {
						changeAttributes(List.of(), List.of(), Map.of( //
							"Current Contended Monitor", currentContendedMonitor //
						), "Initialized");
					}
				}
			}
			catch (IncompatibleThreadStateException e2) {
				// Ignore
			}
		}
		if (targetVM.vm.canGetOwnedMonitorInfo()) {
			try {
				this.ownedMonitors = new JdiModelTargetObjectReferenceContainer(this,
					"Owned Monitors", thread.ownedMonitors());
				if (ownedMonitors != null) {
					changeAttributes(List.of(), List.of( //
						ownedMonitors //
					), Map.of(), "Initialized");
				}
			}
			catch (IncompatibleThreadStateException e1) {
				// Ignore
			}
		}
		ThreadGroupReference tg = thread.threadGroup();
		this.threadGroup =
			tg == null ? null : new JdiModelTargetThreadGroupContainer(this, tg, false);
		if (threadGroup != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				"Thread Group", thread.threadGroup() //
			), "Initialized");
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> init() {
		AsyncFence fence = new AsyncFence();
		//fence.include(requestAttributes(true));
		return fence.ready();
	}

	@Override
	public String getDisplay() {
		if (thread == null) {
			return super.getDisplay();
		}
		StringBuilder sb = new StringBuilder();
		sb.append(thread.name());
		if (location != null) {
			sb.append(" in ");
			sb.append(location);
		}
		JdiModelTargetStackFrame top = stack.framesByLevel.get(0);
		if (top != null && top.location != null) {
			sb.append(" in ");
			sb.append(top.location.getDisplay());
		}
		return sb.toString();
	}

	protected TargetExecutionState convertState(int state) {
		switch (state) {
			case ThreadReference.THREAD_STATUS_RUNNING:
			case ThreadReference.THREAD_STATUS_WAIT:
				return thread.isSuspended() ? TargetExecutionState.STOPPED
						: TargetExecutionState.RUNNING;
			case ThreadReference.THREAD_STATUS_NOT_STARTED:
				return TargetExecutionState.ALIVE;
			default:
				return TargetExecutionState.STOPPED;
		}
	}

	@Override
	public void stepComplete(StepEvent evt, JdiCause cause) {
		if (evt.thread().equals(thread)) {
			setLocation(evt.location());
			changeAttributes(List.of(), List.of(), Map.of( //
				LOCATION_ATTRIBUTE_NAME, location //
			), "Refreshed");
			stateChanged(thread.status(), JdiReason.Reasons.STEP);
		}
	}

	@Override
	public void breakpointHit(BreakpointEvent evt, JdiCause cause) {
		if (evt.thread().equals(thread)) {
			setLocation(evt.location());
			changeAttributes(List.of(), List.of(), Map.of( //
				LOCATION_ATTRIBUTE_NAME, location //
			), "Refreshed");
			stateChanged(thread.status(), JdiReason.Reasons.BREAKPOINT_HIT);
		}
	}

	// Which of these is actually going to fire, i.e. are separate events generated for subclasses?

	@Override
	public void watchpointHit(WatchpointEvent evt, JdiCause cause) {
		if (evt.thread().equals(thread)) {
			setLocation(evt.location());
			changeAttributes(List.of(), List.of(), Map.of( //
				LOCATION_ATTRIBUTE_NAME, location //
			), "Refreshed");
			stateChanged(thread.status(), JdiReason.Reasons.WATCHPOINT_HIT);
		}
	}

	@Override
	public void accessWatchpointHit(AccessWatchpointEvent evt, JdiCause cause) {
		if (evt.thread().equals(thread)) {
			setLocation(evt.location());
			changeAttributes(List.of(), List.of(), Map.of( //
				LOCATION_ATTRIBUTE_NAME, location //
			), "Refreshed");
			stateChanged(thread.status(), JdiReason.Reasons.ACCESS_WATCHPOINT_HIT);
		}
	}

	@Override
	public void threadSelected(ThreadReference eventThread, StackFrame frame, JdiCause cause) {
		if (eventThread.equals(thread) && frame == null) {
			((JdiModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	private void stateChanged(int state, JdiReason reason) {
		TargetExecutionState targetState = convertState(state);
		if (targetState.equals(TargetExecutionState.STOPPED)) {
			update();
			threadSelected(thread, null, JdiCause.Causes.UNCLAIMED);
		}
		targetVM.vmStateChanged(targetState, reason);
		JdiEventHandler eventHandler = getManager().getEventHandler(targetVM.vm);
		eventHandler.listenersEvent.fire.threadStateChanged(thread, state,
			JdiCause.Causes.UNCLAIMED, reason);
	}

	public void threadStateChanged(TargetExecutionState targetState) {
		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState //
		), "Refreshed");
	}

	protected CompletableFuture<?> update() {
		//Msg.debug(this, "Updating stack for " + this);
		registers.update();
		return stack.update().thenAccept(__ -> {
			changeAttributes(List.of(), List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, getDisplay() //
			), "Refreshed");
		}).exceptionally(ex -> {
			Msg.error(this, "Could not update stack for thread " + this, ex);
			return null;
		});
	}

	@Override
	@Internal
	public CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> kill() {
		thread.interrupt();
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		thread.suspend();
		stateChanged(thread.status(), JdiReason.Reasons.INTERRUPT);
		return CompletableFuture.completedFuture(null);
	}

	//@Override
	public CompletableFuture<Void> popFrame(StackFrame frame) {
		try {
			thread.popFrames(frame);
		}
		catch (IncompatibleThreadStateException e) {
			e.printStackTrace();
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> resume() {
		targetVM.vmStateChanged(TargetExecutionState.RUNNING, JdiReason.Reasons.RESUMED);
		invalidateAndContinue();
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		int size = StepRequest.STEP_MIN;
		int depth;
		switch (kind) {
			case INTO:
				depth = StepRequest.STEP_INTO;
				break;
			case LINE:
				depth = StepRequest.STEP_LINE;
				break;
			case FINISH:
			case ADVANCE:
				depth = StepRequest.STEP_OUT;
				break;
			case SKIP:
				depth = StepRequest.STEP_OVER;
				break;
			default:
				depth = StepRequest.STEP_MIN;
				break;
		}

		StepRequest request = eventManager.createStepRequest(thread, size, depth);
		request.enable();
		invalidateAndContinue();
		return CompletableFuture.completedFuture(null);
	}

	private void invalidateAndContinue() {
		targetVM.invalidateMemoryAndRegisterCaches();
		stack.invalidateRegisterCaches();
		registers.invalidateRegisterCaches();
		thread.resume();
		//EventSet.resume()?
	}

	public JdiModelTargetStack getStack() {
		return stack;
	}

	public Location getLocation() {
		return location == null ? null : location.location;
	}

	public void setLocation(Location location) {
		this.location = new JdiModelTargetLocation(this, location, false);
		Method method = location.method();
		impl.registerMethod(method);
	}

	@Override
	public void threadStarted(ThreadStartEvent evt, JdiCause cause) {
		threadSelected(evt.thread(), null, JdiCause.Causes.UNCLAIMED);
	}

	@Override
	public boolean isAccessible() {
		return thread.isSuspended();
	}
}
