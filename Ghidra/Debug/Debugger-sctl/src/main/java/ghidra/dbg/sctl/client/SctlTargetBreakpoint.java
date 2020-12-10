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
package ghidra.dbg.sctl.client;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointKindSet;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.ListenerSet;

public class SctlTargetBreakpoint
		extends DefaultTargetObject<SctlTargetBreakpoint, SctlTargetBreakpointContainer>
		implements TargetBreakpointSpec<SctlTargetBreakpoint>,
		TargetDeletable<SctlTargetBreakpoint>,
		TargetBreakpointLocation<SctlTargetBreakpoint> {

	protected static String keyBreakpoint(long trpid) {
		return PathUtils.makeKey(indexBreakpoint(trpid));
	}

	protected static String indexBreakpoint(long trpid) {
		return PathUtils.makeIndex(trpid);
	}

	protected final SctlClient client;
	protected final SctlTargetThread thread;

	protected final long trpid;
	protected final long offset;
	protected final Address address;
	protected final String expression;

	protected final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Strong references
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			};
		};
	protected boolean cleared = false;

	public SctlTargetBreakpoint(SctlTargetBreakpointContainer breakpoints, SctlTargetThread thread,
			long trpid, long offset) {
		super(breakpoints.client, breakpoints, keyBreakpoint(trpid), "Breakpoint");
		this.client = breakpoints.client;
		this.thread = thread;

		this.trpid = trpid;
		this.offset = offset;
		this.address = client.addrMapper.mapOffsetToAddress(offset);
		this.expression = "0x" + Long.toHexString(offset);

		/**
		 * TODO: Can AFFECTS be elided since the container exists in one thread? It's a conventional
		 * question we should consider for all implementations. If/when the container is moved to
		 * the process, does the idea still apply? Either way, it seems appropriate to have the
		 * affects attribute provide here, i.e., implement the convention in the breakpoint rather
		 * than everywhere else.
		 */
		changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, this,
			ADDRESS_ATTRIBUTE_NAME, address,
			LENGTH_ATTRIBUTE_NAME, 1,
			EXPRESSION_ATTRIBUTE_NAME, expression,
			KINDS_ATTRIBUTE_NAME, SctlTargetBreakpointContainer.SOFTWARE_ONLY,
			ENABLED_ATTRIBUTE_NAME, true //
		), "Initialized");
	}

	/**
	 * Duplicate this breakpoint into another thread's container
	 * 
	 * This list of actions is copied, but each action is copied by reference. Generally, actions
	 * are immutable. As a consequence, if a user adds an action to a copied breakpoint, that action
	 * does not get applied to the original breakpoint. Thus, when a thread is forked or cloned, its
	 * breakpoints are all copied, but adding an action to a breakpoint will only affect the
	 * breakpoint active on the designated thread. To affect all threads having that breakpoint, the
	 * action must be added explicitly to each copy.
	 * 
	 * @see SctlTargetThread#copyBreakpointsFrom(SctlTargetThread)
	 * @param that the breakpoint to copy
	 * @param to the container (of another thread) into which the copy will be placed
	 */
	protected SctlTargetBreakpoint(SctlTargetBreakpoint that, SctlTargetBreakpointContainer to) {
		this(to, that.thread, that.trpid, that.offset);
		this.actions.addAll(that.actions);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public Integer getLength() {
		return 1;
	}

	@Override
	public TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> getSpecification() {
		return this;
	}

	@Override
	public String getExpression() {
		return expression;
	}

	@Override
	public TargetBreakpointKindSet getKinds() {
		return SctlTargetBreakpointContainer.SOFTWARE_ONLY;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public void addAction(TargetBreakpointAction action) {
		if (cleared) {
			throw new IllegalStateException("Breakpoint is cleared");
		}
		actions.add(action);
	}

	@Override
	public void removeAction(TargetBreakpointAction action) {
		if (cleared) {
			throw new IllegalStateException("Breakpoint is cleared");
		}
		actions.remove(action);
	}

	@Override
	public CompletableFuture<Void> delete() {
		if (cleared) {
			return CompletableFuture
					.failedFuture(new IllegalStateException("Breakpoint is already cleared"));
		}
		actions.clear(); // Expedite gc
		return client.clearTrap(thread.ctlid, trpid);
	}

	@Override
	public CompletableFuture<Void> disable() {
		// SCTL breakpoints are always enabled, so disable by deleting
		// TODO: Consider keeping a record in the client, permitting it to be easily re-enabled.
		return delete();
	}

	@Override
	public CompletableFuture<Void> enable() {
		// SCTL breakpoints are always enabled, or they're absent
		return AsyncUtils.NIL;
	}

	protected void hit() {
		parent.breakpointHit(this);
		actions.fire.breakpointHit(this, thread, null, this);
	}
}
