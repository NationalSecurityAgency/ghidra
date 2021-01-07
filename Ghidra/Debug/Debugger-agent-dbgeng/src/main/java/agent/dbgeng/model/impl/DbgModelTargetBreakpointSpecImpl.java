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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.model.iface2.DbgModelTargetBreakpointContainer;
import agent.dbgeng.model.iface2.DbgModelTargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;

@TargetObjectSchemaInfo(name = "BreakpointSpec", attributes = { //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class DbgModelTargetBreakpointSpecImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetBreakpointSpec {

	protected static String indexBreakpoint(DbgBreakpointInfo info) {
		return PathUtils.makeIndex(info.getNumber());
	}

	protected static String keyBreakpoint(DbgBreakpointInfo info) {
		return PathUtils.makeKey(indexBreakpoint(info));
	}

	protected DbgBreakpointInfo info;
	protected boolean enabled;

	public void changeAttributeSet(String reason) {
		this.changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "[" + info.getNumber() + "] " + info.getLocation(), //
			ADDRESS_ATTRIBUTE_NAME, doGetAddress(), //
			LENGTH_ATTRIBUTE_NAME, info.getSize(), //
			AFFECTS_ATTRIBUTE_NAME, doGetAffects(), //
			SPEC_ATTRIBUTE_NAME, this, //
			KINDS_ATTRIBUTE_NAME, getKinds() //
		), reason);
		this.changeAttributes(List.of(), List.of(), Map.of( //
			BPT_TYPE_ATTRIBUTE_NAME, info.getType().name(), //
			BPT_DISP_ATTRIBUTE_NAME, info.getDisp().name(), //
			BPT_PENDING_ATTRIBUTE_NAME, info.getPending(), //
			BPT_TIMES_ATTRIBUTE_NAME, info.getTimes(), //
			TargetObject.UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
		), reason);
	}

	private final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			}
		};

	public DbgModelTargetBreakpointSpecImpl(DbgModelTargetBreakpointContainer breakpoints,
			DbgBreakpointInfo info) {
		super(breakpoints.getModel(), breakpoints, keyBreakpoint(info), "BreakpointSpec");
		this.setBreakpointInfo(info);

		updateInfo(null, info, "Created");
	}

	public void updateInfo(DbgBreakpointInfo oldInfo, DbgBreakpointInfo newInfo, String reason) {
		synchronized (this) {
			assert oldInfo == getBreakpointInfo();
			setBreakpointInfo(newInfo);
		}
		changeAttributeSet("Refreshed");
		setEnabled(newInfo.isEnabled(), reason);
	}

	@Override
	public DbgBreakpointInfo getBreakpointInfo() {
		return info;
	}

	@Override
	public void setBreakpointId(String id) {
		throw new AssertionError();
	}

	@Override
	public void setBreakpointInfo(DbgBreakpointInfo info) {
		this.info = info;
	}

	/**
	 * Update the enabled field
	 * 
	 * This does not actually toggle the breakpoint. It just updates the field and calls the proper
	 * listeners. To actually toggle the breakpoint, use {@link #toggle(boolean)} instead, which if
	 * effective, should eventually cause this method to be called.
	 * 
	 * @param enabled true if enabled, false if disabled
	 * @param reason a description of the cause (not really used, yet)
	 */
	public void setEnabled(boolean enabled, String reason) {
		setBreakpointEnabled(enabled);
		changeAttributes(List.of(), List.of(), Map.of(ENABLED_ATTRIBUTE_NAME, enabled //
		), reason);
		getListeners().fire(TargetBreakpointSpecListener.class).breakpointToggled(this, enabled);
	}

	@Override
	public boolean isBreakpointEnabled() {
		return enabled;
	}

	@Override
	public void setBreakpointEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public ListenerSet<TargetBreakpointAction> getActions() {
		return actions;
	}

	protected CompletableFuture<DbgBreakpointInfo> getInfo() {
		return getManager().listBreakpoints()
				.thenApply(__ -> getManager().getKnownBreakpoints().get(getNumber()));
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getInfo().thenAccept(i -> {
			synchronized (this) {
				setBreakpointInfo(i);
			}
			changeAttributeSet("Initialized");
		});
	}

}
