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
import java.util.stream.Collectors;

import agent.gdb.manager.breakpoint.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetDeletable;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "BreakpointSpec",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetBreakpointSpec extends
		DefaultTargetObject<GdbModelTargetBreakpointLocation, GdbModelTargetBreakpointContainer>
		implements TargetBreakpointSpec, TargetDeletable {

	protected static String indexBreakpoint(GdbBreakpointInfo info) {
		return PathUtils.makeIndex(info.getNumber());
	}

	protected static String keyBreakpoint(GdbBreakpointInfo info) {
		return PathUtils.makeKey(indexBreakpoint(info));
	}

	protected final GdbModelImpl impl;
	protected final long number;
	protected GdbBreakpointInfo info;
	protected boolean enabled;
	protected String expression;
	protected String display;
	protected TargetBreakpointKindSet kinds;

	protected final Map<Long, GdbModelTargetBreakpointLocation> breaksBySub =
		new WeakValueHashMap<>();
	protected final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			};
		};

	public GdbModelTargetBreakpointSpec(GdbModelTargetBreakpointContainer breakpoints,
			GdbBreakpointInfo info) {
		super(breakpoints.impl, breakpoints, keyBreakpoint(info), "BreakpointSpec");
		this.impl = breakpoints.impl;
		this.number = info.getNumber();
		this.info = info;
		impl.addModelObject(info, this);

		changeAttributes(List.of(), Map.of(CONTAINER_ATTRIBUTE_NAME, breakpoints), "Initialized");
	}

	protected CompletableFuture<Void> init() {
		return updateInfo(info, info, "Created").exceptionally(ex -> {
			Msg.info(this, "Initial breakpoint info update failed", ex);
			return null;
		});
	}

	@Override
	public CompletableFuture<Void> delete() {
		return impl.gateFuture(impl.gdb.deleteBreakpoints(number));
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	@Override
	public String getExpression() {
		return expression;
	}

	protected TargetBreakpointKindSet computeKinds(GdbBreakpointInfo from) {
		switch (from.getType()) {
			case BREAKPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE);
			case HW_BREAKPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.HW_EXECUTE);
			case HW_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.WRITE);
			case READ_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.READ);
			case ACCESS_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.READ,
					TargetBreakpointKind.WRITE);
			default:
				return TargetBreakpointKindSet.of();
		}
	}

	@Override
	public TargetBreakpointKindSet getKinds() {
		return kinds;
	}

	@Override
	public void addAction(TargetBreakpointAction action) {
		actions.add(action);
	}

	@Override
	public void removeAction(TargetBreakpointAction action) {
		actions.remove(action);
	}

	protected CompletableFuture<GdbBreakpointInfo> getInfo(boolean refresh) {
		if (!refresh) {
			return CompletableFuture.completedFuture(impl.gdb.getKnownBreakpoints().get(number));
		}
		return impl.gdb.listBreakpoints()
				.thenApply(__ -> impl.gdb.getKnownBreakpoints().get(number));
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getInfo(refresh).thenCompose(i -> {
			return updateInfo(info, i, "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> disable() {
		return impl.gateFuture(impl.gdb.disableBreakpoints(number));
	}

	@Override
	public CompletableFuture<Void> enable() {
		return impl.gateFuture(impl.gdb.enableBreakpoints(number));
	}

	protected CompletableFuture<Void> updateInfo(GdbBreakpointInfo oldInfo,
			GdbBreakpointInfo newInfo, String reason) {
		if (newInfo.getType().isWatchpoint()) {
			return updateWptInfo(oldInfo, newInfo, reason);
		}
		else {
			return updateBktpInfo(oldInfo, newInfo, reason);
		}
	}

	protected void updateAttributesFromInfo(String reason) {
		changeAttributes(List.of(), Map.of(
			ENABLED_ATTRIBUTE_NAME, enabled = info.isEnabled(),
			EXPRESSION_ATTRIBUTE_NAME,
			expression = info.getType() == GdbBreakpointType.CATCHPOINT ? info.getCatchType()
					: info.getOriginalLocation(),
			KINDS_ATTRIBUTE_NAME, kinds = computeKinds(info),
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay()),
			reason);
	}

	protected synchronized List<GdbModelTargetBreakpointLocation> setInfoAndComputeLocations(
			GdbBreakpointInfo oldInfo, GdbBreakpointInfo newInfo) {
		if (oldInfo != this.info) {
			Msg.error(this, "Manager and model breakpoint info was/is out of sync!");
		}
		this.info = newInfo;
		List<GdbModelTargetBreakpointLocation> effectives = newInfo.getLocations()
				.stream()
				.filter(l -> !"<PENDING>".equals(l.getAddr()))
				.map(this::getTargetBreakpointLocation)
				.collect(Collectors.toList());
		breaksBySub.keySet()
				.retainAll(
					effectives.stream().map(e -> e.loc.getSub()).collect(Collectors.toSet()));
		return effectives;
	}

	protected CompletableFuture<Void> updateBktpInfo(GdbBreakpointInfo oldInfo,
			GdbBreakpointInfo newInfo, String reason) {
		List<GdbModelTargetBreakpointLocation> locs = setInfoAndComputeLocations(oldInfo, newInfo);
		updateAttributesFromInfo(reason);
		setElements(locs, reason);
		return AsyncUtils.NIL;
	}

	protected CompletableFuture<Void> updateWptInfo(GdbBreakpointInfo oldInfo,
			GdbBreakpointInfo newInfo, String reason) {
		List<GdbModelTargetBreakpointLocation> locs = setInfoAndComputeLocations(oldInfo, newInfo);
		updateAttributesFromInfo(reason);
		assert locs.size() == 1;
		return locs.get(0).initWpt().thenAccept(__ -> {
			setElements(locs, reason);
		});
	}

	protected GdbModelTargetBreakpointLocation findLocation(GdbModelTargetStackFrame frame) {
		for (GdbModelTargetBreakpointLocation bp : breaksBySub.values()) {
			// TODO: Is this necessary?
			/*if (bp.range.contains(frame.pc)) {
				continue;
			}*/
			if (!bp.loc.getInferiorIds().contains(frame.inferior.inferior.getId())) {
				continue;
			}
			return bp;
		}
		return null;
	}

	protected void breakpointHit(GdbModelTargetStackFrame frame,
			GdbModelTargetBreakpointLocation eb) {
		actions.fire.breakpointHit(this, frame.thread, frame, eb);
	}

	public synchronized GdbModelTargetBreakpointLocation getTargetBreakpointLocation(
			GdbBreakpointLocation loc) {
		return breaksBySub.computeIfAbsent(loc.getSub(),
			i -> new GdbModelTargetBreakpointLocation(this, loc));
	}

	protected String addressFromInfo() {
		if (info.getAddress() != null) {
			return info.getAddress();
		}
		List<GdbBreakpointLocation> locs = info.getLocations();
		if (locs.isEmpty()) {
			return "<PENDING>";
		}
		if (locs.size() == 1) {
			String addr = locs.get(0).getAddr();
			if (addr == null) {
				return "<PENDING>";
			}
			return addr;
		}
		return "<MULTIPLE>";
	}

	protected String computeDisplay() {
		Object enb = info.isEnabled() ? "y" : "n";
		String addr = addressFromInfo();
		String what = info.getWhat() == null ? "" : info.getWhat();
		switch (info.getType()) {
			case ACCESS_WATCHPOINT:
			case HW_WATCHPOINT:
			case READ_WATCHPOINT:
			case BREAKPOINT:
			case HW_BREAKPOINT:
			case OTHER:
				return String.format("%d %s %s %s %s %s", info.getNumber(), info.getTypeName(),
					info.getDisp(), enb, addr, what).trim();
			case CATCHPOINT:
				return String.format("%d %s %s %s %s", info.getNumber(), info.getTypeName(),
					info.getDisp(), enb, what).trim();
			case DPRINTF:
				// TODO: script?
				return String.format("%d %s %s %s %s %s", info.getNumber(), info.getTypeName(),
					info.getDisp(), enb, addr, what).trim();
		}
		throw new AssertionError();
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public GdbModelTargetBreakpointContainer getContainer() {
		return parent;
	}
}
