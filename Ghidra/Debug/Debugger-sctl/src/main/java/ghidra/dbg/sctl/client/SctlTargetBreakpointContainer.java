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

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * TODO: Document me
 * 
 * TODO: Should this be a child of the process instead? Would be much easier than copying
 * breakpoints around, if in fact, one set of breaks is shared by all ctls of the same process.
 */
public class SctlTargetBreakpointContainer
		extends DefaultTargetObject<SctlTargetBreakpoint, SctlTargetThread>
		implements TargetBreakpointContainer<SctlTargetBreakpointContainer> {

	protected static final TargetBreakpointKindSet SOFTWARE_ONLY =
		TargetBreakpointKindSet.of(TargetBreakpointKind.SOFTWARE);

	protected final SctlClient client;

	private final Map<Long, SctlTargetBreakpoint> breaksByTrpid = new LinkedHashMap<>();

	public SctlTargetBreakpointContainer(SctlTargetThread thread) {
		super(thread.client, thread, "Breakpoints", "BreakpointContainer");
		this.client = thread.client;

		changeAttributes(List.of(), Map.of( //
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, SOFTWARE_ONLY //
		), "Initialized");
	}

	protected void put(long trpid, SctlTargetBreakpoint bpt) {
		synchronized (this) {
			breaksByTrpid.put(trpid, bpt);
		}
		changeElements(List.of(), List.of(bpt), "Placed");
	}

	protected void putAll(Map<Long, SctlTargetBreakpoint> map) {
		synchronized (this) {
			breaksByTrpid.putAll(map);
		}
		changeElements(List.of(), map.values(), "Placed");
	}

	protected Collection<SctlTargetBreakpoint> getAll() {
		return breaksByTrpid.values();
	}

	protected synchronized SctlTargetBreakpoint getByTrpid(long trpid) {
		return breaksByTrpid.get(trpid);
	}

	protected SctlTargetBreakpoint removeByTrpid(long trpid) {
		SctlTargetBreakpoint removed;
		synchronized (this) {
			removed = breaksByTrpid.remove(trpid);
		}
		if (removed != null) {
			changeElements(List.of(PathUtils.makeIndex(trpid)), List.of(), "Removed");
		}
		return removed;
	}

	protected void clear() {
		synchronized (this) {
			breaksByTrpid.clear();
		}
		setElements(List.of(), "Cleared");
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(String expression,
			Set<TargetBreakpointKind> kinds) {
		if (!Objects.equals(kinds, SOFTWARE_ONLY)) {
			throw new UnsupportedOperationException("SCTL supports software breakpoints only");
		}
		long offset;
		try {
			if (expression.startsWith("0x")) {
				offset = Long.parseLong(expression.substring(2), 16);
			}
			else {
				offset = Long.parseLong(expression, 10);
			}
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("SCTL requires address as 0x[hex] or [dec]");
		}
		Address address = client.addrMapper.mapOffsetToAddress(offset);
		return parent.setBreakpoint(address).thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(AddressRange range,
			Set<TargetBreakpointKind> kinds) {
		if (!Objects.equals(kinds, SOFTWARE_ONLY)) {
			throw new UnsupportedOperationException("SCTL supports software breakpoints only");
		}
		if (range.getLength() != 1) {
			throw new UnsupportedOperationException(
				"SCTL supports single-address breakpoints only");
		}
		return parent.setBreakpoint(range.getMinAddress()).thenApply(__ -> null);
	}

	public void breakpointHit(SctlTargetBreakpoint bpt) {
		listeners.fire(TargetBreakpointListener.class).breakpointHit(this, parent, null, bpt, bpt);
	}
}
