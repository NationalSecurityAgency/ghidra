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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import db.Transaction;
import ghidra.async.AsyncUtils;
import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathMatcher;
import ghidra.util.exception.DuplicateNameException;

public record PlaceEmuBreakpointActionItem(Trace trace, long snap, Address address, long length,
		Set<TraceBreakpointKind> kinds, String emuSleigh) implements BreakpointActionItem {

	public static String createName(Address address) {
		return "emu-" + address;
	}

	public PlaceEmuBreakpointActionItem(Trace trace, long snap, Address address, long length,
			Set<TraceBreakpointKind> kinds, String emuSleigh) {
		this.trace = trace;
		this.snap = snap;
		this.address = address;
		this.length = length;
		this.kinds = Set.copyOf(kinds);
		this.emuSleigh = emuSleigh;
	}

	private TraceObjectMemoryRegion findRegion() {
		TraceMemoryRegion region = trace.getMemoryManager().getRegionContaining(snap, address);
		if (region != null) {
			return (TraceObjectMemoryRegion) region;
		}
		AddressSpace space = address.getAddressSpace();
		Collection<? extends TraceMemoryRegion> regionsInSpace = trace.getMemoryManager()
				.getRegionsIntersecting(Lifespan.at(snap),
					new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress()));
		if (!regionsInSpace.isEmpty()) {
			return (TraceObjectMemoryRegion) regionsInSpace.iterator().next();
		}
		return null;
	}

	private TraceObject findBreakpointContainer() {
		TraceObjectMemoryRegion region = findRegion();
		if (region == null) {
			throw new IllegalArgumentException("Address does not belong to a memory in the trace");
		}
		return region.getObject()
				.findSuitableContainerInterface(TraceObjectBreakpointSpec.class);
	}

	private String computePath() {
		String name = createName(address);
		if (Trace.isLegacy(trace)) {
			return "Breakpoints[" + name + "]";
		}
		TraceObject container = findBreakpointContainer();
		if (container == null) {
			throw new IllegalArgumentException(
				"Address is not associated with a breakpoint container");
		}
		PathMatcher specMatcher =
			container.getSchema().searchFor(TraceObjectBreakpointSpec.class, true);
		if (specMatcher == null) {
			throw new IllegalArgumentException("Cannot find path to breakpoint specifications");
		}
		KeyPath specRelPath = specMatcher.applyKeys(name).getSingletonPath();
		if (specRelPath == null) {
			throw new IllegalArgumentException("Too many wildcards to breakpoint specification");
		}
		PathMatcher locMatcher = container.getSchema()
				.getSuccessorSchema(specRelPath)
				.searchFor(TraceObjectBreakpointLocation.class, true);
		if (locMatcher == null) {
			throw new IllegalArgumentException("Cannot find path to breakpoint locations");
		}
		KeyPath locRelPath = locMatcher.applyIntKeys(0).getSingletonPath();
		if (locRelPath == null) {
			throw new IllegalArgumentException("Too many wildcards to breakpoint location");
		}
		return container.getCanonicalPath().extend(specRelPath).extend(locRelPath).toString();
	}

	@Override
	public CompletableFuture<Void> execute() {
		try (Transaction tx = trace.openTransaction("Place Emulated Breakpoint")) {
			// Defaults with emuEnable=true
			TraceBreakpoint bpt = trace.getBreakpointManager()
					.addBreakpoint(computePath(), Lifespan.at(snap),
						BreakpointActionItem.range(address, length), Set.of(), kinds, false, null);
			bpt.setName(createName(address));
			bpt.setEmuSleigh(emuSleigh);
			return AsyncUtils.nil();
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e);
		}
	}
}
