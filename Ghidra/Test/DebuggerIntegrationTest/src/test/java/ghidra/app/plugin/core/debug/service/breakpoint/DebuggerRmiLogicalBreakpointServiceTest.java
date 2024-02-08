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

import static org.junit.Assert.assertEquals;

import java.util.*;

import org.junit.Before;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.time.TraceSnapshot;

public class DebuggerRmiLogicalBreakpointServiceTest extends
		AbstractDebuggerLogicalBreakpointServiceTest<TraceRmiTarget, TraceObjectMemoryRegion> {

	ToyDBTraceBuilder tb3;

	@Before
	public void setUpRmiBreakpointServiceTest() throws Throwable {
		createRmiConnection();
		addBreakpointMethods();
	}

	@Override
	protected void createTarget1() throws Throwable {
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		target1 = rmiCx.publishTarget(tool, tb.trace);
	}

	@Override
	protected void createTarget3() throws Throwable {
		tb3 = new ToyDBTraceBuilder("dynamic3-" + name.getMethodName(), LANGID_TOYBE64);
		try (Transaction tx = tb3.startTransaction()) {
			tb3.trace.getTimeManager().createSnapshot("Fist snapshot");
			tb3.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb3.createObjectsProcessAndThreads();
		}
		target3 = rmiCx.publishTarget(tool, tb3.trace);
	}

	@Override
	protected Trace getTrace(TraceRmiTarget target) {
		return target.getTrace();
	}

	@Override
	protected void simulateTargetStep(TraceRmiTarget target) throws Throwable {
		Trace trace = target.getTrace();
		TraceSnapshot snapshot;
		try (Transaction tx = trace.openTransaction("Simulate step")) {
			snapshot = trace.getTimeManager().createSnapshot("Simulated step");
		}
		rmiCx.setLastSnapshot(trace, snapshot.getKey());
	}

	@Override
	protected long getSnap(TraceRmiTarget target) {
		return target.getSnap();
	}

	@Override
	protected boolean isTargetValid(TraceRmiTarget target) {
		return target.isValid();
	}

	@Override
	protected TraceObjectMemoryRegion addTargetTextRegion(TraceRmiTarget target, long offset)
			throws Throwable {
		Trace trace = target.getTrace();
		try (Transaction tx = trace.openTransaction("Add .text")) {
			return Objects.requireNonNull(
				addMemoryRegion(trace.getObjectManager(), Lifespan.nowOn(target.getSnap()),
					tb.range(offset, offset + 0x0fff), "bin:.text", "rx")
							.queryInterface(TraceObjectMemoryRegion.class));
		}
	}

	@Override
	protected TraceObjectMemoryRegion addTargetTextRegion(TraceRmiTarget target) throws Throwable {
		return addTargetTextRegion(target, 0x55550000);
	}

	@Override
	protected TraceObjectMemoryRegion addTargetDataRegion(TraceRmiTarget target) throws Throwable {
		Trace trace = target.getTrace();
		long offset = 0x56550000;
		try (Transaction tx = trace.openTransaction("Add .data")) {
			return Objects.requireNonNull(
				addMemoryRegion(trace.getObjectManager(), Lifespan.nowOn(target.getSnap()),
					tb.range(offset, offset + 0x0fff), "bin:.data", "rw")
							.queryInterface(TraceObjectMemoryRegion.class));
		}
	}

	@Override
	protected void addTextMapping(TraceRmiTarget target, TraceObjectMemoryRegion text,
			Program program) throws Throwable {
		Trace trace = target.getTrace();
		try (Transaction tx = trace.openTransaction("Add .text mapping")) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(trace, null, text.getLifespan(), text.getMinAddress()),
				new ProgramLocation(program, addr(program, 0x00400000)), 0x1000,
				false);
		}
	}

	@Override
	protected void removeTextMapping(TraceRmiTarget target, Program p) throws Throwable {
		Trace t = target.getTrace();
		try (Transaction tx = t.openTransaction("Remove .text mapping")) {
			TraceStaticMapping mapping =
				t.getStaticMappingManager().findContaining(addr(t, 0x55550000), target.getSnap());
			mapping.delete();
		}
	}

	@Override
	protected void addTargetAccessBreakpoint(TraceRmiTarget target, TraceObjectMemoryRegion region)
			throws Throwable {
		Address min = region.getMinAddress().add(0x0123);
		Trace trace = target.getTrace();
		try (Transaction tx = trace.openTransaction("Add access breakpoint")) {
			addBreakpointAndLoc(trace.getObjectManager(), Lifespan.nowOn(target.getSnap()),
				tb.range(min, min), TraceBreakpointKindSet.ACCESS);
		}
		waitForDomainObject(trace);
	}

	@Override
	protected void addTargetSoftwareBreakpoint(TraceRmiTarget target,
			TraceObjectMemoryRegion region) throws Throwable {
		Address min = region.getMinAddress().add(0x0123);
		Trace trace = target.getTrace();
		try (Transaction tx = trace.openTransaction("Add software breakpoint")) {
			addBreakpointAndLoc(trace.getObjectManager(), Lifespan.nowOn(target.getSnap()),
				tb.range(min, min), TraceBreakpointKindSet.SW_EXECUTE);
		}
		waitForDomainObject(trace);
	}

	@Override
	protected void removeTargetSoftwareBreakpoint(TraceRmiTarget target) throws Throwable {
		Trace trace = target.getTrace();
		Lifespan nowOn = Lifespan.nowOn(target.getSnap());
		List<TraceObjectBreakpointLocation> locsToDel = trace.getBreakpointManager()
				.getAllBreakpoints()
				.stream()
				.filter(bp -> bp.getKinds().equals(TraceBreakpointKindSet.SW_EXECUTE))
				.filter(bp -> bp instanceof TraceObjectBreakpointLocation)
				.map(bp -> (TraceObjectBreakpointLocation) bp)
				.toList();
		List<TraceObjectBreakpointSpec> specsToDel =
			locsToDel.stream().map(bp -> bp.getSpecification()).distinct().toList();
		try (Transaction tx = trace.openTransaction("Delete software breakpoints")) {
			for (TraceObjectBreakpointLocation loc : locsToDel) {
				loc.getObject().remove(nowOn);
			}
			for (TraceObjectBreakpointSpec spec : specsToDel) {
				spec.getObject().remove(nowOn);
			}
		}
	}

	@Override
	protected void terminateTarget(TraceRmiTarget t) {
		t.forceTerminate();
	}

	@Override
	protected TraceBreakpoint findLoc(Set<TraceBreakpoint> locs, int index) {
		return locs.stream()
				.filter(b -> b.getName().equals(Integer.toString(index + 1)))
				.findAny()
				.orElseThrow();
	}

	@Override
	protected void handleToggleBreakpointInvocation(TraceBreakpoint expectedBreakpoint,
			boolean expectedEn) throws Throwable {
		if (!(expectedBreakpoint instanceof TraceObjectBreakpointLocation loc)) {
			throw new AssertionError("Unexpected trace breakpoint type: " + expectedBreakpoint);
		}
		Map<String, Object> args = rmiMethodToggleBreak.expect();
		try (Transaction tx = tb.startTransaction()) {
			loc.setEnabled(Lifespan.nowOn(0), expectedEn);
		}
		rmiMethodToggleBreak.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("breakpoint", loc.getSpecification().getObject()),
			Map.entry("enabled", expectedEn)), args);
	}

	@Override
	protected void handleDeleteBreakpointInvocation(TraceBreakpoint expectedBreakpoint)
			throws Throwable {
		if (!(expectedBreakpoint instanceof TraceObjectBreakpointLocation loc)) {
			throw new AssertionError("Unexpected trace breakpoint type: " + expectedBreakpoint);
		}
		Map<String, Object> args = rmiMethodDeleteBreak.expect();
		try (Transaction tx = tb.startTransaction()) {
			loc.getObject().remove(Lifespan.nowOn(0));
		}
		rmiMethodDeleteBreak.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("breakpoint", loc.getSpecification().getObject())), args);
	}
}
